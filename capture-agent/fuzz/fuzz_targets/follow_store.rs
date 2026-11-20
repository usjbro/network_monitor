#![no_main]
use std::collections::HashMap;

use capture_agent::flow::FlowKey;
use capture_agent::follow::{
    Classification, Direction, FollowSegment, FollowStore, Generation, MAX_DIRECTION_BYTES, MAX_FLOWS,
    MAX_TOTAL_BYTES,
};
use capture_agent::follow_response::{
    encode_stream_data, new_output, MAX_STREAM_DATA_LINE_BYTES, PAGE_DATA_BYTES, PAGE_GAPS, PAGE_RANGES, PAGE_TURNS,
};
use capture_agent::parse::TransportProtocol;
use capture_agent::wire::StreamRequest;
use libfuzzer_sys::fuzz_target;

/// More keys than the store retains, so flow-cap eviction is reachable.
const KEYS: u16 = MAX_FLOWS as u16 + 44;

fn key(n: u16) -> FlowKey {
    FlowKey {
        protocol: TransportProtocol::Tcp,
        local_addr: "192.168.1.10".to_string(),
        local_port: 40_000 + n,
        remote_addr: "93.184.216.34".to_string(),
        remote_port: 80,
    }
}

/// Seeds for the shapes the store must handle exactly: TLS headers (whole
/// and split), credential and folded headers, and an upgrade line.
const SEEDS: &[&[u8]] = &[
    b"\x16\x03\x01\x00\x30\x01\x00\x00\x2c\x03\x03",
    b"\x17\x03\x03\x00\x05hello\x17\x03\x03\x00\x01x",
    b"\x16\x03",
    b"\x01\x00\x05",
    b"Authorization: Bearer s3cr3t\r\n",
    b"X-Custom-Auth:\r\n",
    b" Bearer secret\r\n",
    b"Cookie: a=b\r\nHost: x\r\n\r\n",
    b"STARTTLS\r\n",
    b"GET / HTTP/1.1\r\n",
];

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn byte(&mut self) -> Option<u8> {
        let (&b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(b)
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes([self.byte()?, self.byte()?]))
    }

    fn take(&mut self, n: usize) -> &[u8] {
        let (head, rest) = self.0.split_at(n.min(self.0.len()));
        self.0 = rest;
        head
    }
}

fn direction(i: usize) -> Direction {
    if i == 0 {
        Direction::C2s
    } else {
        Direction::S2c
    }
}

/// Checks one flow's emission against what it emitted before. Within one
/// generation, emitted bytes are immutable: they may only grow. The single
/// exception is a flow found to be TLS from its first byte (D3), which drops
/// everything, including the other direction's earlier cleartext.
fn check_flow(store: &FollowStore, n: u16, seen: &mut HashMap<(u16, usize), (Generation, Vec<u8>)>, buf: &mut [u8]) {
    let id = key(n).connection_id();
    store.with_entry(&id, |entry| {
        let Some(entry) = entry else {
            seen.remove(&(n, 0));
            seen.remove(&(n, 1));
            return;
        };
        for i in 0..2 {
            let d = entry.direction(direction(i));
            let len = entry.copy_masked(direction(i), 0, u32::MAX, buf);
            assert_eq!(len as u32, d.emittable, "copy_masked disagrees with the horizon");
            assert!(d.stored_bytes <= MAX_DIRECTION_BYTES);
            match d.classification {
                Classification::Pending => assert_eq!(len, 0, "pending bytes emitted"),
                Classification::Tls => assert!(len as u32 <= d.tls_from.unwrap_or(0), "TLS bytes emitted"),
                Classification::Cleartext => {}
            }
            for r in d.redacted_ranges {
                let end = (r.start + r.len).min(len as u32);
                if r.start < end {
                    assert!(buf[r.start as usize..end as usize].iter().all(|&b| b == b'*'), "a masked byte was emitted");
                }
            }
            let dropped = d.classification == Classification::Tls && d.tls_from.is_none();
            let generation = entry.generation();
            match seen.get(&(n, i)) {
                Some((g, before)) if *g == generation && !dropped => {
                    assert!(len >= before.len(), "emitted bytes shrank");
                    assert_eq!(&buf[..before.len()], &before[..], "emitted bytes changed");
                }
                _ => {}
            }
            seen.insert((n, i), (generation, buf[..len].to_vec()));
        }
    });
}

/// KAN-110 Task 3c-2: pages flow `n` through the response builder from
/// `start` (one direction's offset; the other starts at 0) to the end. Every
/// line fits the ceiling; every page progresses and keeps its metadata
/// limits; and the pages' bytes, joined, are exactly what `copy_masked`
/// emits, so no pending, TLS or masked byte can be paged out.
fn check_pages(store: &FollowStore, n: u16, start: u32, turns_from: u32, buf: &mut [u8]) {
    let id = key(n).connection_id();
    // A wrong relay port or a stale generation is answered without content.
    let mut out = new_output();
    for (generation, relay_port) in [(None, Some(3001)), (Some((2, 0)), Some(3000))] {
        let request = StreamRequest {
            request_id: "0".repeat(32),
            connection_id: id.clone(),
            generation,
            c2s_offset: 0,
            s2c_offset: 0,
            turns_from,
            relay_port,
        };
        encode_stream_data(Some(store), &request, Some(3000), &mut out).expect("a content-free reply fits");
        let reply: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");
        for name in ["clientToServer", "serverToClient"] {
            assert_eq!(reply["directions"][name]["dataBase64"], "", "content in a refused reply");
        }
        assert!(reply["turns"].as_array().is_none_or(|t| t.is_empty()), "turns in a refused reply");
    }
    let Some(emitted) = store.with_entry(&id, |entry| {
        entry.map(|entry| {
            [Direction::C2s, Direction::S2c].map(|d| {
                let len = entry.copy_masked(d, 0, u32::MAX, buf);
                buf[..len].to_vec()
            })
        })
    }) else {
        return;
    };
    let mut offsets = [start.min(emitted[0].len() as u32), 0];
    let mut joined = [emitted[0][..offsets[0] as usize].to_vec(), Vec::new()];
    for _ in 0..=(2 * capture_agent::follow::MAX_DIRECTION_BYTES / 1024 + 4) {
        let request = StreamRequest {
            request_id: "0".repeat(32),
            connection_id: id.clone(),
            generation: None,
            c2s_offset: offsets[0],
            s2c_offset: offsets[1],
            turns_from,
            relay_port: Some(3000),
        };
        encode_stream_data(Some(store), &request, Some(3000), &mut out).expect("a reply always fits");
        assert!(out.len() <= MAX_STREAM_DATA_LINE_BYTES && out.last() == Some(&b'\n'), "line ceiling");
        let reply: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");
        assert!(reply["turns"].as_array().unwrap().len() <= PAGE_TURNS);
        let mut moved = false;
        for (i, name) in ["clientToServer", "serverToClient"].into_iter().enumerate() {
            let page = &reply["directions"][name];
            let (offset, next) = (page["offset"].as_u64().unwrap() as u32, page["nextOffset"].as_u64().unwrap() as u32);
            assert_eq!(offset, offsets[i]);
            let data = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, page["dataBase64"].as_str().unwrap())
                .unwrap();
            assert_eq!(data.len() as u32, next - offset);
            assert!(data.len() <= PAGE_DATA_BYTES as usize);
            assert!(page["gaps"].as_array().unwrap().len() <= PAGE_GAPS);
            assert!(page["redactedRanges"].as_array().unwrap().len() <= PAGE_RANGES);
            if (offset as usize) < emitted[i].len() {
                assert!(next > offset, "a page with bytes left made no progress");
            }
            joined[i].extend_from_slice(&data);
            moved |= next > offset;
            offsets[i] = next;
        }
        if !moved {
            break;
        }
    }
    assert_eq!(joined, emitted, "paged bytes differ from the masked emission");
}

fuzz_target!(|data: &[u8]| {
    // JAM-17 / KAN-110 Task 1. Arbitrary segments, timing and lifecycle
    // operations must never panic, never exceed the reserved-capacity and
    // flow caps, never emit pending, TLS or masked bytes, and never change a
    // byte already emitted.
    let mut input = Reader(data);
    let mut store = FollowStore::new(1);
    let mut now_ms = 0u64;
    let mut cursor: HashMap<(u16, bool), u32> = HashMap::new();
    let mut seen = HashMap::new();
    let mut buf = vec![0u8; MAX_DIRECTION_BYTES as usize];
    let mut ops = 0;
    while let Some(op) = input.byte() {
        ops += 1;
        if ops > 512 {
            break;
        }
        match op % 9 {
            0..=2 => {
                // A segment: flow, side, flags, a sequence delta from the
                // side's cursor (so data is mostly near the edge, sometimes
                // behind it, ahead of it, or across a u32 wrap), and payload.
                let Some(n) = input.u16() else { break };
                let n = n % KEYS;
                let Some(flags) = input.byte() else { break };
                let Some(delta) = input.u16() else { break };
                let Some(len) = input.byte() else { break };
                let outbound = flags & 1 != 0;
                let payload: Vec<u8> = match op % 8 {
                    0 => input.take(usize::from(len)).to_vec(),
                    1 => SEEDS[usize::from(len) % SEEDS.len()].to_vec(),
                    // Large fills reach the direction and global caps.
                    _ => vec![b'a' + (len % 26); usize::from(len) * 1024],
                };
                let base = *cursor.entry((n, outbound)).or_insert(u32::from(delta) << 16);
                let seq = base.wrapping_add(i32::from(delta as i16) as u32 >> (flags >> 6));
                // Acknowledge near the other side's cursor, so an RST from a
                // side that sent nothing is reachable (KAN-292).
                let peer = cursor.get(&(n, !outbound)).copied().unwrap_or(0);
                let segment = FollowSegment {
                    seq,
                    ack_number: peer.wrapping_add(u32::from(len) >> (flags >> 6)),
                    syn: flags & 2 != 0,
                    ack: flags & 4 != 0,
                    fin: flags & 8 != 0,
                    rst: flags & 16 == 16 && flags & 32 == 32,
                    payload: &payload,
                    now_ms,
                };
                store.ingest(&key(n), outbound, segment);
                let consumed = payload.len() as u32 + u32::from(segment.syn) + u32::from(segment.fin);
                cursor.insert((n, outbound), seq.wrapping_add(consumed));
                check_flow(&store, n, &mut seen, &mut buf);
            }
            3 => {
                let Some(step) = input.byte() else { break };
                now_ms += u64::from(step) * 32;
                store.tick(now_ms);
            }
            4 => store.note_frame_cut_at_snaplen(now_ms),
            5 => {
                let Some(n) = input.u16() else { break };
                store.drop_flow(&key(n % KEYS));
            }
            6 => {
                store.reset();
                seen.clear();
            }
            7 => {
                for n in 0..KEYS {
                    check_flow(&store, n, &mut seen, &mut buf);
                }
            }
            _ => {
                let Some(n) = input.u16() else { break };
                let Some(start) = input.u16() else { break };
                let Some(turns_from) = input.u16() else { break };
                check_pages(&store, n % KEYS, u32::from(start) * 4, u32::from(turns_from), &mut buf);
            }
        }
        store.audit().expect("store invariants");
        assert!(store.reserved_bytes() <= MAX_TOTAL_BYTES, "global reserved-capacity cap breached");
        assert!(store.flow_count() <= MAX_FLOWS, "flow cap breached");
    }
    store.reset();
    store.audit().expect("store invariants after reset");
});
