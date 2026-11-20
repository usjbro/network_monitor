//! KAN-110 Task 3b (JAM-17): one `stream_data` reply from the Follow Stream
//! store, built against a hard ceiling on the whole encoded line (spec D4).
//!
//! Per direction a page carries at most 32 KiB of stored bytes, 128 gaps and
//! 128 redacted ranges; per reply at most 256 turns. Metadata is never
//! dropped to fit: a page whose window holds more is shortened, and its
//! `nextOffset` says where to continue. The line is written through a writer
//! that refuses to pass `MAX_STREAM_DATA_LINE_BYTES`, into a buffer the
//! caller preallocates to exactly that size, so serde can never grow it.
//! Every byte buffer here zeroizes when dropped.

use crate::follow::{Classification, Direction, FollowDirection, FollowEntry, FollowStore, GapReason, MaskReason, StopReason, Turn};
use crate::wire::{
    render_generation, StreamDataJson, StreamDirectionsJson, StreamGapJson, StreamLastTurnJson, StreamMaskJson,
    StreamPageJson, StreamRequest, StreamTurnJson,
};
use base64::Engine;
use std::io::{self, Write};
use zeroize::{Zeroize, Zeroizing};

/// The whole encoded line, LF included.
pub const MAX_STREAM_DATA_LINE_BYTES: usize = 192 * 1024;
pub const PAGE_DATA_BYTES: u32 = 32 * 1024;
pub const PAGE_GAPS: usize = 128;
pub const PAGE_RANGES: usize = 128;
pub const PAGE_TURNS: usize = 256;
const PAGE_BASE64_BYTES: usize = (PAGE_DATA_BYTES as usize).div_ceil(3) * 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamResponseError {
    /// The line would pass the ceiling. A bug by spec D4's arithmetic; the
    /// output is zeroized and nothing should be sent.
    TooLarge,
    /// The store copied fewer bytes than the page planned. A bug; rather
    /// than send metadata for bytes it does not carry, nothing is sent.
    ShortCopy,
}

/// A reply buffer with exactly the ceiling's capacity.
pub fn new_output() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(Vec::with_capacity(MAX_STREAM_DATA_LINE_BYTES))
}

/// Writes the `stream_data` line, LF included, for `request` into `output`.
/// `store` is `None` when Follow Stream is off; `relay_port` is the port the
/// agent excludes. Checks run in plan order: disabled, then the relay's
/// reported port (plan P2) before any entry is looked up, then the entry
/// and its generation. Only a found, current entry yields content.
pub fn encode_stream_data(
    store: Option<&FollowStore>,
    request: &StreamRequest,
    relay_port: Option<u16>,
    output: &mut Zeroizing<Vec<u8>>,
) -> Result<(), StreamResponseError> {
    let Some(store) = store else {
        return write_line(&content_free(request, false), output);
    };
    if relay_port.is_none() || request.relay_port != relay_port {
        let mut reply = content_free(request, true);
        reply.unavailable = Some("relay_port_mismatch");
        return write_line(&reply, output);
    }
    store.with_entry(&request.connection_id, |entry| {
        let Some(entry) = entry else {
            return write_line(&content_free(request, true), output);
        };
        let generation = entry.generation();
        let current = (generation.epoch, generation.counter);
        if request.generation.is_some_and(|g| g != current) {
            let mut reply = content_free(request, true);
            reply.found = true;
            reply.stale = true;
            reply.generation = Some(render_generation(current));
            return write_line(&reply, output);
        }
        encode_entry(entry, request, output)
    })
}

/// A content-free reply saying the agent is busy (Task 3c's writer budget).
pub fn encode_stream_busy(request: &StreamRequest, output: &mut Zeroizing<Vec<u8>>) -> Result<(), StreamResponseError> {
    let mut reply = content_free(request, true);
    reply.busy = Some(true);
    write_line(&reply, output)
}

fn content_free(request: &StreamRequest, enabled: bool) -> StreamDataJson<'_> {
    StreamDataJson {
        kind: "stream_data",
        request_id: &request.request_id,
        connection_id: &request.connection_id,
        enabled,
        found: false,
        stale: false,
        generation: None,
        flow_start_captured: false,
        closed: false,
        client_is_local: None,
        directions: StreamDirectionsJson {
            client_to_server: StreamPageJson::empty(),
            server_to_client: StreamPageJson::empty(),
        },
        turns_from: request.turns_from,
        turns_next: None,
        last_turn: None,
        turns: Vec::new(),
        busy: None,
        unavailable: None,
    }
}

fn encode_entry(entry: &FollowEntry, request: &StreamRequest, output: &mut Zeroizing<Vec<u8>>) -> Result<(), StreamResponseError> {
    let mut raw = Zeroizing::new(vec![0u8; PAGE_DATA_BYTES as usize]);
    let mut c2s_b64 = Zeroizing::new(vec![0u8; PAGE_BASE64_BYTES]);
    let mut s2c_b64 = Zeroizing::new(vec![0u8; PAGE_BASE64_BYTES]);
    let c2s = page(entry, Direction::C2s, request.c2s_offset, &mut raw, &mut c2s_b64)?;
    let s2c = page(entry, Direction::S2c, request.s2c_offset, &mut raw, &mut s2c_b64)?;

    let all = entry.turns();
    let from = (request.turns_from as usize).min(all.len());
    let to = (from + PAGE_TURNS).min(all.len());
    let generation = entry.generation();
    let reply = StreamDataJson {
        kind: "stream_data",
        request_id: &request.request_id,
        connection_id: &request.connection_id,
        enabled: true,
        found: true,
        stale: false,
        generation: Some(render_generation((generation.epoch, generation.counter))),
        flow_start_captured: entry.flow_start_captured(),
        closed: entry.closed(),
        client_is_local: entry.client_is_local(),
        directions: StreamDirectionsJson { client_to_server: c2s, server_to_client: s2c },
        turns_from: request.turns_from,
        turns_next: (to < all.len()).then_some(to as u32),
        last_turn: all.last().map(|t| StreamLastTurnJson { index: (all.len() - 1) as u32, turn: turn_json(t) }),
        turns: all[from..to].iter().map(turn_json).collect(),
        busy: None,
        unavailable: None,
    };
    write_line(&reply, output)
}

/// One direction's page, its masked bytes base64-encoded into `b64`.
fn page<'a>(
    entry: &FollowEntry,
    dir: Direction,
    offset: u32,
    raw: &mut [u8],
    b64: &'a mut [u8],
) -> Result<StreamPageJson<'a>, StreamResponseError> {
    let view = entry.direction(dir);
    let plan = plan_page(&view, offset);
    let n = entry.copy_masked(dir, offset, plan.end, raw);
    if n as u32 != plan.end.saturating_sub(offset) {
        raw[..n].zeroize();
        return Err(StreamResponseError::ShortCopy);
    }
    let len = base64::engine::general_purpose::STANDARD
        .encode_slice(&raw[..n], b64)
        .expect("a page's base64 fits its scratch");
    raw[..n].zeroize();
    Ok(StreamPageJson {
        classification: match view.classification {
            Classification::Pending => "pending",
            Classification::Cleartext => "cleartext",
            Classification::Tls => "tls",
        },
        tls_from: view.tls_from,
        offset,
        next_offset: offset + n as u32,
        stored_bytes: view.stored_bytes,
        seen_bytes: view.seen_bytes,
        stopped_reason: view.stopped.map(|s| match s {
            StopReason::StoreCap => "store_cap",
            StopReason::GapLimit => "gap_limit",
            StopReason::TurnLimit => "turn_limit",
            StopReason::RedactionLimit => "redaction_limit",
        }),
        gaps: plan.gaps,
        conflicting_overlap_bytes: view.conflicting_overlap_bytes,
        redacted_ranges: plan.ranges,
        data_base64: std::str::from_utf8(&b64[..len]).expect("base64 is ASCII"),
    })
}

/// Where a page ends and the metadata it carries.
#[derive(Debug, PartialEq)]
struct PagePlan {
    end: u32,
    gaps: Vec<StreamGapJson>,
    ranges: Vec<StreamMaskJson>,
}

/// The page `[offset, end)`. Data stops at the emission horizon. A gap
/// belongs to the page holding its offset. One at the very end belongs to
/// the empty page that starts there, and only once nothing more can follow
/// it, so no gap is sent on two pages with different offsets (a page cut
/// short by the gap limit can end exactly there). Gaps at one offset are
/// merged, so a page always ends past its offset when it is shortened to
/// fit the metadata limits.
fn plan_page(view: &FollowDirection<'_>, offset: u32) -> PagePlan {
    let horizon = view.emittable;
    if offset > horizon {
        return PagePlan { end: offset, gaps: Vec::new(), ranges: Vec::new() };
    }
    let mut end = offset.saturating_add(PAGE_DATA_BYTES).min(horizon);
    // The empty page at the end of a direction that can no longer grow.
    let at_the_end = offset == horizon && horizon == view.stored_bytes && (view.closed || view.stopped.is_some());

    let mut gaps = Vec::new();
    let mut i = view.gaps.partition_point(|g| g.at < offset);
    while let Some(g) = view.gaps.get(i) {
        let at = g.at;
        if at > end || (at == end && !at_the_end) {
            break;
        }
        if gaps.len() == PAGE_GAPS {
            end = at;
            break;
        }
        let (mut missing, mut snaplen) = (0u32, true);
        while let Some(g) = view.gaps.get(i).filter(|g| g.at == at) {
            missing = missing.saturating_add(g.missing);
            snaplen &= g.reason == GapReason::SnaplenLikely;
            i += 1;
        }
        // A merged hole claims snaplen only if every part did.
        gaps.push(StreamGapJson { at, missing, reason: if snaplen { "snaplen_likely" } else { "missing" } });
    }

    let mut ranges: Vec<StreamMaskJson> = Vec::new();
    let first = view.redacted_ranges.partition_point(|r| r.start + r.len <= offset);
    for r in &view.redacted_ranges[first..] {
        if r.start >= end {
            break;
        }
        if ranges.len() == PAGE_RANGES {
            // Now short of the horizon, so a gap here waits for the next page.
            end = r.start;
            gaps.retain(|g| g.at < end);
            break;
        }
        let start = r.start.max(offset);
        ranges.push(StreamMaskJson {
            start,
            len: (r.start + r.len).min(end) - start,
            reason: match r.reason {
                MaskReason::Credential => "credential",
                MaskReason::Uncertain => "uncertain",
            },
        });
    }
    PagePlan { end, gaps, ranges }
}

fn turn_json(t: &Turn) -> StreamTurnJson {
    StreamTurnJson {
        dir: match t.dir {
            Direction::C2s => "c2s",
            Direction::S2c => "s2c",
        },
        start: t.start,
        len: t.len,
        first_seen_ms: t.first_seen_ms,
    }
}

/// Refuses any write past the ceiling, so `output` never reallocates.
struct Bounded<'a>(&'a mut Vec<u8>);

impl Write for Bounded<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.0.len() + buf.len() > MAX_STREAM_DATA_LINE_BYTES {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "stream_data over its ceiling"));
        }
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn write_line(reply: &StreamDataJson<'_>, output: &mut Zeroizing<Vec<u8>>) -> Result<(), StreamResponseError> {
    // Every byte ever written lies below the previous length: every exit
    // leaves it zeroed or as the line just written.
    output.as_mut_slice().zeroize();
    output.clear();
    if output.capacity() < MAX_STREAM_DATA_LINE_BYTES {
        output.reserve_exact(MAX_STREAM_DATA_LINE_BYTES);
    }
    let mut w = Bounded(output);
    let written = serde_json::to_writer(&mut w, reply).is_ok() && w.write_all(b"\n").is_ok();
    if !written {
        output.as_mut_slice().zeroize();
        output.clear();
        return Err(StreamResponseError::TooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::FlowKey;
    use crate::follow::{FollowSegment, Gap, MaskRange, CLASSIFY_MS, REORDER_BYTES};
    use crate::parse::TransportProtocol;
    use serde_json::Value;

    const RID: &str = "0123456789abcdef0123456789abcdef";
    const PORT: u16 = 3000;
    const T0: u64 = 10_000;
    const C_ISN: u32 = 1_000;
    const S_ISN: u32 = 5_000;
    const C0: u32 = C_ISN + 1;
    const S0: u32 = S_ISN + 1;
    const SECRET: &[u8] = b"s3cr3t-token";

    fn key() -> FlowKey {
        FlowKey {
            protocol: TransportProtocol::Tcp,
            local_addr: "10.0.0.1".into(),
            local_port: 40_000,
            remote_addr: "93.184.216.34".into(),
            remote_port: 80,
        }
    }

    fn seg(seq: u32, payload: &[u8], ack_number: u32, now_ms: u64) -> FollowSegment<'_> {
        FollowSegment { seq, ack_number, syn: false, ack: true, fin: false, rst: false, payload, now_ms }
    }

    /// A captured handshake, then a harmless line each way, classified
    /// cleartext. Returns the next sequence numbers.
    fn open_cleartext(store: &mut FollowStore) -> (u32, u32) {
        let k = key();
        store.ingest(&k, true, FollowSegment { seq: C_ISN, ack_number: 0, syn: true, ack: false, fin: false, rst: false, payload: &[], now_ms: T0 });
        store.ingest(&k, false, FollowSegment { seq: S_ISN, ack_number: C0, syn: true, ack: true, fin: false, rst: false, payload: &[], now_ms: T0 });
        store.ingest(&k, true, seg(C0, b"GET / HTTP/1.1\r\n", S0, T0));
        store.ingest(&k, false, seg(S0, b"HTTP/1.1 200 OK\r\n", C0 + 16, T0));
        store.tick(T0 + CLASSIFY_MS);
        (C0 + 16, S0 + 17)
    }

    fn request(c2s: u32, s2c: u32, turns_from: u32, generation: Option<(u64, u64)>) -> StreamRequest {
        StreamRequest {
            request_id: RID.into(),
            connection_id: key().connection_id(),
            generation,
            c2s_offset: c2s,
            s2c_offset: s2c,
            turns_from,
            relay_port: Some(PORT),
        }
    }

    fn reply(store: Option<&FollowStore>, req: &StreamRequest, relay_port: Option<u16>) -> Value {
        let mut out = new_output();
        encode_stream_data(store, req, relay_port, &mut out).expect("fits");
        assert_eq!(out.last(), Some(&b'\n'));
        assert!(out.len() <= MAX_STREAM_DATA_LINE_BYTES);
        assert_eq!(out.capacity(), MAX_STREAM_DATA_LINE_BYTES, "the line never grew its buffer");
        serde_json::from_slice(&out[..out.len() - 1]).unwrap()
    }

    fn data(dir: &Value) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD.decode(dir["dataBase64"].as_str().unwrap()).unwrap()
    }

    fn generation_of(store: &FollowStore) -> (u64, u64) {
        store.with_entry(&key().connection_id(), |e| {
            let g = e.unwrap().generation();
            (g.epoch, g.counter)
        })
    }

    fn assert_content_free(v: &Value) {
        for d in ["clientToServer", "serverToClient"] {
            let p = &v["directions"][d];
            assert_eq!(p["dataBase64"], "", "{d}");
            assert_eq!(p["gaps"], serde_json::json!([]));
            assert_eq!(p["redactedRanges"], serde_json::json!([]));
            assert_eq!(p["storedBytes"], 0);
        }
        assert_eq!(v["turns"], serde_json::json!([]));
        assert_eq!(v["lastTurn"], Value::Null);
    }

    fn stocked_store() -> FollowStore {
        let mut store = FollowStore::new(0xfeed);
        let (c, s) = open_cleartext(&mut store);
        store.ingest(&key(), true, seg(c, b"Authorization: Bearer s3cr3t-token\r\nHost: a\r\n\r\n", s, T0 + 3_000));
        store
    }

    #[test]
    fn with_follow_stream_off_the_reply_is_disabled_and_empty() {
        let v = reply(None, &request(0, 0, 0, None), None);
        assert_eq!((v["type"].as_str(), v["requestId"].as_str()), (Some("stream_data"), Some(RID)));
        assert_eq!((v["enabled"].as_bool(), v["found"].as_bool()), (Some(false), Some(false)));
        assert_eq!(v["generation"], Value::Null);
        assert!(v.get("unavailable").is_none(), "disabled is checked before the port");
        assert_content_free(&v);
    }

    #[test]
    fn a_missing_or_mismatched_relay_port_gets_no_content() {
        let store = stocked_store();
        let mut missing = request(0, 0, 0, None);
        missing.relay_port = None;
        let mut other = request(0, 0, 0, None);
        other.relay_port = Some(3001);
        for (req, agent) in [(&missing, Some(PORT)), (&other, Some(PORT)), (&request(0, 0, 0, None), None)] {
            let v = reply(Some(&store), req, agent);
            assert_eq!(v["unavailable"], "relay_port_mismatch");
            assert_eq!((v["enabled"].as_bool(), v["found"].as_bool()), (Some(true), Some(false)));
            assert_eq!(v["generation"], Value::Null, "nothing about the entry");
            assert_content_free(&v);
        }
        let v = reply(Some(&store), &request(0, 0, 0, None), Some(PORT));
        assert_eq!(v["found"], true);
        assert!(v.get("unavailable").is_none());
    }

    #[test]
    fn an_unknown_flow_is_not_found() {
        let store = stocked_store();
        let mut req = request(0, 0, 0, None);
        req.connection_id = "Tcp-10.0.0.1:40001-93.184.216.34:80".into();
        let v = reply(Some(&store), &req, Some(PORT));
        assert_eq!((v["enabled"].as_bool(), v["found"].as_bool(), v["stale"].as_bool()), (Some(true), Some(false), Some(false)));
        assert_eq!(v["generation"], Value::Null);
        assert_content_free(&v);
    }

    #[test]
    fn a_wrong_generation_is_stale_with_the_current_one_and_no_content() {
        let store = stocked_store();
        let current = generation_of(&store);
        let v = reply(Some(&store), &request(0, 0, 0, Some((current.0, current.1 + 1))), Some(PORT));
        assert_eq!((v["found"].as_bool(), v["stale"].as_bool()), (Some(true), Some(true)));
        assert_eq!(v["generation"], render_generation(current));
        assert_content_free(&v);
        let v = reply(Some(&store), &request(0, 0, 0, Some(current)), Some(PORT));
        assert_eq!((v["found"].as_bool(), v["stale"].as_bool()), (Some(true), Some(false)));
    }

    #[test]
    fn a_found_entry_carries_its_masked_bytes_and_never_the_secret() {
        let store = stocked_store();
        let mut out = new_output();
        encode_stream_data(Some(&store), &request(0, 0, 0, None), Some(PORT), &mut out).unwrap();
        assert!(!out.windows(SECRET.len()).any(|w| w == SECRET));
        let v: Value = serde_json::from_slice(&out[..out.len() - 1]).unwrap();
        let c2s = data(&v["directions"]["clientToServer"]);
        assert_eq!(c2s, b"GET / HTTP/1.1\r\nAuthorization: *******************\r\nHost: a\r\n\r\n", "{:?}", String::from_utf8_lossy(&c2s));
        assert!(!c2s.windows(SECRET.len()).any(|w| w == SECRET));
        assert!(c2s.contains(&b'*'));
        assert_eq!(v["directions"]["clientToServer"]["nextOffset"], c2s.len());
        assert_eq!(data(&v["directions"]["serverToClient"]), b"HTTP/1.1 200 OK\r\n");
        assert_eq!(v["directions"]["clientToServer"]["classification"], "cleartext");
        assert_eq!(v["generation"], render_generation(generation_of(&store)));
        assert_eq!((v["flowStartCaptured"].as_bool(), v["clientIsLocal"].as_bool()), (Some(true), Some(true)));
        let ranges = v["directions"]["clientToServer"]["redactedRanges"].as_array().unwrap();
        assert!(!ranges.is_empty() && ranges.iter().all(|r| r["reason"] == "credential"));
    }

    #[test]
    fn full_pages_in_both_directions_fit_the_line() {
        let mut store = FollowStore::new(1);
        let (mut c, mut s) = open_cleartext(&mut store);
        let block = vec![b'x'; 1_024];
        for _ in 0..40 {
            store.ingest(&key(), true, seg(c, &block, s, T0 + 3_000));
            c += 1_024;
            store.ingest(&key(), false, seg(s, &block, c, T0 + 3_000));
            s += 1_024;
        }
        let v = reply(Some(&store), &request(0, 0, 0, None), Some(PORT));
        for d in ["clientToServer", "serverToClient"] {
            assert_eq!(data(&v["directions"][d]).len(), PAGE_DATA_BYTES as usize, "{d}");
            assert_eq!(v["directions"][d]["nextOffset"], PAGE_DATA_BYTES);
        }
        assert_eq!(v["turns"].as_array().unwrap().len(), 82);
    }

    /// Pages through one direction from 0, checking progress and the
    /// limits; returns every gap and (re-joined) range it was given.
    fn page_through(store: &FollowStore, dir: &str) -> (Vec<Value>, Vec<(u64, u64)>, Vec<u8>) {
        let (mut offset, mut gaps, mut ranges, mut bytes) = (0u32, Vec::new(), Vec::<(u64, u64)>::new(), Vec::new());
        for _ in 0..1_000 {
            let req = if dir == "clientToServer" { request(offset, 0, 0, None) } else { request(0, offset, 0, None) };
            let v = reply(Some(store), &req, Some(PORT));
            let p = &v["directions"][dir];
            let page_gaps = p["gaps"].as_array().unwrap();
            let page_ranges = p["redactedRanges"].as_array().unwrap();
            assert!(page_gaps.len() <= PAGE_GAPS && page_ranges.len() <= PAGE_RANGES);
            gaps.extend(page_gaps.iter().cloned());
            for r in page_ranges {
                let (start, len) = (r["start"].as_u64().unwrap(), r["len"].as_u64().unwrap());
                assert!(start >= u64::from(offset) && len > 0, "ranges are clipped to the page");
                match ranges.last_mut() {
                    Some(last) if last.0 + last.1 == start => last.1 += len,
                    _ => ranges.push((start, len)),
                }
            }
            bytes.extend(data(p));
            let next = p["nextOffset"].as_u64().unwrap() as u32;
            if next == offset {
                return (gaps, ranges, bytes);
            }
            offset = next;
        }
        panic!("paging never finished");
    }

    #[test]
    fn more_than_a_pages_gaps_are_all_delivered_once_in_order() {
        let mut store = FollowStore::new(1);
        let (mut c, s) = open_cleartext(&mut store);
        for _ in 0..PAGE_GAPS * 2 + 5 {
            store.ingest(&key(), true, seg(c, b"z", s, T0 + 3_000));
            c = c.wrapping_add(1 + REORDER_BYTES + 1);
        }
        let want: Vec<Value> = store.with_entry(&key().connection_id(), |e| {
            e.unwrap()
                .direction(Direction::C2s)
                .gaps
                .iter()
                .map(|g| serde_json::json!({ "at": g.at, "missing": g.missing, "reason": "missing" }))
                .collect()
        });
        assert!(want.len() > PAGE_GAPS * 2);
        let (got, _, bytes) = page_through(&store, "clientToServer");
        assert_eq!(got, want);
        assert_eq!(bytes.len(), 16 + PAGE_GAPS * 2 + 5);
    }

    #[test]
    fn a_closed_directions_tail_gap_is_delivered_exactly_once() {
        let mut store = FollowStore::new(1);
        let (c, s) = open_cleartext(&mut store);
        store.ingest(&key(), true, seg(c, &[b'a'; 50], s, T0 + 3_000));
        // The server acknowledges 50 bytes the capture never saw, then the client resets.
        store.ingest(&key(), false, seg(s, b"", c + 100, T0 + 3_000));
        store.ingest(&key(), true, FollowSegment { seq: c + 100, ack_number: 0, syn: false, ack: false, fin: false, rst: true, payload: &[], now_ms: T0 + 3_000 });
        let (gaps, _, bytes) = page_through(&store, "clientToServer");
        assert_eq!(gaps, vec![serde_json::json!({ "at": 66, "missing": 50, "reason": "missing" })]);
        assert_eq!(bytes.len(), 66);
    }

    #[test]
    fn more_than_a_pages_redacted_ranges_are_all_delivered_with_absolute_offsets() {
        let mut store = FollowStore::new(1);
        let (mut c, s) = open_cleartext(&mut store);
        let line = b"Authorization: x\r\nA: b\r\n";
        for _ in 0..PAGE_RANGES * 2 + 5 {
            store.ingest(&key(), true, seg(c, line, s, T0 + 3_000));
            c += line.len() as u32;
        }
        let want: Vec<(u64, u64)> = store.with_entry(&key().connection_id(), |e| {
            e.unwrap().direction(Direction::C2s).redacted_ranges.iter().map(|r| (u64::from(r.start), u64::from(r.len))).collect()
        });
        assert!(want.len() > PAGE_RANGES * 2);
        let (_, got, bytes) = page_through(&store, "clientToServer");
        assert_eq!(got, want);
        for (start, len) in &got {
            assert!(bytes[*start as usize..(*start + *len) as usize].iter().all(|b| *b == b'*'));
        }
    }

    #[test]
    fn turns_page_separately_and_the_last_turn_is_always_current() {
        let mut store = FollowStore::new(1);
        let (mut c, mut s) = open_cleartext(&mut store);
        for _ in 0..PAGE_TURNS {
            store.ingest(&key(), true, seg(c, b"c", s, T0 + 3_000));
            c += 1;
            store.ingest(&key(), false, seg(s, b"s", c, T0 + 3_000));
            s += 1;
        }
        let total = store.with_entry(&key().connection_id(), |e| e.unwrap().turns().len());
        assert!(total > PAGE_TURNS * 2);
        let (mut from, mut seen) = (0u32, 0usize);
        loop {
            let v = reply(Some(&store), &request(0, 0, from, None), Some(PORT));
            let turns = v["turns"].as_array().unwrap();
            assert!(turns.len() <= PAGE_TURNS);
            assert_eq!(v["turnsFrom"], from);
            assert_eq!(v["lastTurn"]["index"], total - 1);
            seen += turns.len();
            match v["turnsNext"].as_u64() {
                Some(next) => {
                    assert_eq!(next, u64::from(from) + turns.len() as u64);
                    from = next as u32;
                }
                None => break,
            }
        }
        assert_eq!(seen, total);
        let v = reply(Some(&store), &request(0, 0, 4_096, None), Some(PORT));
        assert_eq!(v["turns"], serde_json::json!([]));
        assert_eq!(v["turnsNext"], Value::Null);
        assert_eq!(v["lastTurn"]["index"], total - 1, "lastTurn even past the end");
    }

    #[test]
    fn the_busy_reply_carries_no_content() {
        let mut out = new_output();
        encode_stream_busy(&request(0, 0, 0, None), &mut out).unwrap();
        let v: Value = serde_json::from_slice(&out[..out.len() - 1]).unwrap();
        assert_eq!((v["busy"].as_bool(), v["enabled"].as_bool(), v["found"].as_bool()), (Some(true), Some(true), Some(false)));
        assert_content_free(&v);
    }

    #[test]
    fn the_writer_refuses_a_line_past_the_ceiling_and_zeroizes() {
        let mut out = new_output();
        out.extend_from_slice(b"previous");
        let mut req = request(0, 0, 0, None);
        req.connection_id = "x".repeat(MAX_STREAM_DATA_LINE_BYTES);
        assert_eq!(encode_stream_data(None, &req, None, &mut out), Err(StreamResponseError::TooLarge));
        assert!(out.is_empty());
        assert_eq!(out.capacity(), MAX_STREAM_DATA_LINE_BYTES);
    }

    /// `lib/__tests__/fixtures/stream-data-samples.jsonl` is exactly what
    /// this encoder writes, so the TypeScript mapper's test runs on real
    /// output, not a hand-written belief about it (JAM-150). Regenerate with
    /// `UPDATE_STREAM_FIXTURE=1 cargo test --lib the_typescript_fixture`.
    #[test]
    fn the_typescript_fixture_is_what_the_encoder_writes() {
        let mut store = stocked_store();
        let (c, s) = (C0 + 16 + 47, S0 + 17);
        // A hole, closed as a gap once a segment lands past the window.
        store.ingest(&key(), true, seg(c + 10, b"late", s, T0 + 4_000));
        store.ingest(&key(), true, seg(c + 10 + REORDER_BYTES, b"!", s, T0 + 4_000));
        store.ingest(&key(), false, seg(s, b"Content-Length: 0\r\n\r\n", c, T0 + 5_000));
        let current = generation_of(&store);
        let mut mismatch = request(0, 0, 0, None);
        mismatch.relay_port = Some(3001);
        let mut unknown = request(0, 0, 0, None);
        unknown.connection_id = "Tcp-10.0.0.1:40001-93.184.216.34:80".into();
        let mut lines = Vec::new();
        let mut push = |r: Result<(), StreamResponseError>, out: &Zeroizing<Vec<u8>>| {
            r.unwrap();
            lines.extend_from_slice(out);
        };
        let mut out = new_output();
        push(encode_stream_data(Some(&store), &request(0, 0, 0, None), Some(PORT), &mut out), &out);
        push(encode_stream_data(Some(&store), &request(16, 0, 1, Some(current)), Some(PORT), &mut out), &out);
        push(encode_stream_data(None, &request(0, 0, 0, None), None, &mut out), &out);
        push(encode_stream_data(Some(&store), &mismatch, Some(PORT), &mut out), &out);
        push(encode_stream_data(Some(&store), &unknown, Some(PORT), &mut out), &out);
        push(encode_stream_data(Some(&store), &request(0, 0, 0, Some((current.0, current.1 + 1))), Some(PORT), &mut out), &out);
        push(encode_stream_busy(&request(0, 0, 0, None), &mut out), &out);
        assert!(!lines.windows(SECRET.len()).any(|w| w == SECRET));

        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../lib/__tests__/fixtures/stream-data-samples.jsonl");
        if std::env::var_os("UPDATE_STREAM_FIXTURE").is_some() {
            std::fs::write(&path, &lines).unwrap();
        }
        let fixture = std::fs::read(&path).expect("fixture present");
        assert!(fixture == lines, "the fixture is stale: regenerate it (see this test's doc)");
    }

    // ---------- page planning, on synthetic views ----------

    fn view<'a>(emittable: u32, stored: u32, gaps: &'a [Gap], ranges: &'a [MaskRange], closed: bool) -> FollowDirection<'a> {
        FollowDirection {
            classification: Classification::Cleartext,
            tls_from: None,
            emittable,
            stored_bytes: stored,
            seen_bytes: u64::from(stored),
            stopped: None,
            gaps,
            redacted_ranges: ranges,
            conflicting_overlap_bytes: 0,
            start_captured: true,
            closed,
        }
    }

    fn gap(at: u32, missing: u32, reason: GapReason) -> Gap {
        Gap { at, missing, reason }
    }

    #[test]
    fn gaps_at_one_offset_merge_so_paging_always_moves() {
        let mut gaps: Vec<Gap> = (0..PAGE_GAPS + 10).map(|_| gap(5, 2, GapReason::SnaplenLikely)).collect();
        gaps.push(gap(5, 1, GapReason::Missing));
        gaps.push(gap(7, 1, GapReason::SnaplenLikely));
        gaps.push(gap(7, 1, GapReason::SnaplenLikely));
        let plan = plan_page(&view(100, 100, &gaps, &[], false), 0);
        assert_eq!(plan.end, 100);
        assert_eq!(
            plan.gaps,
            vec![
                StreamGapJson { at: 5, missing: (PAGE_GAPS as u32 + 10) * 2 + 1, reason: "missing" },
                StreamGapJson { at: 7, missing: 2, reason: "snaplen_likely" },
            ]
        );
    }

    #[test]
    fn a_page_with_too_many_gaps_ends_at_the_first_one_left_out() {
        let gaps: Vec<Gap> = (0..PAGE_GAPS as u32 + 1).map(|i| gap(10 + i, 1, GapReason::Missing)).collect();
        let plan = plan_page(&view(1_000, 1_000, &gaps, &[], false), 10);
        assert_eq!(plan.gaps.len(), PAGE_GAPS);
        assert_eq!(plan.end, 10 + PAGE_GAPS as u32);
        assert_eq!(plan_page(&view(1_000, 1_000, &gaps, &[], false), plan.end).gaps.len(), 1);
    }

    #[test]
    fn a_gap_at_the_end_is_sent_once_nothing_more_can_follow() {
        let gaps = [gap(50, 9, GapReason::Missing)];
        let live = plan_page(&view(50, 50, &gaps, &[], false), 0);
        assert_eq!((live.end, live.gaps.len()), (50, 0), "live: held until the horizon passes it");
        assert!(plan_page(&view(50, 50, &gaps, &[], false), 50).gaps.is_empty());
        assert!(plan_page(&view(50, 50, &gaps, &[], true), 0).gaps.is_empty(), "not on the page ending there");
        let closed = plan_page(&view(50, 50, &gaps, &[], true), 50);
        assert_eq!((closed.end, closed.gaps.len()), (50, 1), "on the empty page starting there");
        assert!(plan_page(&view(50, 60, &gaps, &[], true), 50).gaps.is_empty(), "bytes withheld past it");
        let mut grown = view(80, 80, &gaps, &[], false);
        assert_eq!(plan_page(&grown, 50).gaps.len(), 1, "then on the page holding it");
        grown.closed = true;
        assert!(plan_page(&grown, 51).gaps.is_empty());
    }

    #[test]
    fn ranges_are_clipped_to_the_page_and_shorten_it_past_the_limit() {
        let ranges = [MaskRange { start: 2, len: 10, reason: MaskReason::Uncertain }];
        let plan = plan_page(&view(100, 100, &[], &ranges, false), 5);
        assert_eq!(plan.ranges, vec![StreamMaskJson { start: 5, len: 7, reason: "uncertain" }]);
        assert!(plan_page(&view(100, 100, &[], &ranges, false), 12).ranges.is_empty());

        let many: Vec<MaskRange> = (0..PAGE_RANGES as u32 + 1)
            .map(|i| MaskRange { start: 2 * i, len: 1, reason: MaskReason::Credential })
            .collect();
        let gaps = [gap(255, 1, GapReason::Missing), gap(257, 1, GapReason::Missing)];
        let plan = plan_page(&view(1_000, 1_000, &gaps, &many, false), 0);
        assert_eq!(plan.ranges.len(), PAGE_RANGES);
        assert_eq!(plan.end, 2 * PAGE_RANGES as u32);
        assert_eq!(plan.gaps, vec![StreamGapJson { at: 255, missing: 1, reason: "missing" }], "a gap past the shortened end waits");
    }

    #[test]
    fn data_stops_at_the_horizon_and_past_it_nothing_is_planned() {
        let plan = plan_page(&view(40, 100, &[], &[], false), 0);
        assert_eq!(plan.end, 40, "held-back bytes are not paged");
        assert_eq!(plan_page(&view(40_000, 40_000, &[], &[], false), 0).end, PAGE_DATA_BYTES);
        let past = plan_page(&view(40, 100, &[gap(60, 1, GapReason::Missing)], &[], true), 70);
        assert_eq!(past, PagePlan { end: 70, gaps: Vec::new(), ranges: Vec::new() });
        assert_eq!(plan_page(&view(0, 0, &[], &[], false), 0).end, 0);
    }
}
