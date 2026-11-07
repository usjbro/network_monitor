#![no_main]
use capture_agent::flow::FlowKey;
use capture_agent::parse::{parse_packet, LinkType, TransportProtocol};
use capture_agent::reassembly::{
    IpFragmentReassembler, StreamReassembler, TcpReassembler, TcpStreamKey, MAX_FRAGMENT_BYTES_TOTAL,
    MAX_FRAGMENT_GROUPS, MAX_TCP_BYTES_TOTAL, MAX_TCP_STREAMS, MAX_TCP_STREAM_BYTES,
};
use libfuzzer_sys::fuzz_target;

/// One flow identity, reused for every segment so the fuzzer's inputs pile
/// into the same stream buffer rather than each getting a fresh one — that is
/// where overlap, reordering, and the per-stream cap actually interact.
fn flow() -> FlowKey {
    FlowKey {
        protocol: TransportProtocol::Tcp,
        local_addr: "192.168.1.10".to_string(),
        local_port: 51000,
        remote_addr: "93.184.216.34".to_string(),
        remote_port: 80,
    }
}

/// A minimal IPv4/TCP packet around `payload`: to port 53, or, with
/// `from_server`, from port 53 to an ephemeral port. `syn` sets the SYN flag.
fn tcp53_packet(payload: &[u8], seq: u32, from_server: bool, syn: bool) -> Vec<u8> {
    let total = (40 + payload.len()) as u16;
    let (src_port, dst_port) = if from_server { (53u16, 51000u16) } else { (51000, 53) };
    let mut p = vec![0x45, 0];
    p.extend_from_slice(&total.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1]);
    p.extend_from_slice(&src_port.to_be_bytes());
    p.extend_from_slice(&dst_port.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 0, 0x50, if syn { 0x12 } else { 0x10 }, 0xff, 0xff, 0, 0, 0, 0]);
    p.extend_from_slice(payload);
    p
}

fuzz_target!(|data: &[u8]| {
    // JAM-16. Two properties under test, not one:
    //
    // 1. Arbitrary bytes must never panic. Reassembly runs on completely
    //    attacker-controlled input in the same process that holds the raw
    //    capture handle.
    // 2. **The accounted memory caps must actually hold.** `bytes_held()`
    //    includes retained capacities for both data and coverage vectors.
    //    This is asserted rather than merely hoped for because unit tests can
    //    only try the cap-breaking
    //    shapes someone thought of; JAM-125's real out-of-memory bug was
    //    found by a fuzz target and missed by unit tests. An unbounded-growth
    //    regression here is a crash the fuzzer reports, not a slow leak
    //    nobody notices.

    // ---- IP fragment reassembly -----------------------------------------
    //
    // Driven through the real `parse_packet`, so this is the same path the
    // capture loop takes: arbitrary bytes in, and only what genuinely parses
    // as an IPv4 fragment reaches the reassembler.
    let mut fragments = IpFragmentReassembler::new();
    let mut now_ms = 0u64;
    for (i, chunk) in data.chunks(64).enumerate().take(64) {
        // Vary the link type from the input itself so all three framing
        // assumptions are exercised, as `parse_packet.rs` does.
        let link_type = match chunk.first().map(|b| b % 3) {
            Some(0) => LinkType::NullLoopback,
            Some(1) => LinkType::Raw,
            _ => LinkType::Ethernet,
        };
        if let Some(parsed) = parse_packet(chunk, link_type) {
            let _ = fragments.feed(&parsed, now_ms);
        }
        // Also feed the whole input as a raw IP packet: a fuzzer-built IPv4
        // header with a fragment offset is far more likely to survive
        // `from_ip` than to survive Ethernet framing first.
        if let Some(parsed) = parse_packet(data, LinkType::Raw) {
            let _ = fragments.feed(&parsed, now_ms);
        }
        assert!(
            fragments.bytes_held() <= MAX_FRAGMENT_BYTES_TOTAL,
            "fragment byte cap breached: {} > {}",
            fragments.bytes_held(),
            MAX_FRAGMENT_BYTES_TOTAL
        );
        assert!(
            fragments.groups_held() <= MAX_FRAGMENT_GROUPS,
            "fragment group cap breached: {}",
            fragments.groups_held()
        );
        // Advance time unevenly, including not at all, so eviction and
        // never-eviction are both exercised.
        now_ms = now_ms.wrapping_add(u64::from(i as u8));
        let _ = fragments.evict_stale(now_ms);
    }

    // ---- TCP segment reassembly -----------------------------------------
    //
    // Fed directly, with sequence numbers taken from the input, because that
    // is the only way to reach out-of-order, overlapping, wildly-distant, and
    // wrapping offsets densely. Every one of those is a bounds-arithmetic
    // path, which is exactly what needs fuzzing.
    let mut segments = TcpReassembler::new();
    let key = TcpStreamKey { flow: flow(), from_local: true };
    let mut now_ms = 0u64;
    for chunk in data.chunks(16).take(256) {
        // Derive a sequence number from the bytes so the fuzzer can steer
        // offsets, including negative deltas and u32 wraparound.
        let mut seq_bytes = [0u8; 4];
        for (dst, src) in seq_bytes.iter_mut().zip(chunk.iter()) {
            *dst = *src;
        }
        let seq = u32::from_le_bytes(seq_bytes);
        // A declared length the fuzzer also controls, including values far
        // larger than the payload — the capture-truncation path.
        let declared = u32::from(chunk.first().copied().unwrap_or(0)) * 37;
        let _ = segments.feed(&key, seq, chunk, declared, now_ms);
        assert!(
            segments.bytes_held() <= MAX_TCP_BYTES_TOTAL,
            "TCP total byte cap breached: {}",
            segments.bytes_held()
        );
        assert!(segments.streams_held() <= MAX_TCP_STREAMS);
        assert!(
            segments.max_buffered_len() <= MAX_TCP_STREAM_BYTES,
            "a TCP direction exceeded its logical buffer cap: {}",
            segments.max_buffered_len()
        );
        // The exposed prefix must always be a real slice of held bytes —
        // indexing it proves no out-of-range prefix length was recorded.
        let prefix = segments.prefix(&key);
        assert!(prefix.len() <= MAX_TCP_STREAM_BYTES);
        now_ms = now_ms.wrapping_add(u64::from(chunk.len() as u8));
        segments.evict_stale(now_ms);
    }

    // Many distinct keys, to drive the stream-count ceiling and its
    // oldest-first eviction rather than one stream's growth.
    let mut many = TcpReassembler::new();
    for (i, chunk) in data.chunks(8).enumerate().take(512) {
        let key = TcpStreamKey {
            flow: FlowKey { remote_port: i as u16, ..flow() },
            from_local: i % 2 == 0,
        };
        let _ = many.feed(&key, i as u32, chunk, chunk.len() as u32, i as u64);
        assert!(many.streams_held() <= MAX_TCP_STREAMS);
        assert!(many.bytes_held() <= MAX_TCP_BYTES_TOTAL);
    }

    // ---- The capture-loop facade ----------------------------------------
    //
    // Exercises the fragment path, the per-frame fallback, and the
    // desegmenting L7 hand-off together, as `main.rs` calls them.
    let mut whole = StreamReassembler::new();
    let key = flow();
    for (i, chunk) in data.chunks(128).enumerate().take(32) {
        if let Some(parsed) = parse_packet(chunk, LinkType::Raw) {
            let _ = whole.sniff(&parsed, Some((&key, i % 2 == 0)), i as u64);
        }
        if i % 3 == 0 {
            whole.note_frame_cut_at_snaplen(i as u64);
        }
        whole.maybe_evict(i as u64 * 1_000);
        assert!(whole.bytes_held() <= MAX_FRAGMENT_BYTES_TOTAL + MAX_TCP_BYTES_TOTAL);
    }

    // ---- DNS over TCP through the facade (JAM-21) -------------------------
    //
    // `TcpReassembler::feed` never sees a port, so the framed-DNS path is only
    // reached through `StreamReassembler::sniff` with real TCP/53 packets. The
    // sequence numbers start near `u32::MAX` so message boundaries wrap, move
    // backwards and forwards by small amounts so segments reorder, overlap and
    // leave gaps, and the clock steps past the 2 s decision window and, over a
    // long input, the idle timeout.
    let mut dns = StreamReassembler::new();
    let dns_key = FlowKey { remote_port: 53, ..flow() };
    let base = u32::MAX - u32::from(data.first().copied().unwrap_or(0));
    let mut cursor = 0u32;
    let mut dns_now_ms = 0u64;
    for chunk in data.chunks(24).take(256) {
        let control = chunk.first().copied().unwrap_or(0);
        // Half the segments start a message with a correct length prefix, so
        // the fuzzer reaches `sniff_dns` past the length check.
        let mut payload = Vec::new();
        if control & 0x80 != 0 {
            payload.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        }
        payload.extend_from_slice(chunk);
        let step = i32::from(control >> 2 & 0x1f) - 16;
        let seq = base.wrapping_add(cursor).wrapping_add_signed(if control & 0x03 == 0 { step } else { 0 });
        cursor = cursor.wrapping_add(payload.len() as u32);
        dns_now_ms = dns_now_ms.saturating_add(u64::from(control & 0x03) * 1_000 + u64::from(control >> 5) * 400);
        // Two more control bits: the direction (a response from source port
        // 53, which tries HTTP and TLS first) and SYN, which forgets a boundary.
        let from_server = control & 0x40 != 0;
        let syn = control & 0x01 != 0 && control & 0x20 != 0;
        if let Some(parsed) = parse_packet(&tcp53_packet(&payload, seq, from_server, syn), LinkType::Raw) {
            let _ = dns.sniff(&parsed, Some((&dns_key, !from_server)), dns_now_ms);
        }
        dns.maybe_evict(dns_now_ms);
        assert!(dns.dns_framing_len() <= MAX_TCP_STREAMS, "DNS framing table breached its bound: {}", dns.dns_framing_len());
        assert!(dns.bytes_held() <= MAX_FRAGMENT_BYTES_TOTAL + MAX_TCP_BYTES_TOTAL);
    }
    dns.reset();
    assert_eq!(dns.dns_framing_len(), 0);

    whole.drop_flow(&key);
});
