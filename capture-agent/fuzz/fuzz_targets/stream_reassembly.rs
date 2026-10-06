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

fuzz_target!(|data: &[u8]| {
    // JAM-16. Two properties under test, not one:
    //
    // 1. Arbitrary bytes must never panic. Reassembly runs on completely
    //    attacker-controlled input in the same process that holds the raw
    //    capture handle.
    // 2. **The accounted memory caps must actually hold.** `bytes_held()`
    // includes retained capacities for both data and coverage vectors. This
    // is asserted rather than
    //    merely hoped for because unit tests can only try the cap-breaking
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
    whole.drop_flow(&key);
});
