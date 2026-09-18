#![no_main]
use capture_agent::l7::sniff_l7;
use capture_agent::parse::{parse_packet, LinkType};
use capture_agent::traceroute::parse_icmp_reply;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The only property under test: arbitrary bytes must never panic.
    // A None/Some result are both acceptable outcomes. Exercises all three
    // LinkType framing paths (issue #63), not just Ethernet — the first
    // byte (consumed here, not passed to the parser) selects which, so the
    // same corpus fuzzes every link-layer assumption parse_packet makes.
    let link_type = match data.first() {
        Some(0) => LinkType::NullLoopback,
        Some(1) => LinkType::Raw,
        _ => LinkType::Ethernet,
    };
    let rest = if data.is_empty() { data } else { &data[1..] };
    if let Some(parsed) = parse_packet(rest, link_type) {
        // Also fuzzes l7::sniff_l7 (HTTP/DNS/TLS ClientHello + JA3 field
        // extraction, Task 2) on whatever payload parse_packet extracted —
        // this is the same attacker-reachable entry point the real capture
        // loop calls immediately after parse_packet, so folding it into this
        // existing target gives JA3 parsing fuzz coverage without a second,
        // largely-duplicate harness.
        let _ = sniff_l7(&parsed.payload, parsed.dst_port);
    }

    // traceroute::parse_icmp_reply (capture-agent/src/traceroute.rs) parses
    // a different input class than parse_packet above — raw bytes read off
    // the traceroute probe socket (ICMP Echo Reply / Time Exceeded
    // messages), not captured L2 frames — so it isn't reachable from
    // parse_packet's own call graph and needs its own fuzz entry point
    // here. Same "untrusted bytes must never panic" property; same
    // corpus/target rather than a second fuzz_target, since both consume
    // arbitrary &[u8] with no other setup.
    let _ = parse_icmp_reply(data);
});
