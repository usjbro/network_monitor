#![no_main]
use capture_agent::l7::sniff_l7;
use capture_agent::parse::parse_packet;
use capture_agent::traceroute::parse_icmp_reply;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The only property under test: arbitrary bytes must never panic.
    // A None/Some result are both acceptable outcomes.
    if let Some(parsed) = parse_packet(data) {
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
