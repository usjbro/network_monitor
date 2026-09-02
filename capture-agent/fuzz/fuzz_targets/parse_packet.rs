#![no_main]
use capture_agent::l7::sniff_l7;
use capture_agent::parse::parse_packet;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The only property under test: arbitrary bytes must never panic.
    // A None/Some result are both acceptable outcomes.
    let Some(parsed) = parse_packet(data) else { return };
    // Also fuzzes l7::sniff_l7 (HTTP/DNS/TLS ClientHello + JA3 field
    // extraction, Task 2) on whatever payload parse_packet extracted —
    // this is the same attacker-reachable entry point the real capture
    // loop calls immediately after parse_packet, so folding it into this
    // existing target gives JA3 parsing fuzz coverage without a second,
    // largely-duplicate harness.
    let _ = sniff_l7(&parsed.payload, parsed.dst_port);
});
