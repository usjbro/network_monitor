#![no_main]
use libfuzzer_sys::fuzz_target;
use capture_agent::parse::parse_packet;

fuzz_target!(|data: &[u8]| {
    // The only property under test: arbitrary bytes must never panic.
    // A None/Some result are both acceptable outcomes.
    let _ = parse_packet(data);
});
