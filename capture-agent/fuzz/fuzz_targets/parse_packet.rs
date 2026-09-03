#![no_main]
use libfuzzer_sys::fuzz_target;
use capture_agent::parse::parse_packet;
use capture_agent::traceroute::parse_icmp_reply;

fuzz_target!(|data: &[u8]| {
    // The only property under test: arbitrary bytes must never panic.
    // A None/Some result are both acceptable outcomes.
    let _ = parse_packet(data);

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
