#![no_main]
use capture_agent::pcapng::Reader;
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // The only property under test: arbitrary bytes must never panic,
    // whether they come from a corrupted capture file or a hostile one —
    // Reader is the one place this agent parses attacker-reachable content
    // it did not itself just write. An Ok or an Err result are both
    // acceptable outcomes; a panic is the only failure.
    if let Ok((mut reader, _interface)) = Reader::new(Cursor::new(data)) {
        // Keep pulling packets until either a clean end of stream or an
        // error — both are fine, an infinite loop on malformed input is
        // not (every non-error path advances the cursor by at least one
        // block, so this always terminates).
        while let Ok(Some(_packet)) = reader.next_packet() {}
    }
});
