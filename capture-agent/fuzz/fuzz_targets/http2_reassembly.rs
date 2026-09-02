#![no_main]
use capture_agent::http2::Http2Reassembler;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must never panic, regardless of input — a DesyncFallback outcome is
    // a correct, expected result for garbage/malformed/out-of-order input,
    // not a failure (spec Components §4: no safe per-frame recovery once
    // HPACK's dynamic table state is in question, so garbage input is
    // expected to desync the whole connection, not to be tolerated).
    let mut r = Http2Reassembler::new();
    let _ = r.feed(0, data);
    // A second feed at an unrelated, likely-non-contiguous sequence number
    // exercises the desync-detection path itself (not just in-order
    // parsing) without needing two separately fuzzed inputs.
    let _ = r.feed(data.len() as u64 + 12345, data);
});
