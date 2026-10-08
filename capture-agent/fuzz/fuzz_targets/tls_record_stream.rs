#![no_main]
use capture_agent::tls_stream::{TlsDirectionStream, TlsRecordFramer};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let initial = u32::from_be_bytes(data[..4].try_into().unwrap());
    let bytes = &data[4..];

    // Exercise record framing for arbitrary length fields and content bytes.
    let mut framer = TlsRecordFramer::new();
    let _ = framer.feed(bytes);

    // Exercise bounded TCP ordering, overlaps, sequence wraparound, and
    // reassembly using data-derived chunks. Errors are expected for hostile
    // overlap or reorder patterns; the invariant is that they never panic or
    // retain more than the documented one-record window.
    let mut stream = TlsDirectionStream::new(initial);
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let control = bytes[cursor];
        cursor += 1;
        if cursor == bytes.len() {
            break;
        }
        let len = (usize::from(control & 0x1f) + 1).min(bytes.len() - cursor);
        let offset = usize::from(control >> 5) * 257;
        let seq = initial.wrapping_add(offset as u32);
        let _ = stream.feed_segment(seq, &bytes[cursor..cursor + len]);
        cursor += len;
        assert!(stream.bytes_held() <= 3 * 16_645 + 128);
    }
});
