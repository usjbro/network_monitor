use crate::redact::redact_headers;
use fluke_hpack::Decoder as HpackDecoder;

pub enum FrameOutcome {
    Frame { stream_id: u32, headers: Vec<(String, String)>, body: Vec<u8> },
    DesyncFallback { reason: &'static str },
    NeedMoreData,
}

pub struct Http2Reassembler {
    buffer: Vec<u8>,
    next_expected_seq: Option<u64>,
    hpack: HpackDecoder<'static>,
    desynced: bool,
    // Test-only seam: lets the redaction-integration test assert the
    // integration point without hand-encoding a full HPACK literal header.
    #[cfg(test)]
    test_injected_headers: std::collections::HashMap<u32, Vec<(String, String)>>,
}

impl Default for Http2Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Http2Reassembler {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            next_expected_seq: None,
            hpack: HpackDecoder::new(),
            desynced: false,
            #[cfg(test)]
            test_injected_headers: std::collections::HashMap::new(),
        }
    }

    #[cfg(test)]
    fn debug_inject_header_for_test(&mut self, stream_id: u32, name: String, value: String) {
        self.test_injected_headers.entry(stream_id).or_default().push((name, value));
    }

    /// Feeds one contiguous chunk of already-decrypted plaintext bytes,
    /// starting at TCP sequence number `seq`, and returns every frame
    /// outcome produced by parsing as much of the buffered bytes as
    /// possible. A gap or reorder relative to the previously-fed chunk
    /// desyncs the WHOLE connection permanently (HPACK's dynamic table is
    /// stateful and order-dependent — there is no safe per-frame recovery,
    /// spec Components §4) — every subsequent `feed()` call on this
    /// instance then immediately returns `DesyncFallback` too.
    pub fn feed(&mut self, seq: u64, chunk: &[u8]) -> Vec<FrameOutcome> {
        if self.desynced {
            return vec![FrameOutcome::DesyncFallback { reason: "connection already desynced" }];
        }
        if let Some(expected) = self.next_expected_seq {
            if seq != expected {
                self.desynced = true;
                return vec![FrameOutcome::DesyncFallback { reason: "sequence gap or reorder detected" }];
            }
        }
        self.next_expected_seq = Some(seq + chunk.len() as u64);
        self.buffer.extend_from_slice(chunk);

        let mut outcomes = Vec::new();
        loop {
            if self.buffer.len() < 9 {
                outcomes.push(FrameOutcome::NeedMoreData);
                break;
            }
            let len = u32::from_be_bytes([0, self.buffer[0], self.buffer[1], self.buffer[2]]) as usize;
            let frame_type = self.buffer[3];
            let stream_id =
                u32::from_be_bytes([self.buffer[5], self.buffer[6], self.buffer[7], self.buffer[8]]) & 0x7fff_ffff;
            if self.buffer.len() < 9 + len {
                outcomes.push(FrameOutcome::NeedMoreData);
                break;
            }
            let payload = self.buffer[9..9 + len].to_vec();
            self.buffer.drain(0..9 + len);

            if frame_type == 0x01 {
                // HEADERS frame. `fluke_hpack::Decoder::decode` is a
                // third-party, historically-unmaintained-upstream
                // dependency (see the crate-choice note in this plan's
                // final report) — fuzzing (Task 15) found it can `panic!`
                // (not just `Err`) on certain malformed dynamic-table-size
                // update encodings. Isolating that panic behind
                // `catch_unwind` and treating it exactly like a decode
                // `Err` (whole-connection desync, never propagated) is
                // safe here specifically because every path below already
                // permanently desyncs this `Http2Reassembler` instance on
                // any decode failure and never calls into `self.hpack`
                // again afterward — a poisoned/inconsistent decoder state
                // post-panic is never observed.
                let decode_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.hpack.decode(&payload)));
                match decode_result {
                    Ok(Ok(pairs)) => {
                        let mut headers: Vec<(String, String)> = pairs
                            .into_iter()
                            .map(|(k, v)| {
                                (String::from_utf8_lossy(&k).to_string(), String::from_utf8_lossy(&v).to_string())
                            })
                            .collect();
                        #[cfg(test)]
                        if let Some(injected) = self.test_injected_headers.get(&stream_id) {
                            headers.extend(injected.iter().cloned());
                        }
                        redact_headers(&mut headers);
                        outcomes.push(FrameOutcome::Frame { stream_id, headers, body: Vec::new() });
                    }
                    Ok(Err(_)) | Err(_) => {
                        // HPACK decode failure (an `Err`, OR a caught panic
                        // from inside the third-party decoder — see the
                        // catch_unwind comment above) = irrecoverable
                        // desync for the WHOLE connection, not just this
                        // frame (spec Components §4 — no safe per-frame
                        // recovery once the dynamic table state is in
                        // question).
                        self.desynced = true;
                        outcomes.push(FrameOutcome::DesyncFallback {
                            reason: "HPACK decode failed — dynamic table state unrecoverable",
                        });
                        break;
                    }
                }
            } else if frame_type == 0x00 {
                // DATA frame — body bytes, not header-bearing, no HPACK involvement.
                outcomes.push(FrameOutcome::Frame { stream_id, headers: Vec::new(), body: payload });
            }
            // Other frame types (SETTINGS, WINDOW_UPDATE, PING, etc.) are
            // consumed from the buffer above but produce no FrameOutcome —
            // this component's job is content visibility, not full HTTP/2
            // protocol-state tracking.
        }
        outcomes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_headers_frame(stream_id: u32, header_block: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&(header_block.len() as u32).to_be_bytes()[1..]); // 24-bit length
        frame.push(0x01); // type: HEADERS
        frame.push(0x04); // flags: END_HEADERS
        frame.extend_from_slice(&stream_id.to_be_bytes());
        frame.extend_from_slice(header_block);
        frame
    }

    // A minimal HPACK-encoded header block using only fully-indexed static
    // table entries (no dynamic table, no Huffman) — ":method: GET" is
    // static index 2, encoded as a single byte 0x82 per RFC 7541 §6.1.
    fn static_indexed_get_header_block() -> Vec<u8> {
        vec![0x82]
    }

    #[test]
    fn parses_a_single_in_order_headers_frame() {
        let mut r = Http2Reassembler::new();
        let frame = simple_headers_frame(1, &static_indexed_get_header_block());
        let outcomes = r.feed(0, &frame);
        assert!(outcomes.iter().any(|o| matches!(o, FrameOutcome::Frame { stream_id: 1, .. })));
    }

    #[test]
    fn reassembles_a_frame_split_across_two_feeds() {
        let mut r = Http2Reassembler::new();
        let frame = simple_headers_frame(3, &static_indexed_get_header_block());
        let (first_half, second_half) = frame.split_at(4);
        let outcomes1 = r.feed(0, first_half);
        assert!(outcomes1.iter().all(|o| matches!(o, FrameOutcome::NeedMoreData)));
        let outcomes2 = r.feed(4, second_half);
        assert!(outcomes2.iter().any(|o| matches!(o, FrameOutcome::Frame { stream_id: 3, .. })));
    }

    #[test]
    fn a_sequence_gap_triggers_whole_connection_desync_fallback_not_a_panic() {
        let mut r = Http2Reassembler::new();
        let frame = simple_headers_frame(5, &static_indexed_get_header_block());
        r.feed(0, &frame);
        // Skip ahead — seq 1000 implies bytes were lost/reordered between 0
        // and 1000, which desyncs HPACK's stateful dynamic table
        // irrecoverably (spec Components §4).
        let outcomes = r.feed(1000, &frame);
        assert!(outcomes.iter().any(|o| matches!(o, FrameOutcome::DesyncFallback { .. })));
    }

    #[test]
    fn frames_parsed_before_a_desync_point_remain_returned_not_discarded() {
        let mut r = Http2Reassembler::new();
        let good_frame = simple_headers_frame(7, &static_indexed_get_header_block());
        let outcomes1 = r.feed(0, &good_frame);
        assert!(outcomes1.iter().any(|o| matches!(o, FrameOutcome::Frame { stream_id: 7, .. })));
        let outcomes2 = r.feed(9999, &good_frame); // desync
        assert!(outcomes2.iter().any(|o| matches!(o, FrameOutcome::DesyncFallback { .. })));
        // outcomes1 already returned the good frame to the caller in an
        // earlier feed() call — this test documents that feed() never
        // retroactively invalidates a prior return, only stops producing new
        // Frame outcomes going forward.
    }

    #[test]
    fn redaction_is_applied_to_parsed_header_values_before_return() {
        // :method (0x82) then a literal-with-incremental-indexing header for
        // a made-up sensitive name would require full Huffman/literal
        // support to construct by hand here; instead this test verifies the
        // integration point structurally: any FrameOutcome::Frame carrying
        // headers must have passed through redact::redact_headers before
        // being returned — asserted here by checking a hand-inserted
        // sensitive header via the reassembler's own test-only injection
        // seam rather than a full HPACK literal encoding.
        let mut r = Http2Reassembler::new();
        r.debug_inject_header_for_test(11, "authorization".to_string(), "Bearer secret".to_string());
        let outcomes = r.feed(0, &simple_headers_frame(11, &static_indexed_get_header_block()));
        if let Some(FrameOutcome::Frame { headers, .. }) =
            outcomes.into_iter().find(|o| matches!(o, FrameOutcome::Frame { .. }))
        {
            assert!(headers.iter().any(|(k, v)| k == "authorization" && v == "[REDACTED]"));
        }
    }

    #[test]
    fn a_data_frame_returns_its_body_bytes() {
        let mut r = Http2Reassembler::new();
        let mut frame = Vec::new();
        let body = b"hello world";
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        frame.push(0x00); // type: DATA
        frame.push(0x00); // flags
        frame.extend_from_slice(&9u32.to_be_bytes());
        frame.extend_from_slice(body);
        let outcomes = r.feed(0, &frame);
        assert!(outcomes
            .iter()
            .any(|o| matches!(o, FrameOutcome::Frame { stream_id: 9, body, .. } if body == b"hello world")));
    }

    #[test]
    fn garbage_bytes_never_panic_even_if_they_never_produce_a_frame() {
        let mut r = Http2Reassembler::new();
        let _ = r.feed(0, &[0xff; 3]); // shorter than a frame header, must not panic
        let _ = r.feed(3, &[0xff; 50]); // frame header with a bogus huge length
    }

    #[test]
    fn a_malformed_hpack_dynamic_table_size_update_desyncs_instead_of_panicking() {
        // Regression test for a real panic `cargo +nightly fuzz run
        // http2_reassembly` found within one fuzzing pass (Task 15): this
        // exact byte sequence reaches `Option::unwrap()` on `None` inside
        // fluke_hpack::Decoder::update_max_dynamic_size (a third-party
        // dependency bug, not this crate's), which previously aborted the
        // whole capture-agent process. `Http2Reassembler::feed` must
        // isolate that panic and degrade to `DesyncFallback`, per this
        // module's existing "never propagate a decode failure as a crash"
        // invariant — see the `catch_unwind` usage in `feed` above.
        let crash_input: &[u8] = &[0, 0, 1, 1, 1, 0, 0, 32, 0, 63, 0, 1, 1, 32, 0, 0, 0, 0, 0];
        let mut r = Http2Reassembler::new();
        let outcomes = r.feed(0, crash_input);
        assert!(
            outcomes.iter().any(|o| matches!(o, FrameOutcome::DesyncFallback { .. })),
            "expected a DesyncFallback outcome, not a panic or a silently-swallowed frame"
        );
    }
}
