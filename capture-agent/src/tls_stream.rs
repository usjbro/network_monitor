use std::fmt;

pub const MAX_TLS_RECORD_BODY_BYTES: usize = (1 << 14) + 256;
pub const MAX_TLS_RECORD_WIRE_BYTES: usize = 5 + MAX_TLS_RECORD_BODY_BYTES;
pub const TLS_REORDER_WINDOW_BYTES: usize = MAX_TLS_RECORD_WIRE_BYTES;

pub fn first_data_sequence(tcp_sequence: u32, syn: bool) -> u32 {
    tcp_sequence.wrapping_add(u32::from(syn))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsStreamError {
    ReorderWindowExceeded,
    ConflictingOverlap,
    RecordTooLarge,
}

impl fmt::Display for TlsStreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReorderWindowExceeded => f.write_str("TLS TCP reorder window exceeded"),
            Self::ConflictingOverlap => f.write_str("conflicting TCP overlap in TLS stream"),
            Self::RecordTooLarge => f.write_str("TLS record length exceeds the protocol limit"),
        }
    }
}

impl std::error::Error for TlsStreamError {}

/// Sliding byte consumer for one TCP direction. `initial_seq` is the first
/// data sequence after an observed SYN; without that anchor the caller must
/// not create a decryptable stream.
#[derive(Debug, Clone)]
pub struct TlsTcpStream {
    next_seq: u32,
    bytes: Vec<u8>,
    present: Vec<u8>,
}

impl TlsTcpStream {
    pub fn new(initial_seq: u32) -> Self {
        Self {
            next_seq: initial_seq,
            bytes: Vec::new(),
            present: Vec::new(),
        }
    }

    /// Adds a segment and returns only the newly contiguous prefix. Out of
    /// order bytes are retained inside a one-record window; first-seen bytes
    /// win if retransmissions overlap.
    pub fn feed(&mut self, seq: u32, payload: &[u8]) -> Result<Vec<u8>, TlsStreamError> {
        if payload.is_empty() {
            return Ok(Vec::new());
        }
        let relative = seq.wrapping_sub(self.next_seq) as i32;
        let (offset, payload) = if relative < 0 {
            let overlap = relative.unsigned_abs() as usize;
            if overlap >= payload.len() {
                return Ok(Vec::new());
            }
            (0, &payload[overlap..])
        } else {
            (relative as usize, payload)
        };
        let end = offset
            .checked_add(payload.len())
            .ok_or(TlsStreamError::ReorderWindowExceeded)?;
        if end > TLS_REORDER_WINDOW_BYTES {
            if offset == 0 && self.bytes.is_empty() {
                self.next_seq = self.next_seq.wrapping_add(payload.len() as u32);
                return Ok(payload.to_vec());
            }
            return Err(TlsStreamError::ReorderWindowExceeded);
        }
        if end > self.bytes.len() {
            self.bytes.resize(end, 0);
            self.present.resize(end, 0);
        }
        for (index, byte) in payload.iter().copied().enumerate() {
            let slot = offset + index;
            if self.present[slot] != 0 {
                if self.bytes[slot] != byte {
                    return Err(TlsStreamError::ConflictingOverlap);
                }
            } else {
                self.bytes[slot] = byte;
                self.present[slot] = 1;
            }
        }
        let contiguous = self
            .present
            .iter()
            .take_while(|&&present| present != 0)
            .count();
        if contiguous == 0 {
            return Ok(Vec::new());
        }
        let output = self.bytes[..contiguous].to_vec();
        self.bytes.drain(..contiguous);
        self.present.drain(..contiguous);
        self.next_seq = self.next_seq.wrapping_add(contiguous as u32);
        Ok(output)
    }

    pub fn bytes_held(&self) -> usize {
        self.bytes.capacity() + self.present.capacity()
    }

    pub fn has_pending_gap(&self) -> bool {
        self.present.contains(&0) && self.present.iter().any(|&present| present != 0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsRecordError {
    RecordTooLarge,
}

/// Incremental TLS record framer. It retains at most the current partial
/// record and checks the protocol length before buffering its body.
#[derive(Debug, Default)]
pub struct TlsRecordFramer {
    buffer: Vec<u8>,
}

impl TlsRecordFramer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed(&mut self, mut input: &[u8]) -> Result<Vec<Vec<u8>>, TlsRecordError> {
        let mut records = Vec::new();
        while !input.is_empty() {
            let target = if self.buffer.len() < 5 {
                5
            } else {
                let body_len = u16::from_be_bytes([self.buffer[3], self.buffer[4]]) as usize;
                if body_len > MAX_TLS_RECORD_BODY_BYTES {
                    self.buffer = Vec::new();
                    return Err(TlsRecordError::RecordTooLarge);
                }
                5 + body_len
            };
            let amount = (target - self.buffer.len()).min(input.len());
            self.buffer.extend_from_slice(&input[..amount]);
            input = &input[amount..];

            if self.buffer.len() == 5 {
                let body_len = u16::from_be_bytes([self.buffer[3], self.buffer[4]]) as usize;
                if body_len > MAX_TLS_RECORD_BODY_BYTES {
                    self.buffer = Vec::new();
                    return Err(TlsRecordError::RecordTooLarge);
                }
                if body_len == 0 {
                    records.push(std::mem::take(&mut self.buffer));
                }
            } else if self.buffer.len() == target {
                records.push(std::mem::take(&mut self.buffer));
            }
        }
        Ok(records)
    }

    pub fn bytes_held(&self) -> usize {
        self.buffer.capacity()
    }
}

/// Couples TCP ordering with TLS record framing for one direction. Callers
/// create it only after observing the flow's SYN, with the first data
/// sequence (`SYN.seq + 1`).
#[derive(Debug)]
pub struct TlsDirectionStream {
    tcp: TlsTcpStream,
    records: TlsRecordFramer,
}

impl TlsDirectionStream {
    pub fn new(initial_seq: u32) -> Self {
        Self {
            tcp: TlsTcpStream::new(initial_seq),
            records: TlsRecordFramer::new(),
        }
    }

    pub fn feed_segment(
        &mut self,
        seq: u32,
        payload: &[u8],
    ) -> Result<Vec<Vec<u8>>, TlsStreamError> {
        let contiguous = self.tcp.feed(seq, payload)?;
        self.records.feed(&contiguous).map_err(|error| match error {
            TlsRecordError::RecordTooLarge => TlsStreamError::RecordTooLarge,
        })
    }

    pub fn bytes_held(&self) -> usize {
        self.tcp.bytes_held() + self.records.bytes_held()
    }

    pub fn has_pending_gap(&self) -> bool {
        self.tcp.has_pending_gap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn releases_tcp_bytes_only_after_out_of_order_holes_are_filled() {
        let mut stream = TlsTcpStream::new(100);
        assert!(stream.feed(104, b"EF").unwrap().is_empty());
        assert!(stream.feed(102, b"CD").unwrap().is_empty());
        assert_eq!(stream.feed(100, b"AB").unwrap(), b"ABCDEF");
    }

    #[test]
    fn conflicting_retransmission_inside_the_pending_window_is_rejected() {
        let mut stream = TlsTcpStream::new(100);
        assert!(stream.feed(104, b"EF").unwrap().is_empty());
        assert_eq!(
            stream.feed(104, b"XX"),
            Err(TlsStreamError::ConflictingOverlap)
        );
    }

    #[test]
    fn retransmissions_before_consumed_edge_are_ignored_and_straddling_tail_is_fed() {
        let mut stream = TlsTcpStream::new(100);
        assert_eq!(stream.feed(100, b"abcdef").unwrap(), b"abcdef");
        let consumed_edge = stream.next_seq;
        assert!(stream.feed(102, b"XYZ").unwrap().is_empty());
        assert_eq!(stream.next_seq, consumed_edge);
        assert_eq!(stream.feed(104, b"efgh").unwrap(), b"gh");
        assert_eq!(stream.next_seq, consumed_edge.wrapping_add(2));
    }

    #[test]
    fn accepts_large_in_order_tcp_segments_without_using_the_reorder_window() {
        let mut stream = TlsTcpStream::new(100);
        let payload = vec![0x5a; TLS_REORDER_WINDOW_BYTES + 100];
        assert_eq!(stream.feed(100, &payload).unwrap(), payload);
    }

    #[test]
    fn frames_tls_record_split_across_multiple_contiguous_chunks() {
        let mut framer = TlsRecordFramer::new();
        assert!(framer.feed(&[0x17, 0x03, 0x03, 0x00]).unwrap().is_empty());
        assert!(framer.feed(&[0x03, b'a']).unwrap().is_empty());
        assert_eq!(
            framer.feed(b"bc").unwrap(),
            vec![vec![0x17, 0x03, 0x03, 0x00, 0x03, b'a', b'b', b'c']]
        );
    }

    #[test]
    fn frames_two_complete_records_from_one_stream_chunk() {
        let mut framer = TlsRecordFramer::new();
        assert_eq!(
            framer
                .feed(&[0x17, 3, 3, 0, 1, b'a', 0x17, 3, 3, 0, 1, b'b'])
                .unwrap(),
            vec![vec![0x17, 3, 3, 0, 1, b'a'], vec![0x17, 3, 3, 0, 1, b'b']]
        );
    }

    #[test]
    fn rejects_oversized_tls_record_before_waiting_for_its_body() {
        let mut framer = TlsRecordFramer::new();
        assert_eq!(
            framer.feed(&[0x17, 3, 3, 0x41, 1]),
            Err(TlsRecordError::RecordTooLarge)
        );
        assert_eq!(framer.bytes_held(), 0);
    }

    #[test]
    fn reconstructs_a_record_split_across_three_out_of_order_tcp_segments() {
        let mut stream = TlsDirectionStream::new(100);
        assert!(stream.feed_segment(102, &[3, 0]).unwrap().is_empty());
        assert!(stream
            .feed_segment(104, &[3, b'a', b'b', b'c'])
            .unwrap()
            .is_empty());
        assert_eq!(
            stream.feed_segment(100, &[0x17, 3]).unwrap(),
            vec![vec![0x17, 3, 3, 0, 3, b'a', b'b', b'c']]
        );
    }

    #[test]
    fn frames_maximum_size_record_after_out_of_order_reassembly() {
        let mut record = vec![0x17, 0x03, 0x03, 0x41, 0x00];
        record.extend(vec![0x5a; MAX_TLS_RECORD_BODY_BYTES]);
        assert_eq!(record.len(), MAX_TLS_RECORD_WIRE_BYTES);
        let mut stream = TlsDirectionStream::new(900);
        let split = 8_000;
        assert!(stream
            .feed_segment(900 + split as u32, &record[split..])
            .unwrap()
            .is_empty());
        assert_eq!(
            stream.feed_segment(900, &record[..split]).unwrap(),
            vec![record]
        );
    }

    #[test]
    fn pending_gap_is_reported_until_the_missing_sequence_range_arrives() {
        let mut stream = TlsTcpStream::new(100);
        assert!(stream.feed(104, b"EF").unwrap().is_empty());
        assert!(stream.has_pending_gap());
        assert_eq!(stream.feed(100, b"ABCD").unwrap(), b"ABCDEF");
        assert!(!stream.has_pending_gap());
    }

    #[test]
    fn initial_stream_anchor_skips_the_syn_sequence_number() {
        assert_eq!(first_data_sequence(u32::MAX, true), 0);
        assert_eq!(first_data_sequence(42, false), 42);
    }
}
