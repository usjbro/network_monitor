//! KAN-110 Task 3a: the authenticated control connection reads one line at
//! a time with a hard byte cap, checked before the buffer grows. Tokio's
//! `Lines` grows its `String` to whatever the peer sends before anything
//! can look at it; this reader never holds more than
//! `MAX_CONTROL_LINE_BYTES`.

use tokio::io::{AsyncBufRead, AsyncBufReadExt};

/// The longest control line, LF included. The largest current control is
/// `set_io_series` at its bounds: 8 series, each a 2,048-unit filter, which
/// the relay's `JSON.stringify` can write as six-byte escapes (about 99 KB
/// in all). The plan's 32 KiB would refuse a legitimate set of non-ASCII
/// filters, so the cap is 128 KiB: at 64 authenticated connections that
/// is at most 8 MiB held.
pub const MAX_CONTROL_LINE_BYTES: usize = 128 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum ControlRead {
    /// One line, without its LF (a CR before it is left for the parser,
    /// as `Lines` did). A final line at EOF without an LF still counts.
    Line(String),
    /// The peer closed with nothing pending.
    Eof,
    /// The line would exceed the cap; nothing of it beyond the cap was
    /// buffered. The connection should close without parsing it.
    TooLong,
    /// The line is not UTF-8.
    NotUtf8,
}

/// Reads control lines from `R`. Cancel-safe: `next_line` may be dropped
/// at its only await (`fill_buf`) and called again without losing bytes,
/// because bytes are consumed from the reader only once they are copied
/// into the persistent buffer.
pub struct ControlLines<R> {
    reader: R,
    buf: Vec<u8>,
}

impl<R: AsyncBufRead + Unpin> ControlLines<R> {
    pub fn new(reader: R) -> Self {
        ControlLines { reader, buf: Vec::new() }
    }

    pub async fn next_line(&mut self) -> std::io::Result<ControlRead> {
        loop {
            let available = self.reader.fill_buf().await?;
            if available.is_empty() {
                if self.buf.is_empty() {
                    return Ok(ControlRead::Eof);
                }
                return Ok(self.finish(0));
            }
            let newline = available.iter().position(|b| *b == b'\n');
            let take = newline.map_or(available.len(), |n| n + 1);
            // Checked before the buffer grows: a line over the cap is
            // never held, only refused.
            if self.buf.len() + take > MAX_CONTROL_LINE_BYTES {
                self.buf = Vec::new();
                return Ok(ControlRead::TooLong);
            }
            self.buf.reserve_exact(take);
            self.buf.extend_from_slice(&available[..take]);
            self.reader.consume(take);
            if newline.is_some() {
                return Ok(self.finish(1));
            }
        }
    }

    /// Hands over the buffered line minus its `lf` trailing bytes.
    fn finish(&mut self, lf: usize) -> ControlRead {
        let mut bytes = std::mem::take(&mut self.buf);
        bytes.truncate(bytes.len() - lf);
        match String::from_utf8(bytes) {
            Ok(text) => ControlRead::Line(text),
            Err(_) => ControlRead::NotUtf8,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, BufReader};

    async fn read_all(input: &[u8]) -> Vec<ControlRead> {
        let mut lines = ControlLines::new(BufReader::new(input));
        let mut out = Vec::new();
        loop {
            let r = lines.next_line().await.unwrap();
            let stop = matches!(r, ControlRead::Eof | ControlRead::TooLong | ControlRead::NotUtf8);
            out.push(r);
            if stop {
                return out;
            }
        }
    }

    fn line_of(len_with_lf: usize) -> Vec<u8> {
        let mut v = vec![b'a'; len_with_lf - 1];
        v.push(b'\n');
        v
    }

    #[tokio::test]
    async fn a_line_exactly_at_the_cap_is_read() {
        let input = line_of(MAX_CONTROL_LINE_BYTES);
        let out = read_all(&input).await;
        assert_eq!(out, vec![ControlRead::Line("a".repeat(MAX_CONTROL_LINE_BYTES - 1)), ControlRead::Eof]);
    }

    #[tokio::test]
    async fn a_line_one_byte_over_the_cap_is_refused() {
        let input = line_of(MAX_CONTROL_LINE_BYTES + 1);
        assert_eq!(read_all(&input).await, vec![ControlRead::TooLong]);
    }

    #[tokio::test]
    async fn the_buffer_never_grows_past_the_cap() {
        // An unterminated stream far past the cap: refused at the cap.
        let input = vec![b'{'; 4 * MAX_CONTROL_LINE_BYTES];
        let mut lines = ControlLines::new(BufReader::with_capacity(512, &input[..]));
        assert_eq!(lines.next_line().await.unwrap(), ControlRead::TooLong);
        assert!(lines.buf.capacity() <= MAX_CONTROL_LINE_BYTES, "buffered {}", lines.buf.capacity());
    }

    #[tokio::test]
    async fn lines_split_across_reads_are_joined() {
        let (mut tx, rx) = tokio::io::duplex(8);
        let writer = tokio::spawn(async move {
            for chunk in [&b"{\"type\":"[..], b"\"pause\"}", b"\n{\"type\":\"res", b"ume\"}\n"] {
                tx.write_all(chunk).await.unwrap();
            }
        });
        let mut lines = ControlLines::new(BufReader::new(rx));
        assert_eq!(lines.next_line().await.unwrap(), ControlRead::Line("{\"type\":\"pause\"}".into()));
        assert_eq!(lines.next_line().await.unwrap(), ControlRead::Line("{\"type\":\"resume\"}".into()));
        writer.await.unwrap();
        assert_eq!(lines.next_line().await.unwrap(), ControlRead::Eof);
    }

    #[tokio::test]
    async fn a_valid_line_after_a_previous_valid_line_is_read_whole() {
        let out = read_all(b"{\"type\":\"pause\"}\r\n{\"type\":\"resume\"}\n").await;
        assert_eq!(
            out,
            vec![
                ControlRead::Line("{\"type\":\"pause\"}\r".into()),
                ControlRead::Line("{\"type\":\"resume\"}".into()),
                ControlRead::Eof,
            ]
        );
    }

    #[tokio::test]
    async fn a_final_line_without_lf_still_counts_as_lines_did() {
        assert_eq!(
            read_all(b"{\"type\":\"pause\"}").await,
            vec![ControlRead::Line("{\"type\":\"pause\"}".into()), ControlRead::Eof]
        );
        assert_eq!(read_all(b"").await, vec![ControlRead::Eof]);
    }

    #[tokio::test]
    async fn an_oversized_final_line_without_lf_is_refused() {
        let input = vec![b'a'; MAX_CONTROL_LINE_BYTES + 1];
        assert_eq!(read_all(&input).await, vec![ControlRead::TooLong]);
    }

    #[tokio::test]
    async fn non_utf8_is_reported_not_lossily_decoded() {
        assert_eq!(read_all(b"{\"type\":\"pa\xffuse\"}\n").await, vec![ControlRead::NotUtf8]);
    }

    #[tokio::test]
    async fn a_long_unknown_field_under_the_cap_reaches_the_parser() {
        let line = format!("{{\"type\":\"pause\",\"x\":\"{}\"}}\n", "z".repeat(30_000));
        let out = read_all(line.as_bytes()).await;
        let ControlRead::Line(text) = &out[0] else { panic!("{out:?}") };
        assert!(matches!(
            crate::wire::classify_control_line(text),
            crate::wire::ControlLine::Message(crate::wire::ControlMessage::Pause)
        ));
    }

    #[tokio::test]
    async fn the_largest_current_control_fits_with_every_character_escaped() {
        // A 4,096-character keylog path, every character a six-byte escape.
        let path = "\\u002f".repeat(4096);
        let line = format!("{{\"type\":\"register_decrypt_eligible\",\"pid\":4294967295,\"keylogPath\":\"{path}\"}}\n");
        assert!(line.len() < MAX_CONTROL_LINE_BYTES, "{} bytes", line.len());
        let out = read_all(line.as_bytes()).await;
        let ControlRead::Line(text) = &out[0] else { panic!("{out:?}") };
        let crate::wire::ControlLine::Message(crate::wire::ControlMessage::RegisterDecryptEligible { keylog_path, .. }) =
            crate::wire::classify_control_line(text)
        else {
            panic!("not a register_decrypt_eligible control")
        };
        assert_eq!(keylog_path.chars().count(), 4096);
    }

    #[tokio::test]
    async fn the_largest_io_series_set_fits_with_every_filter_unit_escaped() {
        // Every bound the relay allows (app/api/control/route.ts), with each
        // filter code unit written by JSON.stringify as a six-byte escape.
        let hex = "f".repeat(32);
        let series: Vec<String> = (0..crate::io_series::MAX_IO_SERIES)
            .map(|n| {
                format!(
                    "{{\"id\":\"{:0>32}\",\"filter\":\"{}\",\"aggregate\":{{\"fn\":\"avg\",\"field\":\"{}\"}}}}",
                    n,
                    "\\u0001".repeat(crate::io_series::MAX_FILTER_UTF16),
                    "f".repeat(64)
                )
            })
            .collect();
        let line = format!(
            "{{\"type\":\"set_io_series\",\"baseEpoch\":\"{hex}\",\"baseRevision\":4294967295,\"requestId\":\"{hex}\",\"series\":[{}]}}\n",
            series.join(",")
        );
        assert!(line.len() <= MAX_CONTROL_LINE_BYTES, "{} bytes", line.len());
        let out = read_all(line.as_bytes()).await;
        let ControlRead::Line(text) = &out[0] else { panic!("{out:?}") };
        assert!(matches!(
            crate::wire::classify_control_line(text),
            crate::wire::ControlLine::Message(crate::wire::ControlMessage::SetIoSeries { .. })
        ));
    }

    #[tokio::test]
    async fn a_cancelled_read_loses_no_bytes() {
        let (mut tx, rx) = tokio::io::duplex(64);
        let mut lines = ControlLines::new(BufReader::new(rx));
        tx.write_all(b"{\"type\":").await.unwrap();
        // Poll until it blocks waiting for more, then drop that future.
        let pending = tokio::time::timeout(std::time::Duration::from_millis(50), lines.next_line()).await;
        assert!(pending.is_err(), "read finished without an LF");
        tx.write_all(b"\"pause\"}\n").await.unwrap();
        assert_eq!(lines.next_line().await.unwrap(), ControlRead::Line("{\"type\":\"pause\"}".into()));
    }
}
