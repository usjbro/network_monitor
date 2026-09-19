//! A hand-rolled pcapng encoder and decoder (issue #70/#71, JAM-132/JAM-133).
//! Deliberately narrow: four block types (Section Header, Interface
//! Description, Enhanced Packet, Interface Statistics), no Name Resolution
//! or Decryption Secrets blocks, no per-packet comments. See
//! docs/superpowers/specs/2026-09-19-capture-files-design.md Components §1
//! for why this is hand-rolled rather than a new crate dependency.
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt; // mode() — Unix-only, matching this repo's existing macOS/Linux-only posture
use std::path::Path;
use std::time::SystemTime;

const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;
const BT_SECTION_HEADER: u32 = 0x0A0D_0D0A;
const BT_INTERFACE_DESCRIPTION: u32 = 0x0000_0001;
const BT_ENHANCED_PACKET: u32 = 0x0000_0006;
const BT_INTERFACE_STATISTICS: u32 = 0x0000_0005;

const OPT_END_OF_OPT: u16 = 0;
const SHB_USERAPPL: u16 = 4;
const IF_NAME: u16 = 2;
const IF_TSRESOL: u16 = 9;
const EPB_FLAGS: u16 = 2;
const ISB_IFRECV: u16 = 4;
const ISB_IFDROP: u16 = 5;

/// Rounds `n` up to the next multiple of 4 — every pcapng block body, and
/// every option value, is padded to a 32-bit boundary.
fn pad4(n: usize) -> usize {
    (n + 3) & !3
}

/// Writes one option's TLV (code, length, value, padding) — shared by every
/// block type, since pcapng's option encoding is identical regardless of
/// which block or which option code is being written.
fn write_option(w: &mut impl Write, code: u16, value: &[u8]) -> io::Result<()> {
    w.write_all(&code.to_le_bytes())?;
    w.write_all(&(value.len() as u16).to_le_bytes())?;
    w.write_all(value)?;
    let padding = pad4(value.len()) - value.len();
    w.write_all(&vec![0u8; padding])
}

fn write_end_of_opt(w: &mut impl Write) -> io::Result<()> {
    w.write_all(&OPT_END_OF_OPT.to_le_bytes())?;
    w.write_all(&0u16.to_le_bytes())
}

/// Writes one full block: type, length, body, length repeated. `body` must
/// already end on a 4-byte boundary — every block-body builder below
/// guarantees this by construction (every option is padded, and the
/// fixed-width fields before the options are all already multiples of 4).
fn write_block(w: &mut impl Write, block_type: u32, body: &[u8]) -> io::Result<()> {
    let total_len = 12 + body.len() as u32; // type + len + body + len
    w.write_all(&block_type.to_le_bytes())?;
    w.write_all(&total_len.to_le_bytes())?;
    w.write_all(body)?;
    w.write_all(&total_len.to_le_bytes())
}

/// Section Header Block — written once, at file open.
pub struct SectionHeaderBlock {
    pub hostname: String,
    pub agent_version: String,
}

impl SectionHeaderBlock {
    pub fn write_to(&self, w: &mut impl Write) -> io::Result<()> {
        let mut body = Vec::new();
        body.extend_from_slice(&BYTE_ORDER_MAGIC.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes()); // major version
        body.extend_from_slice(&0u16.to_le_bytes()); // minor version
        body.extend_from_slice(&(-1i64).to_le_bytes()); // section length: unknown

        let userappl = format!("capture-agent/{} on {}", self.agent_version, self.hostname);
        write_option(&mut body, SHB_USERAPPL, userappl.as_bytes())?;
        write_end_of_opt(&mut body)?;

        write_block(w, BT_SECTION_HEADER, &body)
    }
}

/// pcapng LINKTYPE_* values this agent can produce — a small, closed
/// mapping from `parse::LinkType` (the agent's own internal link-type enum,
/// already resolved once at startup), not a general-purpose pcapng
/// linktype table.
fn pcapng_linktype(link_type: crate::parse::LinkType) -> u16 {
    match link_type {
        crate::parse::LinkType::Ethernet => 1,     // LINKTYPE_ETHERNET
        crate::parse::LinkType::NullLoopback => 0, // LINKTYPE_NULL
        crate::parse::LinkType::Raw => 101,        // LINKTYPE_RAW
    }
}

/// Interface Description Block — written once, at file open.
#[derive(Clone)]
pub struct InterfaceDescriptionBlock {
    pub interface_name: String,
    pub link_type: crate::parse::LinkType,
    pub snaplen: u32,
    /// Honest per the platform clock's actual resolution. `9` means
    /// nanosecond (10^-9); pcapng's `if_tsresol` encodes resolution as a
    /// power-of-ten exponent with the high bit clear, so a plain byte value
    /// of the exponent is correct here.
    pub timestamp_resolution_exponent: u8,
}

impl InterfaceDescriptionBlock {
    pub fn write_to(&self, w: &mut impl Write) -> io::Result<()> {
        let mut body = Vec::new();
        body.extend_from_slice(&pcapng_linktype(self.link_type).to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes()); // reserved
        body.extend_from_slice(&self.snaplen.to_le_bytes());

        write_option(&mut body, IF_NAME, self.interface_name.as_bytes())?;
        write_option(&mut body, IF_TSRESOL, &[self.timestamp_resolution_exponent])?;
        write_end_of_opt(&mut body)?;

        write_block(w, BT_INTERFACE_DESCRIPTION, &body)
    }
}

/// A captured frame's direction relative to this agent's local address(es),
/// already computed by `FlowTable`'s existing `is_local` check — cheap to
/// carry through since the caller has it on hand for every packet anyway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
    Unknown,
}

impl Direction {
    /// epb_flags is a 32-bit field; bits 0-1 encode direction per the
    /// pcapng spec (00 = unknown/not available, 01 = inbound, 10 =
    /// outbound). No other bits are set by this agent — a per-packet
    /// *error* flag would require classifying an individual frame as
    /// errored at a granularity this agent doesn't have, and inventing a
    /// value would violate this codebase's "report zero/absent rather than
    /// fabricate" convention.
    fn epb_flags_bits(&self) -> u32 {
        match self {
            Direction::Unknown => 0b00,
            Direction::Inbound => 0b01,
            Direction::Outbound => 0b10,
        }
    }
}

/// Every captured frame this agent writes uses interface id `0` — this
/// agent only ever writes one interface's traffic per file, so pcapng's
/// multi-interface support (interface IDs beyond 0) is unused, deliberately
/// narrow scope.
const INTERFACE_ID: u32 = 0;

fn epb_timestamp_halves(timestamp: SystemTime) -> (u32, u32) {
    // pcapng's EPB timestamp is a 64-bit value split into two 32-bit
    // halves, in whatever unit the owning IDB's if_tsresol declared — this
    // agent always declares resolution as nanoseconds where the platform
    // clock supports it (InterfaceDescriptionBlock's own doc comment), so
    // this encodes nanoseconds-since-epoch split high/low.
    let ts_ns = timestamp
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    ((ts_ns >> 32) as u32, (ts_ns & 0xFFFF_FFFF) as u32)
}

fn write_enhanced_packet_block(
    w: &mut impl Write,
    timestamp: SystemTime,
    direction: Direction,
    data: &[u8],
) -> io::Result<()> {
    let (ts_high, ts_low) = epb_timestamp_halves(timestamp);

    let mut body = Vec::new();
    body.extend_from_slice(&INTERFACE_ID.to_le_bytes());
    body.extend_from_slice(&ts_high.to_le_bytes());
    body.extend_from_slice(&ts_low.to_le_bytes());
    body.extend_from_slice(&(data.len() as u32).to_le_bytes()); // captured length
    body.extend_from_slice(&(data.len() as u32).to_le_bytes()); // original length — never truncated below what was captured
    body.extend_from_slice(data);
    let padding = pad4(data.len()) - data.len();
    body.extend_from_slice(&vec![0u8; padding]);

    write_option(&mut body, EPB_FLAGS, &direction.epb_flags_bits().to_le_bytes())?;
    write_end_of_opt(&mut body)?;

    write_block(w, BT_ENHANCED_PACKET, &body)
}

fn write_interface_statistics_block(w: &mut impl Write, timestamp: SystemTime, received: u64, dropped: u64) -> io::Result<()> {
    let (ts_high, ts_low) = epb_timestamp_halves(timestamp);

    let mut body = Vec::new();
    body.extend_from_slice(&INTERFACE_ID.to_le_bytes());
    body.extend_from_slice(&ts_high.to_le_bytes());
    body.extend_from_slice(&ts_low.to_le_bytes());

    write_option(&mut body, ISB_IFRECV, &received.to_le_bytes())?;
    write_option(&mut body, ISB_IFDROP, &dropped.to_le_bytes())?;
    write_end_of_opt(&mut body)?;

    write_block(w, BT_INTERFACE_STATISTICS, &body)
}

/// Ties the Section Header, Interface Description, Enhanced Packet, and
/// Interface Statistics block writers to one open file. `create` writes
/// the Section Header and Interface Description blocks immediately (both
/// are written exactly once, at file open); `write_packet`/
/// `write_interface_stats` append further blocks; `finish` flushes and
/// closes the handle.
///
/// `finish` deliberately does NOT rename the file — `ring.rs` (a later
/// task) owns the write-to-`.partial`-then-rename sequence, since that
/// policy belongs to rotation, not to the codec itself. A caller that only
/// ever writes one file, never rotating, still wants a correctly-closed
/// file without needing to know about `.partial` naming at all.
pub struct Writer {
    file: File,
    bytes_written: u64,
}

impl Writer {
    /// Opens `path` fresh (`0600`, refusing to silently overwrite an
    /// existing file at that path) and writes the Section Header and
    /// Interface Description blocks.
    pub fn create(path: &Path, idb: &InterfaceDescriptionBlock, hostname: &str, agent_version: &str) -> io::Result<Self> {
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
        SectionHeaderBlock {
            hostname: hostname.to_string(),
            agent_version: agent_version.to_string(),
        }
        .write_to(&mut file)?;
        idb.write_to(&mut file)?;
        file.flush()?;
        Ok(Self { file, bytes_written: 0 })
    }

    pub fn write_packet(&mut self, timestamp: SystemTime, direction: Direction, data: &[u8]) -> io::Result<()> {
        let before = self.bytes_written;
        write_enhanced_packet_block(&mut self.file, timestamp, direction, data)?;
        // Recomputed from the block's own known layout rather than tracked
        // by a separate running total elsewhere, so bytes_written can never
        // drift from what was actually written to the file handle: 4 fixed
        // fields (interface id, ts-high, ts-low, captured-len, original-len
        // = 20 bytes) + padded data + the epb_flags option (4-byte header +
        // 4-byte value) + the 4-byte end-of-options marker + 12 bytes of
        // block framing (type + length + length).
        let written = 20 + pad4(data.len()) + 4 + 4 + 4 + 12;
        self.bytes_written = before + written as u64;
        Ok(())
    }

    pub fn write_interface_stats(&mut self, received: u64, dropped: u64) -> io::Result<()> {
        write_interface_statistics_block(&mut self.file, SystemTime::now(), received, dropped)
        // Deliberately not counted toward bytes_written: that field tracks
        // packet-data volume for the UI ("N bytes written" of *capture*),
        // and an ISB is periodic bookkeeping, not captured traffic.
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Flushes and fsyncs the handle. Does not rename the file — see the
    /// struct doc comment.
    pub fn finish(mut self) -> io::Result<()> {
        self.file.flush()?;
        self.file.sync_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_block_header(bytes: &[u8]) -> (u32, u32) {
        let block_type = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let total_len = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        (block_type, total_len)
    }

    #[test]
    fn every_written_block_has_matching_length_prefix_and_suffix() {
        let mut buf = Vec::new();
        SectionHeaderBlock {
            hostname: "test-host".into(),
            agent_version: "0.1.0".into(),
        }
        .write_to(&mut buf)
        .unwrap();
        let (block_type, total_len) = parse_block_header(&buf);
        assert_eq!(block_type, BT_SECTION_HEADER);
        assert_eq!(buf.len(), total_len as usize);
        let suffix = u32::from_le_bytes(buf[buf.len() - 4..].try_into().unwrap());
        assert_eq!(suffix, total_len);
    }

    #[test]
    fn block_length_is_always_a_multiple_of_four() {
        let mut buf = Vec::new();
        // An odd-length interface name forces the padding path — this is
        // exactly the case most likely to produce a misaligned block if
        // write_option's padding math is wrong.
        InterfaceDescriptionBlock {
            interface_name: "en0x".into(), // 4 bytes
            link_type: crate::parse::LinkType::Ethernet,
            snaplen: 65535,
            timestamp_resolution_exponent: 9,
        }
        .write_to(&mut buf)
        .unwrap();
        assert_eq!(buf.len() % 4, 0);

        buf.clear();
        InterfaceDescriptionBlock {
            interface_name: "lo".into(), // 2 bytes — odd relative to 4-byte option padding
            link_type: crate::parse::LinkType::NullLoopback,
            snaplen: 65535,
            timestamp_resolution_exponent: 6,
        }
        .write_to(&mut buf)
        .unwrap();
        assert_eq!(buf.len() % 4, 0);
    }

    #[test]
    fn pcapng_linktype_maps_each_supported_link_type_to_a_distinct_value() {
        let values: Vec<u16> = [
            crate::parse::LinkType::Ethernet,
            crate::parse::LinkType::NullLoopback,
            crate::parse::LinkType::Raw,
        ]
        .into_iter()
        .map(pcapng_linktype)
        .collect();
        let mut sorted = values.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), values.len(), "each LinkType must map to a distinct pcapng LINKTYPE_*");
    }

    #[test]
    fn section_header_block_userappl_option_contains_hostname_and_version() {
        let mut buf = Vec::new();
        SectionHeaderBlock {
            hostname: "my-mac".into(),
            agent_version: "0.1.0".into(),
        }
        .write_to(&mut buf)
        .unwrap();
        let haystack = String::from_utf8_lossy(&buf);
        assert!(haystack.contains("my-mac"));
        assert!(haystack.contains("0.1.0"));
    }
}

#[cfg(test)]
mod writer_tests {
    use super::*;
    use std::time::SystemTime;

    fn temp_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("pcapng-writer-test-{label}-{}.pcapng", std::process::id()))
    }

    fn test_idb() -> InterfaceDescriptionBlock {
        InterfaceDescriptionBlock {
            interface_name: "lo".into(),
            link_type: crate::parse::LinkType::NullLoopback,
            snaplen: 65535,
            timestamp_resolution_exponent: 9,
        }
    }

    #[test]
    fn creates_a_file_with_0600_permissions() {
        let path = temp_path("perms");
        let writer = Writer::create(&path, &test_idb(), "test-host", "0.1.0").unwrap();
        writer.finish().unwrap();

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn refuses_to_overwrite_an_existing_file() {
        let path = temp_path("no-overwrite");
        std::fs::write(&path, b"pre-existing").unwrap();
        let result = Writer::create(&path, &test_idb(), "test-host", "0.1.0");
        assert!(result.is_err(), "create_new should refuse an existing path");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn bytes_written_matches_actual_file_size_growth_after_several_packets() {
        let path = temp_path("byte-count");
        let mut writer = Writer::create(&path, &test_idb(), "test-host", "0.1.0").unwrap();
        let header_size = std::fs::metadata(&path).unwrap().len();

        for _ in 0..5 {
            writer.write_packet(SystemTime::now(), Direction::Inbound, &[0u8; 64]).unwrap();
        }
        let bytes_after = writer.bytes_written();
        writer.finish().unwrap();

        let actual_file_size = std::fs::metadata(&path).unwrap().len();
        assert_eq!(actual_file_size, header_size + bytes_after);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn bytes_written_is_unaffected_by_writing_interface_stats() {
        let path = temp_path("stats-not-counted");
        let mut writer = Writer::create(&path, &test_idb(), "test-host", "0.1.0").unwrap();
        writer.write_packet(SystemTime::now(), Direction::Outbound, &[1, 2, 3]).unwrap();
        let before = writer.bytes_written();
        writer.write_interface_stats(100, 2).unwrap();
        assert_eq!(writer.bytes_written(), before, "an ISB write must not change the packet-volume counter");
        writer.finish().unwrap();
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn odd_length_payload_still_produces_a_four_byte_aligned_block() {
        let mut buf = Vec::new();
        write_enhanced_packet_block(&mut buf, SystemTime::now(), Direction::Inbound, &[1, 2, 3]).unwrap();
        assert_eq!(buf.len() % 4, 0);
        let total_len = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        assert_eq!(buf.len(), total_len as usize);
    }

    #[test]
    fn interface_statistics_block_has_matching_length_prefix_and_suffix() {
        let mut buf = Vec::new();
        write_interface_statistics_block(&mut buf, SystemTime::now(), 1000, 5).unwrap();
        let block_type = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let total_len = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        assert_eq!(block_type, BT_INTERFACE_STATISTICS);
        assert_eq!(buf.len(), total_len as usize);
        let suffix = u32::from_le_bytes(buf[buf.len() - 4..].try_into().unwrap());
        assert_eq!(suffix, total_len);
    }
}
