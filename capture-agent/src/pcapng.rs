//! A hand-rolled pcapng encoder and decoder (issue #70/#71, JAM-132/JAM-133).
//! Deliberately narrow: four block types (Section Header, Interface
//! Description, Enhanced Packet, Interface Statistics), no Name Resolution
//! or Decryption Secrets blocks, no per-packet comments. See
//! docs/superpowers/specs/2026-09-19-capture-files-design.md Components §1
//! for why this is hand-rolled rather than a new crate dependency.
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
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

/// pcapng LINKTYPE_* values this agent can read back — the exact reverse of
/// `pcapng_linktype` above, and deliberately no more permissive: a file
/// this agent didn't write itself, or one from a corrupted write, might
/// carry a linktype it has no `parse::LinkType` for, and silently guessing
/// one would misparse every packet in it.
fn linktype_from_pcapng(value: u16) -> Option<crate::parse::LinkType> {
    match value {
        1 => Some(crate::parse::LinkType::Ethernet),
        0 => Some(crate::parse::LinkType::NullLoopback),
        101 => Some(crate::parse::LinkType::Raw),
        _ => None,
    }
}

/// Reads exactly `buf.len()` bytes, distinguishing a clean end-of-stream
/// (zero bytes read before anything else) from a truncated read (some
/// bytes read, then the stream ends mid-header) — `read_block` needs this
/// distinction to know whether it's at a legitimate end of file or reading
/// a corrupted one.
fn read_exact_or_eof(r: &mut impl Read, buf: &mut [u8]) -> io::Result<bool> {
    let mut total = 0;
    while total < buf.len() {
        match r.read(&mut buf[total..])? {
            0 if total == 0 => return Ok(false),
            0 => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated pcapng block header")),
            n => total += n,
        }
    }
    Ok(true)
}

/// Blocks larger than this are rejected outright rather than allocated. A
/// truncated or hostile stream can claim any length up to `u32::MAX` in
/// its 4-byte length field, and this reader must never let that untrusted
/// value drive an unbounded allocation before the length is even known to
/// be real (found by the `pcapng_reader` fuzz target as an out-of-memory
/// crash). 16 MiB is far larger than any block this agent's own `Writer`
/// ever produces — every packet it captures is bounded by an at-most-65535
/// byte snaplen — so this only ever rejects corrupt or hostile input,
/// never a legitimate one.
const MAX_BLOCK_LEN: u32 = 16 * 1024 * 1024;

/// Reads one block's type and body, validating that its trailing length
/// matches its leading length (the same invariant `write_block` guarantees
/// on write) and that the declared length is within
/// `[12, MAX_BLOCK_LEN]` and a multiple of 4. Returns `Ok(None)` only at a
/// clean end of stream, between blocks.
fn read_block(r: &mut impl Read) -> io::Result<Option<(u32, Vec<u8>)>> {
    let mut header = [0u8; 8];
    if !read_exact_or_eof(r, &mut header)? {
        return Ok(None);
    }
    let block_type = u32::from_le_bytes(header[0..4].try_into().unwrap());
    let total_len = u32::from_le_bytes(header[4..8].try_into().unwrap());
    if !(12..=MAX_BLOCK_LEN).contains(&total_len) || total_len % 4 != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("invalid pcapng block length {total_len}")));
    }

    let body_len = (total_len - 12) as usize;
    let mut body = vec![0u8; body_len];
    r.read_exact(&mut body)?;

    let mut trailer = [0u8; 4];
    r.read_exact(&mut trailer)?;
    let trailing_len = u32::from_le_bytes(trailer);
    if trailing_len != total_len {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "pcapng block length prefix/suffix mismatch"));
    }

    Ok(Some((block_type, body)))
}

/// Walks a block body's option TLVs, calling `on_option` for each one up to
/// (not including) the end-of-options marker. `body` must already be
/// positioned right after a block's fixed-width fields.
fn for_each_option(mut body: &[u8], mut on_option: impl FnMut(u16, &[u8])) -> io::Result<()> {
    while body.len() >= 4 {
        let code = u16::from_le_bytes(body[0..2].try_into().unwrap());
        let len = u16::from_le_bytes(body[2..4].try_into().unwrap()) as usize;
        if code == OPT_END_OF_OPT {
            return Ok(());
        }
        let padded = pad4(len);
        if body.len() < 4 + padded {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated pcapng option"));
        }
        on_option(code, &body[4..4 + len]);
        body = &body[4 + padded..];
    }
    Ok(())
}

/// An Interface Description Block, decoded back from a file — the reader's
/// counterpart to `InterfaceDescriptionBlock` above. `interface_name` is
/// `None` only if a file lacks an `if_name` option, which this agent's own
/// `Writer` never produces; a reader for a foreign pcapng file would need
/// to tolerate that, so it's modeled as optional rather than assumed.
#[derive(Debug, Clone)]
pub struct ParsedInterface {
    pub interface_name: Option<String>,
    pub link_type: crate::parse::LinkType,
    pub snaplen: u32,
}

fn parse_interface_description(body: &[u8]) -> io::Result<ParsedInterface> {
    if body.len() < 8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated interface description block"));
    }
    let linktype_raw = u16::from_le_bytes(body[0..2].try_into().unwrap());
    let snaplen = u32::from_le_bytes(body[4..8].try_into().unwrap());
    let link_type = linktype_from_pcapng(linktype_raw)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("unsupported pcapng linktype {linktype_raw}")))?;

    let mut interface_name = None;
    for_each_option(&body[8..], |code, value| {
        if code == IF_NAME {
            interface_name = Some(String::from_utf8_lossy(value).into_owned());
        }
    })?;

    Ok(ParsedInterface { interface_name, link_type, snaplen })
}

/// A captured frame, decoded back from an Enhanced Packet Block —
/// `direction` reads back the same `epb_flags` option `Writer` always
/// writes; a foreign pcapng file lacking that option decodes as
/// `Direction::Unknown`, matching the flags value (`00`) the spec assigns
/// to "not available".
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub timestamp: SystemTime,
    pub direction: Direction,
    pub data: Vec<u8>,
}

fn parse_enhanced_packet(body: &[u8]) -> io::Result<ParsedPacket> {
    if body.len() < 20 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated enhanced packet block"));
    }
    let ts_high = u32::from_le_bytes(body[4..8].try_into().unwrap());
    let ts_low = u32::from_le_bytes(body[8..12].try_into().unwrap());
    let cap_len = u32::from_le_bytes(body[12..16].try_into().unwrap()) as usize;
    let padded_len = pad4(cap_len);
    if body.len() < 20 + padded_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "enhanced packet block shorter than its declared capture length",
        ));
    }
    let data = body[20..20 + cap_len].to_vec();

    let ts_ns = ((ts_high as u64) << 32) | ts_low as u64;
    let timestamp = std::time::UNIX_EPOCH + std::time::Duration::from_nanos(ts_ns);

    let mut direction = Direction::Unknown;
    for_each_option(&body[20 + padded_len..], |code, value| {
        if code == EPB_FLAGS && value.len() == 4 {
            let flags = u32::from_le_bytes(value.try_into().unwrap());
            direction = match flags & 0b11 {
                0b01 => Direction::Inbound,
                0b10 => Direction::Outbound,
                _ => Direction::Unknown,
            };
        }
    })?;

    Ok(ParsedPacket { timestamp, direction, data })
}

/// Reads back a pcapng file/stream written by `Writer` above. Deliberately
/// narrow to match the writer: understands exactly the four block types
/// `Writer` produces, skips Interface Statistics blocks transparently (the
/// caller — file replay, a later task — has no use for periodic
/// receive/drop counters describing the *original* capture host), and
/// errors on any other block type rather than silently skipping it, since
/// an unrecognized block in a file this agent wrote itself would mean data
/// corruption, not a legitimate extension.
pub struct Reader<R: Read> {
    inner: R,
}

impl<R: Read> Reader<R> {
    /// Consumes the Section Header and Interface Description blocks and
    /// returns the parsed interface metadata alongside a `Reader`
    /// positioned to read packets.
    pub fn new(mut inner: R) -> io::Result<(Self, ParsedInterface)> {
        let (block_type, _body) =
            read_block(&mut inner)?.ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "empty pcapng stream"))?;
        if block_type != BT_SECTION_HEADER {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "expected a pcapng Section Header Block first"));
        }

        let (block_type, body) = read_block(&mut inner)?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "pcapng stream ended before an Interface Description Block")
        })?;
        if block_type != BT_INTERFACE_DESCRIPTION {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "expected a pcapng Interface Description Block second"));
        }
        let interface = parse_interface_description(&body)?;

        Ok((Self { inner }, interface))
    }

    /// Returns the next captured packet, transparently skipping any
    /// Interface Statistics blocks in between, or `Ok(None)` at a clean end
    /// of stream.
    pub fn next_packet(&mut self) -> io::Result<Option<ParsedPacket>> {
        loop {
            match read_block(&mut self.inner)? {
                None => return Ok(None),
                Some((BT_ENHANCED_PACKET, body)) => return Ok(Some(parse_enhanced_packet(&body)?)),
                Some((BT_INTERFACE_STATISTICS, _)) => continue,
                Some((other, _)) => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, format!("unexpected pcapng block type {other:#x}")));
                }
            }
        }
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

#[cfg(test)]
mod reader_tests {
    use super::*;
    use std::io::Cursor;

    fn test_idb() -> InterfaceDescriptionBlock {
        InterfaceDescriptionBlock {
            interface_name: "en0".into(),
            link_type: crate::parse::LinkType::Ethernet,
            snaplen: 65535,
            timestamp_resolution_exponent: 9,
        }
    }

    #[test]
    fn linktype_from_pcapng_inverts_pcapng_linktype_for_every_supported_link_type() {
        for link_type in [
            crate::parse::LinkType::Ethernet,
            crate::parse::LinkType::NullLoopback,
            crate::parse::LinkType::Raw,
        ] {
            let encoded = pcapng_linktype(link_type);
            assert_eq!(linktype_from_pcapng(encoded), Some(link_type));
        }
    }

    #[test]
    fn linktype_from_pcapng_rejects_an_unrecognized_value() {
        assert_eq!(linktype_from_pcapng(0xFFFF), None);
    }

    #[test]
    fn read_block_returns_none_at_a_clean_end_of_stream() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        assert!(read_block(&mut cursor).unwrap().is_none());
    }

    #[test]
    fn read_block_errors_on_a_header_truncated_mid_read() {
        let mut buf = Vec::new();
        write_interface_statistics_block(&mut buf, SystemTime::now(), 1, 2).unwrap();
        buf.truncate(buf.len() - 2); // chop off part of the trailing length
        let mut cursor = Cursor::new(buf);
        assert!(read_block(&mut cursor).is_err());
    }

    #[test]
    fn read_block_rejects_an_implausibly_large_declared_length_without_allocating_it() {
        // Regression for a real out-of-memory crash the pcapng_reader fuzz
        // target found: a bogus length field must be rejected before it
        // ever drives an allocation, not after failing to read that many
        // bytes.
        let header: [u8; 8] = [10, 0, 0, 0, 0, 6, 0, 196]; // declares a ~3.2 GiB block
        let mut cursor = Cursor::new(header.to_vec());
        assert!(read_block(&mut cursor).is_err());
    }

    #[test]
    fn read_block_rejects_a_mismatched_length_prefix_and_suffix() {
        let mut buf = Vec::new();
        write_interface_statistics_block(&mut buf, SystemTime::now(), 1, 2).unwrap();
        let last = buf.len() - 1;
        buf[last] ^= 0xFF; // corrupt one byte of the trailing length
        let mut cursor = Cursor::new(buf);
        assert!(read_block(&mut cursor).is_err());
    }

    #[test]
    fn for_each_option_visits_every_option_up_to_end_of_opt() {
        let mut body = Vec::new();
        write_option(&mut body, 11, b"hello").unwrap();
        write_option(&mut body, 22, b"hi").unwrap();
        write_end_of_opt(&mut body).unwrap();

        let mut seen = Vec::new();
        for_each_option(&body, |code, value| seen.push((code, value.to_vec()))).unwrap();
        assert_eq!(seen, vec![(11, b"hello".to_vec()), (22, b"hi".to_vec())]);
    }

    #[test]
    fn reader_recovers_the_written_interface_metadata() {
        let mut buf = Vec::new();
        SectionHeaderBlock {
            hostname: "test-host".into(),
            agent_version: "0.1.0".into(),
        }
        .write_to(&mut buf)
        .unwrap();
        test_idb().write_to(&mut buf).unwrap();

        let (_reader, interface) = Reader::new(Cursor::new(buf)).unwrap();
        assert_eq!(interface.interface_name.as_deref(), Some("en0"));
        assert_eq!(interface.link_type, crate::parse::LinkType::Ethernet);
        assert_eq!(interface.snaplen, 65535);
    }

    #[test]
    fn reader_rejects_a_stream_not_starting_with_a_section_header_block() {
        let mut buf = Vec::new();
        test_idb().write_to(&mut buf).unwrap(); // IDB first, no SHB — invalid
        assert!(Reader::new(Cursor::new(buf)).is_err());
    }

    #[test]
    fn reader_round_trips_packets_written_by_writer_in_order_with_direction_and_data_intact() {
        let path = std::env::temp_dir().join(format!("pcapng-reader-test-round-trip-{}.pcapng", std::process::id()));
        let mut writer = Writer::create(&path, &test_idb(), "test-host", "0.1.0").unwrap();
        let packets: Vec<(Direction, Vec<u8>)> = vec![
            (Direction::Inbound, vec![1, 2, 3]),
            (Direction::Outbound, vec![4, 5, 6, 7, 8]),
            (Direction::Unknown, vec![9]),
        ];
        for (direction, data) in &packets {
            writer.write_packet(SystemTime::now(), *direction, data).unwrap();
        }
        writer.write_interface_stats(100, 3).unwrap(); // interleaved ISB must be skipped transparently
        writer.finish().unwrap();

        let file = File::open(&path).unwrap();
        let (mut reader, interface) = Reader::new(file).unwrap();
        assert_eq!(interface.link_type, crate::parse::LinkType::Ethernet);

        for (direction, data) in &packets {
            let parsed = reader.next_packet().unwrap().expect("expected a packet");
            assert_eq!(parsed.direction, *direction);
            assert_eq!(&parsed.data, data);
        }
        assert!(reader.next_packet().unwrap().is_none(), "no packets should remain after the last one written");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn reader_errors_on_a_packet_whose_declared_capture_length_exceeds_the_block() {
        let mut body = vec![0u8; 20];
        body[12..16].copy_from_slice(&1_000_000u32.to_le_bytes()); // claims a huge capture length
        assert!(parse_enhanced_packet(&body).is_err());
    }
}
