//! A hand-rolled pcapng encoder and decoder (issue #70/#71, JAM-132/JAM-133).
//! The writer emits four block types. The reader accepts independently
//! ordered sections and interfaces and skips unrecognized framed blocks,
//! including Decryption Secrets Blocks without importing their contents. See
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
}

/// The `if_tsresol` this agent always writes: nanoseconds (10^-9 s; a
/// power-of-ten exponent with the high bit clear). Not configurable, because
/// `epb_timestamp_halves` always encodes nanoseconds: since the reader
/// honours `if_tsresol` (JAM-182), declaring any other unit would make the
/// agent's own files replay at the wrong speed.
const WRITER_TSRESOL: u8 = 9;

impl InterfaceDescriptionBlock {
    pub fn write_to(&self, w: &mut impl Write) -> io::Result<()> {
        let mut body = Vec::new();
        body.extend_from_slice(&pcapng_linktype(self.link_type).to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes()); // reserved
        body.extend_from_slice(&self.snaplen.to_le_bytes());

        write_option(&mut body, IF_NAME, self.interface_name.as_bytes())?;
        write_option(&mut body, IF_TSRESOL, &[WRITER_TSRESOL])?;
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
    // agent always declares nanoseconds (`WRITER_TSRESOL`), so this encodes
    // nanoseconds-since-epoch split high/low.
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

#[derive(Clone, Copy, Debug)]
enum ByteOrder {
    Little,
    Big,
}

impl ByteOrder {
    fn u16(self, bytes: &[u8]) -> u16 {
        let bytes = bytes.try_into().unwrap();
        match self {
            Self::Little => u16::from_le_bytes(bytes),
            Self::Big => u16::from_be_bytes(bytes),
        }
    }
    fn u32(self, bytes: &[u8]) -> u32 {
        let bytes = bytes.try_into().unwrap();
        match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
        }
    }
    fn i64(self, bytes: &[u8]) -> i64 {
        let bytes = bytes.try_into().unwrap();
        match self {
            Self::Little => i64::from_le_bytes(bytes),
            Self::Big => i64::from_be_bytes(bytes),
        }
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// The SHB type is byte-order independent. Read its magic before decoding
/// even its length; every subsequent block uses the current section order.
fn read_section_block(
    r: &mut impl Read,
    order: &mut Option<ByteOrder>,
) -> io::Result<Option<(u32, Vec<u8>)>> {
    let mut header = [0u8; 8];
    if !read_exact_or_eof(r, &mut header)? {
        return Ok(None);
    }
    let is_section = header[..4] == BT_SECTION_HEADER.to_le_bytes();
    let mut magic = [0u8; 4];
    let current_order = if is_section {
        r.read_exact(&mut magic)?;
        match magic {
            [0x4d, 0x3c, 0x2b, 0x1a] => ByteOrder::Little,
            [0x1a, 0x2b, 0x3c, 0x4d] => ByteOrder::Big,
            _ => return Err(invalid("invalid pcapng byte-order magic")),
        }
    } else {
        order.ok_or_else(|| invalid("expected a pcapng Section Header Block first"))?
    };
    let block_type = current_order.u32(&header[..4]);
    let total_len = current_order.u32(&header[4..]);
    let minimum = if is_section { 28 } else { 12 };
    if !(minimum..=MAX_BLOCK_LEN).contains(&total_len) || total_len % 4 != 0 {
        return Err(invalid(format!("invalid pcapng block length {total_len}")));
    }
    let mut body = vec![0u8; (total_len - 12) as usize];
    if is_section {
        body[..4].copy_from_slice(&magic);
        r.read_exact(&mut body[4..])?;
    } else {
        r.read_exact(&mut body)?;
    }
    let mut trailer = [0u8; 4];
    r.read_exact(&mut trailer)?;
    if current_order.u32(&trailer) != total_len {
        return Err(invalid("pcapng block length prefix/suffix mismatch"));
    }
    *order = Some(current_order);
    Ok(Some((block_type, body)))
}

#[cfg(test)]
fn read_block(r: &mut impl Read) -> io::Result<Option<(u32, Vec<u8>)>> {
    read_section_block(r, &mut Some(ByteOrder::Little))
}

fn for_each_ordered_option(
    mut body: &[u8],
    order: ByteOrder,
    mut on_option: impl FnMut(u16, &[u8]),
) -> io::Result<()> {
    while !body.is_empty() {
        if body.len() < 4 {
            return Err(invalid("truncated pcapng option header"));
        }
        let code = order.u16(&body[..2]);
        let len = order.u16(&body[2..4]) as usize;
        if code == OPT_END_OF_OPT {
            if len != 0 {
                return Err(invalid("pcapng end-of-options length must be zero"));
            }
            return Ok(());
        }
        let padded = pad4(len);
        if body.len() < 4 + padded {
            return Err(invalid("truncated pcapng option"));
        }
        on_option(code, &body[4..4 + len]);
        body = &body[4 + padded..];
    }
    Ok(())
}

#[cfg(test)]
fn for_each_option(body: &[u8], on_option: impl FnMut(u16, &[u8])) -> io::Result<()> {
    for_each_ordered_option(body, ByteOrder::Little, on_option)
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
    /// The raw `if_tsresol` byte: the unit of this interface's packet
    /// timestamps. Defaults to microseconds when the option is absent, as
    /// the pcapng spec says, which is what most other tools write. This
    /// agent's own `Writer` always writes nanoseconds.
    pub timestamp_resolution: u8,
}

/// `if_tsresol`'s default when an IDB omits it: 10^-6 s.
const DEFAULT_TSRESOL: u8 = 6;

/// Converts an EPB's raw 64-bit timestamp counter to a `SystemTime`, in the
/// unit its IDB's `if_tsresol` declared. JAM-182: reading every counter as
/// nanoseconds made a standard microsecond file replay 1,000x slowly, which
/// kept reassembly timeouts from ever expiring.
///
/// `if_tsresol`'s high bit selects the base: clear means 10^-n seconds, set
/// means 2^-n. A unit too fine to represent (which no real capture uses) is
/// rejected as invalid data rather than allowed to overflow.
fn epb_timestamp(counter: u64, tsresol: u8) -> io::Result<SystemTime> {
    let exponent = u32::from(tsresol & 0x7f);
    let units_per_second: Option<u128> = if tsresol & 0x80 == 0 {
        10u128.checked_pow(exponent)
    } else {
        2u128.checked_pow(exponent)
    };
    let units_per_second = units_per_second.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported pcapng if_tsresol {tsresol:#04x}"),
        )
    })?;
    let nanos = u128::from(counter) * 1_000_000_000 / units_per_second;
    let nanos = u64::try_from(nanos)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "pcapng timestamp out of range"))?;
    Ok(std::time::UNIX_EPOCH + std::time::Duration::from_nanos(nanos))
}

struct StoredInterface {
    linktype_raw: u16,
    interface_name: Option<String>,
    snaplen: u32,
    timestamp_resolution: u8,
}

impl StoredInterface {
    fn supported(&self) -> io::Result<ParsedInterface> {
        let link_type = linktype_from_pcapng(self.linktype_raw).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported pcapng linktype {}", self.linktype_raw),
            )
        })?;
        Ok(ParsedInterface {
            interface_name: self.interface_name.clone(),
            link_type,
            snaplen: self.snaplen,
            timestamp_resolution: self.timestamp_resolution,
        })
    }
}

fn parse_ordered_interface(body: &[u8], order: ByteOrder) -> io::Result<StoredInterface> {
    if body.len() < 8 {
        return Err(invalid("truncated interface description block"));
    }
    let linktype_raw = order.u16(&body[..2]);
    let snaplen = order.u32(&body[4..8]);
    let mut interface_name = None;
    let mut timestamp_resolution = DEFAULT_TSRESOL;
    let mut invalid_tsresol = false;
    for_each_ordered_option(&body[8..], order, |code, value| match code {
        IF_NAME => interface_name = Some(String::from_utf8_lossy(value).into_owned()),
        IF_TSRESOL => {
            if value.len() == 1 {
                timestamp_resolution = value[0];
            } else {
                invalid_tsresol = true;
            }
        }
        _ => {}
    })?;
    if invalid_tsresol {
        return Err(invalid("invalid pcapng if_tsresol option length"));
    }
    Ok(StoredInterface {
        linktype_raw,
        interface_name,
        snaplen,
        timestamp_resolution,
    })
}

#[cfg(test)]
fn parse_interface_description(body: &[u8]) -> io::Result<ParsedInterface> {
    parse_ordered_interface(body, ByteOrder::Little)?.supported()
}

/// A captured frame, decoded back from an Enhanced Packet Block —
/// `direction` reads back the same `epb_flags` option `Writer` always
/// writes; a foreign pcapng file lacking that option decodes as
/// `Direction::Unknown`, matching the flags value (`00`) the spec assigns
/// to "not available".
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    /// Link type of this packet's section-local interface.
    pub link_type: crate::parse::LinkType,
    pub timestamp: SystemTime,
    pub direction: Direction,
    /// Packet length before capture truncation, distinct from `data.len()`.
    pub original_len: u32,
    pub data: Vec<u8>,
}

fn parse_ordered_packet(
    body: &[u8],
    order: ByteOrder,
    tsresol: u8,
    link_type: crate::parse::LinkType,
) -> io::Result<ParsedPacket> {
    if body.len() < 20 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated enhanced packet block",
        ));
    }
    let ts_high = order.u32(&body[4..8]);
    let ts_low = order.u32(&body[8..12]);
    let cap_len = order.u32(&body[12..16]) as usize;
    let original_len = order.u32(&body[16..20]);
    // Check against the bounded body before rounding, including on 32-bit platforms.
    if cap_len > body.len() - 20 {
        return Err(invalid(
            "enhanced packet block shorter than its declared capture length",
        ));
    }
    let padded_len = pad4(cap_len);
    if body.len() < 20 + padded_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "enhanced packet block shorter than its declared capture length",
        ));
    }
    let data = body[20..20 + cap_len].to_vec();

    let timestamp = epb_timestamp(((ts_high as u64) << 32) | ts_low as u64, tsresol)?;

    let mut direction = Direction::Unknown;
    let mut invalid_flags = false;
    for_each_ordered_option(&body[20 + padded_len..], order, |code, value| {
        if code == EPB_FLAGS {
            if value.len() != 4 {
                invalid_flags = true;
                return;
            }
            let flags = order.u32(value);
            direction = match flags & 0b11 {
                0b01 => Direction::Inbound,
                0b10 => Direction::Outbound,
                _ => Direction::Unknown,
            };
        }
    })?;

    if invalid_flags {
        return Err(invalid("invalid pcapng epb_flags option length"));
    }
    Ok(ParsedPacket {
        link_type,
        timestamp,
        direction,
        original_len,
        data,
    })
}

#[cfg(test)]
fn parse_enhanced_packet(body: &[u8], tsresol: u8) -> io::Result<ParsedPacket> {
    parse_ordered_packet(
        body,
        ByteOrder::Little,
        tsresol,
        crate::parse::LinkType::Ethernet,
    )
}

/// Limit retained interface records and decoded names independently of the
/// per-block bound, so many small IDBs cannot grow memory without limit.
const MAX_INTERFACES: usize = 4096;
const MAX_INTERFACE_NAME_BYTES: usize = 16 * 1024 * 1024;

/// Section-aware third-party pcapng reader. Unrecognized blocks are skipped
/// after validating framing, without interpreting or retaining their data.
pub struct Reader<R: Read> {
    inner: R,
    order: Option<ByteOrder>,
    supported_section: bool,
    interfaces: Vec<StoredInterface>,
    interface_name_bytes: usize,
}

impl<R: Read> Reader<R> {
    /// Return the first supported interface for startup display; every packet
    /// independently resolves its actual section-local interface on read.
    pub fn new(inner: R) -> io::Result<(Self, ParsedInterface)> {
        let mut reader = Self {
            inner,
            order: None,
            supported_section: false,
            interfaces: Vec::new(),
            interface_name_bytes: 0,
        };
        loop {
            let (kind, body) = read_section_block(&mut reader.inner, &mut reader.order)?
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "pcapng stream has no supported Interface Description Block",
                    )
                })?;
            if kind == BT_SECTION_HEADER {
                reader.start_section(&body)?;
            } else if reader.supported_section {
                match kind {
                    BT_INTERFACE_DESCRIPTION => {
                        reader.add_interface(&body)?;
                        let entry = reader.interfaces.last().unwrap();
                        if linktype_from_pcapng(entry.linktype_raw).is_some() {
                            let interface = entry.supported()?;
                            return Ok((reader, interface));
                        }
                    }
                    BT_ENHANCED_PACKET => {
                        reader.decode_packet(&body)?;
                    }
                    2 | 3 => return Err(Self::unsupported_packet(kind)),
                    _ => {}
                }
            }
        }
    }

    fn start_section(&mut self, body: &[u8]) -> io::Result<()> {
        let order = self.order.unwrap();
        let major = order.u16(&body[4..6]);
        let minor = order.u16(&body[6..8]);
        self.supported_section = major == 1 && (minor == 0 || minor == 2);
        self.interfaces.clear();
        self.interface_name_bytes = 0;
        if self.supported_section {
            let section_length = order.i64(&body[8..16]);
            if section_length < -1 || (section_length >= 0 && section_length % 4 != 0) {
                return Err(invalid("invalid pcapng section length"));
            }
            for_each_ordered_option(&body[16..], order, |_, _| {})?;
        }
        Ok(())
    }

    fn add_interface(&mut self, body: &[u8]) -> io::Result<()> {
        if self.interfaces.len() >= MAX_INTERFACES {
            return Err(invalid("pcapng section exceeds interface limit"));
        }
        let entry = parse_ordered_interface(body, self.order.unwrap())?;
        let bytes = entry.interface_name.as_ref().map_or(0, String::len);
        if bytes > MAX_INTERFACE_NAME_BYTES - self.interface_name_bytes {
            return Err(invalid("pcapng section exceeds interface metadata limit"));
        }
        self.interface_name_bytes += bytes;
        self.interfaces.push(entry);
        Ok(())
    }

    fn decode_packet(&self, body: &[u8]) -> io::Result<ParsedPacket> {
        if body.len() < 20 {
            return Err(invalid("truncated enhanced packet block"));
        }
        let order = self.order.unwrap();
        let id = order.u32(&body[..4]);
        let entry = self
            .interfaces
            .get(id as usize)
            .ok_or_else(|| invalid(format!("undefined pcapng interface ID {id}")))?;
        let link_type = linktype_from_pcapng(entry.linktype_raw).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "unsupported pcapng linktype {} for interface {id}",
                    entry.linktype_raw
                ),
            )
        })?;
        parse_ordered_packet(body, order, entry.timestamp_resolution, link_type)
    }

    fn unsupported_packet(kind: u32) -> io::Error {
        let name = if kind == 3 {
            "Simple Packet"
        } else {
            "obsolete Packet"
        };
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!("pcapng {name} Block replay is unsupported"),
        )
    }

    pub fn next_packet(&mut self) -> io::Result<Option<ParsedPacket>> {
        loop {
            let Some((kind, body)) = read_section_block(&mut self.inner, &mut self.order)? else {
                return Ok(None);
            };
            if kind == BT_SECTION_HEADER {
                self.start_section(&body)?;
                continue;
            }
            if !self.supported_section {
                continue;
            }
            match kind {
                BT_INTERFACE_DESCRIPTION => self.add_interface(&body)?,
                BT_ENHANCED_PACKET => return self.decode_packet(&body).map(Some),
                2 | 3 => return Err(Self::unsupported_packet(kind)),
                _ => {}
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
        }
        .write_to(&mut buf)
        .unwrap();
        assert_eq!(buf.len() % 4, 0);

        buf.clear();
        InterfaceDescriptionBlock {
            interface_name: "lo".into(), // 2 bytes — odd relative to 4-byte option padding
            link_type: crate::parse::LinkType::NullLoopback,
            snaplen: 65535,
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
        assert!(parse_enhanced_packet(&body, 9).is_err());
    }

    #[test]
    fn epb_original_length_survives_independently_of_captured_bytes() {
        // The original length is metadata, never an allocation size. The
        // draft permits inherited original < captured records as well.
        for original in [0u32, 4, 128, u32::MAX] {
            let mut body = vec![0u8; 24];
            body[12..16].copy_from_slice(&4u32.to_le_bytes());
            body[16..20].copy_from_slice(&original.to_le_bytes());
            body[20..24].copy_from_slice(b"data");
            let packet = parse_enhanced_packet(&body, 6).unwrap();
            assert_eq!(packet.original_len, original);
            assert_eq!(packet.data, b"data");
        }
    }

    #[test]
    fn epb_timestamps_are_decoded_in_the_idbs_declared_unit() {
        // JAM-182: the same instant, as written by tools using each unit.
        let one_and_a_half_s = std::time::UNIX_EPOCH + std::time::Duration::from_millis(1_500);
        assert_eq!(epb_timestamp(1_500_000_000, 9).unwrap(), one_and_a_half_s, "nanoseconds");
        assert_eq!(epb_timestamp(1_500_000, 6).unwrap(), one_and_a_half_s, "microseconds, the default");
        assert_eq!(epb_timestamp(1_500, 3).unwrap(), one_and_a_half_s, "milliseconds");
        assert_eq!(epb_timestamp(3 << 19, 0x80 | 20).unwrap(), one_and_a_half_s, "binary: 2^-20 s units");
    }

    #[test]
    fn epb_timestamp_rejects_an_unrepresentable_unit_instead_of_overflowing() {
        assert!(epb_timestamp(1, 0x7f).is_err(), "10^-127 s overflows");
        assert!(epb_timestamp(u64::MAX, 3).is_err(), "u64::MAX milliseconds is past SystemTime's nanosecond range");
    }

    /// An IDB body (linktype Raw, snaplen 65535) with the given options.
    fn idb_body(options: &[(u16, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&pcapng_linktype(crate::parse::LinkType::Raw).to_le_bytes());
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&65535u32.to_le_bytes());
        for (code, value) in options {
            body.extend_from_slice(&code.to_le_bytes());
            body.extend_from_slice(&(value.len() as u16).to_le_bytes());
            body.extend_from_slice(value);
            body.resize(pad4(body.len()), 0);
        }
        body.extend_from_slice(&[0, 0, 0, 0]); // opt_endofopt
        body
    }

    #[test]
    fn an_idb_without_if_tsresol_defaults_to_microseconds() {
        assert_eq!(parse_interface_description(&idb_body(&[])).unwrap().timestamp_resolution, 6);
        assert_eq!(parse_interface_description(&idb_body(&[(IF_TSRESOL, &[9])])).unwrap().timestamp_resolution, 9);
    }
    fn foreign_block(out: &mut Vec<u8>, be: bool, kind: u32, body: &[u8]) {
        let len = (body.len() + 12) as u32;
        let encode = |n: u32| if be { n.to_be_bytes() } else { n.to_le_bytes() };
        out.extend_from_slice(&encode(kind));
        out.extend_from_slice(&encode(len));
        out.extend_from_slice(body);
        out.extend_from_slice(&encode(len));
    }

    fn foreign_section(out: &mut Vec<u8>, be: bool, major: u16, minor: u16) {
        let mut body = Vec::new();
        body.extend_from_slice(&if be {
            0x1a2b3c4du32.to_be_bytes()
        } else {
            0x1a2b3c4du32.to_le_bytes()
        });
        body.extend_from_slice(&if be {
            major.to_be_bytes()
        } else {
            major.to_le_bytes()
        });
        body.extend_from_slice(&if be {
            minor.to_be_bytes()
        } else {
            minor.to_le_bytes()
        });
        body.extend_from_slice(&(-1i64).to_le_bytes());
        foreign_block(out, be, BT_SECTION_HEADER, &body);
    }

    fn foreign_idb(out: &mut Vec<u8>, be: bool, link: u16, unit: u8) {
        let mut body = Vec::new();
        body.extend_from_slice(&if be {
            link.to_be_bytes()
        } else {
            link.to_le_bytes()
        });
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&if be {
            65535u32.to_be_bytes()
        } else {
            65535u32.to_le_bytes()
        });
        body.extend_from_slice(&if be {
            IF_TSRESOL.to_be_bytes()
        } else {
            IF_TSRESOL.to_le_bytes()
        });
        body.extend_from_slice(&if be {
            1u16.to_be_bytes()
        } else {
            1u16.to_le_bytes()
        });
        body.extend_from_slice(&[unit, 0xff, 0xff, 0xff]); // nonzero padding is legal
        foreign_block(out, be, BT_INTERFACE_DESCRIPTION, &body);
    }

    fn foreign_packet(out: &mut Vec<u8>, be: bool, iface: u32, timestamp: u32) {
        let mut body = Vec::new();
        for n in [iface, 0, timestamp, 3, 7] {
            body.extend_from_slice(&if be { n.to_be_bytes() } else { n.to_le_bytes() });
        }
        body.extend_from_slice(&[1, 2, 3, 0xff]);
        body.extend_from_slice(&if be { EPB_FLAGS.to_be_bytes() } else { EPB_FLAGS.to_le_bytes() });
        body.extend_from_slice(&if be { 4u16.to_be_bytes() } else { 4u16.to_le_bytes() });
        body.extend_from_slice(&if be { 2u32.to_be_bytes() } else { 2u32.to_le_bytes() });
        foreign_block(out, be, BT_ENHANCED_PACKET, &body);
    }

    #[test]
    fn reader_foreign_mixed_sections_interfaces_and_unknown_blocks() {
        let mut bytes = Vec::new();
        foreign_section(&mut bytes, true, 1, 0);
        foreign_block(&mut bytes, true, 4, &[0, 0, 0, 0]); // NRB before IDB
        foreign_idb(&mut bytes, true, 1, 6);
        foreign_idb(&mut bytes, true, 101, 9);
        for kind in [4, 10, 0x00000bad, 0x40000bad] {
            foreign_block(&mut bytes, true, kind, &[0; 8]);
        }
        foreign_packet(&mut bytes, true, 1, 1_500_000_000);
        foreign_packet(&mut bytes, true, 0, 2_500_000);
        foreign_section(&mut bytes, false, 1, 2); // specified compatibility alias
        foreign_idb(&mut bytes, false, 0, 3);
        foreign_packet(&mut bytes, false, 0, 3500);
        let (mut reader, _) = Reader::new(Cursor::new(bytes)).unwrap();
        for (millis, link_type) in [
            (1500, crate::parse::LinkType::Raw),
            (2500, crate::parse::LinkType::Ethernet),
            (3500, crate::parse::LinkType::NullLoopback),
        ] {
            let packet = reader.next_packet().unwrap().unwrap();
            assert_eq!(
                packet.timestamp,
                std::time::UNIX_EPOCH + std::time::Duration::from_millis(millis)
            );
            assert_eq!(packet.link_type, link_type);
            assert_eq!(packet.direction, Direction::Outbound);
            assert_eq!(packet.original_len, 7);
            assert_eq!(packet.data, [1, 2, 3]);
        }
        assert!(reader.next_packet().unwrap().is_none());
    }

    #[test]
    fn reader_skips_unsupported_sections_without_interpreting_their_contents() {
        let mut bytes = Vec::new();
        foreign_section(&mut bytes, true, 2, 0);
        foreign_block(&mut bytes, true, BT_INTERFACE_DESCRIPTION, &[0; 4]);
        foreign_block(&mut bytes, true, BT_ENHANCED_PACKET, &[0; 4]);
        foreign_section(&mut bytes, false, 1, 0);
        foreign_idb(&mut bytes, false, 1, 6);
        foreign_packet(&mut bytes, false, 0, 42);
        let (mut reader, _) = Reader::new(Cursor::new(bytes)).unwrap();
        assert!(reader.next_packet().unwrap().is_some());
    }

    #[test]
    fn reader_rejects_undefined_and_previous_section_interface_ids() {
        for new_section in [false, true] {
            let mut bytes = Vec::new();
            foreign_section(&mut bytes, false, 1, 0);
            foreign_idb(&mut bytes, false, 1, 6);
            if new_section {
                foreign_section(&mut bytes, true, 1, 0);
            }
            foreign_packet(&mut bytes, new_section, if new_section { 0 } else { 1 }, 0);
            let (mut reader, _) = Reader::new(Cursor::new(bytes)).unwrap();
            assert_eq!(
                reader.next_packet().unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn reader_unused_unsupported_interfaces_preserve_interface_numbering() {
        let mut bytes = Vec::new();
        foreign_section(&mut bytes, false, 1, 0);
        foreign_idb(&mut bytes, false, 0xffff, 6);
        foreign_idb(&mut bytes, false, 101, 6);
        foreign_packet(&mut bytes, false, 1, 42);
        foreign_packet(&mut bytes, false, 0, 42);
        let (mut reader, startup) = Reader::new(Cursor::new(bytes)).unwrap();
        assert_eq!(startup.link_type, crate::parse::LinkType::Raw);
        assert_eq!(
            reader.next_packet().unwrap().unwrap().link_type,
            crate::parse::LinkType::Raw
        );
        assert_eq!(
            reader.next_packet().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn reader_diagnoses_unsupported_packet_blocks_instead_of_losing_packets() {
        for kind in [2, 3] {
            let mut bytes = Vec::new();
            foreign_section(&mut bytes, false, 1, 0);
            foreign_idb(&mut bytes, false, 1, 6);
            foreign_block(&mut bytes, false, kind, &[0; 20]);
            let (mut reader, _) = Reader::new(Cursor::new(bytes)).unwrap();
            assert_eq!(
                reader.next_packet().unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
        }
    }

    #[test]
    fn reader_bounds_interfaces_and_resets_the_budget_for_a_new_section() {
        let mut bytes = Vec::new();
        foreign_section(&mut bytes, false, 1, 0);
        for _ in 0..MAX_INTERFACES {
            foreign_idb(&mut bytes, false, 1, 6);
        }
        foreign_packet(&mut bytes, false, (MAX_INTERFACES - 1) as u32, 42);
        let mut too_many = bytes.clone();
        foreign_idb(&mut too_many, false, 1, 6);
        let (mut reader, _) = Reader::new(Cursor::new(too_many)).unwrap();
        assert!(reader.next_packet().unwrap().is_some());
        assert!(reader
            .next_packet()
            .unwrap_err()
            .to_string()
            .contains("interface limit"));
        foreign_section(&mut bytes, true, 1, 0);
        foreign_idb(&mut bytes, true, 1, 6);
        foreign_packet(&mut bytes, true, 0, 42);
        let (mut reader, _) = Reader::new(Cursor::new(bytes)).unwrap();
        assert!(reader.next_packet().unwrap().is_some());
        assert!(reader.next_packet().unwrap().is_some());
        assert!(reader.next_packet().unwrap().is_none());
    }

    #[test]
    fn reader_unknown_blocks_still_require_valid_framing_in_both_orders() {
        for be in [false, true] {
            let mut prefix = Vec::new();
            foreign_section(&mut prefix, be, 1, 0);
            foreign_idb(&mut prefix, be, 1, 6);
            let encode = |n: u32| if be { n.to_be_bytes() } else { n.to_le_bytes() };
            for length in [8, 13, MAX_BLOCK_LEN + 4, u32::MAX] {
                let mut bytes = prefix.clone();
                bytes.extend_from_slice(&encode(0xfeed));
                bytes.extend_from_slice(&encode(length));
                let (mut reader, _) = Reader::new(Cursor::new(bytes)).unwrap();
                assert_eq!(
                    reader.next_packet().unwrap_err().kind(),
                    io::ErrorKind::InvalidData
                );
            }
            let mut unknown = Vec::new();
            foreign_block(&mut unknown, be, 0xfeed, &[0; 4]);
            for suffix in [vec![0u8; 4], vec![0u8; 2]] {
                let mut bytes = prefix.clone();
                bytes.extend_from_slice(&unknown[..unknown.len() - 4]);
                bytes.extend_from_slice(&suffix);
                let (mut reader, _) = Reader::new(Cursor::new(bytes)).unwrap();
                assert!(reader.next_packet().is_err());
            }
        }
    }

    #[test]
    fn reader_rejects_bad_magic_short_section_and_invalid_option_lengths() {
        for be in [false, true] {
            let mut bytes = Vec::new();
            foreign_section(&mut bytes, be, 1, 0);
            bytes[8] ^= 1;
            assert!(Reader::new(Cursor::new(bytes)).is_err());
            let mut bytes = Vec::new();
            foreign_block(
                &mut bytes,
                be,
                BT_SECTION_HEADER,
                &if be {
                    BYTE_ORDER_MAGIC.to_be_bytes()
                } else {
                    BYTE_ORDER_MAGIC.to_le_bytes()
                },
            );
            assert!(Reader::new(Cursor::new(bytes)).is_err());
            let order = if be {
                ByteOrder::Big
            } else {
                ByteOrder::Little
            };
            let encode = |n: u16| if be { n.to_be_bytes() } else { n.to_le_bytes() };
            let mut bad_end = Vec::from(encode(OPT_END_OF_OPT));
            bad_end.extend_from_slice(&encode(4));
            bad_end.extend_from_slice(&[0; 4]);
            assert!(for_each_ordered_option(&bad_end, order, |_, _| {}).is_err());
            let mut truncated = Vec::from(encode(IF_NAME));
            truncated.extend_from_slice(&encode(8));
            truncated.extend_from_slice(&[0; 4]);
            assert!(for_each_ordered_option(&truncated, order, |_, _| {}).is_err());
            assert!(for_each_ordered_option(&[1, 2], order, |_, _| {}).is_err());
        }
    }

    #[test]
    fn reader_bounds_retained_interface_names_after_utf8_repair() {
        let mut reader = Reader {
            inner: Cursor::new(Vec::<u8>::new()),
            order: Some(ByteOrder::Little),
            supported_section: true,
            interfaces: Vec::new(),
            interface_name_bytes: MAX_INTERFACE_NAME_BYTES - 2,
        };
        let body = idb_body(&[(IF_NAME, &[0xff])]); // repair becomes three UTF-8 bytes
        assert!(reader
            .add_interface(&body)
            .unwrap_err()
            .to_string()
            .contains("metadata limit"));
    }
}
