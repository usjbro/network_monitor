//! Follow Stream's bounded, zeroizing per-flow byte store (JAM-17 / KAN-110;
//! spec `docs/superpowers/specs/2026-10-31-follow-stream-design.md` D2, D3,
//! D7 and D7a, plan `docs/superpowers/plans/2026-11-05-follow-stream.md`
//! Task 1).
//!
//! Head-keeping, never a rolling window: each direction keeps its bytes from
//! the stream start, records holes as exact gaps, and stops appending at a cap
//! while still counting what it saw. Original bytes live only in fixed-size
//! zeroizing chunks and the zeroizing out-of-order buffer; callers only ever
//! get masked copies ([`FollowEntry::copy_masked`]), and only of bytes below
//! the emission horizon — never pending, TLS, suspect, or undecided-line bytes.
//!
//! Two deliberate readings of the spec, recorded here because the code
//! depends on them:
//! - Metadata vectors (gaps, ranges, turns) grow by bounded doubling, each
//!   growth charged to the 16 MiB budget before it is allocated, rather than
//!   being allocated at their cap's size on first use: at cap size the turn
//!   vectors alone would need 256 × 4 096 × 24 B = 24 MiB. They hold offsets,
//!   lengths and timestamps, never payload, so reallocating them leaves no
//!   payload copy behind. Payload storage itself never reallocates.
//! - An upgrade (D3) is confirmed by a chain, as the spec says, and also by a
//!   ClientHello/ServerHello header at the suspect offset — the same
//!   structural rule that classifies a stream start. Erring towards TLS only
//!   ever withholds more.

use std::collections::HashMap;
use std::fmt;

use zeroize::{Zeroize, Zeroizing};

use crate::flow::FlowKey;
use crate::reassembly::CUT_ATTRIBUTION_WINDOW_MS;
use crate::redact::{is_sensitive_header_name, looks_like_bearer_token};

/// Stored bytes per direction (D2).
pub const MAX_DIRECTION_BYTES: u32 = 256 * 1024;
pub const MAX_GAPS_PER_DIRECTION: usize = 1_024;
pub const MAX_RANGES_PER_DIRECTION: usize = 1_024;
pub const MAX_TURNS_PER_FLOW: usize = 4_096;
pub const MAX_FLOWS: usize = 256;
/// Global cap, counted in reserved capacity rather than length.
pub const MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024;
/// Payload is stored in fixed chunks of this size so growth never copies it.
pub const CHUNK_BYTES: usize = 16 * 1024;
/// Out-of-order window: bytes held ahead of the contiguous edge, per direction.
pub const REORDER_BYTES: u32 = 64 * 1024;
/// How long (capture time) a hole may stay open before it becomes a gap.
pub const REORDER_MS: u64 = 2_000;
/// Pending and suspect deadline (D3), capture time.
pub const CLASSIFY_MS: u64 = 2_000;
/// Candidate first-record offsets are tried within this many bytes (D3).
pub const TLS_CANDIDATE_BYTES: u32 = 20 * 1024;
/// A pending direction becomes cleartext once this many bytes are stored.
pub const TLS_LOOKAHEAD_BYTES: u32 = 40 * 1024;
/// RFC 8446 §5.2's largest ciphertext record: 2^14 + 2048.
pub const MAX_TLS_RECORD_LEN: u16 = 18_432;
/// Bound on an undecided scanner line (D7).
pub const MAX_LINE_BYTES: u32 = 16 * 1024;

const CHUNKS_PER_DIRECTION: usize = MAX_DIRECTION_BYTES as usize / CHUNK_BYTES;
const OOO_RESERVED: usize = REORDER_BYTES as usize + REORDER_BYTES as usize / 8;
const LF: u8 = b'\n';
const CR: u8 = b'\r';

/// Distinguishes a replacement flow on a reused tuple from the original.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Generation {
    pub epoch: u64,
    pub counter: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    C2s,
    S2c,
}

impl Direction {
    fn index(self) -> usize {
        match self {
            Direction::C2s => 0,
            Direction::S2c => 1,
        }
    }

    fn from_index(i: usize) -> Self {
        if i == 0 {
            Direction::C2s
        } else {
            Direction::S2c
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    StoreCap,
    GapLimit,
    TurnLimit,
    RedactionLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    Pending,
    Cleartext,
    Tls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GapReason {
    Missing,
    SnaplenLikely,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskReason {
    Credential,
    Uncertain,
}

/// An exact sequence-space hole at stored offset `at`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gap {
    pub at: u32,
    pub missing: u32,
    pub reason: GapReason,
}

/// Stream-relative bytes that every emitted copy overwrites with `*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaskRange {
    pub start: u32,
    pub len: u32,
    pub reason: MaskReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Turn {
    pub dir: Direction,
    pub start: u32,
    pub len: u32,
    pub first_seen_ms: u64,
}

/// One logical TCP segment. Deliberately has no `Debug`: it borrows payload.
#[derive(Clone, Copy)]
pub struct FollowSegment<'a> {
    pub seq: u32,
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub payload: &'a [u8],
    pub now_ms: u64,
}

/// Read-only metadata for one direction. Carries no payload.
#[derive(Debug, Clone, Copy)]
pub struct FollowDirection<'a> {
    pub classification: Classification,
    pub tls_from: Option<u32>,
    /// Bytes `[0, emittable)` may be copied; everything after is withheld.
    pub emittable: u32,
    pub stored_bytes: u32,
    pub seen_bytes: u64,
    pub stopped: Option<StopReason>,
    pub gaps: &'a [Gap],
    pub redacted_ranges: &'a [MaskRange],
    pub conflicting_overlap_bytes: u64,
    pub start_captured: bool,
    pub closed: bool,
}

/// A zeroizing heap buffer that never grows. Every release path for payload
/// bytes goes through its `Drop`.
struct Buf(Box<[u8]>);

impl Buf {
    fn new(len: usize) -> Self {
        Buf(vec![0; len].into_boxed_slice())
    }
}

impl Drop for Buf {
    fn drop(&mut self) {
        self.0.zeroize();
        #[cfg(test)]
        release_hook::record(self.0.iter().all(|&b| b == 0));
    }
}

/// Bytes held ahead of the contiguous edge, indexed by stream position modulo
/// the window so no position ever moves.
struct Ooo {
    data: Buf,
    cover: Box<[u64]>,
    held: u32,
    since_ms: u64,
}

impl Ooo {
    fn new(now_ms: u64) -> Self {
        Ooo {
            data: Buf::new(REORDER_BYTES as usize),
            cover: vec![0; REORDER_BYTES as usize / 64].into_boxed_slice(),
            held: 0,
            since_ms: now_ms,
        }
    }

    fn covered(&self, i: usize) -> bool {
        self.cover[i / 64] & (1 << (i % 64)) != 0
    }

    fn set(&mut self, i: usize, on: bool) {
        if on {
            self.cover[i / 64] |= 1 << (i % 64);
        } else {
            self.cover[i / 64] &= !(1 << (i % 64));
        }
    }
}

fn window_index(pos: u64) -> usize {
    (pos % u64::from(REORDER_BYTES)) as usize
}

/// A store-wide byte budget for one operation, plus the entries that may be
/// evicted to make room. The entry being worked on is never in `others`.
struct Ctx<'a> {
    reserved: &'a mut usize,
    others: Option<&'a mut Entries>,
    last_cut_ms: Option<u64>,
    turn_limit: bool,
    truncated: bool,
}

impl Ctx<'_> {
    fn admit(&mut self, n: usize) -> bool {
        while *self.reserved + n > MAX_TOTAL_BYTES {
            let Some(others) = self.others.as_deref_mut() else {
                return false;
            };
            let Some(victim) = pressure_victim(others) else {
                return false;
            };
            if let Some(entry) = others.remove(&victim) {
                *self.reserved -= entry.heap_bytes();
            }
        }
        *self.reserved += n;
        true
    }

    fn refund(&mut self, n: usize) {
        *self.reserved -= n;
    }

    fn gap_reason(&self, now_ms: u64) -> GapReason {
        match self.last_cut_ms {
            Some(cut) if now_ms.saturating_sub(cut) <= CUT_ATTRIBUTION_WINDOW_MS => GapReason::SnaplenLikely,
            _ => GapReason::Missing,
        }
    }
}

/// Entries are boxed so the map's slots stay small and moving an entry out
/// for one packet's work moves a pointer, not the entry.
type Entries = HashMap<FlowKey, Box<FollowEntry>>;

/// The map is reserved once for twice the flow cap and charged once for that
/// table. With at most half its usable capacity occupied, hashbrown reclaims
/// deleted slots by rehashing in place rather than allocating a larger table,
/// so remove/insert churn never grows it (`audit` checks). `capacity()` is
/// not the table size: it shrinks as deleted slots build up.
const MAP_RESERVE: usize = 2 * MAX_FLOWS;

/// Closed entries go first, then the least recently active, then the oldest.
fn pressure_victim(entries: &Entries) -> Option<FlowKey> {
    entries
        .iter()
        .min_by_key(|(_, e)| (!e.closed(), e.last_activity_ms, e.insertion))
        .map(|(k, _)| k.clone())
}

/// Ensures room for one more element, doubling up to `max`, charging the
/// growth before allocating it.
fn grow<T>(v: &mut Vec<T>, max: usize, ctx: &mut Ctx) -> bool {
    if v.len() < v.capacity() {
        return true;
    }
    if v.len() >= max {
        return false;
    }
    let new_cap = (v.capacity() * 2).clamp(8, max);
    if !ctx.admit((new_cap - v.capacity()) * std::mem::size_of::<T>()) {
        return false;
    }
    v.reserve_exact(new_cap - v.len());
    true
}

fn release_vec<T>(v: &mut Vec<T>, ctx: &mut Ctx) {
    ctx.refund(v.capacity() * std::mem::size_of::<T>());
    *v = Vec::new();
}

/// hashbrown's bucket count for `cap` usable slots.
fn map_buckets(cap: usize) -> usize {
    (cap * 8).div_ceil(7).next_power_of_two()
}

/// The bucket array plus one control byte per bucket: an estimate of the
/// map's real reservation.
fn map_estimate(cap: usize) -> usize {
    map_buckets(cap) * (std::mem::size_of::<(FlowKey, Box<FollowEntry>)>() + 1)
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// A valid TLS record header (D3): its content type and length.
fn record_header(h: [u8; 5]) -> Option<(u8, u16)> {
    let len = u16::from_be_bytes([h[3], h[4]]);
    ((0x14..=0x17).contains(&h[0]) && h[1] == 0x03 && (0x01..=0x04).contains(&h[2]) && len <= MAX_TLS_RECORD_LEN)
        .then_some((h[0], len))
}

/// Whether `p` (at most four bytes) could still begin a valid header.
fn header_prefix(p: &[u8]) -> bool {
    p.iter().enumerate().all(|(i, &b)| match i {
        0 => (0x14..=0x17).contains(&b),
        1 => b == 0x03,
        2 => (0x01..=0x04).contains(&b),
        _ => b <= 0x48,
    })
}

enum TlsEvent {
    /// The direction is TLS from its first byte: the whole flow is dropped.
    Initial,
    /// The direction switched to TLS at this stored offset.
    Upgrade(u32),
}

enum TlsState {
    /// Nothing is emitted. `cand` is the first candidate offset not yet ruled
    /// out; `cand_since` is when a complete header was first seen parked
    /// there, waiting for its chained record.
    Pending { since_ms: Option<u64>, cand: u32, cand_since: Option<u64> },
    /// Bytes before `at` are cleartext; `at` is the first offset that could
    /// still start a record header. `suspect_since` is set when a complete
    /// valid header sits at `at`.
    Cleartext { at: u32, suspect_since: Option<u64> },
    Tls,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Line {
    /// At a line start, before its first byte.
    Start,
    /// Not a header line: visible.
    Plain,
    /// Token characters so far, no `:` yet: withheld.
    Name,
    /// A header line after its `:`: withheld until decided.
    Value { colon: u32, value_start: Option<u32> },
    /// A folded continuation of a header: withheld, then masked.
    Cont,
    /// Masked, CR included, to the next LF, for at most `MAX_LINE_BYTES`.
    Uncertain,
    /// An overlong undecided line: masked to its LF however long it is.
    LongMask(MaskReason),
    /// Nothing more is scanned.
    Done,
}

/// What the previous complete line still needs from this line's first byte.
#[derive(Clone, Copy)]
enum Prev {
    None,
    Header { line_start: u32, value_start: u32, value_end: u32, credential: bool },
    Folded,
    Uncertain,
}

/// D7's line scanner state, over a direction's stored offsets.
struct Scanner {
    pos: u32,
    line_start: u32,
    line: Line,
    prev: Prev,
    last_cr: bool,
    next_gap: usize,
}

impl Scanner {
    fn new(start_captured: bool) -> Self {
        Scanner {
            pos: 0,
            line_start: 0,
            line: if start_captured { Line::Start } else { Line::Uncertain },
            prev: Prev::None,
            last_cr: false,
            next_gap: 0,
        }
    }

    /// Bytes below this are decided and may be emitted.
    fn decided(&self) -> u32 {
        match self.line {
            Line::Name | Line::Value { .. } | Line::Cont => self.line_start,
            _ => match self.prev {
                Prev::Header { line_start, .. } => line_start,
                _ => self.pos,
            },
        }
    }
}

/// Where to cut the stored bytes, and why, when a mask cannot be recorded.
type Cut = (u32, StopReason);

struct DirState {
    base: Option<u32>,
    start_captured: bool,
    /// Sequence-space bytes consumed from `base`, gaps included.
    edge: u64,
    fin_at: Option<u64>,
    closed: bool,
    seen: u64,
    conflicts: u64,
    stored: u32,
    /// How many bytes just behind the edge map one-to-one onto the stored tail.
    contig: u64,
    chunks: Vec<Buf>,
    ooo: Option<Ooo>,
    gaps: Vec<Gap>,
    ranges: Vec<MaskRange>,
    stopped: Option<StopReason>,
    finalized: bool,
    tls: TlsState,
    tls_from: Option<u32>,
    scan: Scanner,
}

impl DirState {
    fn new() -> Self {
        DirState {
            base: None,
            start_captured: false,
            edge: 0,
            fin_at: None,
            closed: false,
            seen: 0,
            conflicts: 0,
            stored: 0,
            contig: 0,
            chunks: Vec::new(),
            ooo: None,
            gaps: Vec::new(),
            ranges: Vec::new(),
            stopped: None,
            finalized: false,
            tls: TlsState::Pending { since_ms: None, cand: 0, cand_since: None },
            tls_from: None,
            scan: Scanner::new(false),
        }
    }

    fn begin(&mut self, base: u32, start_captured: bool) {
        self.base = Some(base);
        self.start_captured = start_captured;
        self.scan = Scanner::new(start_captured);
    }

    fn heap_bytes(&self) -> usize {
        self.chunks.capacity() * std::mem::size_of::<Buf>()
            + self.chunks.len() * CHUNK_BYTES
            + self.ooo.as_ref().map_or(0, |_| OOO_RESERVED)
            + self.gaps.capacity() * std::mem::size_of::<Gap>()
            + self.ranges.capacity() * std::mem::size_of::<MaskRange>()
    }

    fn is_tls(&self) -> bool {
        matches!(self.tls, TlsState::Tls)
    }

    fn accepting(&self) -> bool {
        !self.closed && self.stopped.is_none() && !self.finalized && !self.is_tls()
    }

    fn classification(&self) -> Classification {
        match self.tls {
            TlsState::Pending { .. } => Classification::Pending,
            TlsState::Cleartext { .. } => Classification::Cleartext,
            TlsState::Tls => Classification::Tls,
        }
    }

    fn tls_horizon(&self) -> u32 {
        match self.tls {
            TlsState::Pending { .. } => 0,
            TlsState::Cleartext { at, .. } => at,
            TlsState::Tls => self.tls_from.unwrap_or(0).min(self.stored),
        }
    }

    fn emittable(&self) -> u32 {
        self.tls_horizon().min(self.scan.decided()).min(self.stored)
    }

    fn byte(&self, off: u32) -> u8 {
        let off = off as usize;
        self.chunks[off / CHUNK_BYTES].0[off % CHUNK_BYTES]
    }

    fn read(&self, off: u32, out: &mut [u8]) {
        let mut off = off as usize;
        let mut done = 0;
        while done < out.len() {
            let within = off % CHUNK_BYTES;
            let take = (CHUNK_BYTES - within).min(out.len() - done);
            out[done..done + take].copy_from_slice(&self.chunks[off / CHUNK_BYTES].0[within..within + take]);
            done += take;
            off += take;
        }
    }

    fn header_at(&self, off: u32) -> Option<(u8, u16)> {
        if off.checked_add(5)? > self.stored {
            return None;
        }
        let mut h = [0u8; 5];
        self.read(off, &mut h);
        record_header(h)
    }

    fn prefix_at(&self, off: u32) -> bool {
        let mut p = [0u8; 4];
        let n = (self.stored - off) as usize;
        self.read(off, &mut p[..n]);
        header_prefix(&p[..n])
    }

    fn stop(&mut self, reason: StopReason) {
        if self.stopped.is_none() {
            self.stopped = Some(reason);
        }
    }

    fn free_ooo(&mut self, ctx: &mut Ctx) {
        if self.ooo.take().is_some() {
            ctx.refund(OOO_RESERVED);
        }
    }

    fn close(&mut self, ctx: &mut Ctx) {
        self.closed = true;
        self.free_ooo(ctx);
    }

    fn check_fin(&mut self, ctx: &mut Ctx) {
        if !self.closed && self.fin_at.is_some_and(|f| self.edge >= f) {
            self.close(ctx);
        }
    }

    /// Zeroizes and releases stored bytes from `len` on, clipping metadata.
    fn truncate(&mut self, len: u32, ctx: &mut Ctx) {
        if len >= self.stored {
            return;
        }
        let keep = (len as usize).div_ceil(CHUNK_BYTES);
        while self.chunks.len() > keep {
            self.chunks.pop();
            ctx.refund(CHUNK_BYTES);
        }
        if let Some(last) = self.chunks.last_mut() {
            let within = len as usize % CHUNK_BYTES;
            if within != 0 {
                last.0[within..].zeroize();
            }
        }
        self.stored = len;
        self.contig = 0;
        self.gaps.retain(|g| g.at <= len);
        self.ranges.retain_mut(|r| {
            r.len = r.len.min(len.saturating_sub(r.start));
            r.len > 0
        });
        if let TlsState::Cleartext { at, .. } = &mut self.tls {
            *at = (*at).min(len);
        }
        ctx.truncated = true;
    }

    /// Writes as much of `bytes` as the budget allows; returns how much.
    fn write(&mut self, bytes: &[u8], ctx: &mut Ctx) -> u32 {
        let mut done = 0;
        while done < bytes.len() {
            let off = self.stored as usize;
            if off / CHUNK_BYTES == self.chunks.len() {
                if self.chunks.capacity() == 0 {
                    if !ctx.admit(CHUNKS_PER_DIRECTION * std::mem::size_of::<Buf>()) {
                        break;
                    }
                    self.chunks.reserve_exact(CHUNKS_PER_DIRECTION);
                }
                if !ctx.admit(CHUNK_BYTES) {
                    break;
                }
                self.chunks.push(Buf::new(CHUNK_BYTES));
            }
            let within = off % CHUNK_BYTES;
            let take = (CHUNK_BYTES - within).min(bytes.len() - done);
            self.chunks[off / CHUNK_BYTES].0[within..within + take].copy_from_slice(&bytes[done..done + take]);
            done += take;
            self.stored += take as u32;
        }
        done as u32
    }

    /// Appends bytes that just became contiguous.
    fn append(&mut self, bytes: &[u8], now_ms: u64, d: Direction, turns: &mut Vec<Turn>, ctx: &mut Ctx) {
        if bytes.is_empty() || !self.accepting() {
            return;
        }
        let room = (MAX_DIRECTION_BYTES - self.stored) as usize;
        if room == 0 {
            self.stop(StopReason::StoreCap);
            return;
        }
        let new_turn = !matches!(turns.last(), Some(t) if t.dir == d);
        if new_turn {
            if turns.len() >= MAX_TURNS_PER_FLOW {
                self.contig = 0;
                self.stop(StopReason::TurnLimit);
                ctx.turn_limit = true;
                return;
            }
            if !grow(turns, MAX_TURNS_PER_FLOW, ctx) {
                self.stop(StopReason::StoreCap);
                return;
            }
        }
        let before = self.stored;
        let written = self.write(&bytes[..bytes.len().min(room)], ctx);
        if written > 0 {
            match turns.last_mut() {
                Some(t) if !new_turn => t.len += written,
                _ => turns.push(Turn { dir: d, start: before, len: written, first_seen_ms: now_ms }),
            }
            if let TlsState::Pending { since_ms, .. } = &mut self.tls {
                since_ms.get_or_insert(now_ms);
            }
        }
        if written as usize == bytes.len() {
            self.contig += u64::from(written);
        } else {
            self.stop(StopReason::StoreCap);
        }
    }

    /// Counts conflicts between already-consumed positions and their stored
    /// bytes; the stored bytes always win.
    fn compare_behind(&mut self, pos: i64, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            let p = pos + i as i64;
            if p < 0 {
                continue;
            }
            let back = self.edge - p as u64;
            if back <= self.contig && back <= u64::from(self.stored) && self.byte(self.stored - back as u32) != b {
                self.conflicts += 1;
            }
        }
    }

    fn first_held(&self) -> Option<u64> {
        let ooo = self.ooo.as_ref()?;
        let mut off = 0u64;
        while off < u64::from(REORDER_BYTES) {
            let i = window_index(self.edge + off);
            if i.is_multiple_of(64) && ooo.cover[i / 64] == 0 {
                off += 64;
                continue;
            }
            if ooo.covered(i) {
                return Some(self.edge + off);
            }
            off += 1;
        }
        None
    }

    fn declare_gap(&mut self, missing: u64, now_ms: u64, ctx: &mut Ctx) -> bool {
        if self.gaps.len() >= MAX_GAPS_PER_DIRECTION {
            self.stop(StopReason::GapLimit);
            return false;
        }
        if !grow(&mut self.gaps, MAX_GAPS_PER_DIRECTION, ctx) {
            self.stop(StopReason::StoreCap);
            return false;
        }
        let reason = ctx.gap_reason(now_ms);
        self.gaps.push(Gap { at: self.stored, missing: missing.min(u64::from(u32::MAX)) as u32, reason });
        self.edge += missing;
        self.contig = 0;
        true
    }

    /// Holds bytes ahead of the edge. First-seen bytes win.
    fn hold(&mut self, pos: u64, bytes: &[u8], now_ms: u64, ctx: &mut Ctx) {
        if self.ooo.is_none() {
            if !ctx.admit(OOO_RESERVED) {
                return;
            }
            self.ooo = Some(Ooo::new(now_ms));
        }
        let Some(ooo) = self.ooo.as_mut() else { return };
        if ooo.held == 0 {
            ooo.since_ms = now_ms;
        }
        let mut conflicts = 0;
        for (i, &b) in bytes.iter().enumerate() {
            let idx = window_index(pos + i as u64);
            if ooo.covered(idx) {
                conflicts += u64::from(ooo.data.0[idx] != b);
            } else {
                ooo.data.0[idx] = b;
                ooo.set(idx, true);
                ooo.held += 1;
            }
        }
        self.conflicts += conflicts;
    }

    /// Moves held bytes that are now contiguous into the store.
    fn drain(&mut self, now_ms: u64, d: Direction, turns: &mut Vec<Turn>, ctx: &mut Ctx) {
        let Some(mut ooo) = self.ooo.take() else { return };
        loop {
            let idx = window_index(self.edge);
            if !ooo.covered(idx) {
                break;
            }
            let mut n = 0;
            while idx + n < REORDER_BYTES as usize && ooo.covered(idx + n) {
                n += 1;
            }
            if let Some(f) = self.fin_at {
                n = n.min(f.saturating_sub(self.edge) as usize);
                if n == 0 {
                    break;
                }
            }
            for i in idx..idx + n {
                ooo.set(i, false);
            }
            ooo.held -= n as u32;
            self.edge += n as u64;
            self.append(&ooo.data.0[idx..idx + n], now_ms, d, turns, ctx);
            ooo.data.0[idx..idx + n].zeroize();
        }
        if ooo.held > 0 && self.accepting() {
            self.ooo = Some(ooo);
        } else {
            ctx.refund(OOO_RESERVED);
        }
    }

    /// Places at most a window's worth of bytes at stream position `pos`,
    /// which is at or after the edge.
    fn place(&mut self, pos: u64, bytes: &[u8], now_ms: u64, d: Direction, turns: &mut Vec<Turn>, ctx: &mut Ctx) {
        // A segment past the window forces the earliest hole closed as a gap,
        // repeatedly, until it fits.
        while pos + bytes.len() as u64 > self.edge + u64::from(REORDER_BYTES) {
            let hole_end = self.hole_end(pos);
            if hole_end <= self.edge || !self.declare_gap(hole_end - self.edge, now_ms, ctx) {
                return;
            }
            self.drain(now_ms, d, turns, ctx);
            if !self.accepting() {
                return;
            }
        }
        if pos == self.edge && self.ooo.is_none() {
            self.edge += bytes.len() as u64;
            self.append(bytes, now_ms, d, turns, ctx);
        } else {
            self.hold(pos, bytes, now_ms, ctx);
            self.drain(now_ms, d, turns, ctx);
        }
    }

    /// `seq` is where `seg`'s payload starts (past the SYN, if it has one).
    fn receive(&mut self, seq: u32, seg: &FollowSegment<'_>, d: Direction, turns: &mut Vec<Turn>, ctx: &mut Ctx) {
        let (payload, fin, now_ms) = (seg.payload, seg.fin, seg.now_ms);
        let Some(base) = self.base else { return };
        let edge_seq = base.wrapping_add(self.edge as u32);
        let mut pos = self.edge as i64 + i64::from(seq.wrapping_sub(edge_seq) as i32);
        if fin && self.fin_at.is_none() {
            let f = pos + payload.len() as i64;
            if f >= self.edge as i64 {
                self.fin_at = Some(f as u64);
            }
        }
        let mut rest = payload;
        if let Some(f) = self.fin_at {
            rest = &rest[..rest.len().min((f as i64 - pos).max(0) as usize)];
        }
        if pos < self.edge as i64 && !rest.is_empty() {
            let behind = ((self.edge as i64 - pos) as usize).min(rest.len());
            if self.accepting() {
                self.compare_behind(pos, &rest[..behind]);
            }
            rest = &rest[behind..];
            pos += behind as i64;
        }
        for piece in rest.chunks(REORDER_BYTES as usize) {
            if !self.accepting() {
                break;
            }
            self.place(pos as u64, piece, now_ms, d, turns, ctx);
            pos += piece.len() as i64;
        }
        self.check_fin(ctx);
    }

    /// Where the hole at the edge ends for a segment at `limit`: the first
    /// held byte or `limit`, whichever is earlier, and never past the FIN.
    fn hole_end(&self, limit: u64) -> u64 {
        let end = self.first_held().unwrap_or(limit).min(limit);
        self.fin_at.map_or(end, |f| end.min(f))
    }

    /// Declares every open hole a gap once the oldest has waited 2 s.
    fn expire_holes(&mut self, now_ms: u64, d: Direction, turns: &mut Vec<Turn>, ctx: &mut Ctx) {
        while self.accepting() && self.ooo.as_ref().is_some_and(|o| now_ms.saturating_sub(o.since_ms) >= REORDER_MS) {
            let before = self.edge;
            let Some(held) = self.first_held() else { break };
            let first = self.fin_at.map_or(held, |f| held.min(f));
            if first > self.edge && !self.declare_gap(first - self.edge, now_ms, ctx) {
                break;
            }
            self.drain(now_ms, d, turns, ctx);
            self.check_fin(ctx);
            if self.edge == before {
                // Nothing held can ever become contiguous (it lies past the FIN).
                self.free_ooo(ctx);
                break;
            }
        }
        if !self.accepting() {
            self.free_ooo(ctx);
        }
        self.check_fin(ctx);
    }

    /// D3. `last` means no more bytes will ever be stored, so anything still
    /// undecided is decided now.
    fn classify(&mut self, now_ms: u64, last: bool) -> Option<TlsEvent> {
        if let TlsState::Pending { since_ms, cand, cand_since } = self.tls {
            if self.stored >= 6
                && self.header_at(0).is_some_and(|(t, _)| t == 0x16)
                && matches!(self.byte(5), 0x01 | 0x02)
            {
                return Some(TlsEvent::Initial);
            }
            let window = self.stored.min(TLS_CANDIDATE_BYTES);
            let mut c = cand;
            let mut parked = false;
            while c < window {
                if !(0x14..=0x17).contains(&self.byte(c)) {
                    c += 1;
                    continue;
                }
                if c + 5 > self.stored {
                    if last {
                        c += 1;
                        continue;
                    }
                    break;
                }
                let Some((_, len)) = self.header_at(c) else {
                    c += 1;
                    continue;
                };
                let next = c + 5 + u32::from(len);
                if next + 5 > self.stored {
                    if last {
                        c += 1;
                        continue;
                    }
                    parked = true;
                    break;
                }
                if self.header_at(next).is_some() {
                    return Some(TlsEvent::Initial);
                }
                c += 1;
            }
            // A header parked at `c` is suspect from when it was first seen
            // there, not from the direction's first byte.
            let cand_since = match (parked, c == cand) {
                (false, _) => None,
                (true, true) => cand_since.or(Some(now_ms)),
                (true, false) => Some(now_ms),
            };
            let expired = since_ms.is_some_and(|s| now_ms.saturating_sub(s) >= CLASSIFY_MS);
            if !(last || expired || self.stored >= TLS_LOOKAHEAD_BYTES) {
                self.tls = TlsState::Pending { since_ms, cand: c, cand_since };
                return None;
            }
            // Its wait so far counts toward the 2 s suspect deadline.
            self.tls = TlsState::Cleartext { at: c, suspect_since: cand_since };
        }
        let TlsState::Cleartext { mut at, suspect_since } = self.tls else { return None };
        let mut since = suspect_since;
        while at < self.stored {
            let first = self.byte(at);
            let header = if (0x14..=0x17).contains(&first) { self.header_at(at) } else { None };
            let Some((content_type, len)) = header else {
                since = None;
                if (0x14..=0x17).contains(&first) && at + 5 > self.stored && self.prefix_at(at) && !last {
                    break;
                }
                at += 1;
                continue;
            };
            let suspect_since = *since.get_or_insert(now_ms);
            if content_type == 0x16 && at + 6 <= self.stored && matches!(self.byte(at + 5), 0x01 | 0x02) {
                return Some(TlsEvent::Upgrade(at));
            }
            let next = at + 5 + u32::from(len);
            if next + 5 <= self.stored {
                if self.header_at(next).is_some() {
                    return Some(TlsEvent::Upgrade(at));
                }
            } else if !last && now_ms.saturating_sub(suspect_since) < CLASSIFY_MS {
                break;
            }
            since = None;
            at += 1;
        }
        // A deadline belongs to the header at `at`; with no bytes there, none.
        if at >= self.stored {
            since = None;
        }
        self.tls = TlsState::Cleartext { at, suspect_since: since };
        None
    }

    /// Records a mask, coalescing with the previous range. On failure the
    /// stored bytes must be cut at `cut_at`, since they cannot be masked.
    fn mask(&mut self, start: u32, end: u32, reason: MaskReason, cut_at: u32, ctx: &mut Ctx) -> Result<(), Cut> {
        if start >= end {
            return Ok(());
        }
        if let Some(last) = self.ranges.last_mut() {
            let last_end = last.start + last.len;
            if last.reason == reason && last_end >= start {
                last.len = last_end.max(end) - last.start;
                return Ok(());
            }
        }
        if self.ranges.len() >= MAX_RANGES_PER_DIRECTION {
            return Err((cut_at, StopReason::RedactionLimit));
        }
        if !grow(&mut self.ranges, MAX_RANGES_PER_DIRECTION, ctx) {
            return Err((cut_at, StopReason::StoreCap));
        }
        debug_assert!(self.ranges.last().is_none_or(|r| r.start + r.len <= start));
        self.ranges.push(MaskRange { start, len: end - start, reason });
        Ok(())
    }

    fn header_is_credential(&self, line_start: u32, colon: u32, value_start: u32, value_end: u32) -> bool {
        let mut name = [0u8; 32];
        let name_len = (colon - line_start) as usize;
        if name_len <= name.len() {
            self.read(line_start, &mut name[..name_len]);
            if std::str::from_utf8(&name[..name_len]).is_ok_and(is_sensitive_header_name) {
                return true;
            }
        }
        let mut value = Zeroizing::new([0u8; 16]);
        let n = ((value_end - value_start) as usize).min(value.len());
        self.read(value_start, &mut value[..n]);
        let prefix = &value[..n];
        let text = match std::str::from_utf8(prefix) {
            Ok(text) => text,
            Err(e) => std::str::from_utf8(&prefix[..e.valid_up_to()]).unwrap_or(""),
        };
        looks_like_bearer_token(text)
    }

    /// The end of the current line's content, excluding a trailing CR.
    fn content_end(&self, at: u32) -> u32 {
        if self.scan.last_cr && at > self.scan.line_start {
            at - 1
        } else {
            at
        }
    }

    fn end_line(&mut self, prev: Prev) {
        self.scan.line = Line::Start;
        self.scan.prev = prev;
    }

    fn scan_byte(&mut self, b: u8, ctx: &mut Ctx) -> Result<(), Cut> {
        let o = self.scan.pos;
        if self.scan.line == Line::Start {
            let fold = b == b' ' || b == b'\t';
            let first = if b == LF || !is_tchar(b) { Line::Plain } else { Line::Name };
            self.scan.line_start = o;
            self.scan.last_cr = false;
            self.scan.line = match std::mem::replace(&mut self.scan.prev, Prev::None) {
                Prev::Header { line_start, value_start, value_end, credential } => {
                    // A continuation makes the whole logical value a credential.
                    if fold || credential {
                        self.mask(value_start, value_end, MaskReason::Credential, line_start, ctx)?;
                    }
                    if fold {
                        Line::Cont
                    } else {
                        first
                    }
                }
                Prev::Folded if fold => Line::Cont,
                Prev::Uncertain if fold => Line::Uncertain,
                _ => first,
            };
        }
        let line_len = o + 1 - self.scan.line_start;
        match self.scan.line {
            Line::Start | Line::Done => {}
            Line::Plain => {
                if b == LF {
                    self.end_line(Prev::None);
                }
            }
            Line::Name => {
                if b == LF {
                    self.end_line(Prev::None);
                } else if b == b':' {
                    self.scan.line = Line::Value { colon: o, value_start: None };
                } else if !is_tchar(b) {
                    self.scan.line = Line::Plain;
                } else if line_len > MAX_LINE_BYTES {
                    self.scan.line = Line::LongMask(MaskReason::Uncertain);
                    self.mask(self.scan.line_start, o + 1, MaskReason::Uncertain, self.scan.line_start, ctx)?;
                }
            }
            Line::Value { colon, value_start } => {
                if b == LF {
                    let value_end = self.content_end(o);
                    let value_start = value_start.unwrap_or(value_end).min(value_end);
                    let line_start = self.scan.line_start;
                    let credential = self.header_is_credential(line_start, colon, value_start, value_end);
                    self.end_line(Prev::Header { line_start, value_start, value_end, credential });
                } else if line_len > MAX_LINE_BYTES {
                    self.scan.line = Line::LongMask(MaskReason::Uncertain);
                    self.mask(self.scan.line_start, o + 1, MaskReason::Uncertain, self.scan.line_start, ctx)?;
                } else if value_start.is_none() && b != b' ' && b != b'\t' {
                    self.scan.line = Line::Value { colon, value_start: Some(o) };
                }
            }
            Line::Cont => {
                let line_start = self.scan.line_start;
                if b == LF {
                    self.mask(line_start, self.content_end(o), MaskReason::Credential, line_start, ctx)?;
                    self.end_line(Prev::Folded);
                } else if line_len > MAX_LINE_BYTES {
                    self.scan.line = Line::LongMask(MaskReason::Credential);
                    self.mask(line_start, o + 1, MaskReason::Credential, line_start, ctx)?;
                }
            }
            Line::Uncertain => {
                if b == LF {
                    self.end_line(Prev::Uncertain);
                } else if o - self.scan.line_start >= MAX_LINE_BYTES {
                    // The stated trade-off: a newline-free body after a gap
                    // is masked for 16 KiB, not entirely.
                    self.scan.line = Line::Plain;
                } else {
                    self.mask(o, o + 1, MaskReason::Uncertain, o, ctx)?;
                }
            }
            Line::LongMask(reason) => {
                if b == LF {
                    self.end_line(if reason == MaskReason::Credential { Prev::Folded } else { Prev::Uncertain });
                } else {
                    self.mask(o, o + 1, reason, o, ctx)?;
                }
            }
        }
        self.scan.last_cr = b == CR;
        self.scan.pos = o + 1;
        Ok(())
    }

    /// Masks whatever is undecided at `at`, because what follows it (a gap,
    /// a cap edge, an upgrade point) is unknown.
    fn mask_undecided(&mut self, at: u32, ctx: &mut Ctx) -> Result<(), Cut> {
        if let Prev::Header { line_start, value_start, value_end, credential } =
            std::mem::replace(&mut self.scan.prev, Prev::None)
        {
            let reason = if credential { MaskReason::Credential } else { MaskReason::Uncertain };
            self.mask(value_start, value_end, reason, line_start, ctx)?;
        }
        let line_start = self.scan.line_start;
        match self.scan.line {
            Line::Name | Line::Value { .. } => self.mask(line_start, at, MaskReason::Uncertain, line_start, ctx)?,
            Line::Cont => self.mask(line_start, at, MaskReason::Credential, line_start, ctx)?,
            _ => {}
        }
        Ok(())
    }

    fn scan_to(&mut self, limit: u32, ctx: &mut Ctx) -> Result<(), Cut> {
        loop {
            if self.scan.line == Line::Done {
                return Ok(());
            }
            let pos = self.scan.pos;
            if let Some(gap) = self.gaps.get(self.scan.next_gap) {
                if gap.at == pos && pos <= limit {
                    self.mask_undecided(pos, ctx)?;
                    self.scan.line = Line::Uncertain;
                    self.scan.line_start = pos;
                    self.scan.last_cr = false;
                    self.scan.next_gap += 1;
                    continue;
                }
            }
            if pos >= limit {
                return Ok(());
            }
            let b = self.byte(pos);
            self.scan_byte(b, ctx)?;
        }
    }

    /// The direction closed: no continuation can follow, so every undecided
    /// line is decided as complete.
    fn finish_close(&mut self, ctx: &mut Ctx) -> Result<(), Cut> {
        if let Prev::Header { line_start, value_start, value_end, credential: true } =
            std::mem::replace(&mut self.scan.prev, Prev::None)
        {
            self.mask(value_start, value_end, MaskReason::Credential, line_start, ctx)?;
        }
        let (pos, line_start) = (self.scan.pos, self.scan.line_start);
        match self.scan.line {
            Line::Value { colon, value_start } => {
                let value_end = self.content_end(pos);
                let value_start = value_start.unwrap_or(value_end).min(value_end);
                if self.header_is_credential(line_start, colon, value_start, value_end) {
                    self.mask(value_start, value_end, MaskReason::Credential, line_start, ctx)?;
                }
            }
            Line::Cont => self.mask(line_start, self.content_end(pos), MaskReason::Credential, line_start, ctx)?,
            _ => {}
        }
        self.scan.line = Line::Done;
        Ok(())
    }

    fn cut(&mut self, (at, reason): Cut, ctx: &mut Ctx) {
        self.truncate(at, ctx);
        self.stop(reason);
        self.scan.line = Line::Done;
        self.scan.prev = Prev::None;
        self.scan.pos = self.stored;
        self.finalized = true;
        self.free_ooo(ctx);
    }

    /// Ends the direction at stored offset `at`: nothing after it is kept,
    /// and whatever line it interrupts is masked.
    fn seal(&mut self, at: u32, ctx: &mut Ctx) {
        self.truncate(at, ctx);
        let result = self.scan_to(at, ctx).and_then(|()| self.mask_undecided(at, ctx));
        if let Err(cut) = result {
            self.cut(cut, ctx);
            return;
        }
        self.scan.line = Line::Done;
        self.scan.pos = self.stored;
        self.finalized = true;
        self.free_ooo(ctx);
    }

    /// Drops every stored byte and the metadata describing them (D3 `tls`).
    fn drop_all(&mut self, ctx: &mut Ctx) {
        self.truncate(0, ctx);
        release_vec(&mut self.chunks, ctx);
        release_vec(&mut self.gaps, ctx);
        release_vec(&mut self.ranges, ctx);
        self.free_ooo(ctx);
        self.tls = TlsState::Tls;
        self.tls_from = None;
        self.scan = Scanner { line: Line::Done, ..Scanner::new(true) };
        self.finalized = true;
    }

    fn settle_scan(&mut self, ctx: &mut Ctx) {
        if self.finalized || self.is_tls() {
            return;
        }
        let limit = self.tls_horizon();
        if let Err(cut) = self.scan_to(limit, ctx) {
            self.cut(cut, ctx);
            return;
        }
        if self.stopped.is_some() {
            self.seal(limit, ctx);
        } else if self.closed && limit == self.stored {
            match self.finish_close(ctx) {
                Ok(()) => self.finalized = true,
                Err(cut) => self.cut(cut, ctx),
            }
        }
    }

    fn view(&self) -> FollowDirection<'_> {
        FollowDirection {
            classification: self.classification(),
            tls_from: self.tls_from,
            emittable: self.emittable(),
            stored_bytes: self.stored,
            seen_bytes: self.seen,
            stopped: self.stopped,
            gaps: &self.gaps,
            redacted_ranges: &self.ranges,
            conflicting_overlap_bytes: self.conflicts,
            start_captured: self.start_captured,
            closed: self.closed,
        }
    }
}

/// One retained flow. Exposes metadata and masked copies, never raw bytes.
pub struct FollowEntry {
    fixed_heap: usize,
    generation: Generation,
    insertion: u64,
    client_is_local: Option<bool>,
    c2s_outbound: bool,
    flow_start_captured: bool,
    rst: bool,
    tls_flow: bool,
    last_activity_ms: u64,
    turns: Vec<Turn>,
    dirs: [DirState; 2],
}

impl FollowEntry {
    pub fn generation(&self) -> Generation {
        self.generation
    }

    /// `Some(true)`/`Some(false)` from the SYN/SYN+ACK orientation; `None`
    /// for a midstream start, where C2s means local-to-remote.
    pub fn client_is_local(&self) -> Option<bool> {
        self.client_is_local
    }

    pub fn flow_start_captured(&self) -> bool {
        self.flow_start_captured
    }

    pub fn closed(&self) -> bool {
        self.rst || self.dirs.iter().all(|d| d.closed)
    }

    pub fn turns(&self) -> &[Turn] {
        &self.turns
    }

    pub fn direction(&self, dir: Direction) -> FollowDirection<'_> {
        self.dirs[dir.index()].view()
    }

    /// Copies stored bytes `[offset, end)` into `output`, every masked byte
    /// replaced by `*`, stopping at the emission horizon. Returns the count.
    pub fn copy_masked(&self, dir: Direction, offset: u32, end: u32, output: &mut [u8]) -> usize {
        let d = &self.dirs[dir.index()];
        let end = end.min(d.emittable());
        if offset >= end {
            return 0;
        }
        let n = ((end - offset) as usize).min(output.len());
        let out = &mut output[..n];
        d.read(offset, out);
        let page_end = offset + n as u32;
        let first = d.ranges.partition_point(|r| r.start + r.len <= offset);
        for r in &d.ranges[first..] {
            if r.start >= page_end {
                break;
            }
            let from = r.start.max(offset) - offset;
            let to = (r.start + r.len).min(page_end) - offset;
            out[from as usize..to as usize].fill(b'*');
        }
        n
    }

    fn heap_bytes(&self) -> usize {
        self.fixed_heap
            + self.turns.capacity() * std::mem::size_of::<Turn>()
            + self.dirs.iter().map(DirState::heap_bytes).sum::<usize>()
    }

    fn stop_both(&mut self, reason: StopReason) {
        for d in &mut self.dirs {
            if !d.finalized && !d.is_tls() {
                d.stop(reason);
            }
        }
    }

    fn clip_turns(&mut self) {
        let stored = [self.dirs[0].stored, self.dirs[1].stored];
        self.turns.retain_mut(|t| {
            t.len = t.len.min(stored[t.dir.index()].saturating_sub(t.start));
            t.len > 0
        });
    }

    fn tls_initial(&mut self, ctx: &mut Ctx) {
        for d in &mut self.dirs {
            d.drop_all(ctx);
        }
        release_vec(&mut self.turns, ctx);
        self.tls_flow = true;
    }

    fn tls_upgrade(&mut self, upgraded: usize, at: u32, ctx: &mut Ctx) {
        for (i, d) in self.dirs.iter_mut().enumerate() {
            if !d.finalized {
                // The other direction keeps only what was already decided
                // cleartext; a pending one keeps nothing.
                let edge = if i == upgraded { at } else { d.tls_horizon() };
                d.seal(edge, ctx);
            }
            d.tls_from = Some(d.stored);
            d.tls = TlsState::Tls;
        }
        self.tls_flow = true;
        ctx.truncated = true;
    }

    fn settle(&mut self, now_ms: u64, ctx: &mut Ctx) {
        for i in 0..2 {
            self.dirs[i].expire_holes(now_ms, Direction::from_index(i), &mut self.turns, ctx);
        }
        if std::mem::take(&mut ctx.turn_limit) {
            self.stop_both(StopReason::TurnLimit);
        }
        if !self.tls_flow {
            for i in 0..2 {
                let d = &mut self.dirs[i];
                let last = d.closed || d.stopped.is_some();
                match d.classify(now_ms, last) {
                    Some(TlsEvent::Initial) => {
                        self.tls_initial(ctx);
                        break;
                    }
                    Some(TlsEvent::Upgrade(at)) => {
                        self.tls_upgrade(i, at, ctx);
                        break;
                    }
                    None => {}
                }
            }
        }
        for d in &mut self.dirs {
            d.settle_scan(ctx);
        }
        if std::mem::take(&mut ctx.truncated) {
            self.clip_turns();
        }
    }

    fn ingest(&mut self, outbound: bool, seg: FollowSegment<'_>, ctx: &mut Ctx) {
        self.last_activity_ms = seg.now_ms;
        let i = if outbound == self.c2s_outbound { 0 } else { 1 };
        let d = &mut self.dirs[i];
        d.seen = d.seen.saturating_add(seg.payload.len() as u64);
        if self.rst {
            return;
        }
        if seg.rst {
            self.rst = true;
            for d in &mut self.dirs {
                d.close(ctx);
            }
        } else {
            let seq = if seg.syn {
                // A SYN on a direction that already has its start is a
                // retransmit or a forgery: it changes nothing.
                (d.base.is_none()).then(|| {
                    d.begin(seg.seq.wrapping_add(1), true);
                    seg.seq.wrapping_add(1)
                })
            } else {
                if d.base.is_none() && (!seg.payload.is_empty() || seg.fin) {
                    d.begin(seg.seq, false);
                }
                d.base.map(|_| seg.seq)
            };
            if let Some(seq) = seq {
                let dir = Direction::from_index(i);
                self.dirs[i].receive(seq, &seg, dir, &mut self.turns, ctx);
            }
            if std::mem::take(&mut ctx.turn_limit) {
                self.stop_both(StopReason::TurnLimit);
            }
        }
        self.settle(seg.now_ms, ctx);
    }
}

impl fmt::Debug for FollowEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dir = |d: &DirState| (d.classification(), d.stored, d.seen, d.gaps.len(), d.ranges.len(), d.stopped);
        f.debug_struct("FollowEntry")
            .field("generation", &self.generation)
            .field("client_is_local", &self.client_is_local)
            .field("closed", &self.closed())
            .field("turns", &self.turns.len())
            .field("c2s", &dir(&self.dirs[0]))
            .field("s2c", &dir(&self.dirs[1]))
            .finish_non_exhaustive()
    }
}

/// Every retained flow's head, bounded per D2, keyed by flow identity.
pub struct FollowStore {
    epoch: u64,
    counter: u64,
    insertions: u64,
    entries: Entries,
    reserved: usize,
    map_bytes: usize,
    last_cut_ms: Option<u64>,
}

impl fmt::Debug for FollowStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FollowStore")
            .field("flows", &self.entries.len())
            .field("reserved_bytes", &self.reserved)
            .finish_non_exhaustive()
    }
}

impl FollowStore {
    /// `epoch` is drawn once at agent start; `reset` keeps it.
    pub fn new(epoch: u64) -> Self {
        FollowStore {
            epoch,
            counter: 0,
            insertions: 0,
            entries: HashMap::new(),
            reserved: 0,
            map_bytes: 0,
            last_cut_ms: None,
        }
    }

    pub fn flow_count(&self) -> usize {
        self.entries.len()
    }

    /// Reserved capacity: chunks, held bytes, metadata and the flow index.
    pub fn reserved_bytes(&self) -> usize {
        self.reserved
    }

    /// The pre-parse snaplen notifier (`main.rs::note_capture_truncation`).
    pub fn note_frame_cut_at_snaplen(&mut self, now_ms: u64) {
        self.last_cut_ms = Some(now_ms);
    }

    fn remove(&mut self, key: &FlowKey) {
        if let Some(entry) = self.entries.remove(key) {
            self.reserved -= entry.heap_bytes();
        }
    }

    fn create(&mut self, key: &FlowKey, outbound: bool, seg: &FollowSegment<'_>) -> bool {
        let Some(counter) = self.counter.checked_add(1) else {
            return false;
        };
        if self.map_bytes == 0 {
            self.entries.reserve(MAP_RESERVE);
            self.map_bytes = map_estimate(MAP_RESERVE);
            self.reserved += self.map_bytes;
        }
        if self.entries.len() >= MAX_FLOWS {
            if let Some(victim) = pressure_victim(&self.entries) {
                self.remove(&victim);
            }
        }
        let key = key.clone();
        let fixed_heap =
            key.local_addr.capacity() + key.remote_addr.capacity() + std::mem::size_of::<FollowEntry>();
        let mut ctx = Ctx {
            reserved: &mut self.reserved,
            others: Some(&mut self.entries),
            last_cut_ms: None,
            turn_limit: false,
            truncated: false,
        };
        if !ctx.admit(fixed_heap) {
            return false;
        }
        let (client_is_local, c2s_outbound) = match (seg.syn, seg.ack) {
            (true, false) => (Some(outbound), outbound),
            (true, true) => (Some(!outbound), !outbound),
            _ => (None, true),
        };
        self.counter = counter;
        self.insertions += 1;
        let entry = Box::new(FollowEntry {
            fixed_heap,
            generation: Generation { epoch: self.epoch, counter },
            insertion: self.insertions,
            client_is_local,
            c2s_outbound,
            flow_start_captured: seg.syn,
            rst: false,
            tls_flow: false,
            last_activity_ms: seg.now_ms,
            turns: Vec::new(),
            dirs: [DirState::new(), DirState::new()],
        });
        self.entries.insert(key, entry);
        true
    }

    /// Runs `work` on one entry with every other entry available for
    /// eviction, so growth never fails only because of which path did it.
    fn with_ctx(&mut self, key: &FlowKey, work: impl FnOnce(&mut FollowEntry, &mut Ctx)) {
        let Some((key, mut entry)) = self.entries.remove_entry(key) else { return };
        let mut ctx = Ctx {
            reserved: &mut self.reserved,
            others: Some(&mut self.entries),
            last_cut_ms: self.last_cut_ms,
            turn_limit: false,
            truncated: false,
        };
        work(&mut entry, &mut ctx);
        self.entries.insert(key, entry);
    }

    pub fn ingest(&mut self, key: &FlowKey, outbound: bool, segment: FollowSegment<'_>) {
        // Only replacement of a terminal tuple starts a new generation.
        if segment.syn && self.entries.get(key).is_some_and(|e| e.closed()) {
            self.remove(key);
        }
        if !self.entries.contains_key(key) {
            let starts = segment.syn || (!segment.payload.is_empty() && !segment.rst);
            if !starts || !self.create(key, outbound, &segment) {
                return;
            }
        }
        self.with_ctx(key, |entry, ctx| entry.ingest(outbound, segment, ctx));
    }

    /// Advances capture time: hole expiry and the D3 deadlines. Never reads
    /// the wall clock.
    pub fn tick(&mut self, now_ms: u64) {
        let keys: Vec<FlowKey> = self.entries.keys().cloned().collect();
        for key in &keys {
            // An entry evicted earlier in this tick is simply skipped.
            self.with_ctx(key, |entry, ctx| entry.settle(now_ms, ctx));
        }
    }

    /// Called when `FlowTable` evicts the flow.
    pub fn drop_flow(&mut self, key: &FlowKey) {
        self.remove(key);
    }

    /// Interface switch: every entry goes; the epoch and counter stay, so
    /// generations remain monotonic.
    pub fn reset(&mut self) {
        let freed: usize = self.entries.values().map(|e| e.heap_bytes()).sum();
        self.entries.clear();
        self.reserved -= freed;
        self.last_cut_ms = None;
    }

    pub fn with_entry<R>(&self, connection_id: &str, f: impl FnOnce(Option<&FollowEntry>) -> R) -> R {
        let key = FlowKey::from_connection_id(connection_id);
        f(key.and_then(|k| self.entries.get(&k)).map(|e| &**e))
    }

    /// Structural invariants, for tests and the fuzz target. Reports counts
    /// and fixed messages only, never payload.
    #[cfg(any(test, fuzzing))]
    pub fn audit(&self) -> Result<(), &'static str> {
        // A table larger than the reservation would hold more usable slots
        // than the reserved one ever has.
        if self.entries.capacity() > map_buckets(MAP_RESERVE) / 8 * 7 {
            return Err("flow index grew past its reservation");
        }
        if self.map_bytes != 0 && self.map_bytes != map_estimate(MAP_RESERVE) {
            return Err("flow index charge changed");
        }
        let recomputed = self.map_bytes + self.entries.values().map(|e| e.heap_bytes()).sum::<usize>();
        if recomputed != self.reserved {
            return Err("reserved byte counter drifted from reserved capacity");
        }
        if self.reserved > MAX_TOTAL_BYTES || self.entries.len() > MAX_FLOWS {
            return Err("store over its global caps");
        }
        for e in self.entries.values() {
            if e.turns.len() > MAX_TURNS_PER_FLOW {
                return Err("turns over cap");
            }
            for d in &e.dirs {
                if d.stored > MAX_DIRECTION_BYTES || d.gaps.len() > MAX_GAPS_PER_DIRECTION {
                    return Err("direction over cap");
                }
                if d.ranges.len() > MAX_RANGES_PER_DIRECTION {
                    return Err("ranges over cap");
                }
                if d.chunks.len() != (d.stored as usize).div_ceil(CHUNK_BYTES) {
                    return Err("chunk count does not match stored bytes");
                }
                if let Some(last) = d.chunks.last() {
                    let within = d.stored as usize % CHUNK_BYTES;
                    if within != 0 && last.0[within..].iter().any(|&b| b != 0) {
                        return Err("bytes past the stored end are not zero");
                    }
                }
                let mut prev_end = 0;
                for r in &d.ranges {
                    if r.len == 0 || r.start < prev_end || r.start + r.len > d.stored {
                        return Err("mask ranges unordered or out of bounds");
                    }
                    prev_end = r.start + r.len;
                }
                let emittable = d.emittable();
                match d.tls {
                    TlsState::Pending { .. } if emittable != 0 => return Err("pending bytes emittable"),
                    TlsState::Tls if emittable > d.tls_from.unwrap_or(0) => return Err("TLS bytes emittable"),
                    _ => {}
                }
                if emittable > d.stored {
                    return Err("emission horizon past the stored end");
                }
            }
        }
        Ok(())
    }

    /// Whether bytes past the direction's stored end, within its last chunk,
    /// are zero.
    #[cfg(test)]
    fn stored_tail_is_zero(&self, key: &FlowKey, dir: Direction) -> bool {
        let d = &self.entries[key].dirs[dir.index()];
        let within = d.stored as usize % CHUNK_BYTES;
        d.chunks.last().is_none_or(|c| within == 0 || c.0[within..].iter().all(|&b| b == 0))
    }
}

/// Test seam (D7a): every payload buffer reports, just before it is freed,
/// whether it was all zeros.
#[cfg(test)]
mod release_hook {
    use std::cell::RefCell;

    thread_local! {
        static RELEASED: RefCell<Vec<bool>> = const { RefCell::new(Vec::new()) };
    }

    pub fn record(all_zero: bool) {
        RELEASED.with(|r| r.borrow_mut().push(all_zero));
    }

    pub fn take() -> Vec<bool> {
        RELEASED.with(|r| std::mem::take(&mut *r.borrow_mut()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::TransportProtocol;

    const T0: u64 = 10_000;
    const C_ISN: u32 = 1_000;
    const S_ISN: u32 = 5_000;
    const C0: u32 = C_ISN + 1;
    const S0: u32 = S_ISN + 1;

    fn key_n(n: u16) -> FlowKey {
        FlowKey {
            protocol: TransportProtocol::Tcp,
            local_addr: "10.0.0.1".to_string(),
            local_port: 40_000 + n,
            remote_addr: "93.184.216.34".to_string(),
            remote_port: 80,
        }
    }

    fn key() -> FlowKey {
        key_n(0)
    }

    fn seg(seq: u32, payload: &[u8], now_ms: u64) -> FollowSegment<'_> {
        FollowSegment { seq, syn: false, ack: true, fin: false, rst: false, payload, now_ms }
    }

    fn syn(seq: u32, ack: bool, now_ms: u64) -> FollowSegment<'static> {
        FollowSegment { seq, syn: true, ack, fin: false, rst: false, payload: &[], now_ms }
    }

    fn fin(seq: u32, payload: &[u8], now_ms: u64) -> FollowSegment<'_> {
        FollowSegment { seq, syn: false, ack: true, fin: true, rst: false, payload, now_ms }
    }

    fn rst(seq: u32, now_ms: u64) -> FollowSegment<'static> {
        FollowSegment { seq, syn: false, ack: true, fin: false, rst: true, payload: &[], now_ms }
    }

    /// A client on this host opens the connection: SYN out, SYN+ACK in.
    fn open(store: &mut FollowStore, k: &FlowKey) {
        store.ingest(k, true, syn(C_ISN, false, T0));
        store.ingest(k, false, syn(S_ISN, true, T0));
    }

    /// Opens a connection and makes both directions cleartext by sending one
    /// harmless line each way and letting the 2 s classification window pass.
    fn open_cleartext(store: &mut FollowStore, k: &FlowKey) -> (u32, u32) {
        open(store, k);
        store.ingest(k, true, seg(C0, b"GET / HTTP/1.1\r\n", T0));
        store.ingest(k, false, seg(S0, b"HTTP/1.1 200 OK\r\n", T0));
        store.tick(T0 + CLASSIFY_MS);
        (C0 + 16, S0 + 17)
    }

    fn id(k: &FlowKey) -> String {
        k.connection_id()
    }

    fn emitted(store: &FollowStore, k: &FlowKey, dir: Direction) -> Vec<u8> {
        store.audit().expect("store invariants");
        store.with_entry(&id(k), |e| {
            let e = e.expect("entry");
            let mut out = vec![0u8; MAX_DIRECTION_BYTES as usize];
            let n = e.copy_masked(dir, 0, u32::MAX, &mut out);
            out.truncate(n);
            out
        })
    }

    #[derive(Debug, Clone, PartialEq)]
    struct Snap {
        class: Classification,
        tls_from: Option<u32>,
        emittable: u32,
        stored: u32,
        seen: u64,
        stopped: Option<StopReason>,
        gaps: Vec<Gap>,
        ranges: Vec<MaskRange>,
        conflicts: u64,
        start_captured: bool,
        closed: bool,
    }

    fn snap(store: &FollowStore, k: &FlowKey, dir: Direction) -> Snap {
        store.audit().expect("store invariants");
        store.with_entry(&id(k), |e| {
            let d = e.expect("entry").direction(dir);
            Snap {
                class: d.classification,
                tls_from: d.tls_from,
                emittable: d.emittable,
                stored: d.stored_bytes,
                seen: d.seen_bytes,
                stopped: d.stopped,
                gaps: d.gaps.to_vec(),
                ranges: d.redacted_ranges.to_vec(),
                conflicts: d.conflicting_overlap_bytes,
                start_captured: d.start_captured,
                closed: d.closed,
            }
        })
    }

    fn generation(store: &FollowStore, k: &FlowKey) -> Option<Generation> {
        store.with_entry(&id(k), |e| e.map(FollowEntry::generation))
    }

    fn tls_record(content_type: u8, body_len: usize, fill: u8) -> Vec<u8> {
        let mut r = vec![content_type, 0x03, 0x03];
        r.extend_from_slice(&(body_len as u16).to_be_bytes());
        r.extend(std::iter::repeat_n(fill, body_len));
        r
    }

    fn client_hello(sni: bool) -> Vec<u8> {
        let mut body = vec![0x01, 0x00, 0x00, 0x30, 0x03, 0x03];
        body.extend([0xAB; 32]);
        if sni {
            body.extend_from_slice(b"\x00\x00\x00\x0e\x00\x0c\x00\x00\x09example.c");
        }
        let mut r = vec![0x16, 0x03, 0x01];
        r.extend_from_slice(&(body.len() as u16).to_be_bytes());
        r.extend(body);
        r
    }

    /// Every byte of `secret` that appears at its own offset in `out` must be
    /// masked: an emitted copy may stop short of the secret, never show it.
    fn assert_secret_masked(out: &[u8], stream: &[u8], secret: &[u8]) {
        let at = stream.windows(secret.len()).position(|w| w == secret).expect("secret in stream");
        for i in at..(at + secret.len()).min(out.len()) {
            assert_eq!(out[i], b'*', "byte {i} of the secret emitted: {:?}", String::from_utf8_lossy(out));
        }
    }

    // ---------- D2: store, directions, generations ----------

    #[test]
    fn a_new_store_reserves_nothing() {
        let store = FollowStore::new(1);
        assert_eq!(store.reserved_bytes(), 0);
        assert_eq!(store.flow_count(), 0);
        assert!(store.with_entry("nope", |e| e.is_none()));
    }

    #[test]
    fn an_in_order_exchange_is_stored_per_direction_with_turns() {
        let mut store = FollowStore::new(7);
        let k = key();
        open(&mut store, &k);
        store.ingest(&k, true, fin(C0, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", T0 + 10));
        store.ingest(&k, false, fin(S0, b"HTTP/1.1 200 OK\r\n\r\nhi", T0 + 20));
        assert_eq!(emitted(&store, &k, Direction::C2s), b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
        assert_eq!(emitted(&store, &k, Direction::S2c), b"HTTP/1.1 200 OK\r\n\r\nhi");
        store.with_entry(&id(&k), |e| {
            let e = e.unwrap();
            assert_eq!(e.client_is_local(), Some(true));
            assert!(e.flow_start_captured());
            assert!(e.closed());
            assert_eq!(e.generation(), Generation { epoch: 7, counter: 1 });
            assert_eq!(
                e.turns(),
                &[
                    Turn { dir: Direction::C2s, start: 0, len: 27, first_seen_ms: T0 + 10 },
                    Turn { dir: Direction::S2c, start: 0, len: 21, first_seen_ms: T0 + 20 },
                ]
            );
        });
        let c = snap(&store, &k, Direction::C2s);
        assert_eq!((c.class, c.stored, c.seen, c.start_captured, c.closed), (Classification::Cleartext, 27, 27, true, true));
    }

    #[test]
    fn an_inbound_syn_makes_the_remote_endpoint_the_client() {
        let mut store = FollowStore::new(1);
        let k = key();
        store.ingest(&k, false, syn(7_000, false, T0));
        store.ingest(&k, true, syn(9_000, true, T0));
        store.ingest(&k, false, fin(7_001, b"hello\n", T0));
        store.ingest(&k, true, fin(9_001, b"world\n", T0));
        assert_eq!(emitted(&store, &k, Direction::C2s), b"hello\n");
        assert_eq!(emitted(&store, &k, Direction::S2c), b"world\n");
        assert!(store.with_entry(&id(&k), |e| e.unwrap().client_is_local() == Some(false)));
    }

    #[test]
    fn a_first_syn_ack_makes_its_receiver_the_client() {
        let mut store = FollowStore::new(1);
        let k = key();
        store.ingest(&k, false, syn(9_000, true, T0)); // SYN+ACK in: we are the client
        assert!(store.with_entry(&id(&k), |e| e.unwrap().client_is_local() == Some(true)));
    }

    #[test]
    fn a_midstream_start_is_local_outbound_first_and_its_first_line_is_uncertain() {
        let mut store = FollowStore::new(1);
        let k = key();
        store.ingest(&k, true, fin(50, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", T0));
        store.with_entry(&id(&k), |e| {
            let e = e.unwrap();
            assert_eq!(e.client_is_local(), None);
            assert!(!e.flow_start_captured());
        });
        let mut want = vec![b'*'; 15];
        want.extend_from_slice(b"\nHost: x\r\n\r\n");
        assert_eq!(emitted(&store, &k, Direction::C2s), want);
        assert!(!snap(&store, &k, Direction::C2s).start_captured);
    }

    #[test]
    fn reverse_order_segments_fill_the_hole() {
        let mut store = FollowStore::new(1);
        let k = key();
        open(&mut store, &k);
        store.ingest(&k, true, fin(C0 + 6, b"world\n", T0));
        store.ingest(&k, true, seg(C0, b"hello ", T0));
        assert_eq!(emitted(&store, &k, Direction::C2s), b"hello world\n");
        assert!(snap(&store, &k, Direction::C2s).gaps.is_empty());
    }

    #[test]
    fn syn_and_fin_consume_sequence_space() {
        let mut store = FollowStore::new(1);
        let k = key();
        open(&mut store, &k);
        store.ingest(&k, true, fin(C0, b"ab\n", T0));
        assert!(snap(&store, &k, Direction::C2s).closed);
        // Bytes after the FIN are not part of the stream.
        store.ingest(&k, true, seg(C0 + 4, b"zz", T0));
        assert_eq!(emitted(&store, &k, Direction::C2s), b"ab\n");
    }

    #[test]
    fn wrapping_sequence_numbers_join() {
        let mut store = FollowStore::new(1);
        let k = key();
        let isn = u32::MAX - 2;
        store.ingest(&k, true, syn(isn, false, T0));
        store.ingest(&k, true, seg(isn.wrapping_add(1), b"abc", T0));
        store.ingest(&k, true, fin(isn.wrapping_add(4), b"def\n", T0));
        assert_eq!(emitted(&store, &k, Direction::C2s), b"abcdef\n");
    }

    #[test]
    fn retransmits_do_not_duplicate_and_conflicting_overlaps_are_counted() {
        let mut store = FollowStore::new(1);
        let k = key();
        open(&mut store, &k);
        store.ingest(&k, true, seg(C0, b"hello world", T0));
        store.ingest(&k, true, seg(C0, b"hello world", T0));
        assert_eq!(snap(&store, &k, Direction::C2s).conflicts, 0);
        store.ingest(&k, true, seg(C0, b"hellX wYrld", T0));
        assert_eq!(snap(&store, &k, Direction::C2s).conflicts, 2);
        // Held ahead of the edge first, then overlapped: the held bytes win.
        store.ingest(&k, true, seg(C0 + 15, b"abc", T0));
        store.ingest(&k, true, seg(C0 + 11, b"\n123xbc", T0));
        store.ingest(&k, true, fin(C0 + 18, b"\n", T0));
        let s = snap(&store, &k, Direction::C2s);
        assert_eq!(s.conflicts, 3);
        assert_eq!(s.seen, 11 * 3 + 3 + 7 + 1);
        assert_eq!(emitted(&store, &k, Direction::C2s), b"hello world\n123abc\n");
    }

    #[test]
    fn a_duplicate_syn_keeps_the_generation_but_a_replaced_closed_tuple_gets_a_new_one() {
        let mut store = FollowStore::new(1);
        let k = key();
        open(&mut store, &k);
        store.ingest(&k, true, seg(C0, b"first\n", T0));
        let g1 = generation(&store, &k).unwrap();
        store.ingest(&k, true, syn(C_ISN, false, T0 + 1)); // retransmitted SYN
        store.ingest(&k, true, syn(77, false, T0 + 2)); // forged SYN on a live tuple
        assert_eq!(generation(&store, &k), Some(g1));
        assert_eq!(snap(&store, &k, Direction::C2s).stored, 6);
        assert!(store.with_entry(&id(&k), |e| e.unwrap().client_is_local() == Some(true)));

        store.ingest(&k, false, rst(S0, T0 + 3));
        store.ingest(&k, false, syn(400, false, T0 + 4)); // new connection, inbound this time
        let g2 = generation(&store, &k).unwrap();
        assert_eq!((g2.epoch, g2.counter), (1, g1.counter + 1));
        assert_eq!(snap(&store, &k, Direction::C2s).stored, 0);
        assert!(store.with_entry(&id(&k), |e| e.unwrap().client_is_local() == Some(false)));
    }

    #[test]
    fn a_pure_ack_for_an_unknown_flow_creates_nothing() {
        let mut store = FollowStore::new(1);
        store.ingest(&key(), true, seg(10, b"", T0));
        assert_eq!(store.flow_count(), 0);
        assert_eq!(store.reserved_bytes(), 0);
    }

    // ---------- D2: reordering, gaps, snaplen ----------

    #[test]
    fn a_hole_becomes_an_exact_gap_after_2000_ms_of_capture_time_only() {
        let mut store = FollowStore::new(1);
        let k = key();
        open(&mut store, &k);
        store.ingest(&k, true, seg(C0, b"a\n", T0 + 100));
        store.ingest(&k, true, seg(C0 + 12, b"b\nok\n", T0 + 100));
        store.tick(T0 + 100 + REORDER_MS - 1);
        assert!(snap(&store, &k, Direction::C2s).gaps.is_empty());
        store.tick(T0 + 100 + REORDER_MS);
        assert_eq!(snap(&store, &k, Direction::C2s).gaps, vec![Gap { at: 2, missing: 10, reason: GapReason::Missing }]);
        store.ingest(&k, true, fin(C0 + 17, b"", T0 + 3_000));
        // The line after the gap is uncertain up to its LF; the next is not.
        assert_eq!(emitted(&store, &k, Direction::C2s), b"a\n*\nok\n");
    }

    #[test]
    fn gap_reason_follows_the_snaplen_attribution_window() {
        for (cut_at, want) in [
            (Some(T0 + 100), GapReason::SnaplenLikely),
            (Some(T0 + 2_100 - CUT_ATTRIBUTION_WINDOW_MS - 1), GapReason::Missing),
            (None, GapReason::Missing),
        ] {
            let mut store = FollowStore::new(1);
            let k = key();
            open(&mut store, &k);
            if let Some(at) = cut_at {
                store.note_frame_cut_at_snaplen(at);
            }
            store.ingest(&k, true, seg(C0, b"a\n", T0 + 100));
            store.ingest(&k, true, seg(C0 + 5, b"b\n", T0 + 100));
            store.tick(T0 + 2_100);
            assert_eq!(snap(&store, &k, Direction::C2s).gaps[0].reason, want, "cut at {cut_at:?}");
        }
    }

    #[test]
    fn data_beyond_the_64k_reorder_window_forces_exact_gaps() {
        let mut store = FollowStore::new(1);
        let k = key();
        open(&mut store, &k);
        store.ingest(&k, true, seg(C0, b"a\n", T0));
        store.ingest(&k, true, seg(C0 + 12, b"held\n", T0)); // hole of 10
        store.ingest(&k, true, seg(C0 + 2 + REORDER_BYTES + 100, b"far\n", T0));
        let s = snap(&store, &k, Direction::C2s);
        assert_eq!(
            s.gaps,
            vec![
                Gap { at: 2, missing: 10, reason: GapReason::Missing },
                Gap { at: 7, missing: REORDER_BYTES + 100 - 15, reason: GapReason::Missing },
            ]
        );
        assert_eq!(s.stored, 11);
    }

    // ---------- D2: caps ----------

    #[test]
    fn the_direction_cap_is_256k_exactly() {
        let mut store = FollowStore::new(1);
        let k = key();
        open(&mut store, &k);
        let block = vec![b'x'; 16 * 1024];
        let mut seq = C0;
        for _ in 0..16 {
            store.ingest(&k, true, seg(seq, &block, T0));
            seq += block.len() as u32;
        }
        let s = snap(&store, &k, Direction::C2s);
        assert_eq!((s.stored, s.stopped), (MAX_DIRECTION_BYTES, None));
        store.ingest(&k, true, seg(seq, b"y", T0));
        store.ingest(&k, true, seg(seq + 1, b"more", T0));
        let s = snap(&store, &k, Direction::C2s);
        assert_eq!((s.stored, s.stopped, s.seen), (MAX_DIRECTION_BYTES, Some(StopReason::StoreCap), 256 * 1024 + 5));
    }

    #[test]
    fn the_gap_cap_stops_the_direction() {
        let mut store = FollowStore::new(1);
        let k = key();
        open(&mut store, &k);
        let mut seq = C0;
        // Iteration i needs gap number i: the cap admits 1 024, not 1 025.
        for i in 0..=MAX_GAPS_PER_DIRECTION + 1 {
            store.ingest(&k, true, seg(seq, b"z", T0));
            seq = seq.wrapping_add(1 + REORDER_BYTES + 1);
            let s = snap(&store, &k, Direction::C2s);
            let want = if i > MAX_GAPS_PER_DIRECTION { Some(StopReason::GapLimit) } else { None };
            assert_eq!(s.stopped, want, "iteration {i}");
        }
        assert_eq!(snap(&store, &k, Direction::C2s).gaps.len(), MAX_GAPS_PER_DIRECTION);
    }

    #[test]
    fn the_turn_cap_stops_both_directions() {
        let mut store = FollowStore::new(1);
        let k = key();
        open(&mut store, &k);
        for i in 0..MAX_TURNS_PER_FLOW as u32 / 2 {
            store.ingest(&k, true, seg(C0 + i, b"c", T0));
            store.ingest(&k, false, seg(S0 + i, b"s", T0));
        }
        assert_eq!(snap(&store, &k, Direction::C2s).stopped, None);
        let n = MAX_TURNS_PER_FLOW as u32 / 2;
        store.ingest(&k, true, seg(C0 + n, b"c", T0));
        for dir in [Direction::C2s, Direction::S2c] {
            let s = snap(&store, &k, dir);
            assert_eq!((s.stopped, s.stored), (Some(StopReason::TurnLimit), n), "{dir:?}");
        }
        assert_eq!(store.with_entry(&id(&k), |e| e.unwrap().turns().len()), MAX_TURNS_PER_FLOW);
    }

    #[test]
    fn the_redaction_range_cap_stops_before_an_unmaskable_value() {
        let mut store = FollowStore::new(1);
        let k = key();
        let (cseq, _) = open_cleartext(&mut store, &k);
        let line = b"Authorization: x\r\nA: b\r\n";
        let mut body = Vec::new();
        for _ in 0..=MAX_RANGES_PER_DIRECTION {
            body.extend_from_slice(line);
        }
        store.ingest(&k, true, fin(cseq, &body, T0 + 5_000));
        let s = snap(&store, &k, Direction::C2s);
        assert_eq!(s.stopped, Some(StopReason::RedactionLimit));
        assert_eq!(s.ranges.len(), MAX_RANGES_PER_DIRECTION);
        // Stored up to, not including, the line whose value could not be masked.
        let expect_len = 16 + MAX_RANGES_PER_DIRECTION * line.len();
        assert_eq!(s.stored as usize, expect_len);
        let out = emitted(&store, &k, Direction::C2s);
        assert_eq!(out.len(), expect_len);
        assert!(!out.windows(3).any(|w| w == b": x"), "a value escaped masking");
    }

    #[test]
    fn the_flow_cap_evicts_closed_first_then_oldest_activity() {
        let mut store = FollowStore::new(1);
        for n in 0..MAX_FLOWS as u16 {
            store.ingest(&key_n(n), true, seg(10, b"x", T0 + u64::from(n)));
        }
        assert_eq!(store.flow_count(), MAX_FLOWS);
        store.ingest(&key_n(100), true, rst(11, T0 + 999));
        store.ingest(&key_n(500), true, seg(10, b"x", T0 + 1_000));
        assert_eq!(store.flow_count(), MAX_FLOWS);
        assert!(generation(&store, &key_n(100)).is_none(), "the closed flow goes first");
        assert!(generation(&store, &key_n(0)).is_some());
        store.ingest(&key_n(501), true, seg(10, b"x", T0 + 1_001));
        assert!(generation(&store, &key_n(0)).is_none(), "then the least recently active");
        assert!(generation(&store, &key_n(1)).is_some());
    }

    #[test]
    fn pressure_eviction_ties_break_on_insertion_order() {
        let mut store = FollowStore::new(1);
        for n in 0..MAX_FLOWS as u16 {
            store.ingest(&key_n(n), true, seg(10, b"x", T0));
        }
        store.ingest(&key_n(600), true, seg(10, b"x", T0));
        assert!(generation(&store, &key_n(0)).is_none());
        assert!(generation(&store, &key_n(1)).is_some());
    }

    #[test]
    fn the_global_cap_binds_and_counts_reserved_capacity() {
        let mut store = FollowStore::new(1);
        let block = vec![b'x'; 16 * 1024];
        for n in 0..80u16 {
            let k = key_n(n);
            open(&mut store, &k);
            let mut seq = C0;
            for _ in 0..16 {
                store.ingest(&k, true, seg(seq, &block, T0 + u64::from(n)));
                seq += block.len() as u32;
                assert!(store.reserved_bytes() <= MAX_TOTAL_BYTES);
            }
            if n == 3 {
                store.ingest(&k, true, rst(seq, T0 + u64::from(n)));
            }
        }
        assert!(store.reserved_bytes() > MAX_TOTAL_BYTES - 512 * 1024);
        assert!(generation(&store, &key_n(3)).is_none(), "closed flow evicted first");
        assert!(generation(&store, &key_n(79)).is_some());
        assert_eq!(snap(&store, &key_n(79), Direction::C2s).stored, MAX_DIRECTION_BYTES);
    }

    #[test]
    fn drop_flow_and_reset_release_everything_and_keep_generations_monotonic() {
        let mut store = FollowStore::new(9);
        let k = key();
        open(&mut store, &k);
        store.ingest(&k, true, seg(C0, b"abc", T0));
        let maps_only = {
            let mut probe = FollowStore::new(9);
            probe.ingest(&k, true, seg(C0, b"abc", T0));
            probe.drop_flow(&k);
            probe.reserved_bytes()
        };
        store.drop_flow(&k);
        assert!(generation(&store, &k).is_none());
        assert_eq!(store.reserved_bytes(), maps_only);
        open(&mut store, &k);
        let before = generation(&store, &k).unwrap().counter;
        store.reset();
        assert_eq!(store.flow_count(), 0);
        assert_eq!(store.reserved_bytes(), maps_only);
        open(&mut store, &k);
        assert_eq!(generation(&store, &k), Some(Generation { epoch: 9, counter: before + 1 }));
    }

    // ---------- D3: TLS classification ----------

    #[test]
    fn a_client_hello_with_or_without_sni_or_a_server_hello_is_tls() {
        for first in [client_hello(true), client_hello(false), {
            let mut h = client_hello(false);
            h[5] = 0x02;
            h
        }] {
            let mut store = FollowStore::new(1);
            let k = key();
            open(&mut store, &k);
            store.ingest(&k, true, seg(C0, &first, T0));
            store.ingest(&k, false, seg(S0, b"cleartext banner\n", T0));
            for dir in [Direction::C2s, Direction::S2c] {
                let s = snap(&store, &k, dir);
                assert_eq!((s.class, s.tls_from, s.stored, s.emittable), (Classification::Tls, None, 0, 0), "{dir:?}");
            }
            store.ingest(&k, true, seg(C0 + first.len() as u32, b"more", T0));
            assert_eq!(snap(&store, &k, Direction::C2s).seen, first.len() as u64 + 4);
            assert_eq!(snap(&store, &k, Direction::C2s).stored, 0);
        }
    }

    #[test]
    fn two_chained_records_are_tls_including_after_a_midrecord_start() {
        for prefix in [&b""[..], b"\x00\x11garbage from the middle of a record"] {
            let mut store = FollowStore::new(1);
            let k = key();
            let mut bytes = prefix.to_vec();
            bytes.extend(tls_record(0x17, 300, 0x5A));
            bytes.extend(tls_record(0x17, 20, 0x5B));
            store.ingest(&k, true, seg(10, &bytes, T0));
            assert_eq!(snap(&store, &k, Direction::C2s).class, Classification::Tls);
        }
    }

    #[test]
    fn a_split_record_header_is_classified_and_never_emitted() {
        let mut bytes = tls_record(0x17, 40, 0x41);
        bytes.extend(tls_record(0x17, 8, 0x42));
        for split in 1..bytes.len() {
            let mut store = FollowStore::new(1);
            let k = key();
            open(&mut store, &k);
            store.ingest(&k, true, seg(C0, &bytes[..split], T0));
            assert!(emitted(&store, &k, Direction::C2s).is_empty(), "split {split}");
            store.ingest(&k, true, seg(C0 + split as u32, &bytes[split..], T0));
            assert_eq!(snap(&store, &k, Direction::C2s).class, Classification::Tls, "split {split}");
        }
    }

    #[test]
    fn record_length_18432_is_valid_and_18433_is_not() {
        for (len, want) in [(18_432, Classification::Tls), (18_433, Classification::Cleartext)] {
            let mut store = FollowStore::new(1);
            let k = key();
            open(&mut store, &k);
            let mut bytes = tls_record(0x17, len, 0x20);
            bytes.extend(tls_record(0x17, 4, 0x20));
            store.ingest(&k, true, fin(C0, &bytes, T0));
            assert_eq!(snap(&store, &k, Direction::C2s).class, want, "len {len}");
        }
    }

    #[test]
    fn candidates_inside_20k_classify_the_flow_and_later_ones_are_an_upgrade() {
        for (start, want_from) in [(TLS_CANDIDATE_BYTES - 1, None), (TLS_CANDIDATE_BYTES, Some(TLS_CANDIDATE_BYTES))] {
            let mut store = FollowStore::new(1);
            let k = key();
            open(&mut store, &k);
            let mut bytes = vec![b'a'; start as usize];
            bytes.extend(tls_record(0x17, 100, 0x30));
            bytes.extend(tls_record(0x17, 4, 0x30));
            store.ingest(&k, true, seg(C0, &bytes, T0));
            // Past the candidate window the direction stays pending until it
            // resolves; the offsets it held back are then checked as upgrades.
            store.tick(T0 + CLASSIFY_MS);
            let s = snap(&store, &k, Direction::C2s);
            assert_eq!((s.class, s.tls_from), (Classification::Tls, want_from), "start {start}");
        }
    }

    #[test]
    fn pending_ends_at_40k_at_2000_ms_or_at_close() {
        let mut store = FollowStore::new(1);
        let k = key();
        open(&mut store, &k);
        store.ingest(&k, true, seg(C0, &vec![b'a'; TLS_LOOKAHEAD_BYTES as usize - 1], T0));
        assert_eq!(snap(&store, &k, Direction::C2s).class, Classification::Pending);
        store.ingest(&k, true, seg(C0 + TLS_LOOKAHEAD_BYTES - 1, b"a", T0));
        assert_eq!(snap(&store, &k, Direction::C2s).class, Classification::Cleartext);

        let mut store = FollowStore::new(1);
        open(&mut store, &k);
        store.ingest(&k, true, seg(C0, b"hello\n", T0 + 5));
        store.tick(T0 + 5 + CLASSIFY_MS - 1);
        assert_eq!(snap(&store, &k, Direction::C2s).class, Classification::Pending);
        assert!(emitted(&store, &k, Direction::C2s).is_empty());
        store.tick(T0 + 5 + CLASSIFY_MS);
        assert_eq!(snap(&store, &k, Direction::C2s).class, Classification::Cleartext);
        assert_eq!(emitted(&store, &k, Direction::C2s), b"hello\n");

        let mut store = FollowStore::new(1);
        open(&mut store, &k);
        store.ingest(&k, true, fin(C0, b"bye\n", T0));
        assert_eq!(snap(&store, &k, Direction::C2s).class, Classification::Cleartext);
    }

    #[test]
    fn an_upgrade_is_withheld_while_split_then_drops_the_suffix_and_stops_the_flow() {
        let prefix = b"STARTTLS\r\n";
        let mut tls = client_hello(true);
        tls.extend(tls_record(0x17, 10, 0x77));
        for split in 1..=6 {
            let mut store = FollowStore::new(1);
            let k = key();
            let (cseq, sseq) = open_cleartext(&mut store, &k);
            store.ingest(&k, false, seg(sseq, b"220 ready\r\n", T0 + 3_000));
            store.ingest(&k, true, seg(cseq, prefix, T0 + 3_000));
            let k_at = 16 + prefix.len() as u32;
            store.ingest(&k, true, seg(cseq + prefix.len() as u32, &tls[..split], T0 + 3_000));
            let out = emitted(&store, &k, Direction::C2s);
            assert!(out.len() as u32 <= k_at, "split {split}: suspect bytes emitted");
            let at = cseq + prefix.len() as u32 + split as u32;
            store.ingest(&k, true, seg(at, &tls[split..], T0 + 3_000));
            let s = snap(&store, &k, Direction::C2s);
            assert_eq!((s.class, s.tls_from, s.stored), (Classification::Tls, Some(k_at), k_at), "split {split}");
            let mut want = b"GET / HTTP/1.1\r\n".to_vec();
            want.extend_from_slice(prefix);
            assert_eq!(emitted(&store, &k, Direction::C2s), want);
            let other = snap(&store, &k, Direction::S2c);
            assert_eq!((other.class, other.tls_from), (Classification::Tls, Some(other.stored)));
            store.ingest(&k, false, seg(sseq + 11, b"ciphertext", T0 + 3_000));
            assert_eq!(snap(&store, &k, Direction::S2c).stored, other.stored);
        }
    }

    #[test]
    fn a_refuted_or_timed_out_suspicion_releases_the_bytes() {
        let mut store = FollowStore::new(1);
        let k = key();
        let (cseq, _) = open_cleartext(&mut store, &k);
        // Valid-looking header, but what follows its claimed length is text.
        let looks = b"\x16\x03\x01\x00\x05hello world\n";
        store.ingest(&k, true, seg(cseq, looks, T0 + 3_000));
        let mut want = b"GET / HTTP/1.1\r\n".to_vec();
        want.extend_from_slice(looks);
        assert_eq!(emitted(&store, &k, Direction::C2s), want);

        let mut store = FollowStore::new(1);
        let (cseq, _) = open_cleartext(&mut store, &k);
        store.ingest(&k, true, seg(cseq, b"\x17\x03\x03\x00\x40abc\n", T0 + 3_000));
        assert_eq!(emitted(&store, &k, Direction::C2s).len(), 16);
        store.tick(T0 + 3_000 + CLASSIFY_MS);
        assert_eq!(emitted(&store, &k, Direction::C2s).len(), 16 + 9);
    }

    #[test]
    fn a_trailing_partial_header_is_held_back_until_refuted() {
        let mut store = FollowStore::new(1);
        let k = key();
        let (cseq, _) = open_cleartext(&mut store, &k);
        store.ingest(&k, true, seg(cseq, b"ok\n\x16\x03", T0 + 3_000));
        assert_eq!(emitted(&store, &k, Direction::C2s).len(), 16 + 3);
        store.ingest(&k, true, seg(cseq + 5, b"\x09", T0 + 3_000)); // version 0x0309: refuted
        assert_eq!(emitted(&store, &k, Direction::C2s).len(), 16 + 6);
    }

    #[test]
    fn cleartext_that_never_looks_like_tls_stays_cleartext() {
        let mut store = FollowStore::new(1);
        let k = key();
        open(&mut store, &k);
        let text = b"SSH-2.0-OpenSSH_9.6\r\n".repeat(3_000);
        store.ingest(&k, true, seg(C0, &text, T0));
        let s = snap(&store, &k, Direction::C2s);
        assert_eq!((s.class, s.emittable), (Classification::Cleartext, text.len() as u32));
    }

    // ---------- D7: credential scanner ----------

    const AUTH: &[u8] = b"Authorization: Bearer s3cr3t-token\r\nHost: a\r\n\r\n";

    #[test]
    fn a_credential_header_split_at_every_byte_never_shows_its_value() {
        for split in 1..AUTH.len() {
            let mut store = FollowStore::new(1);
            let k = key();
            let (cseq, _) = open_cleartext(&mut store, &k);
            let mut stream = b"GET / HTTP/1.1\r\n".to_vec();
            stream.extend_from_slice(AUTH);
            store.ingest(&k, true, seg(cseq, &AUTH[..split], T0 + 3_000));
            assert_secret_masked(&emitted(&store, &k, Direction::C2s), &stream, b"Bearer s3cr3t-token");
            store.ingest(&k, true, fin(cseq + split as u32, &AUTH[split..], T0 + 3_000));
            let out = emitted(&store, &k, Direction::C2s);
            assert_eq!(out.len(), stream.len(), "split {split}");
            assert_secret_masked(&out, &stream, b"Bearer s3cr3t-token");
            assert!(out.ends_with(b"\r\nHost: a\r\n\r\n"));
        }
    }

    #[test]
    fn a_page_starting_inside_a_value_is_masked() {
        let mut store = FollowStore::new(1);
        let k = key();
        let (cseq, _) = open_cleartext(&mut store, &k);
        store.ingest(&k, true, fin(cseq, AUTH, T0 + 3_000));
        let start = 16 + "Authorization: Bearer s3".len() as u32;
        store.with_entry(&id(&k), |e| {
            let mut out = [0u8; 6];
            assert_eq!(e.unwrap().copy_masked(Direction::C2s, start, start + 6, &mut out), 6);
            assert_eq!(&out, b"******");
        });
    }

    #[test]
    fn a_bearer_value_under_an_unlisted_name_is_masked_and_others_are_not() {
        let mut store = FollowStore::new(1);
        let k = key();
        let (cseq, _) = open_cleartext(&mut store, &k);
        store.ingest(&k, true, fin(cseq, b"X-Thing: bearer abc\r\nX-Other: plain\r\ncookie: c=1\r\n", T0 + 3_000));
        let out = emitted(&store, &k, Direction::C2s);
        assert_eq!(&out[16..], b"X-Thing: **********\r\nX-Other: plain\r\ncookie: ***\r\n");
        assert!(snap(&store, &k, Direction::C2s).ranges.iter().all(|r| r.reason == MaskReason::Credential));
    }

    #[test]
    fn an_empty_header_folded_onto_a_bearer_continuation_is_masked_across_fetches() {
        let mut store = FollowStore::new(1);
        let k = key();
        let (cseq, _) = open_cleartext(&mut store, &k);
        let first = b"X-Custom-Auth:\r\n";
        store.ingest(&k, true, seg(cseq, first, T0 + 3_000));
        let mid = emitted(&store, &k, Direction::C2s);
        assert!(mid.len() <= 16 + "X-Custom-Auth:".len(), "the value is withheld until the next line starts");
        store.ingest(&k, true, seg(cseq + first.len() as u32, b" Bearer secret\r\n", T0 + 3_000));
        store.ingest(&k, true, fin(cseq + first.len() as u32 + 16, b"Host: a\r\n", T0 + 3_000));
        let out = emitted(&store, &k, Direction::C2s);
        assert_eq!(&out[16..], b"X-Custom-Auth:\r\n**************\r\nHost: a\r\n");
    }

    #[test]
    fn a_continuation_masks_the_whole_logical_value_whatever_the_name() {
        let mut store = FollowStore::new(1);
        let k = key();
        let (cseq, _) = open_cleartext(&mut store, &k);
        store.ingest(&k, true, fin(cseq, b"X-Note: abc\r\n\tdef\r\n ghi\r\nok: 1\r\n", T0 + 3_000));
        assert_eq!(&emitted(&store, &k, Direction::C2s)[16..], b"X-Note: ***\r\n****\r\n****\r\nok: 1\r\n");
    }

    #[test]
    fn lines_touching_a_gap_are_masked_uncertain() {
        // (stream before the hole, hole size, stream after, expected output)
        type Case = (&'static [u8], u32, &'static [u8], &'static [u8]);
        let cases: [Case; 3] = [
            // An uncertain mask runs to the LF, CR included; a value mask stops at CR.
            (b"Autho", 4, b"on: Bearer x\r\nok\r\n", b"******************\nok\r\n"),
            (b"Authorization: Bea", 3, b" x\r\nok\r\n", b"*********************\nok\r\n"),
            (b"X-A: v\r\n", 5, b" Bearer x\r\nok\r\n", b"X-A: *\r\n**********\nok\r\n"),
        ];
        for (before, hole, after, want) in cases {
            let mut store = FollowStore::new(1);
            let k = key();
            let (cseq, _) = open_cleartext(&mut store, &k);
            store.ingest(&k, true, seg(cseq, before, T0 + 3_000));
            let after_seq = cseq + before.len() as u32 + hole;
            store.ingest(&k, true, fin(after_seq, after, T0 + 3_000));
            store.tick(T0 + 3_000 + REORDER_MS);
            let out = emitted(&store, &k, Direction::C2s);
            assert_eq!(&out[16..], want, "before {:?}", String::from_utf8_lossy(before));
            assert!(snap(&store, &k, Direction::C2s).ranges.iter().all(|r| r.reason == MaskReason::Uncertain));
        }
    }

    #[test]
    fn an_uncaptured_start_at_any_offset_never_shows_the_secret() {
        let stream = b"Authorization: Bearer s3cr3t\r\nHost: a\r\n";
        let secret = b"s3cr3t";
        let at = stream.windows(6).position(|w| w == secret).unwrap();
        for start in 0..stream.len() {
            let mut store = FollowStore::new(1);
            let k = key();
            store.ingest(&k, true, fin(500, &stream[start..], T0));
            let out = emitted(&store, &k, Direction::C2s);
            assert_eq!(out.len(), stream.len() - start);
            for (i, &b) in out.iter().enumerate() {
                let orig = start + i;
                if orig >= at && orig < at + secret.len() {
                    assert_eq!(b, b'*', "start {start}: secret byte {orig} shown");
                }
            }
        }
    }

    #[test]
    fn uncertainty_carries_through_folded_continuations() {
        let mut store = FollowStore::new(1);
        let k = key();
        store.ingest(&k, true, fin(500, b"abc\r\n secret\r\n\tmore\r\nok\r\n", T0));
        assert_eq!(emitted(&store, &k, Direction::C2s), b"****\n********\n******\nok\r\n");
    }

    #[test]
    fn a_json_body_stays_visible_and_a_header_like_body_line_is_masked() {
        let mut store = FollowStore::new(1);
        let k = key();
        let (cseq, _) = open_cleartext(&mut store, &k);
        store.ingest(&k, true, fin(cseq, b"{\"password\": \"hunter2\"}\nCookie: a=b\n", T0 + 3_000));
        assert_eq!(&emitted(&store, &k, Direction::C2s)[16..], b"{\"password\": \"hunter2\"}\nCookie: ***\n");
    }

    #[test]
    fn a_candidate_line_over_16k_is_masked_to_its_end_and_16k_exactly_is_decided() {
        let mut store = FollowStore::new(1);
        let k = key();
        let (cseq, _) = open_cleartext(&mut store, &k);
        let mut line = b"X-Long: ".to_vec();
        line.resize(MAX_LINE_BYTES as usize, b'v');
        line.extend_from_slice(b"\nok\n");
        store.ingest(&k, true, seg(cseq, &line, T0 + 3_000));
        store.ingest(&k, true, fin(cseq + line.len() as u32, b"", T0 + 3_000));
        assert_eq!(&emitted(&store, &k, Direction::C2s)[16..], &line[..], "exactly 16 KiB is an ordinary line");

        let mut store = FollowStore::new(1);
        let (cseq, _) = open_cleartext(&mut store, &k);
        let mut long = b"X-Long: ".to_vec();
        long.resize(MAX_LINE_BYTES as usize + 10, b'v');
        store.ingest(&k, true, seg(cseq, &long, T0 + 3_000));
        let out = emitted(&store, &k, Direction::C2s);
        assert_eq!(out.len(), 16 + long.len());
        assert!(out[16..].iter().all(|&b| b == b'*'));
        store.ingest(&k, true, fin(cseq + long.len() as u32, b"vv\nok\n", T0 + 3_000));
        assert!(emitted(&store, &k, Direction::C2s).ends_with(b"**\nok\n"));
    }

    #[test]
    fn an_uncertain_mask_without_lf_ends_after_16k() {
        let mut store = FollowStore::new(1);
        let k = key();
        let body = vec![b'b'; MAX_LINE_BYTES as usize + 100];
        store.ingest(&k, true, fin(500, &body, T0));
        let out = emitted(&store, &k, Direction::C2s);
        assert!(out[..MAX_LINE_BYTES as usize].iter().all(|&b| b == b'*'));
        assert!(out[MAX_LINE_BYTES as usize..].iter().all(|&b| b == b'b'));
        assert_eq!(
            snap(&store, &k, Direction::C2s).ranges,
            vec![MaskRange { start: 0, len: MAX_LINE_BYTES, reason: MaskReason::Uncertain }],
            "adjacent masked bytes coalesce into one range"
        );
    }

    // ---------- D7a: zeroization and redacting Debug ----------

    fn fill_two_chunks(store: &mut FollowStore, k: &FlowKey) {
        open(store, k);
        store.ingest(k, true, seg(C0, &vec![b'q'; CHUNK_BYTES + 100], T0));
    }

    fn released_all_zero() -> usize {
        let r = release_hook::take();
        assert!(r.iter().all(|&zero| zero), "a buffer was released without zeroizing: {r:?}");
        r.len()
    }

    #[test]
    fn every_release_path_zeroizes_its_buffers() {
        let k = key();
        let _ = release_hook::take();

        let mut store = FollowStore::new(1);
        fill_two_chunks(&mut store, &k);
        store.drop_flow(&k);
        assert_eq!(released_all_zero(), 2, "drop_flow");

        fill_two_chunks(&mut store, &k);
        store.reset();
        assert_eq!(released_all_zero(), 2, "reset");

        fill_two_chunks(&mut store, &k);
        store.ingest(&k, true, seg(C0 + CHUNK_BYTES as u32 + 200, b"held", T0)); // reorder buffer
        drop(store);
        assert_eq!(released_all_zero(), 3, "store drop, including the reorder buffer");

        let mut store = FollowStore::new(1);
        open(&mut store, &k);
        store.ingest(&k, true, seg(C0, &client_hello(true), T0));
        assert_eq!(released_all_zero(), 1, "initial TLS");

        let mut store = FollowStore::new(1);
        let (cseq, _) = open_cleartext(&mut store, &k);
        let mut tls = client_hello(false);
        tls.extend(tls_record(0x17, 4, 1));
        // The switch point lands 10 bytes before a chunk boundary, so the TLS
        // bytes fill the rest of chunk 0 and spill into a chunk of their own.
        let lead = CHUNK_BYTES - 16 - 10;
        store.ingest(&k, true, seg(cseq, &vec![b'p'; lead], T0 + 3_000));
        store.ingest(&k, true, seg(cseq + lead as u32, &tls, T0 + 3_000));
        assert_eq!(released_all_zero(), 1, "upgrade drops the chunk past the switch point");
        assert!(store.stored_tail_is_zero(&k, Direction::C2s), "the partly kept chunk is zeroed past the end");

        let mut store = FollowStore::new(1);
        for n in 0..=MAX_FLOWS as u16 {
            store.ingest(&key_n(n), true, seg(10, b"x", T0));
        }
        assert_eq!(released_all_zero(), 1, "capacity eviction");
    }

    #[test]
    fn debug_output_never_contains_payload() {
        let mut store = FollowStore::new(1);
        let k = key();
        open(&mut store, &k);
        store.ingest(&k, true, fin(C0, b"password=supersecret\n", T0));
        let all = format!("{store:?}");
        assert!(!all.contains("supersecret"), "{all}");
        store.with_entry(&id(&k), |e| {
            let one = format!("{:?}", e.unwrap());
            assert!(!one.contains("supersecret"), "{one}");
        });
    }

    #[test]
    fn copy_masked_refuses_bytes_past_the_emission_horizon() {
        let mut store = FollowStore::new(1);
        let k = key();
        open(&mut store, &k);
        store.ingest(&k, true, seg(C0, b"pending bytes", T0));
        store.with_entry(&id(&k), |e| {
            let mut out = [0u8; 64];
            assert_eq!(e.unwrap().copy_masked(Direction::C2s, 0, 13, &mut out), 0);
        });
    }

    // ---------- review fixes (PR #327) ----------

    #[test]
    fn a_fin_before_held_bytes_ends_the_stream_at_the_fin() {
        let mut store = FollowStore::new(1);
        let k = key();
        open(&mut store, &k);
        store.ingest(&k, true, seg(C0 + 100, &[b'x'; 100], T0));
        store.ingest(&k, true, fin(C0 + 50, b"", T0));
        store.tick(T0 + REORDER_MS);
        let s = snap(&store, &k, Direction::C2s);
        assert!(s.closed);
        assert_eq!(s.gaps, vec![Gap { at: 0, missing: 50, reason: GapReason::Missing }], "no gap past the FIN");
        assert_eq!(s.stored, 0, "bytes after the FIN are not part of the stream");
    }

    #[test]
    fn a_tick_that_drains_held_bytes_may_evict_other_flows() {
        let mut store = FollowStore::new(1);
        let target = key_n(1_000);
        open(&mut store, &target);
        store.ingest(&target, true, seg(C0, b"a", T0));
        store.ingest(&target, true, seg(C0 + 11, &[b'b'; 60_000], T0)); // a 10-byte hole
        // Closed fillers take the store to within one small flow of its cap.
        let block = vec![b'x'; 16 * 1024];
        for n in 0..60u16 {
            let k = key_n(n);
            for i in 0..16u32 {
                store.ingest(&k, true, seg(10 + i * block.len() as u32, &block, T0));
            }
            store.ingest(&k, true, rst(10 + 16 * block.len() as u32, T0));
        }
        let mut n = 60u16;
        while MAX_TOTAL_BYTES - store.reserved_bytes() >= 20_000 {
            store.ingest(&key_n(n), true, seg(10, b"x", T0));
            store.ingest(&key_n(n), true, rst(11, T0));
            n += 1;
        }
        let fillers = store.flow_count();
        // Draining 60 000 bytes needs more chunks than the headroom holds.
        store.tick(T0 + REORDER_MS);
        let s = snap(&store, &target, Direction::C2s);
        assert_eq!((s.stopped, s.stored), (None, 60_001));
        assert!(store.flow_count() < fillers, "a closed flow was evicted to make room");
    }

    #[test]
    fn a_header_pending_for_2000_ms_is_not_withheld_again_as_a_suspect() {
        let mut store = FollowStore::new(1);
        let k = key();
        open(&mut store, &k);
        // A valid header whose chained record never arrives.
        store.ingest(&k, true, seg(C0, b"\x17\x03\x03\x00\x40abc", T0));
        store.tick(T0 + CLASSIFY_MS);
        let s = snap(&store, &k, Direction::C2s);
        assert_eq!((s.class, s.emittable), (Classification::Cleartext, 8));
    }

    #[test]
    fn a_header_that_arrives_late_in_the_pending_window_gets_its_own_deadline() {
        let mut store = FollowStore::new(1);
        let k = key();
        open(&mut store, &k);
        store.ingest(&k, true, seg(C0, b"ab\r\n", T0));
        store.ingest(&k, true, seg(C0 + 4, b"\x17\x03\x03\x00\x05hello", T0 + 1_900));
        store.tick(T0 + CLASSIFY_MS);
        let s = snap(&store, &k, Direction::C2s);
        assert_eq!((s.class, s.emittable), (Classification::Cleartext, 4), "the late header is still suspect");
        store.ingest(&k, true, seg(C0 + 14, b"\x17\x03\x03\x00\x01x", T0 + 2_100));
        let s = snap(&store, &k, Direction::C2s);
        assert_eq!((s.class, s.tls_from), (Classification::Tls, Some(4)));
    }

    #[test]
    fn flow_churn_keeps_the_flow_index_charge_exact() {
        let mut store = FollowStore::new(1);
        for n in 0..MAX_FLOWS as u16 {
            store.ingest(&key_n(n), true, seg(10, b"x", T0));
        }
        let charged = store.reserved_bytes();
        for round in 0..600u16 {
            store.drop_flow(&key_n(round % MAX_FLOWS as u16));
            store.audit().expect("after drop_flow");
            store.ingest(&key_n(round % MAX_FLOWS as u16), true, seg(10, b"x", T0));
            store.audit().expect("after create");
        }
        assert_eq!(store.reserved_bytes(), charged);
        store.reset();
        store.audit().expect("after reset");
    }
}
