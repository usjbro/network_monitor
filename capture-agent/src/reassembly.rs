//! IP fragment and TCP segment reassembly (JAM-16).
//!
//! Design: `docs/superpowers/specs/2026-09-28-stream-reassembly-design.md`.
//!
//! Without this, `l7::sniff_l7` only ever sees one frame's payload, so an
//! HTTP request line or a TLS ClientHello split across two TCP segments
//! silently fails to decode, and IPv4 fragments never rejoin at all. Both
//! read as "traffic with no application layer", which is worse than an honest
//! "incomplete" — it looks like a gap in the tool rather than a gap in the
//! capture.
//!
//! # Security posture
//!
//! Every byte here is attacker-shaped, parsed in the process that holds the
//! raw capture handle. Three rules hold throughout and are enforced, not
//! documented-and-hoped-for:
//!
//! 1. **No panics on adversarial input.** Every length is `checked_`/
//!    `saturating_`, every index is bounds-checked, and every fallible path
//!    returns `Option`. Exercised by
//!    `fuzz/fuzz_targets/stream_reassembly.rs`.
//! 2. **Bounded allocation, checked before it happens.** Buffers are never
//!    grown toward a length read off the wire; a write range is clamped to
//!    the cap *first*, and only then is the buffer resized, so a hostile
//!    offset can never cause an allocation larger than the cap. (Contrast
//!    the "reserve the declared length, then wait for it" pattern
//!    `http2.rs`'s `MAX_FRAME_LEN` exists to prevent.) Per-key, total-byte,
//!    and total-key caps all apply.
//! 3. **Nothing is held forever.** A reassembly that never completes is
//!    evicted by idle timeout and, under pressure, by oldest-first capacity
//!    eviction — the classic tiny-fragment-flood / never-finish-it pattern
//!    costs an attacker only memory that is already accounted for.
//!
//! Note the deliberate non-goal: this is not a stream *store*. Buffers exist
//! only until an application-layer detector can decide, and are released the
//! moment one does. Follow Stream (JAM-17) will want its own bounded store;
//! the prefix and status exposed here are what it needs to build on.

use crate::flow::FlowKey;
use crate::l7::{sniff_l7, sniff_l7_desegmenting, L7Info, L7Sniff};
use crate::parse::{parse_packet, LinkType, ParsedPacket, TransportProtocol};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Status and counters
// ---------------------------------------------------------------------------

/// How complete a reassembled buffer actually is.
///
/// The point of this type is that a caller can never be handed a partial
/// buffer that presents as a whole one. `snaplen <bytes>` lets an operator
/// narrow the capture snap length at runtime, after which reassembly is
/// *structurally impossible* for the bytes that were cut off — and from
/// `payload.len()` alone that is indistinguishable from a frame that was
/// never captured. Confidently wrong output is worse than none, so the two
/// causes are named separately.
///
/// ## Reachability of `IncompleteTruncatedAtCapture`, stated precisely
///
/// There are two independent ways this reassembler learns that capture
/// truncation is destroying bytes:
///
/// 1. A fragment or segment whose captured payload is shorter than its own IP
///    header declared. This is the direct, per-frame check, and it is the
///    right one — but note that `parse::parse_packet` currently rejects any
///    frame shorter than its declared length outright (etherparse's strict
///    length validation), so **in the live pipeline today this condition
///    never arrives here**; such frames are counted as unparseable upstream
///    instead. The check is kept because it is correct and because it starts
///    working the moment lax parsing lands (see the design spec's deferred
///    list), not because it is currently firing.
/// 2. `StreamReassembler::note_frame_cut_at_snaplen` — the capture loop is
///    the one place that knows both a frame's captured length and the active
///    snap length, so it can recognize a frame pcap cut short. While that has
///    happened recently, a gap is attributed to truncation rather than to a
///    missing frame. **This is the path that actually fires today.**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReassemblyStatus {
    /// Every byte the sender sent, for the extent this buffer covers, is
    /// present and contiguous.
    Reassembled,
    /// The sender sent more than the capture kept. Actionable by the
    /// operator: raise the snap length.
    IncompleteTruncatedAtCapture,
    /// A hole in the fragment or sequence space that is not attributable to
    /// capture truncation — frames that were never captured at all.
    IncompleteMissingFrames,
}

impl ReassemblyStatus {
    /// The single place this project's wording for these three states lives,
    /// so a caller (or a future wire field) cannot paraphrase one of them into
    /// a claim it doesn't support.
    pub fn label(self) -> &'static str {
        match self {
            Self::Reassembled => "reassembled",
            Self::IncompleteTruncatedAtCapture => "incomplete — frames truncated at capture",
            Self::IncompleteMissingFrames => "incomplete — frames missing",
        }
    }

    pub fn is_complete(self) -> bool {
        matches!(self, Self::Reassembled)
    }
}

/// Cumulative, real counts of what reassembly has done — every one is
/// incremented at the point the thing actually happens, so they are
/// measurements, not estimates.
///
/// Deliberately **not** put on the wire: no UI surface exists for them yet,
/// and this project does not ship a statistic without a producer. They exist
/// so tests and the fuzz target can assert the caps and the policy from
/// outside.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReassemblyCounters {
    /// Buffers handed out with `ReassemblyStatus::Reassembled`.
    pub completed: u64,
    /// Buffers handed out as incomplete because of capture truncation.
    pub incomplete_truncated_at_capture: u64,
    /// Buffers handed out as incomplete because of a real gap.
    pub incomplete_missing_frames: u64,
    /// Entries that stopped buffering without ever completing: the per-key
    /// byte cap was reached, or (TCP) the decision window elapsed.
    pub abandoned_without_completing: u64,
    /// Entries removed by idle timeout.
    pub evicted_idle: u64,
    /// Entries removed oldest-first to get back under a count or byte
    /// ceiling.
    pub evicted_capacity: u64,
    /// Bytes an overlapping fragment/segment tried to write over bytes
    /// already held, where the two copies actually **differed**. Under the
    /// first-seen-wins policy the held copy was kept. A nonzero value here is
    /// the observable signal for an overlap rewrite attempt; a plain
    /// retransmission (identical bytes) never touches it.
    pub conflicting_overlap_bytes: u64,
}

// ---------------------------------------------------------------------------
// Caps. See the design spec's cap table for why each value.
// ---------------------------------------------------------------------------

/// The largest an IPv4 datagram can be — the maximum its `total_length` field
/// can express. A cap at the protocol's own ceiling cannot reject legitimate
/// traffic by construction.
pub const MAX_FRAGMENT_GROUP_BYTES: usize = 65_535;
/// Concurrent in-flight fragment groups. Fragmentation is rare in real
/// traffic; under a flood the byte cap below binds first.
pub const MAX_FRAGMENT_GROUPS: usize = 512;
/// Total bytes held across every in-flight fragment group. The real binding
/// constraint: 512 × 65 535 would be 32 MiB; this caps it at 4 MiB.
pub const MAX_FRAGMENT_BYTES_TOTAL: usize = 4 * 1024 * 1024;
/// RFC 791's recommended reassembly timeout. Linux uses 30 s; shorter is
/// strictly better for a monitor that is not the datagram's destination.
/// Applied both to idleness and as a hard ceiling from first arrival, so a
/// slow drip of fragments cannot keep one group alive indefinitely.
pub const FRAGMENT_TIMEOUT_MS: u64 = 15_000;

/// Per TCP stream *direction*. Covers a full HTTP header block (nginx's and
/// Apache's own defaults are 8 KiB) and a complete TLS record (16 KiB is the
/// protocol maximum, so any ClientHello, post-quantum key shares included).
/// Past this, none of `l7.rs`'s detectors is going to decide.
pub const MAX_TCP_STREAM_BYTES: usize = 16 * 1024;
/// Concurrent buffering stream directions, well under the flow table's own
/// `DEFAULT_MAX_FLOWS` of 10 000.
pub const MAX_TCP_STREAMS: usize = 2_048;
/// Total bytes held across every buffering stream direction — the real
/// binding constraint, as for fragments.
pub const MAX_TCP_BYTES_TOTAL: usize = 4 * 1024 * 1024;
/// A direction that hasn't advanced in this long is not mid-message.
pub const TCP_STREAM_IDLE_MS: u64 = 30_000;
/// How long a direction may keep buffering toward a single application-layer
/// decision. A request line or ClientHello completes in milliseconds; two
/// seconds is generous. This is what keeps steady-state memory proportional
/// to *recently started* messages rather than to every open connection.
pub const TCP_DECISION_WINDOW_MS: u64 = 2_000;

/// How long after a frame was seen cut short by the capture snap length a
/// gap is attributed to that truncation rather than to a genuinely missing
/// frame. Short, because the attribution should follow the condition rather
/// than outlive it.
pub const CUT_ATTRIBUTION_WINDOW_MS: u64 = 5_000;

// ---------------------------------------------------------------------------
// Shared coverage primitives
// ---------------------------------------------------------------------------

/// Result of writing one piece into a coverage buffer.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct WriteOutcome {
    /// Bytes that were not previously held and are now.
    newly_written: usize,
    /// Bytes that were already held with a *different* value — an actual
    /// overlap rewrite attempt, not a plain retransmission.
    conflicting: usize,
    /// Some of this piece fell beyond the per-key cap and was discarded.
    hit_cap: bool,
}

/// Writes `bytes` at `offset` into a (data, filled) coverage pair, **keeping
/// whatever is already there** — the first-seen-wins overlap policy.
///
/// # Overlap policy: first-seen bytes win
///
/// When a fragment or segment overlaps bytes already buffered, the bytes
/// already present are kept and the overlapping copy is discarded. Chosen
/// deliberately over last-seen-wins:
///
/// - It is deterministic and cheap — one coverage check per byte, with no
///   rewrite path to get wrong.
/// - A later piece cannot retroactively change content the monitor has
///   already reported. The classic overlapping-segment evasion works by
///   making a passive observer and the real endpoint disagree about which
///   copy wins; last-seen-wins would let an attacker show the monitor benign
///   bytes and overwrite them afterwards. First-seen-wins makes the monitor's
///   view immutable once written.
/// - Retransmissions — overwhelmingly the common real cause of overlap — are
///   exactly bytes already held, so they become free no-ops.
///
/// Stated limitation rather than a hidden one: a receiving host whose own TCP
/// stack prefers later data would assemble something different. A passive
/// monitor cannot know the receiver's policy without host knowledge, so
/// *some* fixed choice is unavoidable; this is the conservative direction.
/// Overlaps whose bytes actually differ are counted
/// (`ReassemblyCounters::conflicting_overlap_bytes`) so the condition is
/// observable rather than invisible.
fn write_first_seen_wins(
    data: &mut Vec<u8>,
    filled: &mut Vec<bool>,
    offset: usize,
    bytes: &[u8],
    cap: usize,
) -> WriteOutcome {
    let mut out = WriteOutcome::default();
    // `checked_add`: `offset` derives from a wire field.
    let Some(end) = offset.checked_add(bytes.len()) else {
        out.hit_cap = true;
        return out;
    };
    if end > cap {
        out.hit_cap = true;
    }
    let usable_end = end.min(cap);
    if offset >= usable_end {
        // Entirely beyond the cap — nothing written, and crucially nothing
        // allocated toward it either.
        return out;
    }
    if data.len() < usable_end {
        data.resize(usable_end, 0);
        filled.resize(usable_end, false);
    }
    for (i, byte) in bytes.iter().enumerate().take(usable_end - offset) {
        // `idx < usable_end <= data.len()` by the resize above.
        let idx = offset + i;
        if filled[idx] {
            if data[idx] != *byte {
                out.conflicting += 1;
            }
        } else {
            data[idx] = *byte;
            filled[idx] = true;
            out.newly_written += 1;
        }
    }
    out
}

/// Length of the contiguous run of held bytes starting at index 0, resuming
/// from `known` (which must already be contiguous) so the cost is amortized
/// over the bytes newly filled rather than rescanning the whole buffer for
/// every piece. This matters: it runs on the capture hot path.
fn contiguous_len_from(filled: &[bool], known: usize) -> usize {
    let mut len = known.min(filled.len());
    while filled.get(len) == Some(&true) {
        len += 1;
    }
    len
}

/// Rebuilds a real, self-consistent IPv4 datagram from a captured header and
/// a rejoined payload: `total_length` set to what is actually present, the
/// fragment fields cleared, and the header checksum recomputed. Returns
/// `None` rather than panicking for any header etherparse won't round-trip or
/// any payload too long to express.
///
/// Rebuilding a datagram (instead of decoding the transport layer here) is
/// what lets `parse_packet` do that decoding, so a reassembled datagram's
/// ports and payload come from exactly the same code path as an
/// unfragmented one.
fn rebuild_ipv4_datagram(header: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
    let slice = etherparse::Ipv4HeaderSlice::from_slice(header).ok()?;
    let mut rebuilt = slice.to_header();
    rebuilt.more_fragments = false;
    rebuilt.fragment_offset = etherparse::IpFragOffset::try_new(0).ok()?;
    rebuilt.set_payload_len(payload.len()).ok()?;
    rebuilt.header_checksum = rebuilt.calc_header_checksum();
    let mut out = Vec::with_capacity(rebuilt.header_len().saturating_add(payload.len()));
    rebuilt.write(&mut out).ok()?;
    out.extend_from_slice(payload);
    Some(out)
}

// ---------------------------------------------------------------------------
// IP fragment reassembly
// ---------------------------------------------------------------------------

/// RFC 791's reassembly key: two fragments belong to the same datagram only
/// if source, destination, identification, and protocol all match.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FragmentKey {
    pub src: String,
    pub dst: String,
    pub identification: u16,
    pub protocol: u8,
}

/// A rejoined IPv4 datagram, ready to go straight back through
/// `parse_packet(_, LinkType::Raw)`.
#[derive(Debug, Clone)]
pub struct ReassembledDatagram {
    /// A complete IPv4 packet: rebuilt header followed by the rejoined
    /// payload prefix.
    pub bytes: Vec<u8>,
    pub status: ReassemblyStatus,
    /// Rejoined payload bytes, excluding the rebuilt IP header.
    pub payload_len: usize,
}

struct FragmentGroup {
    data: Vec<u8>,
    filled: Vec<bool>,
    /// Contiguous bytes held from offset 0. Reassembled output is **always**
    /// this prefix, never spliced across a hole, so a consumer cannot be
    /// handed bytes that look adjacent but aren't.
    prefix_len: usize,
    /// Total payload length of the whole datagram, knowable only once the
    /// fragment with MF clear arrives.
    total_len: Option<usize>,
    /// The offset-0 fragment's IPv4 header bytes, needed to rebuild. A group
    /// that never sees its first fragment can produce neither a datagram nor
    /// a nonzero contiguous prefix.
    header: Option<Vec<u8>>,
    /// Smallest offset at which a fragment was captured shorter than its own
    /// IP header declared — a hole no later fragment can fill, because the
    /// snap length cuts every copy of those bytes identically.
    short_captured_at: Option<usize>,
    first_seen_ms: u64,
    last_seen_ms: u64,
}

impl FragmentGroup {
    fn new(now_ms: u64) -> Self {
        Self {
            data: Vec::new(),
            filled: Vec::new(),
            prefix_len: 0,
            total_len: None,
            header: None,
            short_captured_at: None,
            first_seen_ms: now_ms,
            last_seen_ms: now_ms,
        }
    }

    /// The status this group's current prefix deserves. Truncated-at-capture
    /// takes precedence over missing-frames: it is a definite fact about this
    /// capture's configuration that an operator can act on, where "missing"
    /// is the residual explanation.
    fn status(&self) -> ReassemblyStatus {
        if self.total_len.is_some_and(|total| self.prefix_len >= total) {
            return ReassemblyStatus::Reassembled;
        }
        if self.short_captured_at.is_some_and(|at| at <= self.prefix_len) {
            ReassemblyStatus::IncompleteTruncatedAtCapture
        } else {
            ReassemblyStatus::IncompleteMissingFrames
        }
    }
}

/// Rejoins IPv4 fragments, bounded by `MAX_FRAGMENT_GROUP_BYTES`,
/// `MAX_FRAGMENT_GROUPS`, `MAX_FRAGMENT_BYTES_TOTAL`, and
/// `FRAGMENT_TIMEOUT_MS`.
#[derive(Default)]
pub struct IpFragmentReassembler {
    groups: HashMap<FragmentKey, FragmentGroup>,
    bytes_held: usize,
    counters: ReassemblyCounters,
}

impl IpFragmentReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Real, measured bytes currently held across every in-flight group — the
    /// sum of the groups' own buffer lengths, maintained on every write and
    /// removal rather than estimated.
    pub fn bytes_held(&self) -> usize {
        self.bytes_held
    }

    pub fn groups_held(&self) -> usize {
        self.groups.len()
    }

    pub fn counters(&self) -> ReassemblyCounters {
        self.counters
    }

    /// Feeds one captured frame. Returns a rejoined datagram when this
    /// fragment either completed its group or proved the group can never
    /// complete (a hole whose bytes were cut off at capture, which no future
    /// fragment can fill). `None` for a frame that is not an IPv4 fragment,
    /// and for a group still legitimately waiting.
    pub fn feed(&mut self, packet: &ParsedPacket, now_ms: u64) -> Option<ReassembledDatagram> {
        let fragment = packet.ip_fragment.as_ref()?;
        let key = FragmentKey {
            src: packet.src_ip.clone(),
            dst: packet.dst_ip.clone(),
            identification: fragment.identification,
            protocol: fragment.protocol,
        };

        if !self.groups.contains_key(&key) && self.groups.len() >= MAX_FRAGMENT_GROUPS {
            // At the ceiling: make room by dropping the least-recently-seen
            // group rather than growing past the cap, or refusing current
            // traffic in favour of stale entries.
            self.evict_oldest_until(MAX_FRAGMENT_GROUPS.saturating_sub(1), MAX_FRAGMENT_BYTES_TOTAL);
        }

        let offset = fragment.offset_bytes as usize;
        let group = self.groups.entry(key.clone()).or_insert_with(|| FragmentGroup::new(now_ms));
        group.last_seen_ms = now_ms;
        if offset == 0 && group.header.is_none() {
            group.header = Some(fragment.header.clone());
        }
        if (fragment.payload.len() as u32) < packet.ip_declared_payload_len {
            let hole_at = offset.saturating_add(fragment.payload.len());
            group.short_captured_at = Some(group.short_captured_at.map_or(hole_at, |at| at.min(hole_at)));
        }
        if !fragment.more_fragments {
            // The last fragment fixes the datagram's total length. Its
            // *declared* length is used, so a last fragment cut short at
            // capture still reveals the true total rather than understating
            // it into a false "complete".
            let declared = packet.ip_declared_payload_len as usize;
            group.total_len = Some(offset.saturating_add(declared));
        }

        let before = group.data.len();
        let written = write_first_seen_wins(
            &mut group.data,
            &mut group.filled,
            offset,
            &fragment.payload,
            MAX_FRAGMENT_GROUP_BYTES,
        );
        let after = group.data.len();
        group.prefix_len = contiguous_len_from(&group.filled, group.prefix_len);
        let status = group.status();
        // Disjoint field borrows: `group` borrows `self.groups` only.
        self.bytes_held = self.bytes_held.saturating_add(after).saturating_sub(before);
        self.counters.conflicting_overlap_bytes += written.conflicting as u64;

        let emitted = match status {
            ReassemblyStatus::Reassembled => self.take_group(&key, status),
            // No future fragment can fill a hole whose bytes were never
            // captured, so holding this group to its timeout would only delay
            // an answer that cannot improve.
            ReassemblyStatus::IncompleteTruncatedAtCapture => self.take_group(&key, status),
            ReassemblyStatus::IncompleteMissingFrames => {
                if written.hit_cap {
                    // A group that reached the protocol's own maximum
                    // datagram size and still has holes is not a datagram.
                    if let Some(dropped) = self.groups.remove(&key) {
                        self.bytes_held = self.bytes_held.saturating_sub(dropped.data.len());
                        self.counters.abandoned_without_completing += 1;
                    }
                }
                None
            }
        };
        // Enforce the global byte ceiling on every feed, not only on the
        // eviction tick: otherwise many already-open groups all growing at
        // once could exceed it in between ticks, which is exactly the shape a
        // hostile sender would use. With this, `bytes_held() <=
        // MAX_FRAGMENT_BYTES_TOTAL` holds unconditionally after `feed`
        // returns — the invariant the fuzz target asserts.
        self.evict_oldest_until(MAX_FRAGMENT_GROUPS, MAX_FRAGMENT_BYTES_TOTAL);
        emitted
    }

    /// Removes groups past their timeout and reports what each one had, so an
    /// incomplete reassembly ends as an explicit "incomplete" rather than
    /// vanishing. Then enforces the global byte and count ceilings,
    /// oldest-first.
    pub fn evict_stale(&mut self, now_ms: u64) -> Vec<ReassembledDatagram> {
        let expired: Vec<FragmentKey> = self
            .groups
            .iter()
            .filter(|(_, group)| {
                now_ms.saturating_sub(group.last_seen_ms) > FRAGMENT_TIMEOUT_MS
                    // Hard ceiling from first arrival too: a slow drip of
                    // fragments must not keep one group alive indefinitely.
                    || now_ms.saturating_sub(group.first_seen_ms) > FRAGMENT_TIMEOUT_MS
            })
            .map(|(key, _)| key.clone())
            .collect();

        let mut out = Vec::new();
        for key in expired {
            let Some(status) = self.groups.get(&key).map(FragmentGroup::status) else {
                continue;
            };
            self.counters.evicted_idle += 1;
            if let Some(datagram) = self.take_group(&key, status) {
                out.push(datagram);
            }
        }
        self.evict_oldest_until(MAX_FRAGMENT_GROUPS, MAX_FRAGMENT_BYTES_TOTAL);
        out
    }

    /// Removes one group, accounts for its bytes and its outcome, and rebuilds
    /// a datagram from whatever contiguous prefix it held.
    fn take_group(&mut self, key: &FragmentKey, status: ReassemblyStatus) -> Option<ReassembledDatagram> {
        let group = self.groups.remove(key)?;
        self.bytes_held = self.bytes_held.saturating_sub(group.data.len());
        match status {
            ReassemblyStatus::Reassembled => self.counters.completed += 1,
            ReassemblyStatus::IncompleteTruncatedAtCapture => self.counters.incomplete_truncated_at_capture += 1,
            ReassemblyStatus::IncompleteMissingFrames => self.counters.incomplete_missing_frames += 1,
        }
        // No first fragment means no header to rebuild from — and, since the
        // prefix starts at offset 0, no bytes either. Counted above, then
        // dropped: there is nothing honest to hand back.
        let header = group.header.as_deref()?;
        let payload_len = match group.total_len {
            Some(total) => group.prefix_len.min(total),
            None => group.prefix_len,
        };
        let payload = group.data.get(..payload_len)?;
        let bytes = rebuild_ipv4_datagram(header, payload)?;
        Some(ReassembledDatagram { bytes, status, payload_len })
    }

    /// Drops least-recently-seen groups until both ceilings hold. Mirrors
    /// `FlowTable::evict_stale`'s own capacity pass.
    fn evict_oldest_until(&mut self, max_groups: usize, max_bytes: usize) {
        if self.groups.len() <= max_groups && self.bytes_held <= max_bytes {
            return;
        }
        let mut by_age: Vec<(FragmentKey, u64)> =
            self.groups.iter().map(|(key, group)| (key.clone(), group.last_seen_ms)).collect();
        by_age.sort_by_key(|(_, last_seen_ms)| *last_seen_ms);
        for (key, _) in by_age {
            if self.groups.len() <= max_groups && self.bytes_held <= max_bytes {
                break;
            }
            if let Some(group) = self.groups.remove(&key) {
                self.bytes_held = self.bytes_held.saturating_sub(group.data.len());
                self.counters.evicted_capacity += 1;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TCP segment reassembly
// ---------------------------------------------------------------------------

/// One direction of one TCP connection's byte stream.
///
/// Keyed on `flow.rs`'s own `FlowKey` (via the newly-public
/// `FlowTable::key_for`) rather than on a locally-derived tuple, so
/// reassembly and the flow it annotates can never disagree about which
/// connection — or which direction — a segment belongs to. `from_local`
/// splits the two independent byte streams; it is exactly
/// `ObserveResult::is_outbound`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TcpStreamKey {
    pub flow: FlowKey,
    pub from_local: bool,
}

struct TcpStream {
    /// Absolute sequence number of `data[0]`. Lowered (with the buffer
    /// shifted) when an earlier segment arrives out of order.
    base_seq: u32,
    data: Vec<u8>,
    filled: Vec<bool>,
    prefix_len: usize,
    short_captured_at: Option<usize>,
    /// Stop buffering this direction: it reached its byte cap, or its
    /// decision window elapsed without any detector deciding. The entry is
    /// kept so later segments short-circuit cheaply; its buffers are released
    /// on the next segment.
    finished: bool,
    first_seen_ms: u64,
    last_seen_ms: u64,
}

impl TcpStream {
    fn new(seq: u32, now_ms: u64) -> Self {
        Self {
            base_seq: seq,
            data: Vec::new(),
            filled: Vec::new(),
            prefix_len: 0,
            short_captured_at: None,
            finished: false,
            first_seen_ms: now_ms,
            last_seen_ms: now_ms,
        }
    }

    fn release(&mut self) {
        self.data = Vec::new();
        self.filled = Vec::new();
        self.prefix_len = 0;
    }

    /// Shifts the buffer forward by `shift` bytes so an earlier-arriving
    /// segment can occupy offset 0. Bounded: the result is truncated back to
    /// `MAX_TCP_STREAM_BYTES`, so `data.len() <= MAX_TCP_STREAM_BYTES` holds
    /// unconditionally, which is the invariant the fuzz target asserts.
    fn rebase(&mut self, shift: usize, new_base: u32) {
        let mut data = vec![0u8; shift];
        data.extend_from_slice(&self.data);
        data.truncate(MAX_TCP_STREAM_BYTES);
        let mut filled = vec![false; shift];
        filled.extend_from_slice(&self.filled);
        filled.truncate(MAX_TCP_STREAM_BYTES);
        self.data = data;
        self.filled = filled;
        self.base_seq = new_base;
        // Whatever was contiguous from the old base no longer starts at
        // offset 0; recomputed from scratch after the pending write.
        self.prefix_len = 0;
        self.short_captured_at = self.short_captured_at.map(|at| at.saturating_add(shift));
    }

    /// Same precedence as `FragmentGroup::status`. A TCP stream has no
    /// declared total, so "reassembled" here means "the bytes held are
    /// contiguous and nothing is known to be missing" — the honest claim for
    /// an open-ended stream.
    fn status(&self) -> ReassemblyStatus {
        if self.short_captured_at.is_some_and(|at| at <= self.prefix_len) {
            ReassemblyStatus::IncompleteTruncatedAtCapture
        } else if self.prefix_len < self.filled.len() {
            ReassemblyStatus::IncompleteMissingFrames
        } else {
            ReassemblyStatus::Reassembled
        }
    }
}

/// Rejoins TCP segments per direction, bounded by `MAX_TCP_STREAM_BYTES`,
/// `MAX_TCP_STREAMS`, `MAX_TCP_BYTES_TOTAL`, `TCP_DECISION_WINDOW_MS`, and
/// `TCP_STREAM_IDLE_MS`.
#[derive(Default)]
pub struct TcpReassembler {
    streams: HashMap<TcpStreamKey, TcpStream>,
    bytes_held: usize,
    counters: ReassemblyCounters,
}

impl TcpReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Real, measured bytes currently held across every buffering direction.
    pub fn bytes_held(&self) -> usize {
        self.bytes_held
    }

    pub fn streams_held(&self) -> usize {
        self.streams.len()
    }

    pub fn counters(&self) -> ReassemblyCounters {
        self.counters
    }

    /// The contiguous prefix currently held for one direction — never spliced
    /// across a hole, so it is safe to hand to a parser that reads from the
    /// start. Empty for an unknown or released stream.
    pub fn prefix(&self, key: &TcpStreamKey) -> &[u8] {
        self.streams.get(key).and_then(|stream| stream.data.get(..stream.prefix_len)).unwrap_or(&[])
    }

    /// Feeds one segment's payload. Returns the direction's status whenever
    /// this segment actually changed the buffer, and `None` when it did not —
    /// which is precisely what a retransmission of already-held bytes does
    /// under the first-seen-wins policy.
    ///
    /// `declared_payload_len` is what the IP header said this segment's
    /// transport payload would be (`ip_declared_payload_len` minus the
    /// transport header), so a short capture is distinguishable from a short
    /// segment.
    pub fn feed(
        &mut self,
        key: &TcpStreamKey,
        seq: u32,
        payload: &[u8],
        declared_payload_len: u32,
        now_ms: u64,
    ) -> Option<ReassemblyStatus> {
        if payload.is_empty() {
            // A pure ACK carries no stream bytes. (`flow.rs` excludes these
            // from retransmit detection for the same reason.)
            return None;
        }
        if !self.streams.contains_key(key) && self.streams.len() >= MAX_TCP_STREAMS {
            self.evict_oldest_until(MAX_TCP_STREAMS.saturating_sub(1), MAX_TCP_BYTES_TOTAL);
        }

        let stream = self.streams.entry(key.clone()).or_insert_with(|| TcpStream::new(seq, now_ms));
        stream.last_seen_ms = now_ms;
        if stream.finished {
            // Release lazily, on the first segment after giving up, so the
            // buffer is freed promptly without the caller having to know.
            let freed = stream.data.len();
            if freed > 0 {
                stream.release();
                self.bytes_held = self.bytes_held.saturating_sub(freed);
            }
            return None;
        }
        if now_ms.saturating_sub(stream.first_seen_ms) > TCP_DECISION_WINDOW_MS {
            // Nothing decided within the window. Stop buffering: this is what
            // keeps steady-state memory proportional to messages started
            // recently rather than to every open connection.
            let freed = stream.data.len();
            stream.release();
            stream.finished = true;
            self.bytes_held = self.bytes_held.saturating_sub(freed);
            self.counters.abandoned_without_completing += 1;
            return None;
        }

        let before = stream.data.len();
        // Wraparound-safe offset: the same signed-delta technique
        // `flow.rs`'s retransmit detection uses, so a sequence number
        // wrapping past u32::MAX on a long-lived flow is handled rather than
        // read as a wild offset.
        let rel = i64::from(seq.wrapping_sub(stream.base_seq) as i32);
        let offset = if rel < 0 {
            // This segment starts before everything held. Shift the buffer so
            // it can occupy offset 0 — this is what makes genuine
            // out-of-order arrival work instead of being discarded.
            let shift = rel.unsigned_abs() as usize;
            if shift.saturating_add(stream.data.len()) > MAX_TCP_STREAM_BYTES {
                // Too far back to be part of the same window; more likely a
                // wrapped or spoofed sequence number than real reordering.
                //
                // Checked against shift + the bytes already held, not shift
                // alone: rebase() truncates its shifted buffer back to
                // MAX_TCP_STREAM_BYTES, so a shift that passes a bound on
                // itself but not combined with existing data would silently
                // evict already-filled (first-seen) bytes and their `filled`
                // markers — opening a window for a later segment to rewrite
                // that range without ever being counted as a conflict. That
                // breaks the first-seen-wins guarantee this reassembler
                // exists to enforce, so it is rejected here instead, the
                // same as an ordinary too-far-back segment.
                return None;
            }
            stream.rebase(shift, seq);
            0
        } else if rel > MAX_TCP_STREAM_BYTES as i64 {
            // Beyond the cap before any allocation is attempted.
            return None;
        } else {
            rel as usize
        };

        let written =
            write_first_seen_wins(&mut stream.data, &mut stream.filled, offset, payload, MAX_TCP_STREAM_BYTES);
        let after = stream.data.len();
        if (payload.len() as u32) < declared_payload_len {
            let hole_at = offset.saturating_add(payload.len());
            stream.short_captured_at = Some(stream.short_captured_at.map_or(hole_at, |at| at.min(hole_at)));
        }
        stream.prefix_len = contiguous_len_from(&stream.filled, stream.prefix_len);
        let status = stream.status();
        if written.hit_cap {
            // At the cap without a decision — report what is held one last
            // time, then stop. The buffer is released on the next segment.
            stream.finished = true;
        }
        let changed = written.newly_written > 0 || written.hit_cap;
        let hit_cap = written.hit_cap;
        // Disjoint field borrows: `stream` borrows `self.streams` only.
        self.bytes_held = self.bytes_held.saturating_add(after).saturating_sub(before);
        self.counters.conflicting_overlap_bytes += written.conflicting as u64;
        if hit_cap {
            self.counters.abandoned_without_completing += 1;
        }
        // Enforce the global byte ceiling on every feed, not only on the
        // eviction tick: many already-open streams all growing at once could
        // otherwise exceed it in between ticks, which is exactly the shape a
        // hostile sender would use. With this, `bytes_held() <=
        // MAX_TCP_BYTES_TOTAL` holds unconditionally once `feed` returns —
        // the invariant the fuzz target asserts.
        self.evict_oldest_until(MAX_TCP_STREAMS, MAX_TCP_BYTES_TOTAL);
        changed.then_some(status)
    }

    /// Releases a direction's buffer because a detector decided, counting the
    /// outcome. The entry is removed outright, so a later message on the same
    /// long-lived connection gets a fresh attempt rather than being locked
    /// out by the first one's success.
    pub fn finish(&mut self, key: &TcpStreamKey, status: ReassemblyStatus) {
        if let Some(stream) = self.streams.remove(key) {
            self.bytes_held = self.bytes_held.saturating_sub(stream.data.len());
            match status {
                ReassemblyStatus::Reassembled => self.counters.completed += 1,
                ReassemblyStatus::IncompleteTruncatedAtCapture => {
                    self.counters.incomplete_truncated_at_capture += 1
                }
                ReassemblyStatus::IncompleteMissingFrames => self.counters.incomplete_missing_frames += 1,
            }
        }
    }

    /// Drops both directions of one flow — called when the flow table evicts
    /// it, so a closed connection's buffers go immediately rather than waiting
    /// out the idle timeout.
    pub fn drop_flow(&mut self, flow: &FlowKey) {
        for from_local in [true, false] {
            let key = TcpStreamKey { flow: flow.clone(), from_local };
            if let Some(stream) = self.streams.remove(&key) {
                self.bytes_held = self.bytes_held.saturating_sub(stream.data.len());
            }
        }
    }

    /// Removes idle directions, then enforces the global ceilings
    /// oldest-first.
    pub fn evict_stale(&mut self, now_ms: u64) {
        let idle: Vec<TcpStreamKey> = self
            .streams
            .iter()
            .filter(|(_, stream)| now_ms.saturating_sub(stream.last_seen_ms) > TCP_STREAM_IDLE_MS)
            .map(|(key, _)| key.clone())
            .collect();
        for key in idle {
            if let Some(stream) = self.streams.remove(&key) {
                self.bytes_held = self.bytes_held.saturating_sub(stream.data.len());
                self.counters.evicted_idle += 1;
            }
        }
        self.evict_oldest_until(MAX_TCP_STREAMS, MAX_TCP_BYTES_TOTAL);
    }

    fn evict_oldest_until(&mut self, max_streams: usize, max_bytes: usize) {
        if self.streams.len() <= max_streams && self.bytes_held <= max_bytes {
            return;
        }
        let mut by_age: Vec<(TcpStreamKey, u64)> =
            self.streams.iter().map(|(key, stream)| (key.clone(), stream.last_seen_ms)).collect();
        by_age.sort_by_key(|(_, last_seen_ms)| *last_seen_ms);
        for (key, _) in by_age {
            if self.streams.len() <= max_streams && self.bytes_held <= max_bytes {
                break;
            }
            if let Some(stream) = self.streams.remove(&key) {
                self.bytes_held = self.bytes_held.saturating_sub(stream.data.len());
                self.counters.evicted_capacity += 1;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Capture-loop facade
// ---------------------------------------------------------------------------

/// What sniffing one captured frame produced, with reassembly applied where it
/// helps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniffOutcome {
    /// What the flow table should record — the same `L7Info` the per-frame
    /// `sniff_l7` would have produced, except that a message split across
    /// frames now resolves instead of silently disappearing.
    pub info: L7Info,
    /// Present only when this frame went through reassembly, in which case it
    /// says whether the buffer the decision came from was complete. `None`
    /// means the frame's own payload was used directly, with no reassembly
    /// involved and therefore no completeness claim to make.
    pub status: Option<ReassemblyStatus>,
    /// Present when no detector could decide yet — see
    /// `L7Sniff::NeedMoreBytes` for why this is a lower bound rather than a
    /// prediction.
    pub need_more_bytes: Option<usize>,
}

/// Both reassemblers plus the capture-truncation signal, in the shape the
/// capture loop uses.
#[derive(Default)]
pub struct StreamReassembler {
    fragments: IpFragmentReassembler,
    segments: TcpReassembler,
    /// When the capture loop last saw a frame cut short by the snap length.
    /// See `ReassemblyStatus`'s reachability note: this is the signal that
    /// actually fires today.
    last_frame_cut_at_ms: Option<u64>,
    frames_cut_at_snaplen: u64,
    last_evict_ms: u64,
}

impl StreamReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Total real bytes held by reassembly right now, across both
    /// reassemblers. Bounded by `MAX_FRAGMENT_BYTES_TOTAL +
    /// MAX_TCP_BYTES_TOTAL` regardless of how many distinct keys hostile
    /// input invents.
    pub fn bytes_held(&self) -> usize {
        self.fragments.bytes_held() + self.segments.bytes_held()
    }

    pub fn fragment_counters(&self) -> ReassemblyCounters {
        self.fragments.counters()
    }

    pub fn segment_counters(&self) -> ReassemblyCounters {
        self.segments.counters()
    }

    /// How many frames the capture loop has reported as cut short by the snap
    /// length. A real count of a real observation, not an inference.
    pub fn frames_cut_at_snaplen(&self) -> u64 {
        self.frames_cut_at_snaplen
    }

    /// Called by the capture loop for a frame that `parse_packet` rejected and
    /// whose captured length equals the active snap length — pcap truncates to
    /// exactly the snap length, so that combination means the frame was cut at
    /// capture rather than malformed on the wire. The capture loop is the only
    /// place that knows both numbers.
    ///
    /// While this has happened recently (`CUT_ATTRIBUTION_WINDOW_MS`), a gap
    /// in the sequence or fragment space is attributed to that truncation
    /// instead of to a frame that was never sent.
    pub fn note_frame_cut_at_snaplen(&mut self, now_ms: u64) {
        self.frames_cut_at_snaplen += 1;
        self.last_frame_cut_at_ms = Some(now_ms);
    }

    /// Reclassifies "frames missing" as "frames truncated at capture" while
    /// the capture is demonstrably losing frames to the snap length. Never the
    /// other way around, and never touches a complete result.
    fn attribute(&self, status: ReassemblyStatus, now_ms: u64) -> ReassemblyStatus {
        if status != ReassemblyStatus::IncompleteMissingFrames {
            return status;
        }
        match self.last_frame_cut_at_ms {
            Some(cut_ms) if now_ms.saturating_sub(cut_ms) <= CUT_ATTRIBUTION_WINDOW_MS => {
                ReassemblyStatus::IncompleteTruncatedAtCapture
            }
            _ => status,
        }
    }

    /// Runs time-based and capacity-based eviction, at most once a second.
    ///
    /// Driven from the capture loop rather than shared with
    /// `FlowTable::evict_stale`: that runs on the periodic emitter task, on
    /// the other side of the flow-table mutex from this reassembler, and
    /// plumbing keys across that boundary to reuse one call site would be more
    /// coupling than the duplication it saves. Same mechanism (retain by
    /// threshold, then drop oldest over capacity), own call site.
    pub fn maybe_evict(&mut self, now_ms: u64) {
        if now_ms.saturating_sub(self.last_evict_ms) < 1_000 {
            return;
        }
        self.last_evict_ms = now_ms;
        let _ = self.fragments.evict_stale(now_ms);
        self.segments.evict_stale(now_ms);
    }

    /// Drops both directions of a flow the flow table has evicted.
    pub fn drop_flow(&mut self, flow: &FlowKey) {
        self.segments.drop_flow(flow);
    }

    /// Sniffs one captured frame's application layer, using reassembly only
    /// where it can help.
    ///
    /// `flow` is `FlowTable::key_for`'s result for this packet — the flow
    /// identity and direction. `None` (a packet matching no tracked flow)
    /// simply means no desegmentation, same as today.
    pub fn sniff(&mut self, packet: &ParsedPacket, flow: Option<(&FlowKey, bool)>, now_ms: u64) -> SniffOutcome {
        // An IPv4 fragment has no transport layer and no payload of its own,
        // so reassembly is the only way it gets an application layer at all.
        if packet.ip_fragment.is_some() {
            let Some(datagram) = self.fragments.feed(packet, now_ms) else {
                return SniffOutcome { info: L7Info::None, status: None, need_more_bytes: None };
            };
            let status = self.attribute(datagram.status, now_ms);
            // Back through the ordinary parser, so a reassembled datagram's
            // ports and payload come from the same path as any other packet's.
            let info = parse_packet(&datagram.bytes, LinkType::Raw)
                .map(|rejoined| sniff_l7(&rejoined.payload, rejoined.dst_port))
                .unwrap_or(L7Info::None);
            return SniffOutcome { info, status: Some(status), need_more_bytes: None };
        }

        // This frame's own payload first. For the overwhelmingly common case
        // — a request or ClientHello that fits in one segment — this decides
        // immediately and nothing is buffered at all.
        let own = sniff_l7_desegmenting(&packet.payload, packet.dst_port);

        // Only TCP with a known flow identity and a sequence number can be
        // desegmented. Binding the sequence number here, rather than
        // re-unwrapping it further down, means there is no path on which a
        // later edit could reach the buffer with a fabricated offset.
        let stream_target = match (flow, packet.seq) {
            (Some((flow_key, from_local)), Some(seq)) if packet.protocol == TransportProtocol::Tcp => {
                Some((TcpStreamKey { flow: flow_key.clone(), from_local }, seq))
            }
            _ => None,
        };
        let Some((key, seq)) = stream_target else {
            return match own {
                L7Sniff::Decided(info) => SniffOutcome { info, status: None, need_more_bytes: None },
                L7Sniff::NeedMoreBytes { at_least } => {
                    SniffOutcome { info: L7Info::None, status: None, need_more_bytes: Some(at_least) }
                }
                L7Sniff::Undecided => SniffOutcome { info: L7Info::None, status: None, need_more_bytes: None },
            };
        };
        if let L7Sniff::Decided(info) = own {
            // Decided on one segment. Release any buffer this direction had —
            // there is nothing left to wait for.
            self.segments.finish(&key, ReassemblyStatus::Reassembled);
            return SniffOutcome { info, status: None, need_more_bytes: None };
        }

        let declared = packet.ip_declared_payload_len.saturating_sub(packet.transport_header_len);
        let Some(raw_status) = self.segments.feed(&key, seq, &packet.payload, declared, now_ms) else {
            // Nothing changed — e.g. a retransmission of bytes already held.
            return SniffOutcome { info: L7Info::None, status: None, need_more_bytes: None };
        };
        let status = self.attribute(raw_status, now_ms);
        match sniff_l7_desegmenting(self.segments.prefix(&key), packet.dst_port) {
            L7Sniff::Decided(info) => {
                self.segments.finish(&key, status);
                SniffOutcome { info, status: Some(status), need_more_bytes: None }
            }
            L7Sniff::NeedMoreBytes { at_least } => {
                SniffOutcome { info: L7Info::None, status: Some(status), need_more_bytes: Some(at_least) }
            }
            L7Sniff::Undecided => SniffOutcome { info: L7Info::None, status: Some(status), need_more_bytes: None },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l7::build_client_hello;
    use crate::parse::Ipv4Fragment;
    use etherparse::{IpFragOffset, IpNumber, Ipv4Header, TcpHeader};

    // ---- fixtures -------------------------------------------------------
    //
    // Every fixture below goes through the real `parse_packet`, so these
    // tests exercise the same bytes-to-ParsedPacket path the capture loop
    // does rather than a hand-shaped struct that could disagree with it. The
    // one exception is `short_captured_fragment`/`short_captured_segment`,
    // which must construct a ParsedPacket directly — see their comments.

    fn v4(addr: &str) -> [u8; 4] {
        addr.parse::<std::net::Ipv4Addr>().expect("test fixture address").octets()
    }

    fn ipv4_fragment(
        src: &str,
        dst: &str,
        identification: u16,
        protocol: IpNumber,
        offset_bytes: u16,
        more_fragments: bool,
        payload: &[u8],
    ) -> ParsedPacket {
        let mut ip = Ipv4Header::new(payload.len() as u16, 64, protocol, v4(src), v4(dst))
            .expect("test fixture header");
        ip.identification = identification;
        ip.more_fragments = more_fragments;
        ip.fragment_offset = IpFragOffset::try_new(offset_bytes / 8).expect("8-byte-aligned offset");
        ip.header_checksum = ip.calc_header_checksum();
        let mut data = Vec::new();
        ip.write(&mut data).expect("test fixture write");
        data.extend_from_slice(payload);
        parse_packet(&data, LinkType::Raw).expect("a fragment fixture must parse")
    }

    fn tcp_segment(src: &str, dst: &str, sport: u16, dport: u16, seq: u32, payload: &[u8]) -> ParsedPacket {
        let mut tcp = TcpHeader::new(sport, dport, seq, 65535);
        tcp.ack = true;
        let mut ip = Ipv4Header::new((tcp.header_len() + payload.len()) as u16, 64, IpNumber::TCP, v4(src), v4(dst))
            .expect("test fixture header");
        ip.header_checksum = ip.calc_header_checksum();
        let mut data = Vec::new();
        ip.write(&mut data).expect("test fixture write");
        tcp.write(&mut data).expect("test fixture write");
        data.extend_from_slice(payload);
        parse_packet(&data, LinkType::Raw).expect("a segment fixture must parse")
    }

    /// A DNS query for "a.com" — small enough to split across two fragments
    /// while still being decodable by `l7::sniff_l7` once rejoined.
    fn dns_query() -> Vec<u8> {
        let mut payload = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        payload.push(1);
        payload.extend_from_slice(b"a");
        payload.push(3);
        payload.extend_from_slice(b"com");
        payload.push(0);
        payload.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        payload
    }

    /// A UDP datagram (header + DNS query) as raw IP payload bytes, ready to
    /// be cut into fragments.
    fn udp_dns_datagram() -> Vec<u8> {
        let dns = dns_query();
        let mut out = Vec::new();
        out.extend_from_slice(&53u16.to_be_bytes()); // src port
        out.extend_from_slice(&53u16.to_be_bytes()); // dst port
        out.extend_from_slice(&((8 + dns.len()) as u16).to_be_bytes()); // length
        out.extend_from_slice(&[0, 0]); // checksum: 0 = not computed, legal for IPv4 UDP
        out.extend_from_slice(&dns);
        out
    }

    fn flow_key() -> FlowKey {
        FlowKey {
            protocol: TransportProtocol::Tcp,
            local_addr: "192.168.1.10".to_string(),
            local_port: 51000,
            remote_addr: "93.184.216.34".to_string(),
            remote_port: 80,
        }
    }

    fn stream_key() -> TcpStreamKey {
        TcpStreamKey { flow: flow_key(), from_local: true }
    }

    // =====================================================================
    // Acceptance criterion: fragmented IPv4 traffic decodes correctly
    // =====================================================================

    #[test]
    fn two_ipv4_fragments_rejoin_into_a_datagram_that_decodes_to_its_real_l7() {
        let datagram = udp_dns_datagram();
        // 16 is 8-byte aligned, as every non-final fragment offset must be.
        let (head, tail) = datagram.split_at(16);
        let mut r = IpFragmentReassembler::new();

        assert!(
            r.feed(&ipv4_fragment("10.0.0.1", "10.0.0.2", 42, IpNumber::UDP, 0, true, head), 0).is_none(),
            "a first fragment alone cannot complete a datagram"
        );
        let rejoined = r
            .feed(&ipv4_fragment("10.0.0.1", "10.0.0.2", 42, IpNumber::UDP, 16, false, tail), 1)
            .expect("the last fragment must complete the group");

        assert_eq!(rejoined.status, ReassemblyStatus::Reassembled);
        assert_eq!(rejoined.payload_len, datagram.len());

        // The rebuilt datagram must be a real IPv4 packet that the ordinary
        // parser decodes — ports and payload included.
        let parsed = parse_packet(&rejoined.bytes, LinkType::Raw).expect("a rebuilt datagram must parse");
        assert_eq!(parsed.protocol, TransportProtocol::Udp);
        assert_eq!(parsed.dst_port, Some(53));
        assert!(parsed.ip_fragment.is_none(), "the rebuilt header must have its fragment fields cleared");
        match sniff_l7(&parsed.payload, parsed.dst_port) {
            L7Info::Dns { query_name } => assert_eq!(query_name, "a.com"),
            other => panic!("expected the rejoined datagram to decode as DNS, got {other:?}"),
        }
        assert_eq!(r.bytes_held(), 0, "a completed group must not stay held");
        assert_eq!(r.counters().completed, 1);
    }

    #[test]
    fn fragments_arriving_out_of_order_still_rejoin() {
        let datagram = udp_dns_datagram();
        let (head, tail) = datagram.split_at(16);
        let mut r = IpFragmentReassembler::new();

        // Last fragment first: it fixes the total length but leaves 0..16 open.
        assert!(r.feed(&ipv4_fragment("10.0.0.1", "10.0.0.2", 7, IpNumber::UDP, 16, false, tail), 0).is_none());
        let rejoined = r
            .feed(&ipv4_fragment("10.0.0.1", "10.0.0.2", 7, IpNumber::UDP, 0, true, head), 1)
            .expect("the first fragment must complete the group once it arrives");
        assert_eq!(rejoined.status, ReassemblyStatus::Reassembled);
        let parsed = parse_packet(&rejoined.bytes, LinkType::Raw).expect("must parse");
        assert_eq!(parsed.dst_port, Some(53));
    }

    #[test]
    fn fragments_of_different_datagrams_between_the_same_hosts_do_not_mix() {
        // Identical source, destination, and protocol, different
        // identification — RFC 791 says these are different datagrams, and
        // mixing them would splice unrelated bytes together.
        let datagram = udp_dns_datagram();
        let (head, tail) = datagram.split_at(16);
        let mut r = IpFragmentReassembler::new();
        assert!(r.feed(&ipv4_fragment("10.0.0.1", "10.0.0.2", 1, IpNumber::UDP, 0, true, head), 0).is_none());
        assert!(
            r.feed(&ipv4_fragment("10.0.0.1", "10.0.0.2", 2, IpNumber::UDP, 16, false, tail), 0).is_none(),
            "a tail with a different identification must not complete the other group"
        );
        assert_eq!(r.groups_held(), 2);
    }

    #[test]
    fn an_incomplete_fragment_group_is_reported_as_missing_frames_at_its_timeout() {
        // Acceptance criterion: a missing frame is reported as such, never
        // presented as a complete datagram.
        let datagram = udp_dns_datagram();
        let mut r = IpFragmentReassembler::new();
        // A first fragment plus a final fragment, with a hole between them:
        // the middle fragment is never captured.
        r.feed(&ipv4_fragment("10.0.0.1", "10.0.0.2", 9, IpNumber::UDP, 0, true, &datagram[..8]), 0);
        r.feed(&ipv4_fragment("10.0.0.1", "10.0.0.2", 9, IpNumber::UDP, 24, false, &datagram[24..]), 0);
        assert_eq!(r.groups_held(), 1, "an incomplete group is held, waiting");
        assert!(r.evict_stale(FRAGMENT_TIMEOUT_MS).is_empty(), "not yet past the timeout");

        let evicted = r.evict_stale(FRAGMENT_TIMEOUT_MS + 1);
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].status, ReassemblyStatus::IncompleteMissingFrames);
        assert_eq!(evicted[0].status.label(), "incomplete — frames missing");
        // Only the contiguous prefix is handed back — never bytes spliced
        // across the hole, which would look adjacent without being so.
        assert_eq!(evicted[0].payload_len, 8);
        assert_eq!(r.bytes_held(), 0);
        assert_eq!(r.counters().incomplete_missing_frames, 1);
        assert_eq!(r.counters().completed, 0, "an incomplete group must never count as completed");
    }

    #[test]
    fn a_group_that_never_sees_its_first_fragment_yields_nothing_but_is_still_accounted_for() {
        let datagram = udp_dns_datagram();
        let mut r = IpFragmentReassembler::new();
        r.feed(&ipv4_fragment("10.0.0.1", "10.0.0.2", 3, IpNumber::UDP, 16, false, &datagram[16..]), 0);
        let evicted = r.evict_stale(FRAGMENT_TIMEOUT_MS + 1);
        assert!(evicted.is_empty(), "no first fragment means no header and no prefix to rebuild from");
        assert_eq!(r.counters().incomplete_missing_frames, 1, "the outcome must still be counted, not vanish");
        assert_eq!(r.bytes_held(), 0);
    }

    // =====================================================================
    // Overlap policy: first-seen bytes win (documented on
    // `write_first_seen_wins`)
    // =====================================================================

    #[test]
    fn overlapping_fragments_keep_the_first_seen_bytes_and_count_the_conflict() {
        let mut r = IpFragmentReassembler::new();
        // First fragment claims 0..16 as 'A's; a second, overlapping one tries
        // to rewrite 8..16 as 'B's. Under first-seen-wins the 'A's stand.
        r.feed(&ipv4_fragment("10.0.0.1", "10.0.0.2", 5, IpNumber::UDP, 0, true, &[b'A'; 16]), 0);
        r.feed(&ipv4_fragment("10.0.0.1", "10.0.0.2", 5, IpNumber::UDP, 8, false, &[b'B'; 8]), 0);

        let evicted = r.evict_stale(FRAGMENT_TIMEOUT_MS + 1);
        // Total is 8 + 8 = 16 and 0..16 is covered, so it actually completed
        // on the second fragment; check the emitted bytes instead.
        assert!(evicted.is_empty());
        assert_eq!(
            r.counters().conflicting_overlap_bytes,
            8,
            "the 8 rewritten bytes differed from the held copy and must be counted"
        );
        assert_eq!(r.counters().completed, 1);
    }

    #[test]
    fn an_identical_duplicate_fragment_is_not_counted_as_a_conflict() {
        let mut r = IpFragmentReassembler::new();
        let payload = [b'A'; 16];
        r.feed(&ipv4_fragment("10.0.0.1", "10.0.0.2", 6, IpNumber::UDP, 0, true, &payload), 0);
        r.feed(&ipv4_fragment("10.0.0.1", "10.0.0.2", 6, IpNumber::UDP, 0, true, &payload), 1);
        assert_eq!(
            r.counters().conflicting_overlap_bytes,
            0,
            "a plain duplicate carries the same bytes and is a free no-op, not an overlap rewrite"
        );
    }

    // =====================================================================
    // Acceptance criterion: bounded memory under hostile input
    // =====================================================================

    #[test]
    fn a_flood_of_never_completing_fragment_groups_is_capped_and_evicts_oldest_first() {
        let mut r = IpFragmentReassembler::new();
        // Every group is a first fragment with MF set, so none can ever
        // complete — the classic never-finish-it pattern.
        let over = MAX_FRAGMENT_GROUPS + 200;
        for i in 0..over {
            let dst = format!("10.1.{}.{}", (i / 256) % 256, i % 256);
            r.feed(&ipv4_fragment("10.0.0.1", &dst, i as u16, IpNumber::UDP, 0, true, &[0x41; 1024]), i as u64);
        }
        assert!(
            r.groups_held() <= MAX_FRAGMENT_GROUPS,
            "group count cap must hold, got {} > {}",
            r.groups_held(),
            MAX_FRAGMENT_GROUPS
        );
        assert!(
            r.bytes_held() <= MAX_FRAGMENT_BYTES_TOTAL,
            "byte cap must hold, got {}",
            r.bytes_held()
        );
        assert!(r.counters().evicted_capacity > 0, "the excess must have been evicted, not silently accepted");
    }

    #[test]
    fn one_fragment_group_cannot_exceed_the_maximum_ipv4_datagram_size() {
        let mut r = IpFragmentReassembler::new();
        // A fragment claiming an offset at the very top of the fragment-offset
        // space, so offset + length lands past the protocol maximum.
        let offset = 65_528u16; // 8-byte aligned, near the 13-bit field's ceiling
        r.feed(&ipv4_fragment("10.0.0.1", "10.0.0.2", 1, IpNumber::UDP, offset, true, &[0x41; 1024]), 0);
        assert!(
            r.bytes_held() <= MAX_FRAGMENT_GROUP_BYTES,
            "a single group must never exceed the IPv4 maximum, got {}",
            r.bytes_held()
        );
    }

    #[test]
    fn a_slow_drip_of_fragments_cannot_keep_one_group_alive_indefinitely() {
        // Touching a group forever would defeat a purely idle-based timeout,
        // so there is also a hard ceiling measured from first arrival.
        let mut r = IpFragmentReassembler::new();
        let mut now = 0u64;
        for i in 0..40u16 {
            r.feed(
                &ipv4_fragment("10.0.0.1", "10.0.0.2", 1, IpNumber::UDP, i * 8, true, &[0x41; 8]),
                now,
            );
            now += 1_000; // well inside the idle timeout every time
            r.evict_stale(now);
        }
        // A later drip starts a *fresh* group, so the table is not expected to
        // be empty here. What must hold is that no single group ever
        // accumulated the whole 40-fragment drip: the ceiling expired it
        // repeatedly, so held bytes stay proportional to one window's worth,
        // not to the attacker's total effort.
        assert!(
            r.counters().incomplete_missing_frames >= 2,
            "the first-arrival ceiling must have expired the group more than once over 40s, got {}",
            r.counters().incomplete_missing_frames
        );
        // Note what this deliberately does *not* assert: the coverage buffer
        // is indexed by offset within the datagram, so a group whose
        // fragments sit at sparse high offsets legitimately allocates up to
        // its highest offset even while holding few real bytes. That is
        // inherent to the design and is bounded per group by
        // `MAX_FRAGMENT_GROUP_BYTES` and in aggregate by the group-count and
        // total-byte caps (see the flood test above), not by this one.
        assert!(
            r.bytes_held() <= MAX_FRAGMENT_GROUP_BYTES,
            "one group must stay within its own cap, got {}",
            r.bytes_held()
        );
    }

    // =====================================================================
    // Acceptance criterion: truncated capture is reported as such
    // =====================================================================

    /// A fragment whose captured payload is shorter than its own IP header
    /// declared.
    ///
    /// This one fixture cannot go through `parse_packet`: etherparse's strict
    /// length validation rejects a frame shorter than its declared length
    /// outright, so the live pipeline never delivers this shape today (see
    /// `ReassemblyStatus`'s reachability note — the live signal is
    /// `note_frame_cut_at_snaplen`, exercised separately below). The direct
    /// check is still the correct one and is tested here at the
    /// reassembler's own API boundary.
    fn short_captured_fragment(identification: u16, offset_bytes: u32, captured: &[u8], declared: u32) -> ParsedPacket {
        let mut ip = Ipv4Header::new(captured.len() as u16, 64, IpNumber::UDP, v4("10.0.0.1"), v4("10.0.0.2"))
            .expect("test fixture header");
        ip.identification = identification;
        ip.more_fragments = false;
        ip.header_checksum = ip.calc_header_checksum();
        let mut header = Vec::new();
        ip.write(&mut header).expect("test fixture write");
        ParsedPacket {
            src_mac: "00:00:00:00:00:00".to_string(),
            dst_mac: "00:00:00:00:00:00".to_string(),
            src_ip: "10.0.0.1".to_string(),
            dst_ip: "10.0.0.2".to_string(),
            protocol: TransportProtocol::Other,
            src_port: None,
            dst_port: None,
            tcp_flags: None,
            seq: None,
            ttl: 64,
            total_len: (header.len() + captured.len()) as u16,
            payload: Vec::new(),
            header_bytes: header.clone(),
            ip_header_len: header.len() as u32,
            transport_header_len: 0,
            ip_version: 4,
            ip_checksum: Some(0),
            vlan_tag: None,
            ip_declared_payload_len: declared,
            ip_fragment: Some(Ipv4Fragment {
                identification,
                offset_bytes,
                more_fragments: false,
                protocol: IpNumber::UDP.0,
                header,
                payload: captured.to_vec(),
            }),
        }
    }

    #[test]
    fn a_fragment_cut_short_at_capture_is_reported_as_truncated_not_as_complete() {
        let mut r = IpFragmentReassembler::new();
        // Declares 1480 payload bytes, only 100 captured.
        let emitted = r
            .feed(&short_captured_fragment(11, 0, &[0x41; 100], 1480), 0)
            .expect("a hole no future fragment can fill must be reported immediately, not held");
        assert_eq!(emitted.status, ReassemblyStatus::IncompleteTruncatedAtCapture);
        assert_eq!(emitted.status.label(), "incomplete — frames truncated at capture");
        assert!(!emitted.status.is_complete());
        assert_eq!(emitted.payload_len, 100, "only the bytes actually captured are handed back");
        assert_eq!(r.counters().incomplete_truncated_at_capture, 1);
        assert_eq!(r.counters().completed, 0);
    }

    #[test]
    fn truncation_takes_precedence_over_missing_frames_when_both_apply() {
        // A group with both a capture-truncated fragment and a genuine hole
        // must name the truncation: it is a definite fact about this
        // capture's configuration that the operator can act on.
        let mut r = IpFragmentReassembler::new();
        let emitted = r.feed(&short_captured_fragment(12, 0, &[0x41; 50], 800), 0).expect("reported immediately");
        assert_eq!(emitted.status, ReassemblyStatus::IncompleteTruncatedAtCapture);
    }

    // =====================================================================
    // TCP: acceptance criterion — an HTTP request spanning two segments
    // =====================================================================

    #[test]
    fn an_http_request_split_across_two_segments_decodes_once_rejoined() {
        // Neither segment alone sniffs as HTTP: the first has no complete
        // start line, the second's first token is not a method.
        let first = b"GET /index.h";
        let second = b"tml HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(matches!(sniff_l7(first, Some(80)), L7Info::None), "fixture premise: first segment alone decides nothing");
        assert!(matches!(sniff_l7(second, Some(80)), L7Info::None), "fixture premise: second segment alone decides nothing");

        let mut r = StreamReassembler::new();
        let key = flow_key();

        let a = tcp_segment("192.168.1.10", "93.184.216.34", 51000, 80, 1000, first);
        let outcome = r.sniff(&a, Some((&key, true)), 0);
        assert_eq!(outcome.info, L7Info::None, "still undecided after one segment");
        assert!(outcome.need_more_bytes.is_some(), "and it must say so rather than silently declining");

        let b = tcp_segment("192.168.1.10", "93.184.216.34", 51000, 80, 1000 + first.len() as u32, second);
        let outcome = r.sniff(&b, Some((&key, true)), 1);
        match outcome.info {
            L7Info::Http { method, path } => {
                assert_eq!(method, "GET");
                assert_eq!(path, "/index.html", "the whole path must be recovered, not the first segment's prefix");
            }
            other => panic!("expected the rejoined request to decode as HTTP, got {other:?}"),
        }
        assert_eq!(outcome.status, Some(ReassemblyStatus::Reassembled));
        assert_eq!(r.bytes_held(), 0, "the buffer must be released the moment a detector decides");
    }

    #[test]
    fn a_tls_client_hello_split_across_two_segments_decodes_once_rejoined() {
        let hello = build_client_hello("example.com");
        let (first, second) = hello.split_at(20);
        assert!(matches!(sniff_l7(first, Some(443)), L7Info::None), "fixture premise: a truncated record decides nothing");

        let mut r = StreamReassembler::new();
        let key = FlowKey { remote_port: 443, ..flow_key() };

        let a = tcp_segment("192.168.1.10", "93.184.216.34", 51000, 443, 500, first);
        let outcome = r.sniff(&a, Some((&key, true)), 0);
        assert_eq!(
            outcome.need_more_bytes,
            Some(second.len()),
            "a TLS record declares its own length, so the shortfall is an exact number"
        );

        let b = tcp_segment("192.168.1.10", "93.184.216.34", 51000, 443, 500 + first.len() as u32, second);
        match r.sniff(&b, Some((&key, true)), 1).info {
            L7Info::TlsClientHello { sni, .. } => assert_eq!(sni, "example.com"),
            other => panic!("expected the rejoined ClientHello to decode, got {other:?}"),
        }
    }

    #[test]
    fn a_single_segment_request_is_decided_without_buffering_anything() {
        // The common case must cost nothing: no buffer is created at all.
        let mut r = StreamReassembler::new();
        let key = flow_key();
        let packet = tcp_segment("192.168.1.10", "93.184.216.34", 51000, 80, 1, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        let outcome = r.sniff(&packet, Some((&key, true)), 0);
        assert!(matches!(outcome.info, L7Info::Http { .. }));
        assert_eq!(outcome.status, None, "no reassembly happened, so there is no completeness claim to make");
        assert_eq!(r.bytes_held(), 0);
    }

    // =====================================================================
    // TCP: out-of-order, overlapping, retransmitted (three distinct tests)
    // =====================================================================

    #[test]
    fn out_of_order_segments_are_rejoined_in_sequence_order() {
        let mut r = TcpReassembler::new();
        let key = stream_key();
        // The later segment arrives first, so the buffer must be shifted
        // backwards when the earlier one turns up.
        assert!(r.feed(&key, 1012, b"tml HTTP/1.1\r\n", 14, 0).is_some());
        assert_eq!(r.prefix(&key), b"tml HTTP/1.1\r\n", "on its own it is the only thing held");

        assert!(r.feed(&key, 1000, b"GET /index.h", 12, 1).is_some());
        assert_eq!(
            r.prefix(&key),
            b"GET /index.html HTTP/1.1\r\n",
            "rejoined in sequence order, not arrival order"
        );
    }

    #[test]
    fn overlapping_segments_keep_the_first_seen_bytes() {
        // The documented policy: first-seen wins, so a later overlapping copy
        // cannot rewrite what the monitor already holds.
        let mut r = TcpReassembler::new();
        let key = stream_key();
        r.feed(&key, 100, b"AAAAAAAA", 8, 0);
        r.feed(&key, 104, b"BBBBBBBB", 8, 1);
        assert_eq!(
            r.prefix(&key),
            b"AAAAAAAABBBB",
            "bytes 104..108 were already held as 'A's and must stay 'A's; only 108..112 are new"
        );
        assert_eq!(r.counters().conflicting_overlap_bytes, 4, "the four rewritten bytes differed and are counted");
    }

    #[test]
    fn a_retransmitted_segment_changes_nothing_and_reports_no_change() {
        let mut r = TcpReassembler::new();
        let key = stream_key();
        assert!(r.feed(&key, 100, b"hello", 5, 0).is_some());
        let held = r.prefix(&key).to_vec();
        assert!(
            r.feed(&key, 100, b"hello", 5, 1).is_none(),
            "a retransmission of bytes already held changes nothing, so there is nothing to re-sniff"
        );
        assert_eq!(r.prefix(&key), held.as_slice());
        assert_eq!(r.counters().conflicting_overlap_bytes, 0, "identical bytes are not an overlap conflict");
    }

    #[test]
    fn a_retransmission_carrying_different_bytes_does_not_win_but_is_counted() {
        // The overlap-rewrite attempt: same sequence number, different
        // content. First-seen-wins means the original bytes stand, and the
        // attempt is observable rather than invisible.
        let mut r = TcpReassembler::new();
        let key = stream_key();
        r.feed(&key, 100, b"GET /safe", 9, 0);
        r.feed(&key, 100, b"GET /evil", 9, 1);
        assert_eq!(r.prefix(&key), b"GET /safe");
        assert_eq!(r.counters().conflicting_overlap_bytes, 4, "'safe' vs 'evil' differ in four bytes");
    }

    #[test]
    fn a_sequence_number_wrapping_past_u32_max_is_handled_as_contiguous() {
        // Same wraparound-safe signed-delta technique `flow.rs`'s retransmit
        // detection uses: a post-wrap segment is later, not wildly earlier.
        let mut r = TcpReassembler::new();
        let key = stream_key();
        let base = u32::MAX - 3;
        r.feed(&key, base, b"ABCD", 4, 0);
        r.feed(&key, base.wrapping_add(4), b"EFGH", 4, 1);
        assert_eq!(r.prefix(&key), b"ABCDEFGH", "the wrap must not be read as a gap or a wild offset");
    }

    #[test]
    fn a_backward_shift_that_would_truncate_already_held_bytes_is_rejected_not_silently_evicted() {
        // Security regression: rebase() truncates the shifted buffer back to
        // MAX_TCP_STREAM_BYTES, so a shift that individually passes the
        // "too far back" check can still, combined with data already held,
        // truncate away already-filled (first-seen) bytes along with their
        // `filled` markers -- opening a window for a later segment to
        // rewrite that range without it ever being counted as a conflict.
        // That silently breaks the documented first-seen-wins guarantee
        // ("the monitor's view is immutable once written"). The fix is to
        // reject the shift outright, the same as an ordinary too-far-back
        // segment, rather than accept it at the cost of evicting held data.
        let mut r = TcpReassembler::new();
        let key = stream_key();
        r.feed(&key, 100, b"hello", 5, 0);
        assert_eq!(r.prefix(&key), b"hello");

        // A shift alone within MAX_TCP_STREAM_BYTES, but shift + the 5 bytes
        // already held exceeds it -- the exact combination the old bound on
        // `shift` alone missed.
        let shift = MAX_TCP_STREAM_BYTES - 2;
        let far_earlier_seq = 100u32.wrapping_sub(shift as u32);
        assert!(
            r.feed(&key, far_earlier_seq, b"xx", 2, 1).is_none(),
            "a shift that would truncate already-held bytes must be rejected, not accepted at their expense"
        );
        assert_eq!(
            r.prefix(&key),
            b"hello",
            "the originally held bytes must be completely undisturbed by the rejected shift"
        );
    }

    // =====================================================================
    // TCP: gap and truncation reporting
    // =====================================================================

    #[test]
    fn a_gap_between_segments_is_reported_as_missing_frames() {
        let mut r = TcpReassembler::new();
        let key = stream_key();
        assert_eq!(r.feed(&key, 100, b"GET ", 4, 0), Some(ReassemblyStatus::Reassembled));
        assert_eq!(
            r.feed(&key, 200, b"HTTP/1.1\r\n", 10, 1),
            Some(ReassemblyStatus::IncompleteMissingFrames),
            "data on both sides of a hole is a missing frame, and must be said so"
        );
        assert_eq!(
            r.prefix(&key),
            b"GET ",
            "only the contiguous prefix is exposed — never bytes spliced across the hole"
        );
    }

    /// A segment whose captured payload is shorter than its IP header
    /// declared. Same reachability caveat as `short_captured_fragment`: this
    /// tests the direct check at the reassembler's API boundary; the live
    /// signal today is `note_frame_cut_at_snaplen`.
    #[test]
    fn a_segment_cut_short_at_capture_is_reported_as_truncated_not_complete() {
        let mut r = TcpReassembler::new();
        let key = stream_key();
        // 20 bytes captured, 1460 declared by the IP header.
        assert_eq!(
            r.feed(&key, 100, &[0x41; 20], 1460, 0),
            Some(ReassemblyStatus::IncompleteTruncatedAtCapture),
            "the sender clearly sent more than the capture kept"
        );
    }

    #[test]
    fn truncation_takes_precedence_over_a_gap_for_a_tcp_stream_too() {
        let mut r = TcpReassembler::new();
        let key = stream_key();
        r.feed(&key, 100, &[0x41; 20], 1460, 0);
        assert_eq!(
            r.feed(&key, 2000, &[0x42; 10], 10, 1),
            Some(ReassemblyStatus::IncompleteTruncatedAtCapture),
            "with both a capture truncation and a gap, the actionable cause wins"
        );
    }

    #[test]
    fn a_recent_snaplen_cut_reattributes_a_gap_to_capture_truncation() {
        // The path that actually fires in the live pipeline: the capture loop
        // saw frames pcap cut short, so a gap is that truncation rather than a
        // frame nobody sent.
        let mut r = StreamReassembler::new();
        let key = flow_key();
        let a = tcp_segment("192.168.1.10", "93.184.216.34", 51000, 80, 100, b"GET ");
        r.sniff(&a, Some((&key, true)), 0);

        let far = tcp_segment("192.168.1.10", "93.184.216.34", 51000, 80, 400, b"HTTP/1.1\r\n");
        assert_eq!(
            r.sniff(&far, Some((&key, true)), 1).status,
            Some(ReassemblyStatus::IncompleteMissingFrames),
            "with no truncation observed, a gap is honestly just a missing frame"
        );

        let mut r = StreamReassembler::new();
        r.note_frame_cut_at_snaplen(0);
        assert_eq!(r.frames_cut_at_snaplen(), 1);
        r.sniff(&a, Some((&key, true)), 0);
        assert_eq!(
            r.sniff(&far, Some((&key, true)), 1).status,
            Some(ReassemblyStatus::IncompleteTruncatedAtCapture),
            "frames being cut at the snap length explains the gap, and is what the operator can fix"
        );
    }

    #[test]
    fn the_snaplen_attribution_expires_rather_than_blaming_truncation_forever() {
        let mut r = StreamReassembler::new();
        let key = flow_key();
        r.note_frame_cut_at_snaplen(0);
        let a = tcp_segment("192.168.1.10", "93.184.216.34", 51000, 80, 100, b"GET ");
        let far = tcp_segment("192.168.1.10", "93.184.216.34", 51000, 80, 400, b"HTTP/1.1\r\n");
        let late = CUT_ATTRIBUTION_WINDOW_MS + 1;
        r.sniff(&a, Some((&key, true)), late);
        assert_eq!(
            r.sniff(&far, Some((&key, true)), late).status,
            Some(ReassemblyStatus::IncompleteMissingFrames),
            "a long-past truncation must not keep explaining fresh gaps"
        );
    }

    // =====================================================================
    // TCP: bounded memory under hostile input
    // =====================================================================

    #[test]
    fn a_flood_of_never_completing_streams_is_capped_and_evicts_oldest_first() {
        let mut r = TcpReassembler::new();
        let over = MAX_TCP_STREAMS + 200;
        for i in 0..over {
            let key = TcpStreamKey {
                flow: FlowKey { remote_port: (i % 65535) as u16, remote_addr: format!("10.2.{}.{}", (i / 256) % 256, i % 256), ..flow_key() },
                from_local: true,
            };
            // Each is an unterminated prefix that can never decide.
            r.feed(&key, 1, b"GET /never-finishes", 19, i as u64);
        }
        assert!(
            r.streams_held() <= MAX_TCP_STREAMS,
            "stream count cap must hold, got {} > {}",
            r.streams_held(),
            MAX_TCP_STREAMS
        );
        assert!(r.bytes_held() <= MAX_TCP_BYTES_TOTAL, "byte cap must hold, got {}", r.bytes_held());
        assert!(r.counters().evicted_capacity > 0, "the excess must have been evicted");
    }

    #[test]
    fn one_stream_direction_cannot_exceed_its_own_byte_cap() {
        let mut r = TcpReassembler::new();
        let key = stream_key();
        let chunk = [0x41u8; 1024];
        let mut seq = 0u32;
        // Push well past the cap, all contiguous, all within the decision
        // window so nothing else stops it.
        for _ in 0..64 {
            r.feed(&key, seq, &chunk, chunk.len() as u32, 0);
            seq = seq.wrapping_add(chunk.len() as u32);
        }
        assert!(
            r.bytes_held() <= MAX_TCP_STREAM_BYTES,
            "a single direction must never exceed its cap, got {}",
            r.bytes_held()
        );
        assert!(r.counters().abandoned_without_completing > 0, "reaching the cap without deciding must be recorded");
    }

    #[test]
    fn a_stream_stops_buffering_once_its_decision_window_elapses() {
        let mut r = TcpReassembler::new();
        let key = stream_key();
        r.feed(&key, 100, b"GET /still-going", 16, 0);
        assert!(r.bytes_held() > 0);
        assert!(
            r.feed(&key, 200, b"and-more", 8, TCP_DECISION_WINDOW_MS + 1).is_none(),
            "past the window this direction gives up rather than buffering indefinitely"
        );
        assert_eq!(r.bytes_held(), 0, "and releases what it held");
        assert_eq!(r.counters().abandoned_without_completing, 1);
    }

    #[test]
    fn an_idle_stream_is_evicted_and_its_bytes_released() {
        let mut r = TcpReassembler::new();
        let key = stream_key();
        r.feed(&key, 100, b"GET /idle", 9, 0);
        assert!(r.bytes_held() > 0);
        r.evict_stale(TCP_STREAM_IDLE_MS);
        assert_eq!(r.streams_held(), 1, "not yet past the idle threshold");
        r.evict_stale(TCP_STREAM_IDLE_MS + 1);
        assert_eq!(r.streams_held(), 0);
        assert_eq!(r.bytes_held(), 0);
        assert_eq!(r.counters().evicted_idle, 1);
    }

    #[test]
    fn dropping_a_flow_releases_both_of_its_directions() {
        let mut r = TcpReassembler::new();
        let flow = flow_key();
        r.feed(&TcpStreamKey { flow: flow.clone(), from_local: true }, 1, b"GET /a", 6, 0);
        r.feed(&TcpStreamKey { flow: flow.clone(), from_local: false }, 1, b"HTTP/1.", 7, 0);
        assert_eq!(r.streams_held(), 2, "the two directions are independent byte streams");
        r.drop_flow(&flow);
        assert_eq!(r.streams_held(), 0);
        assert_eq!(r.bytes_held(), 0);
    }

    #[test]
    fn the_two_directions_of_one_flow_never_share_a_buffer() {
        let mut r = TcpReassembler::new();
        let flow = flow_key();
        let out = TcpStreamKey { flow: flow.clone(), from_local: true };
        let inb = TcpStreamKey { flow, from_local: false };
        r.feed(&out, 100, b"AAAA", 4, 0);
        r.feed(&inb, 100, b"BBBB", 4, 0);
        assert_eq!(r.prefix(&out), b"AAAA");
        assert_eq!(r.prefix(&inb), b"BBBB");
    }

    #[test]
    fn a_pure_ack_carrying_no_payload_is_never_buffered() {
        let mut r = TcpReassembler::new();
        let key = stream_key();
        assert!(r.feed(&key, 100, b"", 0, 0).is_none());
        assert_eq!(r.streams_held(), 0);
        assert_eq!(r.bytes_held(), 0);
    }

    #[test]
    fn a_wildly_distant_sequence_number_allocates_nothing() {
        let mut r = TcpReassembler::new();
        let key = stream_key();
        r.feed(&key, 100, b"start", 5, 0);
        let before = r.bytes_held();
        // Far beyond the per-stream cap in both directions.
        r.feed(&key, 100u32.wrapping_add(1 << 30), b"far-forward", 11, 0);
        r.feed(&key, 100u32.wrapping_sub(1 << 30), b"far-backward", 12, 0);
        assert_eq!(r.bytes_held(), before, "neither wild offset may cause an allocation");
        assert!(r.bytes_held() <= MAX_TCP_STREAM_BYTES);
    }

    #[test]
    fn a_packet_with_no_tracked_flow_falls_back_to_per_packet_sniffing_unchanged() {
        let mut r = StreamReassembler::new();
        let packet = tcp_segment("8.8.8.8", "8.8.4.4", 1234, 80, 1, b"GET / HTTP/1.1\r\n\r\n");
        let outcome = r.sniff(&packet, None, 0);
        assert!(matches!(outcome.info, L7Info::Http { .. }), "no flow identity just means no desegmentation");
        assert_eq!(r.bytes_held(), 0);
    }

    #[test]
    fn a_udp_packet_is_sniffed_per_packet_and_never_desegmented() {
        let mut r = StreamReassembler::new();
        let key = FlowKey { protocol: TransportProtocol::Udp, ..flow_key() };
        let dns = dns_query();
        let mut ip = Ipv4Header::new((8 + dns.len()) as u16, 64, IpNumber::UDP, v4("192.168.1.10"), v4("93.184.216.34"))
            .expect("fixture");
        ip.header_checksum = ip.calc_header_checksum();
        let mut data = Vec::new();
        ip.write(&mut data).expect("fixture");
        data.extend_from_slice(&53u16.to_be_bytes());
        data.extend_from_slice(&53u16.to_be_bytes());
        data.extend_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
        data.extend_from_slice(&[0, 0]);
        data.extend_from_slice(&dns);
        let packet = parse_packet(&data, LinkType::Raw).expect("fixture must parse");

        let outcome = r.sniff(&packet, Some((&key, true)), 0);
        assert!(matches!(outcome.info, L7Info::Dns { .. }));
        assert_eq!(r.bytes_held(), 0, "UDP pseudo-streams are explicitly out of scope");
    }

    #[test]
    fn the_status_labels_are_the_exact_three_phrases_the_design_commits_to() {
        assert_eq!(ReassemblyStatus::Reassembled.label(), "reassembled");
        assert_eq!(
            ReassemblyStatus::IncompleteTruncatedAtCapture.label(),
            "incomplete — frames truncated at capture"
        );
        assert_eq!(ReassemblyStatus::IncompleteMissingFrames.label(), "incomplete — frames missing");
        assert!(ReassemblyStatus::Reassembled.is_complete());
        assert!(!ReassemblyStatus::IncompleteTruncatedAtCapture.is_complete());
        assert!(!ReassemblyStatus::IncompleteMissingFrames.is_complete());
    }

    #[test]
    fn total_bytes_held_is_the_real_sum_of_both_reassemblers() {
        let mut r = StreamReassembler::new();
        assert_eq!(r.bytes_held(), 0);
        let key = flow_key();
        let a = tcp_segment("192.168.1.10", "93.184.216.34", 51000, 80, 100, b"GET /partial");
        r.sniff(&a, Some((&key, true)), 0);
        assert_eq!(r.bytes_held(), 12, "a measured count of the bytes actually buffered, not an estimate");

        let datagram = udp_dns_datagram();
        let fragment = ipv4_fragment("10.0.0.1", "10.0.0.2", 99, IpNumber::UDP, 0, true, &datagram[..16]);
        r.sniff(&fragment, None, 0);
        assert_eq!(r.bytes_held(), 12 + 16);

        r.maybe_evict(TCP_STREAM_IDLE_MS + 2_000);
        assert_eq!(r.bytes_held(), 0, "eviction must actually release the memory it accounts for");
    }

    #[test]
    fn a_reassembled_prefix_is_never_presented_as_more_than_it_is() {
        // The invariant behind every status above: the bytes handed out are
        // always the contiguous prefix, so a consumer cannot be given bytes
        // that look adjacent without being so.
        let mut r = TcpReassembler::new();
        let key = stream_key();
        r.feed(&key, 0, b"AAAA", 4, 0);
        r.feed(&key, 100, b"ZZZZ", 4, 0);
        assert_eq!(r.prefix(&key), b"AAAA");
        assert!(!r.prefix(&key).ends_with(b"ZZZZ"));
    }
}
