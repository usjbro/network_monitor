//! KAN-129 TCP stream graphs (spec
//! `docs/superpowers/specs/2026-11-11-tcp-stream-graphs-design.md` D1–D4):
//! bounded per-flow rings of TCP header samples, per-ACK RTT matching under
//! Karn's rule, and window-scale application.
//!
//! Samples are header metadata. The only payload-derived data is a sample's
//! optional label (KAN-130 spec D2): an SNI, an HTTP method and path without
//! query or fragment, an HTTP status line, or "ServerHello", made
//! display-safe and at most 64 bytes.
//!
//! A ring belongs to one flow. `FlowTable` keeps each flow's `RingHandle` in
//! its own state, so recording costs no extra hash lookup or key clone per
//! packet, and the ring is released whenever the flow leaves the table.
//! A handle whose ring was taken by a more recent flow is *stale*: the flow
//! keeps no ring from then on (spec D1 allocates a ring on a flow's first
//! segment only, which also stops more than 128 interleaved flows from
//! endlessly taking rings from each other).

use std::mem::size_of;

use crate::display_text::display_safe_bytes;
use crate::l7::L7Info;

pub const SAMPLES_PER_RING: usize = 4096;
pub const MAX_RINGS: usize = 128;
pub const MAX_OUTSTANDING_PER_DIR: usize = 256;
/// RFC 7323 §2.3: a shift count above 14 is treated as 14.
pub const MAX_WINDOW_SHIFT: u8 = 14;

/// One captured TCP segment, 32 bytes, fixed layout (spec D2).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct TcpSample {
    /// The frame's own timestamp: capture time live, recorded time in replay.
    pub t_us: u64,
    /// Raw sequence number (see `RingView::seq_base` for the relative base).
    pub seq: u32,
    /// Raw ACK number, meaningful when `flags` has `flag::ACK`.
    pub ack: u32,
    /// Window, scaled when `mark::WIN_SCALED` is set, else raw.
    pub win: u32,
    /// TCP payload length.
    pub len: u16,
    /// `flag::*` bits, at their on-the-wire positions.
    pub flags: u8,
    /// `mark::*` bits.
    pub mark: u8,
    /// RTT for the data this ACK acknowledged, valid when `mark::RTT` is set.
    pub rtt_us: u32,
    _pad: u32,
}

const _: () = assert!(size_of::<TcpSample>() == 32);

/// TCP header flag bits, at the positions they have in the header's flags
/// byte, so `TcpSample::flags` reads like the wire.
pub mod flag {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
}

pub mod mark {
    /// The local host sent this segment.
    pub const OUTBOUND: u8 = 1;
    /// `FlowTable::observe`'s own `is_retransmit` for this segment.
    pub const RETRANSMIT: u8 = 2;
    /// `win` has the negotiated window scale applied.
    pub const WIN_SCALED: u8 = 4;
    /// An ACK-bearing segment advertising a zero window.
    pub const ZERO_WINDOW: u8 = 8;
    /// `rtt_us` holds an RTT sample.
    pub const RTT: u8 = 16;
}

/// Ring indices `0..HEAD_SAMPLES` are pinned: a flow's handshake stays
/// visible after the rolling buffer has overwritten it (KAN-130 spec D2 (b)).
pub const HEAD_SAMPLES: usize = 16;
/// Labels per ring, pinned head labels included (KAN-130 spec D2 (a)).
pub const MAX_LABELS_PER_RING: usize = 32;
/// Label text bytes, printable ASCII only.
pub const LABEL_TEXT_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LabelKind {
    TlsClientHello,
    TlsServerHello,
    HttpRequest,
    HttpResponse,
}

/// A short, display-safe description of what one sampled segment carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SampleLabel {
    /// The ring index of the labelled sample.
    pub index: u64,
    pub kind: LabelKind,
    len: u8,
    text: [u8; LABEL_TEXT_BYTES],
}

impl SampleLabel {
    /// `text` comes from `label_for` and is already display-safe; anything
    /// that is not printable ASCII, and anything past `LABEL_TEXT_BYTES`, is
    /// still refused here, so `text()` can never return anything else.
    fn new(index: u64, kind: LabelKind, text: &str) -> Self {
        let mut bytes = [0u8; LABEL_TEXT_BYTES];
        let mut len = 0;
        for b in text
            .bytes()
            .take_while(|b| b.is_ascii_graphic() || *b == b' ')
            .take(LABEL_TEXT_BYTES)
        {
            bytes[len] = b;
            len += 1;
        }
        SampleLabel {
            index,
            kind,
            len: len as u8,
            text: bytes,
        }
    }

    /// Always printable ASCII, at most `LABEL_TEXT_BYTES`.
    pub fn text(&self) -> &str {
        std::str::from_utf8(&self.text[..usize::from(self.len)]).expect("printable ASCII")
    }
}

/// The first bytes of a TLS record carrying a ServerHello: content type 22
/// (handshake), a version major of 3, and handshake type 2. Nothing past the
/// sixth byte is read.
pub fn is_tls_server_hello_start(payload: &[u8]) -> bool {
    payload.len() >= 6 && payload[0] == 22 && payload[1] == 3 && payload[5] == 2
}

/// The label for one sampled segment (KAN-130 plan Task 1), from the L7
/// decode the capture loop already did and, for a ServerHello, the segment's
/// first six payload bytes. `None` for an unlabelled segment.
///
/// The query and fragment of an HTTP path are dropped: they often carry
/// tokens. The reason phrase arrives already redacted (`l7.rs`). For a
/// message the capture loop reassembled from several segments, the label
/// goes on the segment that completed it, which is where the decode is
/// reported.
pub fn label_for(l7: &L7Info, payload: &[u8]) -> Option<(LabelKind, String)> {
    let (kind, text) = match l7 {
        L7Info::TlsClientHello { sni, .. } => (
            LabelKind::TlsClientHello,
            format!("ClientHello (SNI: {sni})"),
        ),
        _ if is_tls_server_hello_start(payload) => {
            (LabelKind::TlsServerHello, "ServerHello".to_string())
        }
        L7Info::Http { method, path } => {
            let path = path.split(['?', '#']).next().unwrap_or("");
            (LabelKind::HttpRequest, format!("HTTP {method} {path}"))
        }
        L7Info::HttpResponse { status, reason, .. } => (
            LabelKind::HttpResponse,
            match reason {
                Some(reason) => format!("HTTP {status} {reason}"),
                None => format!("HTTP {status}"),
            },
        ),
        _ => return None,
    };
    Some((kind, display_safe_bytes(&text, LABEL_TEXT_BYTES)))
}

/// What `FlowTable` hands over for one TCP segment.
#[derive(Clone, Copy, Debug, Default)]
pub struct SegmentObservation {
    pub t_us: u64,
    pub outbound: bool,
    pub seq: u32,
    pub ack: u32,
    pub raw_win: u16,
    pub len: u16,
    pub flags: u8,
    pub retransmit: bool,
    /// The window-scale option's shift count, present only on a SYN or
    /// SYN-ACK that carried the option (unclamped, as on the wire).
    pub wscale_option: Option<u8>,
}

/// A flow's claim on one ring. `Copy`, so it lives in `FlowState`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingHandle {
    slot: usize,
    counter: u64,
}

impl RingHandle {
    /// The generation counter (the second half of `RingView::generation`).
    pub fn counter(&self) -> u64 {
        self.counter
    }
}

/// A copy of part of one ring, taken under the flow lock (plan P2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingView {
    /// `(epoch, counter)`, rendered on the wire as `"<epoch hex>:<counter>"`.
    pub generation: (u64, u64),
    /// Index of the oldest sample still held.
    pub first_index: u64,
    /// Index of `samples[0]`: `max(from_index, first_index)`, at most
    /// `next_index`.
    pub start_index: u64,
    /// Index the next recorded sample will get.
    pub next_index: u64,
    /// Both the SYN and the SYN-ACK of this flow were captured.
    pub handshake_seen: bool,
    /// `(local, remote)` shift counts, clamped, when scaling was negotiated
    /// in a captured handshake. `None` means windows are raw.
    pub window_scale: Option<(u8, u8)>,
    /// `(outbound, inbound)` sequence base: the ISN when that direction's
    /// SYN was captured, otherwise its first seen sequence number.
    pub seq_base: (u32, u32),
    /// Both bases are ISNs.
    pub relative_to_isn: bool,
    pub samples: Vec<TcpSample>,
    /// Index of `head[0]` when `head` is non-empty.
    pub head_start_index: u64,
    /// Pinned head samples the rolling buffer no longer holds, from
    /// `max(from_index, 0)` up to the first held index (KAN-130 plan P2), so
    /// no sample appears in both `head` and `samples`.
    pub head: Vec<TcpSample>,
    /// Labels on samples in `head` or `samples`, in index order.
    pub labels: Vec<SampleLabel>,
}

/// A sequence number relative to `base`, across the 2^32 wrap.
pub fn relative_seq(seq: u32, base: u32) -> u32 {
    seq.wrapping_sub(base)
}

/// Reserved bytes per ring, counted by capacity (spec D1/D3): the sample
/// buffer, both directions' outstanding-data tables (12 bytes an entry,
/// kept as parallel `u32`/`u64` arrays so no padding is added), and the
/// ring's own fixed fields.
pub const RING_RESERVED_BYTES: usize = SAMPLES_PER_RING * size_of::<TcpSample>()
    + 2 * MAX_OUTSTANDING_PER_DIR * (size_of::<u32>() + size_of::<u64>())
    + size_of::<Ring>();

// Spec D1/D3: 4 096 × 32 B of samples and 2 × 256 × 12 B of RTT state; KAN-130
// D2: the 16-sample head (inline in `Ring`) and 32 labels of at most 80 B
// (inline in `Ring`); plus a small fixed overhead.
const _: () = assert!(size_of::<Option<SampleLabel>>() <= 80);
const RING_BASE_BYTES: usize =
    4096 * 32 + 2 * 256 * 12 + 16 * 32 + 32 * size_of::<Option<SampleLabel>>();
const _: () = assert!(RING_RESERVED_BYTES >= RING_BASE_BYTES);
const _: () = assert!(RING_RESERVED_BYTES < RING_BASE_BYTES + 1024);

pub struct TcpSampleStore {
    epoch: u64,
    /// Incremented for every ring handed out; never reset, so a generation
    /// is never repeated within one agent process.
    counter: u64,
    /// At most `MAX_RINGS`. `None` is a released slot, reused before the
    /// table grows.
    slots: Vec<Option<Ring>>,
    live: usize,
    recycled: u64,
}

struct Ring {
    counter: u64,
    samples: Box<[TcpSample]>,
    next_index: u64,
    last_t_us: u64,
    /// Indexed by `outbound as usize`: `[inbound, outbound]`.
    dirs: [Direction; 2],
    /// Copies of samples `0..HEAD_SAMPLES`, never overwritten (KAN-130 D2 (b)).
    head: [TcpSample; HEAD_SAMPLES],
    /// Unordered; `None` is a free slot. Labels below `HEAD_SAMPLES` are
    /// pinned with the head (KAN-130 plan P3).
    labels: [Option<SampleLabel>; MAX_LABELS_PER_RING],
}

#[derive(Default)]
struct Direction {
    base: Option<u32>,
    base_is_isn: bool,
    /// The first SYN-flagged segment this direction sent.
    syn: Option<SynSeen>,
    outstanding: Outstanding,
}

#[derive(Clone, Copy)]
struct SynSeen {
    with_ack: bool,
    wscale: Option<u8>,
}

/// Outstanding data sent in one direction, oldest first: `(end_seq, t_us)`
/// kept as parallel arrays (12 bytes an entry). A circular buffer of
/// `MAX_OUTSTANDING_PER_DIR`; a push into a full table drops the oldest.
struct Outstanding {
    end_seq: Box<[u32]>,
    t_us: Box<[u64]>,
    head: usize,
    len: usize,
}

impl Default for Outstanding {
    fn default() -> Self {
        Outstanding {
            end_seq: vec![0; MAX_OUTSTANDING_PER_DIR].into_boxed_slice(),
            t_us: vec![0; MAX_OUTSTANDING_PER_DIR].into_boxed_slice(),
            head: 0,
            len: 0,
        }
    }
}

/// `a` is strictly after `b` in sequence space (RFC 1982 serial
/// arithmetic, as `flow.rs`'s retransmit detection does it).
pub(crate) fn seq_after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

impl Outstanding {
    fn at(&self, i: usize) -> usize {
        (self.head + i) % MAX_OUTSTANDING_PER_DIR
    }

    fn push(&mut self, end_seq: u32, t_us: u64) {
        if self.len == MAX_OUTSTANDING_PER_DIR {
            self.head = self.at(1);
            self.len -= 1;
        }
        let i = self.at(self.len);
        self.end_seq[i] = end_seq;
        self.t_us[i] = t_us;
        self.len += 1;
    }

    /// Removes every entry the cumulative `ack` covers and returns the send
    /// time of the newest of them, or `None` when it covers none (a
    /// duplicate or partial ACK).
    fn acknowledge(&mut self, ack: u32) -> Option<u64> {
        let mut newest = None;
        while self.len > 0 && !seq_after(self.end_seq[self.head], ack) {
            newest = Some(self.t_us[self.head]);
            self.head = self.at(1);
            self.len -= 1;
        }
        newest
    }

    /// Karn's rule: a retransmission starting at `seq` makes any later ACK
    /// of the bytes from `seq` on ambiguous, so every entry ending after
    /// `seq` is discarded. Entries are pushed in sequence order (only
    /// non-retransmitted segments are, and those advance `max_seq_seen`), so
    /// they are a suffix. Entries past the retransmitted range go too, as
    /// spec D3 requires: their cumulative ACK usually waits for the
    /// retransmission to fill the hole, so their RTT would be inflated.
    /// That costs RTT samples, never gives a wrong one.
    fn discard_from(&mut self, seq: u32) {
        while self.len > 0 && seq_after(self.end_seq[self.at(self.len - 1)], seq) {
            self.len -= 1;
        }
    }

    fn reset(&mut self) {
        self.head = 0;
        self.len = 0;
    }
}

impl Ring {
    fn new(counter: u64) -> Self {
        Ring {
            counter,
            samples: vec![TcpSample::default(); SAMPLES_PER_RING].into_boxed_slice(),
            next_index: 0,
            last_t_us: 0,
            dirs: [Direction::default(), Direction::default()],
            head: [TcpSample::default(); HEAD_SAMPLES],
            labels: [None; MAX_LABELS_PER_RING],
        }
    }

    /// Reuses the allocations for a new flow.
    fn reset(&mut self, counter: u64) {
        self.counter = counter;
        self.next_index = 0;
        self.last_t_us = 0;
        for dir in &mut self.dirs {
            dir.base = None;
            dir.base_is_isn = false;
            dir.syn = None;
            dir.outstanding.reset();
        }
        self.head = [TcpSample::default(); HEAD_SAMPLES];
        self.labels = [None; MAX_LABELS_PER_RING];
    }

    /// A SYN one way and a SYN-ACK the other were both captured.
    fn handshake(&self) -> Option<(SynSeen, SynSeen)> {
        match (self.dirs[1].syn, self.dirs[0].syn) {
            (Some(local), Some(remote)) if local.with_ack != remote.with_ack => {
                Some((local, remote))
            }
            _ => None,
        }
    }

    /// RFC 7323 §2.2: scaling is in effect only when both the SYN and the
    /// SYN-ACK carried the option.
    fn window_scale(&self) -> Option<(u8, u8)> {
        let (local, remote) = self.handshake()?;
        Some((
            local.wscale?.min(MAX_WINDOW_SHIFT),
            remote.wscale?.min(MAX_WINDOW_SHIFT),
        ))
    }

    fn record(&mut self, obs: SegmentObservation, label: Option<(LabelKind, String)>) {
        let d = usize::from(obs.outbound);
        let syn = obs.flags & flag::SYN != 0;
        let has_ack = obs.flags & flag::ACK != 0;
        self.last_t_us = obs.t_us;

        let dir = &mut self.dirs[d];
        if dir.base.is_none() {
            dir.base = Some(obs.seq);
            dir.base_is_isn = syn;
        }
        if syn && dir.syn.is_none() {
            dir.syn = Some(SynSeen {
                with_ack: has_ack,
                wscale: obs.wscale_option,
            });
        }

        let mut mark = 0;
        if obs.outbound {
            mark |= mark::OUTBOUND;
        }
        if obs.retransmit {
            mark |= mark::RETRANSMIT;
        }
        let mut win = u32::from(obs.raw_win);
        // A SYN or SYN-ACK's own window is never scaled (RFC 7323 §2.2).
        if !syn {
            if let Some((local, remote)) = self.window_scale() {
                win <<= if obs.outbound { local } else { remote };
                mark |= mark::WIN_SCALED;
            }
        }
        if has_ack && obs.raw_win == 0 {
            mark |= mark::ZERO_WINDOW;
        }

        let mut rtt_us = 0;
        if has_ack {
            if let Some(sent) = self.dirs[1 - d].outstanding.acknowledge(obs.ack) {
                rtt_us = u32::try_from(obs.t_us.saturating_sub(sent)).unwrap_or(u32::MAX);
                mark |= mark::RTT;
            }
        }
        if obs.len > 0 {
            let outstanding = &mut self.dirs[d].outstanding;
            if obs.retransmit {
                outstanding.discard_from(obs.seq);
            } else {
                outstanding.push(obs.seq.wrapping_add(u32::from(obs.len)), obs.t_us);
            }
        }

        let index = self.next_index;
        let sample = TcpSample {
            t_us: obs.t_us,
            seq: obs.seq,
            ack: obs.ack,
            win,
            len: obs.len,
            flags: obs.flags,
            mark,
            rtt_us,
            _pad: 0,
        };
        self.samples[(index % SAMPLES_PER_RING as u64) as usize] = sample;
        if let Some(slot) = self.head.get_mut(index as usize) {
            *slot = sample;
        }
        self.next_index += 1;
        if let Some((kind, text)) = label {
            self.add_label(SampleLabel::new(index, kind, &text));
        }
    }

    fn is_pinned(index: u64) -> bool {
        index < HEAD_SAMPLES as u64
    }

    /// Frees the slots of rolling labels whose sample was overwritten, then
    /// stores `label`, evicting the lowest-index rolling label if the table
    /// is still full. At most `HEAD_SAMPLES` labels are pinned, so a full
    /// table always holds a rolling one.
    fn add_label(&mut self, label: SampleLabel) {
        let first_index = self.first_index();
        for slot in &mut self.labels {
            if slot.is_some_and(|l| !Self::is_pinned(l.index) && l.index < first_index) {
                *slot = None;
            }
        }
        let free = self.labels.iter().position(Option::is_none).or_else(|| {
            self.labels
                .iter()
                .enumerate()
                .filter_map(|(i, l)| {
                    l.filter(|l| !Self::is_pinned(l.index))
                        .map(|l| (i, l.index))
                })
                .min_by_key(|&(_, index)| index)
                .map(|(i, _)| i)
        });
        if let Some(i) = free {
            self.labels[i] = Some(label);
        }
    }

    /// The number of head samples recorded so far.
    fn head_len(&self) -> u64 {
        self.next_index.min(HEAD_SAMPLES as u64)
    }

    fn first_index(&self) -> u64 {
        self.next_index.saturating_sub(SAMPLES_PER_RING as u64)
    }
}

impl TcpSampleStore {
    /// Allocates nothing: a ring is allocated on its flow's first segment.
    pub fn new(epoch: u64) -> Self {
        TcpSampleStore {
            epoch,
            counter: 0,
            slots: Vec::new(),
            live: 0,
            recycled: 0,
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    fn ring(&self, handle: RingHandle) -> Option<&Ring> {
        self.slots
            .get(handle.slot)?
            .as_ref()
            .filter(|ring| ring.counter == handle.counter)
    }

    /// A slot for a new ring: a released one, a new one below `MAX_RINGS`,
    /// or the ring of the flow with the oldest last sample.
    fn allocate(&mut self) -> RingHandle {
        self.counter += 1;
        let counter = self.counter;
        let slot = if let Some(free) = self.slots.iter().position(Option::is_none) {
            self.slots[free] = Some(Ring::new(counter));
            self.live += 1;
            free
        } else if self.slots.len() < MAX_RINGS {
            self.slots.push(Some(Ring::new(counter)));
            self.live += 1;
            self.slots.len() - 1
        } else {
            let (lru, _) = self
                .slots
                .iter()
                .enumerate()
                .filter_map(|(i, ring)| ring.as_ref().map(|ring| (i, ring.last_t_us)))
                .min_by_key(|&(_, last_t_us)| last_t_us)
                .expect("MAX_RINGS live rings");
            if let Some(ring) = self.slots[lru].as_mut() {
                ring.reset(counter);
            }
            self.recycled += 1;
            lru
        };
        RingHandle { slot, counter }
    }

    /// Records one segment. `handle` is the flow's claim: `None` on the
    /// flow's first segment (a ring is allocated), stale once its ring was
    /// taken by a more recent flow (nothing is recorded).
    pub fn record(&mut self, handle: &mut Option<RingHandle>, obs: SegmentObservation) {
        self.record_labelled(handle, obs, None);
    }

    /// `record`, with the segment's label, if any (KAN-130).
    pub fn record_labelled(
        &mut self,
        handle: &mut Option<RingHandle>,
        obs: SegmentObservation,
        label: Option<(LabelKind, String)>,
    ) {
        let current = match *handle {
            Some(current) => current,
            None => *handle.insert(self.allocate()),
        };
        if let Some(Some(ring)) = self.slots.get_mut(current.slot) {
            if ring.counter == current.counter {
                ring.record(obs, label);
            }
        }
    }

    /// The flow left the table; its ring is freed. A stale handle frees
    /// nothing.
    pub fn release(&mut self, handle: RingHandle) {
        if self.ring(handle).is_some() {
            self.slots[handle.slot] = None;
            self.live -= 1;
        }
    }

    /// Interface switch: every ring is freed. Epoch and counter are kept,
    /// so a ring allocated afterwards never repeats a generation.
    pub fn clear(&mut self) {
        self.slots = Vec::new();
        self.live = 0;
    }

    /// Up to `max` samples from `from_index` (or the oldest held, if that is
    /// later). `None` for a stale or released handle.
    pub fn view(&self, handle: RingHandle, from_index: u64, max: usize) -> Option<RingView> {
        let ring = self.ring(handle)?;
        let start = from_index.max(ring.first_index()).min(ring.next_index);
        let end = start.saturating_add(max as u64).min(ring.next_index);
        let samples = (start..end)
            .map(|i| ring.samples[(i % SAMPLES_PER_RING as u64) as usize])
            .collect();
        // KAN-130 plan P2: only the part of the head the ring no longer holds.
        let head_range = if from_index < ring.head_len() && ring.first_index() > from_index {
            from_index..ring.head_len().min(ring.first_index())
        } else {
            0..0
        };
        let head = head_range.clone().map(|i| ring.head[i as usize]).collect();
        let mut labels: Vec<SampleLabel> = ring
            .labels
            .iter()
            .flatten()
            .filter(|l| head_range.contains(&l.index) || (start..end).contains(&l.index))
            .copied()
            .collect();
        labels.sort_by_key(|l| l.index);
        let [inbound, outbound] = &ring.dirs;
        Some(RingView {
            generation: (self.epoch, ring.counter),
            first_index: ring.first_index(),
            start_index: start,
            next_index: ring.next_index,
            handshake_seen: ring.handshake().is_some(),
            window_scale: ring.window_scale(),
            seq_base: (outbound.base.unwrap_or(0), inbound.base.unwrap_or(0)),
            relative_to_isn: outbound.base_is_isn && inbound.base_is_isn,
            samples,
            head_start_index: head_range.start,
            head,
            labels,
        })
    }

    /// Reserved capacity of every live ring (spec D1 "counted by reserved
    /// capacity, not length").
    pub fn reserved_bytes(&self) -> usize {
        self.live * RING_RESERVED_BYTES
    }

    pub fn rings(&self) -> usize {
        self.live
    }

    pub fn recycled(&self) -> u64 {
        self.recycled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPOCH: u64 = 0xfeed_beef;

    fn seg(
        t_us: u64,
        outbound: bool,
        seq: u32,
        ack: u32,
        flags: u8,
        len: u16,
        win: u16,
    ) -> SegmentObservation {
        SegmentObservation {
            t_us,
            outbound,
            seq,
            ack,
            raw_win: win,
            len,
            flags,
            retransmit: false,
            wscale_option: None,
        }
    }

    fn data(t_us: u64, outbound: bool, seq: u32, len: u16) -> SegmentObservation {
        seg(t_us, outbound, seq, 0, flag::ACK, len, 1000)
    }

    fn ack(t_us: u64, outbound: bool, ack: u32) -> SegmentObservation {
        seg(t_us, outbound, 0, ack, flag::ACK, 0, 1000)
    }

    fn all(store: &TcpSampleStore, handle: Option<RingHandle>) -> RingView {
        store
            .view(handle.expect("ring allocated"), 0, SAMPLES_PER_RING)
            .expect("live ring")
    }

    fn last(store: &TcpSampleStore, handle: Option<RingHandle>) -> TcpSample {
        *all(store, handle).samples.last().expect("a sample")
    }

    #[test]
    fn a_new_store_allocates_nothing() {
        let store = TcpSampleStore::new(EPOCH);
        assert_eq!(
            (store.rings(), store.reserved_bytes(), store.recycled()),
            (0, 0, 0)
        );
    }

    #[test]
    fn a_ring_wraps_at_its_capacity_keeping_the_newest_samples_in_order() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        let total = SAMPLES_PER_RING as u32 + 10;
        for i in 0..total {
            store.record(&mut h, data(u64::from(i), true, i * 10, 10));
        }
        let view = all(&store, h);
        assert_eq!((view.first_index, view.next_index), (10, u64::from(total)));
        assert_eq!(view.samples.len(), SAMPLES_PER_RING);
        assert_eq!(
            view.samples[0].seq, 100,
            "the 11th sample is now the oldest"
        );
        assert!(
            view.samples.windows(2).all(|w| w[1].t_us == w[0].t_us + 1),
            "in recording order"
        );

        // Asking from before the horizon starts at the oldest sample held.
        let from_old = store.view(h.unwrap(), 3, 5).unwrap();
        assert_eq!(
            from_old.samples.iter().map(|s| s.t_us).collect::<Vec<_>>(),
            vec![10, 11, 12, 13, 14]
        );
        // Paging from the middle, and the tail.
        let tail = store.view(h.unwrap(), u64::from(total) - 2, 100).unwrap();
        assert_eq!(
            tail.samples.iter().map(|s| s.t_us).collect::<Vec<_>>(),
            vec![4104, 4105]
        );
        // At or past next_index: nothing yet, but the indexes still report.
        let ahead = store.view(h.unwrap(), u64::from(total) + 7, 100).unwrap();
        assert!(ahead.samples.is_empty());
        assert_eq!(ahead.next_index, u64::from(total));
    }

    #[test]
    fn the_ring_at_its_exact_capacity_has_not_dropped_anything() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        for i in 0..SAMPLES_PER_RING as u32 {
            store.record(&mut h, data(u64::from(i), true, i, 1));
        }
        let view = all(&store, h);
        assert_eq!(
            (view.first_index, view.next_index),
            (0, SAMPLES_PER_RING as u64)
        );
        assert_eq!(view.samples.first().unwrap().t_us, 0);
    }

    #[test]
    fn the_129th_flow_takes_the_ring_of_the_least_recently_active_flow() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut handles: Vec<Option<RingHandle>> = vec![None; MAX_RINGS];
        for (i, h) in handles.iter_mut().enumerate() {
            store.record(h, data(i as u64, true, 1, 1));
        }
        assert_eq!((store.rings(), store.recycled()), (MAX_RINGS, 0));
        // Flow 0 was allocated first but is the most recently active now, so
        // the least recently active is flow 1, not the oldest allocation.
        store.record(&mut handles[0], data(10_000, true, 2, 1));

        let mut newcomer = None;
        store.record(&mut newcomer, data(10_001, true, 1, 1));
        assert_eq!((store.rings(), store.recycled()), (MAX_RINGS, 1));
        assert!(
            store.view(handles[1].unwrap(), 0, 10).is_none(),
            "flow 1 lost its ring"
        );
        assert!(
            store.view(handles[0].unwrap(), 0, 10).is_some(),
            "flow 0 kept its ring"
        );
        let view = all(&store, newcomer);
        assert_eq!(view.samples.len(), 1, "a recycled ring starts empty");
        assert_eq!(view.first_index, 0);
        assert_eq!(view.generation.0, EPOCH);
        assert_ne!(
            newcomer.unwrap().counter(),
            handles[1].unwrap().counter(),
            "new generation"
        );

        // The flow that lost its ring does not take one back.
        store.record(&mut handles[1], data(10_002, true, 2, 1));
        assert_eq!((store.rings(), store.recycled()), (MAX_RINGS, 1));
        assert!(store.view(handles[1].unwrap(), 0, 10).is_none());
    }

    #[test]
    fn every_new_ring_gets_a_new_generation_even_in_a_reused_slot() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut first = None;
        store.record(&mut first, data(1, true, 1, 1));
        store.release(first.unwrap());
        let mut second = None;
        store.record(&mut second, data(2, true, 1, 1));
        assert!(second.unwrap().counter() > first.unwrap().counter());
        assert!(
            store.view(first.unwrap(), 0, 10).is_none(),
            "the old handle is stale"
        );
        store.clear();
        let mut third = None;
        store.record(&mut third, data(3, true, 1, 1));
        assert!(
            third.unwrap().counter() > second.unwrap().counter(),
            "clear keeps the counter"
        );
        assert_eq!(
            all(&store, third).generation,
            (EPOCH, third.unwrap().counter())
        );
    }

    #[test]
    fn release_and_clear_free_rings_and_their_reserved_bytes() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut a = None;
        let mut b = None;
        store.record(&mut a, data(1, true, 1, 1));
        store.record(&mut b, data(2, true, 1, 1));
        assert_eq!(store.rings(), 2);
        assert_eq!(store.reserved_bytes(), 2 * RING_RESERVED_BYTES);
        store.release(a.unwrap());
        assert_eq!(
            (store.rings(), store.reserved_bytes()),
            (1, RING_RESERVED_BYTES)
        );
        // Releasing twice (or a stale handle) changes nothing.
        store.release(a.unwrap());
        assert_eq!(store.rings(), 1);
        store.clear();
        assert_eq!((store.rings(), store.reserved_bytes()), (0, 0));
        assert!(store.view(b.unwrap(), 0, 10).is_none());
    }

    #[test]
    fn the_worst_case_is_128_rings() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut handles = vec![None; MAX_RINGS + 5];
        for (i, h) in handles.iter_mut().enumerate() {
            store.record(h, data(i as u64, true, 1, 1));
        }
        assert_eq!(store.rings(), MAX_RINGS);
        assert_eq!(store.recycled(), 5);
        assert_eq!(store.reserved_bytes(), MAX_RINGS * RING_RESERVED_BYTES);
        assert!(
            store.reserved_bytes() < 17 * 1024 * 1024 + 512 * 1024,
            "16 MiB + RTT state + KAN-130 head and labels (384 KiB) + overhead"
        );
    }

    #[test]
    fn sequence_base_is_the_isn_when_both_syns_were_captured() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        store.record(&mut h, seg(1, true, 0xffff_fff0, 0, flag::SYN, 0, 64_240));
        store.record(
            &mut h,
            seg(
                2,
                false,
                7_000,
                0xffff_fff1,
                flag::SYN | flag::ACK,
                0,
                65_535,
            ),
        );
        store.record(&mut h, data(3, true, 0xffff_fff1, 100));
        let view = all(&store, h);
        assert!(view.handshake_seen && view.relative_to_isn);
        assert_eq!(view.seq_base, (0xffff_fff0, 7_000));
        // Wrapping: 100 bytes after an ISN 16 below 2^32.
        assert_eq!(
            relative_seq(0xffff_fff1u32.wrapping_add(100), view.seq_base.0),
            101
        );
    }

    #[test]
    fn sequence_base_is_the_first_seen_number_when_the_handshake_was_missed() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        store.record(&mut h, data(1, true, 5_000, 10));
        store.record(&mut h, data(2, true, 5_010, 10));
        store.record(&mut h, data(3, false, 90, 10));
        let view = all(&store, h);
        assert!(!view.handshake_seen && !view.relative_to_isn);
        assert_eq!(view.seq_base, (5_000, 90));
    }

    #[test]
    fn one_syn_alone_is_not_relative_to_isn() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        store.record(&mut h, seg(1, true, 50, 0, flag::SYN, 0, 64_240));
        store.record(&mut h, data(2, false, 900, 10));
        let view = all(&store, h);
        assert!(!view.handshake_seen && !view.relative_to_isn);
        assert_eq!(view.seq_base, (50, 900));
    }

    #[test]
    fn an_ack_covering_outstanding_data_carries_the_newest_covered_rtt() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        store.record(&mut h, data(1_000, true, 100, 50)); // ends 150
        store.record(&mut h, data(1_200, true, 150, 50)); // ends 200
        store.record(&mut h, data(1_300, true, 200, 50)); // ends 250
        store.record(&mut h, ack(5_000, false, 200));
        let sample = last(&store, h);
        assert_eq!(sample.mark & mark::RTT, mark::RTT);
        assert_eq!(sample.rtt_us, 5_000 - 1_200, "newest entry the ACK covers");
        assert_eq!(sample.mark & mark::OUTBOUND, 0, "the ACK is inbound");
        // The covered entries are gone: the remaining one is measured next.
        store.record(&mut h, ack(6_000, false, 250));
        assert_eq!(last(&store, h).rtt_us, 6_000 - 1_300);
        // Data samples themselves never carry an RTT.
        assert!(all(&store, h).samples[..3]
            .iter()
            .all(|s| s.mark & mark::RTT == 0 && s.rtt_us == 0));
    }

    #[test]
    fn a_duplicate_or_partial_ack_yields_no_rtt() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        store.record(&mut h, data(1_000, true, 100, 50));
        store.record(&mut h, ack(2_000, false, 150));
        assert_eq!(last(&store, h).mark & mark::RTT, mark::RTT);
        store.record(&mut h, ack(3_000, false, 150));
        let dup = last(&store, h);
        assert_eq!((dup.mark & mark::RTT, dup.rtt_us), (0, 0), "duplicate ACK");
        store.record(&mut h, data(4_000, true, 150, 50));
        store.record(&mut h, ack(5_000, false, 170));
        assert_eq!(
            last(&store, h).mark & mark::RTT,
            0,
            "partial ACK covers no whole segment"
        );
    }

    #[test]
    fn rtt_matching_is_per_direction() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        store.record(&mut h, data(1_000, false, 100, 50)); // inbound data
        store.record(&mut h, ack(1_400, false, 150)); // inbound ACK: wrong direction
        assert_eq!(last(&store, h).mark & mark::RTT, 0);
        store.record(&mut h, ack(1_500, true, 150)); // this host's ACK
        let s = last(&store, h);
        assert_eq!((s.mark & mark::RTT, s.rtt_us), (mark::RTT, 500));
        assert_eq!(s.mark & mark::OUTBOUND, mark::OUTBOUND);
    }

    #[test]
    fn karn_a_retransmission_discards_the_entry_it_overlaps() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        store.record(&mut h, data(1_000, true, 100, 50));
        let mut again = data(3_000, true, 100, 50);
        again.retransmit = true;
        store.record(&mut h, again);
        assert_eq!(last(&store, h).mark & mark::RETRANSMIT, mark::RETRANSMIT);
        store.record(&mut h, ack(3_100, false, 150));
        assert_eq!(
            last(&store, h).mark & mark::RTT,
            0,
            "ambiguous: original or retransmission"
        );
        // Data sent after the retransmission is measured again.
        store.record(&mut h, data(4_000, true, 150, 50));
        store.record(&mut h, ack(4_300, false, 200));
        assert_eq!(last(&store, h).rtt_us, 300);
    }

    #[test]
    fn karn_keeps_entries_before_the_retransmitted_range() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        store.record(&mut h, data(1_000, true, 100, 50)); // ends 150
        store.record(&mut h, data(1_100, true, 150, 50)); // ends 200
        let mut again = data(3_000, true, 150, 50);
        again.retransmit = true;
        store.record(&mut h, again);
        store.record(&mut h, ack(3_500, false, 150));
        assert_eq!(
            last(&store, h).rtt_us,
            2_500,
            "the first segment was not retransmitted"
        );
        store.record(&mut h, ack(3_600, false, 200));
        assert_eq!(last(&store, h).mark & mark::RTT, 0);
    }

    #[test]
    fn karn_discards_entries_sent_after_the_retransmitted_range() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        store.record(&mut h, data(1_000, true, 100, 50)); // ends 150, lost
        store.record(&mut h, data(1_100, true, 150, 50)); // ends 200
        let mut again = data(3_000, true, 100, 50);
        again.retransmit = true;
        store.record(&mut h, again);
        // The cumulative ACK for 150..200 waited for the retransmission, so
        // timing it from 1 100 would give an inflated RTT.
        store.record(&mut h, ack(3_100, false, 200));
        assert_eq!(
            last(&store, h).mark & mark::RTT,
            0,
            "a later entry is discarded too"
        );
    }

    #[test]
    fn the_outstanding_table_holds_256_entries_per_direction() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        // 257 segments: the first one's entry is evicted.
        for i in 0..=MAX_OUTSTANDING_PER_DIR as u32 {
            store.record(&mut h, data(1_000 + u64::from(i), true, 100 + i * 10, 10));
        }
        store.record(&mut h, ack(9_000, false, 110)); // covers only the evicted entry
        assert_eq!(
            last(&store, h).mark & mark::RTT,
            0,
            "its entry was dropped, not the ACK's correctness"
        );
        store.record(&mut h, ack(9_100, false, 120)); // covers the oldest kept entry
        assert_eq!(last(&store, h).rtt_us, 9_100 - 1_001);
    }

    #[test]
    fn exactly_256_outstanding_entries_are_all_kept() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        for i in 0..MAX_OUTSTANDING_PER_DIR as u32 {
            store.record(&mut h, data(1_000 + u64::from(i), true, 100 + i * 10, 10));
        }
        store.record(&mut h, ack(9_000, false, 110));
        assert_eq!(last(&store, h).rtt_us, 8_000);
    }

    #[test]
    fn rtt_compares_sequence_numbers_across_the_wrap() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        store.record(&mut h, data(1_000, true, 0xffff_ffe0, 0x40)); // ends 0x20, wrapped
        store.record(&mut h, ack(1_250, false, 0x10));
        assert_eq!(last(&store, h).mark & mark::RTT, 0, "not yet covered");
        store.record(&mut h, ack(1_300, false, 0x20));
        assert_eq!(last(&store, h).rtt_us, 300);
    }

    fn handshake(
        store: &mut TcpSampleStore,
        h: &mut Option<RingHandle>,
        local: Option<u8>,
        remote: Option<u8>,
    ) {
        let mut syn = seg(1, true, 1_000, 0, flag::SYN, 0, 64_240);
        syn.wscale_option = local;
        store.record(h, syn);
        let mut syn_ack = seg(2, false, 9_000, 1_001, flag::SYN | flag::ACK, 0, 65_535);
        syn_ack.wscale_option = remote;
        store.record(h, syn_ack);
    }

    #[test]
    fn window_scale_applies_when_both_handshake_segments_carried_it() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        handshake(&mut store, &mut h, Some(7), Some(9));
        store.record(&mut h, seg(3, true, 1_001, 9_001, flag::ACK, 0, 502));
        store.record(&mut h, seg(4, false, 9_001, 1_001, flag::ACK, 0, 300));
        let view = all(&store, h);
        assert_eq!(view.window_scale, Some((7, 9)));
        let s = &view.samples;
        assert_eq!(
            (s[0].win, s[0].mark & mark::WIN_SCALED),
            (64_240, 0),
            "a SYN's own window is never scaled"
        );
        assert_eq!(
            (s[1].win, s[1].mark & mark::WIN_SCALED),
            (65_535, 0),
            "nor a SYN-ACK's"
        );
        assert_eq!(
            (s[2].win, s[2].mark & mark::WIN_SCALED),
            (502 << 7, mark::WIN_SCALED),
            "local shift"
        );
        assert_eq!(
            (s[3].win, s[3].mark & mark::WIN_SCALED),
            (300 << 9, mark::WIN_SCALED),
            "remote shift"
        );
    }

    #[test]
    fn one_sided_window_scale_is_not_negotiated() {
        for (local, remote) in [(Some(7), None), (None, Some(7)), (None, None)] {
            let mut store = TcpSampleStore::new(EPOCH);
            let mut h = None;
            handshake(&mut store, &mut h, local, remote);
            store.record(&mut h, seg(3, true, 1_001, 9_001, flag::ACK, 0, 502));
            let view = all(&store, h);
            assert!(view.handshake_seen);
            assert_eq!(view.window_scale, None, "{local:?}/{remote:?}");
            let s = view.samples.last().unwrap();
            assert_eq!((s.win, s.mark & mark::WIN_SCALED), (502, 0));
        }
    }

    #[test]
    fn a_shift_above_14_is_clamped_to_14() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        handshake(&mut store, &mut h, Some(15), Some(14));
        store.record(&mut h, seg(3, true, 1_001, 9_001, flag::ACK, 0, 0xffff));
        let view = all(&store, h);
        assert_eq!(view.window_scale, Some((14, 14)));
        assert_eq!(view.samples.last().unwrap().win, 0xffff << 14);
    }

    #[test]
    fn a_midstream_join_leaves_windows_raw() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        store.record(&mut h, seg(1, true, 1_001, 9_001, flag::ACK, 0, 502));
        let view = all(&store, h);
        assert!(!view.handshake_seen);
        assert_eq!(view.window_scale, None);
        assert_eq!(
            (view.samples[0].win, view.samples[0].mark & mark::WIN_SCALED),
            (502, 0)
        );
    }

    #[test]
    fn two_syns_in_the_same_direction_are_not_a_handshake() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        let mut syn = seg(1, true, 1_000, 0, flag::SYN, 0, 64_240);
        syn.wscale_option = Some(7);
        store.record(&mut h, syn);
        let mut syn_ack_wrong_way = seg(2, true, 1_000, 0, flag::SYN | flag::ACK, 0, 64_240);
        syn_ack_wrong_way.wscale_option = Some(7);
        store.record(&mut h, syn_ack_wrong_way);
        let mut late_syn = seg(3, false, 9_000, 0, flag::SYN, 0, 65_535);
        late_syn.wscale_option = Some(7);
        store.record(&mut h, late_syn);
        let view = all(&store, h);
        assert!(
            !view.handshake_seen,
            "a SYN each way is a simultaneous open, not SYN + SYN-ACK"
        );
        assert_eq!(view.window_scale, None);
    }

    #[test]
    fn zero_window_is_marked_only_on_an_ack_bearing_segment() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        store.record(&mut h, seg(1, true, 1, 0, flag::SYN, 0, 0));
        store.record(&mut h, seg(2, false, 5, 2, flag::ACK, 0, 0));
        store.record(&mut h, seg(3, false, 5, 2, flag::ACK, 0, 1));
        store.record(&mut h, seg(4, false, 5, 2, flag::RST, 0, 0));
        let marks: Vec<u8> = all(&store, h)
            .samples
            .iter()
            .map(|s| s.mark & mark::ZERO_WINDOW)
            .collect();
        assert_eq!(marks, vec![0, mark::ZERO_WINDOW, 0, 0]);
    }

    #[test]
    fn a_sample_copies_the_segment_header_fields() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        let mut obs = seg(77, true, 11, 22, flag::ACK | flag::PSH, 33, 44);
        obs.retransmit = true;
        store.record(&mut h, obs);
        let s = last(&store, h);
        assert_eq!(
            (s.t_us, s.seq, s.ack, s.win, s.len, s.flags),
            (77, 11, 22, 44, 33, flag::ACK | flag::PSH)
        );
        assert_eq!(s.mark, mark::OUTBOUND | mark::RETRANSMIT);
    }

    // ---- KAN-130 Task 1: labels, ServerHello check, pinned head ----

    fn hello(sni: &str) -> L7Info {
        L7Info::TlsClientHello {
            sni: sni.to_string(),
            ja3: None,
            ja3_label: None,
            client_random: None,
            sni_offset: 0,
            sni_len: sni.len(),
        }
    }

    const SERVER_HELLO: [u8; 6] = [22, 3, 3, 0, 0x7a, 2];

    #[test]
    fn server_hello_check_needs_exactly_its_three_bytes() {
        assert!(is_tls_server_hello_start(&SERVER_HELLO));
        assert!(is_tls_server_hello_start(&[22, 3, 1, 0, 0x40, 2, 0, 0]));
        for len in 0..SERVER_HELLO.len() {
            assert!(
                !is_tls_server_hello_start(&SERVER_HELLO[..len]),
                "length {len}"
            );
        }
        for (i, delta) in [(0usize, 1u8), (1, 1), (5, 1), (0, 255), (5, 255)] {
            let mut p = SERVER_HELLO;
            p[i] = p[i].wrapping_add(delta);
            assert!(!is_tls_server_hello_start(&p), "byte {i} changed");
        }
        // A ClientHello (type 1) and an application-data record (type 23).
        assert!(!is_tls_server_hello_start(&[22, 3, 1, 0, 0x40, 1]));
        assert!(!is_tls_server_hello_start(&[23, 3, 3, 0, 0x40, 2]));
    }

    #[test]
    fn label_for_each_kind() {
        assert_eq!(
            label_for(&hello("example.com"), &[]),
            Some((
                LabelKind::TlsClientHello,
                "ClientHello (SNI: example.com)".to_string()
            ))
        );
        assert_eq!(
            label_for(&L7Info::None, &SERVER_HELLO),
            Some((LabelKind::TlsServerHello, "ServerHello".to_string()))
        );
        let get = L7Info::Http {
            method: "GET".into(),
            path: "/a/b?token=secret#frag".into(),
        };
        assert_eq!(
            label_for(&get, b"GET /a/b"),
            Some((LabelKind::HttpRequest, "HTTP GET /a/b".to_string()))
        );
        let frag = L7Info::Http {
            method: "GET".into(),
            path: "/x#y?z".into(),
        };
        assert_eq!(
            label_for(&frag, &[]),
            Some((LabelKind::HttpRequest, "HTTP GET /x".to_string()))
        );
        let ok = L7Info::HttpResponse {
            status: "200".into(),
            reason: Some("OK".into()),
            content_type: None,
            content_length: None,
        };
        assert_eq!(
            label_for(&ok, &[]),
            Some((LabelKind::HttpResponse, "HTTP 200 OK".to_string()))
        );
        let bare = L7Info::HttpResponse {
            status: "204".into(),
            reason: None,
            content_type: None,
            content_length: None,
        };
        assert_eq!(
            label_for(&bare, &[]),
            Some((LabelKind::HttpResponse, "HTTP 204".to_string()))
        );
    }

    #[test]
    fn label_for_leaves_other_segments_unlabelled() {
        assert_eq!(label_for(&L7Info::None, &[]), None);
        assert_eq!(label_for(&L7Info::None, b"hello"), None);
        let dns = L7Info::Dns {
            query_name: "example.com".into(),
            id: 1,
            qtype: 1,
        };
        assert_eq!(label_for(&dns, &[]), None);
    }

    #[test]
    fn label_text_is_escaped_and_cut_at_64_bytes() {
        let evil = L7Info::Http {
            method: "GET".into(),
            path: "/a\u{1b}[31m\u{202e}é".into(),
        };
        assert_eq!(
            label_for(&evil, &[]).unwrap().1,
            "HTTP GET /a\\u{1b}[31m\\u{202e}\\u{e9}"
        );
        let long = L7Info::Http {
            method: "GET".into(),
            path: format!("/{}", "p".repeat(200)),
        };
        let text = label_for(&long, &[]).unwrap().1;
        assert_eq!(text.len(), LABEL_TEXT_BYTES);
        assert!(text.ends_with("..."));
    }

    fn labelled(n: u64) -> Option<(LabelKind, String)> {
        Some((LabelKind::HttpRequest, format!("HTTP GET /{n}")))
    }

    fn label_indices(view: &RingView) -> Vec<u64> {
        view.labels.iter().map(|l| l.index).collect()
    }

    #[test]
    fn a_label_is_recorded_against_its_samples_index() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        store.record(&mut h, data(0, true, 0, 10));
        store.record_labelled(&mut h, data(1, true, 10, 10), labelled(1));
        store.record(&mut h, data(2, true, 20, 10));
        let view = all(&store, h);
        assert_eq!(label_indices(&view), vec![1]);
        assert_eq!(view.labels[0].kind, LabelKind::HttpRequest);
        assert_eq!(view.labels[0].text(), "HTTP GET /1");
        // A page that does not cover index 1 carries no label.
        let page = store.view(h.unwrap(), 2, SAMPLES_PER_RING).unwrap();
        assert!(page.labels.is_empty());
    }

    #[test]
    fn the_label_table_holds_32_and_evicts_the_oldest_rolling_label() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        // Two head labels, then 31 rolling ones: 33 in all.
        for i in 0..(HEAD_SAMPLES as u64 + 31) {
            let label = if i < 2 || i >= HEAD_SAMPLES as u64 {
                labelled(i)
            } else {
                None
            };
            store.record_labelled(&mut h, data(i, true, (i * 10) as u32, 10), label);
        }
        let view = all(&store, h);
        assert_eq!(view.labels.len(), MAX_LABELS_PER_RING);
        let mut expected = vec![0, 1];
        expected.extend((HEAD_SAMPLES as u64 + 1)..(HEAD_SAMPLES as u64 + 31));
        assert_eq!(
            label_indices(&view),
            expected,
            "label 16, the oldest rolling one, went first"
        );
    }

    #[test]
    fn head_labels_survive_any_number_of_later_labels() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        for i in 0..10_000u64 {
            let label = if i == 3 || i >= HEAD_SAMPLES as u64 {
                labelled(i)
            } else {
                None
            };
            store.record_labelled(&mut h, data(i, true, (i * 10) as u32, 10), label);
        }
        let view = all(&store, h);
        assert_eq!(view.labels.first().map(|l| l.index), Some(3));
        assert_eq!(view.labels.len(), MAX_LABELS_PER_RING);
        assert_eq!(view.labels.last().map(|l| l.index), Some(9_999));
    }

    #[test]
    fn a_rolling_label_goes_with_its_overwritten_sample() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        store.record_labelled(&mut h, data(0, true, 0, 10), None);
        for i in 1..20u64 {
            store.record(&mut h, data(i, true, (i * 10) as u32, 10));
        }
        store.record_labelled(&mut h, data(20, true, 200, 10), labelled(20));
        for i in 21..(SAMPLES_PER_RING as u64 + 30) {
            store.record(&mut h, data(i, true, (i * 10) as u32, 10));
        }
        // Index 20 was overwritten (first_index is 30).
        let view = all(&store, h);
        assert_eq!(view.first_index, 30);
        assert!(view.labels.is_empty());
    }

    #[test]
    fn a_released_or_cleared_ring_keeps_no_labels_or_head() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        store.record_labelled(&mut h, data(0, true, 0, 10), labelled(0));
        store.release(h.unwrap());
        let mut h2 = None;
        store.record(&mut h2, data(1, true, 0, 10));
        let view = all(&store, h2);
        assert!(view.labels.is_empty() && view.head.is_empty());
        store.record_labelled(&mut h2, data(2, true, 10, 10), labelled(1));
        store.clear();
        let mut h3 = None;
        store.record(&mut h3, data(3, true, 0, 10));
        assert!(all(&store, h3).labels.is_empty());
    }

    #[test]
    fn a_recycled_ring_starts_with_no_labels_or_head() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut handles = Vec::new();
        for f in 0..MAX_RINGS as u64 {
            let mut h = None;
            store.record_labelled(&mut h, data(f, true, 0, 10), labelled(f));
            handles.push(h);
        }
        let mut fresh = None;
        store.record(&mut fresh, data(1_000, true, 0, 10));
        assert_eq!(store.recycled(), 1);
        let view = all(&store, fresh);
        assert!(view.labels.is_empty());
        assert_eq!(view.next_index, 1);
    }

    #[test]
    fn the_head_is_sent_only_once_the_ring_no_longer_holds_it() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        let total = SAMPLES_PER_RING as u64 + 100;
        for i in 0..total {
            store.record(&mut h, data(i, true, (i * 10) as u32, 10));
        }
        let view = store.view(h.unwrap(), 0, SAMPLES_PER_RING).unwrap();
        assert_eq!(view.first_index, 100);
        assert_eq!(view.head_start_index, 0);
        assert_eq!(view.head.len(), HEAD_SAMPLES);
        assert_eq!(
            view.head.iter().map(|s| s.t_us).collect::<Vec<_>>(),
            (0..16).collect::<Vec<_>>()
        );
        assert_eq!(view.start_index, 100);
        assert_eq!(view.samples.first().map(|s| s.t_us), Some(100));

        let tail = store.view(h.unwrap(), 10, SAMPLES_PER_RING).unwrap();
        assert_eq!((tail.head_start_index, tail.head.len()), (10, 6));

        let later = store.view(h.unwrap(), 16, SAMPLES_PER_RING).unwrap();
        assert!(later.head.is_empty());
    }

    #[test]
    fn before_the_ring_wraps_the_head_is_ordinary_samples() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        for i in 0..40u64 {
            store.record(&mut h, data(i, true, (i * 10) as u32, 10));
        }
        let view = all(&store, h);
        assert!(view.head.is_empty());
        assert_eq!(view.samples.len(), 40);
    }

    #[test]
    fn a_partly_overwritten_head_sends_only_the_part_the_ring_lost() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        for i in 0..(SAMPLES_PER_RING as u64 + 5) {
            store.record(&mut h, data(i, true, (i * 10) as u32, 10));
        }
        let view = all(&store, h);
        assert_eq!(view.first_index, 5);
        assert_eq!(
            view.head.iter().map(|s| s.t_us).collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4]
        );
        assert_eq!(view.samples.first().map(|s| s.t_us), Some(5));
    }

    #[test]
    fn a_short_flow_has_a_short_head() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        for i in 0..3u64 {
            store.record(&mut h, data(i, true, (i * 10) as u32, 10));
        }
        let view = all(&store, h);
        assert!(view.head.is_empty());
        assert_eq!(view.samples.len(), 3);
    }

    #[test]
    fn head_labels_are_sent_with_the_head() {
        let mut store = TcpSampleStore::new(EPOCH);
        let mut h = None;
        store.record_labelled(&mut h, data(0, true, 0, 10), None);
        store.record_labelled(
            &mut h,
            data(1, true, 10, 10),
            Some((LabelKind::TlsClientHello, "ClientHello (SNI: a)".into())),
        );
        for i in 2..(SAMPLES_PER_RING as u64 + 50) {
            store.record(&mut h, data(i, true, (i * 10) as u32, 10));
        }
        let view = all(&store, h);
        assert_eq!(label_indices(&view), vec![1]);
        assert_eq!(view.labels[0].text(), "ClientHello (SNI: a)");
    }

    #[test]
    fn reserved_bytes_include_the_head_and_label_table() {
        assert!(
            RING_RESERVED_BYTES
                >= SAMPLES_PER_RING * 32
                    + 2 * 256 * 12
                    + HEAD_SAMPLES * 32
                    + MAX_LABELS_PER_RING * size_of::<SampleLabel>()
        );
        assert!(size_of::<SampleLabel>() <= 80);
    }
}
