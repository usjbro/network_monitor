//! IO-graph series counting (JAM-18, spec
//! `docs/superpowers/specs/2026-11-10-io-graph-design.md`, plan Task 2).
//!
//! Two halves:
//! - [`IoSeriesShared`]: the agent's single shared series set. The control
//!   task replaces it by compare-and-swap on `(epoch, revision)`; the
//!   capture thread notices a change through one atomic generation load per
//!   frame.
//! - [`Accumulator`]: owned by the capture thread. It counts every frame that
//!   matches each series into 100 ms buckets keyed by the frame's own
//!   timestamp, closes buckets once the closing clock passes their end plus
//!   the grace period, attributes late frames to their original bucket, and
//!   hands closed ranges ([`Piece`]s) to the emitter, which turns them into
//!   bounded `io_buckets` lines ([`build_lines`]).
//!
//! Nothing here allocates per frame while no series is configured: the
//! capture loop only holds an `Accumulator` while the set is non-empty, and
//! the field tree is built inside [`Accumulator::observe_with`] only then.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use crate::display_filter::{self, Compiled};
use crate::fields::Field;
use crate::wire::{
    IoAggregate, IoAggregateJson, IoBucket, IoBucketJson, IoBucketsJson, IoLossJson, IoNotObservedJson,
    IoSeriesBucketsJson, IoSeriesDefJson, IoSeriesEntryJson, IoSeriesErrorJson, IoSeriesStatusJson,
};

pub const MAX_IO_SERIES: usize = 8;
pub const MAX_ID_LEN: usize = 32;
pub const MAX_FILTER_UTF16: usize = display_filter::MAX_SOURCE_LENGTH;
pub const BUCKET_MS: u64 = 100;
pub const GRACE_MS: u64 = 500;
/// Closed-but-unsent pieces the capture thread may queue for the emitter.
/// Every piece covers at least one 100 ms bucket of capture time, so this is
/// at least an hour of buckets per series (spec D4).
pub const PIECE_CHANNEL_CAPACITY: usize = 36_000;
pub const MAX_LATE_BUCKETS_PER_MESSAGE: usize = 256;
pub const MAX_LINE_BYTES: usize = 64 * 1024;
/// At most this many `io_buckets` lines per emitter tick, so a fast replay
/// cannot flood the relay's broadcast queue. Replay applies backpressure
/// instead (the capture thread blocks on a full piece channel).
pub const MAX_LINES_PER_TICK: usize = 8;
/// Bound on the backlog spans kept between ticks; beyond it, the last span
/// is widened instead of growing the list.
pub const MAX_BACKLOG_SPANS: usize = 64;
/// Aggregate functions a series may name (spec D10).
pub const AGGREGATE_FNS: [&str; 4] = ["sum", "min", "max", "avg"];
/// Longest aggregate field path accepted.
pub const MAX_AGGREGATE_FIELD_LEN: usize = 64;

pub struct CompiledSeries {
    pub id: String,
    pub filter: String,
    pub compiled: Result<Compiled, display_filter::Error>,
    /// As sent, echoed in `io_series_status`.
    pub aggregate: Option<IoAggregateJson>,
    /// The aggregate's field path, lower-cased for lookup; `None` for a
    /// plain series.
    pub aggregate_path: Option<String>,
}

/// Compiles one series. An aggregate naming a field that is not a uint is
/// a compile error on that series (shown, never counted), like a filter
/// error; the rest of the set is unaffected.
pub fn compile_series(def: &IoSeriesDefJson) -> CompiledSeries {
    let mut compiled = display_filter::compile_for_series(&def.filter);
    let aggregate_path = def.aggregate.as_ref().map(|a| a.field.to_ascii_lowercase());
    if let (Ok(_), Some(a)) = (&compiled, &def.aggregate) {
        if !crate::fields::is_uint_path(&a.field) {
            compiled = Err(display_filter::Error {
                message: format!("{} needs a uint field; {} is not one", a.func, a.field),
                token: a.field.clone(),
                position: 0,
            });
        }
    }
    CompiledSeries { id: def.id.clone(), filter: def.filter.clone(), compiled, aggregate: def.aggregate.clone(), aggregate_path }
}

pub struct SeriesSet {
    pub revision: u32,
    pub series: Vec<CompiledSeries>,
}

impl SeriesSet {
    /// True when at least one series compiled, i.e. there is something to
    /// count. A set of only failing series is shown but never counted.
    pub fn is_countable(&self) -> bool {
        self.series.iter().any(|s| s.compiled.is_ok())
    }
}

struct State {
    set: Arc<SeriesSet>,
    replay_waiting: bool,
    ever_countable: bool,
}

pub struct IoSeriesShared {
    epoch: String,
    state: Mutex<State>,
    generation: AtomicU64,
    started: Condvar,
}

fn is_hex_token(value: &str) -> bool {
    (8..=32).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_valid_id(id: &str) -> bool {
    (1..=MAX_ID_LEN).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Validates a `set_io_series` request as a whole (spec D3). Any failure
/// rejects the entire request; the previous set stays in force.
pub fn validate_request(base_epoch: &str, request_id: &str, series: &[IoSeriesDefJson]) -> Result<(), &'static str> {
    if !is_hex_token(request_id) {
        return Err("invalid_request_id");
    }
    if !is_hex_token(base_epoch) {
        return Err("invalid_epoch");
    }
    if series.len() > MAX_IO_SERIES {
        return Err("too_many_series");
    }
    for (i, s) in series.iter().enumerate() {
        if !is_valid_id(&s.id) {
            return Err("invalid_id");
        }
        if series[..i].iter().any(|earlier| earlier.id == s.id) {
            return Err("duplicate_id");
        }
        if s.filter.chars().map(char::len_utf16).sum::<usize>() > MAX_FILTER_UTF16 {
            return Err("filter_too_long");
        }
        if let Some(a) = &s.aggregate {
            let field_ok = (1..=MAX_AGGREGATE_FIELD_LEN).contains(&a.field.len())
                && a.field.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.');
            if !AGGREGATE_FNS.contains(&a.func.as_str()) || !field_ok {
                return Err("invalid_aggregate");
            }
        }
    }
    Ok(())
}

impl IoSeriesShared {
    pub fn new(epoch: String) -> Self {
        IoSeriesShared {
            epoch,
            state: Mutex::new(State {
                set: Arc::new(SeriesSet { revision: 0, series: Vec::new() }),
                replay_waiting: false,
                ever_countable: false,
            }),
            generation: AtomicU64::new(0),
            started: Condvar::new(),
        }
    }

    /// A fresh random 64-bit epoch: a new agent process is a new history.
    pub fn with_random_epoch() -> Self {
        use ring::rand::{SecureRandom, SystemRandom};
        let mut bytes = [0u8; 8];
        SystemRandom::new().fill(&mut bytes).expect("system random source");
        Self::new(hex::encode(bytes))
    }

    pub fn epoch(&self) -> &str {
        &self.epoch
    }

    /// One atomic load: the capture thread compares this per frame.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub fn snapshot(&self) -> (u64, Arc<SeriesSet>) {
        let state = self.state.lock().unwrap();
        (self.generation.load(Ordering::Acquire), state.set.clone())
    }

    pub fn status(&self) -> IoSeriesStatusJson {
        let state = self.state.lock().unwrap();
        Self::status_of(&self.epoch, &state, None, None)
    }

    fn status_of(epoch: &str, state: &State, request_id: Option<&str>, rejected: Option<&str>) -> IoSeriesStatusJson {
        IoSeriesStatusJson {
            revision: state.set.revision,
            request_id: request_id.map(str::to_string),
            epoch: epoch.to_string(),
            replay_waiting: state.replay_waiting,
            rejected: rejected.map(str::to_string),
            series: state
                .set
                .series
                .iter()
                .map(|s| IoSeriesEntryJson {
                    id: s.id.clone(),
                    filter: s.filter.clone(),
                    ok: s.compiled.is_ok(),
                    error: s.compiled.as_ref().err().map(|e| IoSeriesErrorJson {
                        message: e.message.clone(),
                        token: e.token.clone(),
                        position: e.position,
                    }),
                    aggregate: s.aggregate.clone(),
                })
                .collect(),
        }
    }

    /// Applies a `set_io_series`. Validation, the compare-and-swap and the
    /// swap itself happen under one lock, so two concurrent edits from the
    /// same base can never both be accepted.
    pub fn apply(
        &self,
        base_epoch: &str,
        base_revision: u32,
        request_id: &str,
        series: &[IoSeriesDefJson],
    ) -> IoSeriesStatusJson {
        let mut state = self.state.lock().unwrap();
        if let Err(reason) = validate_request(base_epoch, request_id, series) {
            return Self::status_of(&self.epoch, &state, Some(request_id), Some(reason));
        }
        if base_epoch != self.epoch || base_revision != state.set.revision {
            return Self::status_of(&self.epoch, &state, Some(request_id), Some("conflict"));
        }
        let compiled = series.iter().map(compile_series).collect();
        let set = SeriesSet { revision: state.set.revision.wrapping_add(1), series: compiled };
        if set.is_countable() {
            // Accepting a countable set is what releases the replay barrier,
            // so the status answering it already says "not waiting".
            state.ever_countable = true;
            state.replay_waiting = false;
            self.started.notify_all();
        }
        state.set = Arc::new(set);
        self.generation.fetch_add(1, Ordering::AcqRel);
        Self::status_of(&self.epoch, &state, Some(request_id), None)
    }

    /// Replay start barrier (`REPLAY_WAIT_FOR_IO_SERIES=1`): blocks the
    /// calling (replay reader) thread until a countable set has been
    /// accepted. `replay_waiting` is reported while it waits.
    pub fn wait_for_first_countable_set(&self) {
        let mut state = self.state.lock().unwrap();
        if state.ever_countable {
            return;
        }
        state.replay_waiting = true;
        while !state.ever_countable {
            state = self.started.wait(state).unwrap();
        }
        state.replay_waiting = false;
    }

    pub fn replay_waiting(&self) -> bool {
        self.state.lock().unwrap().replay_waiting
    }
}

/// Parses `REPLAY_WAIT_FOR_IO_SERIES`. Unset or empty means off; `1` means
/// on (valid only with `REPLAY_FILE`); anything else is a startup error.
pub fn parse_replay_wait(value: Option<&str>, replaying: bool) -> Result<bool, String> {
    match value {
        None | Some("") => Ok(false),
        Some("1") if replaying => Ok(true),
        Some("1") => Err("REPLAY_WAIT_FOR_IO_SERIES=1 is only valid with REPLAY_FILE".to_string()),
        Some(other) => Err(format!("REPLAY_WAIT_FOR_IO_SERIES must be unset or 1, not {other:?}")),
    }
}

/// A closed range of capture time for one revision, handed to the emitter.
#[derive(Debug, Clone, PartialEq)]
pub struct Piece {
    pub revision: u32,
    /// The series ids of `revision`, in order (shared, not copied).
    pub ids: Arc<Vec<String>>,
    pub covered_from_ms: u64,
    pub covered_to_ms: u64,
    pub not_observed: Vec<IoNotObservedJson>,
    /// Distinct frames whose results this piece carries (on-time frames in
    /// its closed buckets plus late frames), matched or not. Unlike the
    /// per-series counts, it does not depend on the configured filters, so it
    /// is what a dropped piece reports as lost (`evaluationSkipped`).
    pub frames: u64,
    /// Indexed like the set's series.
    pub series: Vec<SeriesPiece>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SeriesPiece {
    pub buckets: Vec<IoBucket>,
    /// For an aggregate series, one entry per bucket in `buckets` (same
    /// order); empty for a plain series.
    pub aggregates: Vec<IoAggregate>,
    pub late_buckets: BTreeMap<u64, (u64, u64)>,
}

impl Piece {
    pub fn packets(&self) -> u64 {
        self.series
            .iter()
            .flat_map(|s| s.buckets.iter().map(|b| b[1]).chain(s.late_buckets.values().map(|v| v.0)))
            .sum()
    }
}

fn bucket_start(ms: u64) -> u64 {
    ms - ms % BUCKET_MS
}

/// One series' on-time totals in an open bucket.
#[derive(Debug, Clone, Copy, Default)]
struct Counts {
    packets: u64,
    bytes: u64,
    aggregate: IoAggregate,
}

pub struct Accumulator {
    pub generation: u64,
    set: Arc<SeriesSet>,
    ids: Arc<Vec<String>>,
    /// Open buckets: start -> (frames observed, per-series totals).
    open: BTreeMap<u64, (u64, Vec<Counts>)>,
    /// Late frames since the last piece, matched or not.
    late_frames: u64,
    /// Everything before this boundary is closed and reported.
    covered_to_ms: Option<u64>,
    /// Newest frame timestamp seen; never moves backwards.
    high_water_ms: u64,
    late: Vec<BTreeMap<u64, (u64, u64)>>,
    not_observed: Vec<IoNotObservedJson>,
}

impl Accumulator {
    pub fn new(generation: u64, set: Arc<SeriesSet>) -> Self {
        let n = set.series.len();
        let ids = Arc::new(set.series.iter().map(|s| s.id.clone()).collect());
        Accumulator {
            generation,
            set,
            ids,
            open: BTreeMap::new(),
            late_frames: 0,
            covered_to_ms: None,
            high_water_ms: 0,
            late: vec![BTreeMap::new(); n],
            not_observed: Vec::new(),
        }
    }

    pub fn revision(&self) -> u32 {
        self.set.revision
    }

    pub fn high_water_ms(&self) -> u64 {
        self.high_water_ms
    }

    /// Counts one parsed frame. `build_fields` is only called here, so no
    /// field tree is built for any frame while no accumulator exists.
    /// `frame_len` is the captured length (`frame.len`); bytes are counted
    /// as `original_len`, the on-wire length.
    pub fn observe_with(
        &mut self,
        frame_ts_us: u64,
        original_len: u32,
        frame_len: u32,
        build_fields: impl FnOnce() -> Vec<Field>,
    ) {
        let fields = build_fields();
        let matches: Vec<bool> = self
            .set
            .series
            .iter()
            .map(|s| s.compiled.as_ref().is_ok_and(|c| c.matches(&fields, frame_len)))
            .collect();
        // The aggregate value is read only for a matching frame, from the
        // same field tree (first occurrence, spec D10).
        let values: Vec<Option<u64>> = self
            .set
            .series
            .iter()
            .zip(&matches)
            .map(|(s, matched)| match (&s.aggregate_path, matched) {
                (Some(path), true) => display_filter::uint_value(&fields, frame_len, path),
                _ => None,
            })
            .collect();
        self.observe_values(frame_ts_us, original_len, &matches, &values);
    }

    pub fn observe_matches(&mut self, frame_ts_us: u64, original_len: u32, matches: &[bool]) {
        self.observe_values(frame_ts_us, original_len, matches, &[]);
    }

    /// Counts one frame. `values[i]` is series `i`'s aggregate field value
    /// for this frame, if it has one (missing entries mean none). A late
    /// frame's value is not aggregated: like its count, it never joins an
    /// on-time bucket.
    pub fn observe_values(&mut self, frame_ts_us: u64, original_len: u32, matches: &[bool], values: &[Option<u64>]) {
        let ts_ms = frame_ts_us / 1000;
        let start = bucket_start(ts_ms);
        self.high_water_ms = self.high_water_ms.max(ts_ms);
        let covered = *self.covered_to_ms.get_or_insert(start);
        let bytes = u64::from(original_len);
        if start < covered {
            self.late_frames += 1;
            for (i, matched) in matches.iter().enumerate() {
                if *matched {
                    let e = self.late[i].entry(start).or_insert((0, 0));
                    e.0 += 1;
                    e.1 += bytes;
                }
            }
            return;
        }
        let n = self.set.series.len();
        let (frames, counts) = self.open.entry(start).or_insert_with(|| (0, vec![Counts::default(); n]));
        *frames += 1;
        for (i, matched) in matches.iter().enumerate() {
            if *matched {
                counts[i].packets += 1;
                counts[i].bytes += bytes;
                if let Some(Some(value)) = values.get(i) {
                    counts[i].aggregate.add(*value);
                }
            }
        }
    }

    /// Records a span in which frames were not observed (spec D5/D6).
    pub fn mark_not_observed(&mut self, from_ms: u64, to_ms: u64, reason: &'static str) {
        self.not_observed.push(IoNotObservedJson { from_ms, to_ms, reason });
    }

    /// Closes every bucket that ends at least `GRACE_MS` before
    /// `clock_ms`. Returns a piece when the covered range advanced or there
    /// are late frames or not-observed spans to report.
    pub fn advance(&mut self, clock_ms: u64) -> Option<Piece> {
        // Bucket b closes once clock_ms >= b + BUCKET_MS + GRACE_MS, so the
        // first bucket still open starts at bucket_start(clock_ms - GRACE_MS).
        let boundary = bucket_start(clock_ms.saturating_sub(GRACE_MS));
        let covered = *self.covered_to_ms.get_or_insert(boundary);
        if boundary <= covered {
            return self.pending_only(covered);
        }
        Some(self.close_until(covered, boundary))
    }

    /// End of source (replay EOF, replay error, device gone) or a series
    /// change: closes every open bucket now, so no tail is lost.
    pub fn finalize(&mut self) -> Option<Piece> {
        let covered = self.covered_to_ms?;
        // Cover through the bucket of the newest frame seen, matched or not:
        // a tail of frames that match no series is observed zero-count time,
        // not unknown time. Never move back past coverage already reported
        // (the live idle clock may have advanced it).
        let newest_bucket_end = bucket_start(self.high_water_ms) + BUCKET_MS;
        let boundary = self
            .open
            .keys()
            .next_back()
            .map(|start| start + BUCKET_MS)
            .unwrap_or(covered)
            .max(newest_bucket_end)
            .max(covered);
        if boundary <= covered {
            return self.pending_only(covered);
        }
        Some(self.close_until(covered, boundary))
    }

    fn pending_only(&mut self, covered: u64) -> Option<Piece> {
        if self.late_frames == 0 && self.late.iter().all(BTreeMap::is_empty) && self.not_observed.is_empty() {
            return None;
        }
        Some(self.close_until(covered, covered))
    }

    fn close_until(&mut self, from: u64, to: u64) -> Piece {
        let n = self.set.series.len();
        let mut series: Vec<SeriesPiece> = vec![SeriesPiece::default(); n];
        let still_open = self.open.split_off(&to);
        let mut frames = std::mem::take(&mut self.late_frames);
        for (start, (bucket_frames, counts)) in std::mem::replace(&mut self.open, still_open) {
            frames += bucket_frames;
            for (i, c) in counts.into_iter().enumerate() {
                if c.packets > 0 {
                    series[i].buckets.push([start, c.packets, c.bytes]);
                    if self.set.series[i].aggregate_path.is_some() {
                        series[i].aggregates.push(c.aggregate);
                    }
                }
            }
        }
        for (i, late) in self.late.iter_mut().enumerate() {
            series[i].late_buckets = std::mem::take(late);
        }
        self.covered_to_ms = Some(to);
        Piece {
            revision: self.set.revision,
            ids: self.ids.clone(),
            covered_from_ms: from,
            covered_to_ms: to,
            not_observed: std::mem::take(&mut self.not_observed),
            frames,
            series,
        }
    }
}

/// Brings the capture thread's accumulator in line with the shared set.
/// Costs one atomic load when nothing changed. On a change, the old
/// accumulator is finalized (its open buckets are reported under its own
/// revision) and a new one starts if the new set has anything to count.
pub fn sync_accumulator(
    shared: &IoSeriesShared,
    acc: &mut Option<Accumulator>,
    seen_generation: &mut u64,
    send: &mut impl FnMut(Piece),
) {
    if shared.generation() == *seen_generation {
        return;
    }
    if let Some(mut old) = acc.take() {
        if let Some(piece) = old.finalize() {
            send(piece);
        }
    }
    let (generation, set) = shared.snapshot();
    *seen_generation = generation;
    if set.is_countable() {
        *acc = Some(Accumulator::new(generation, set));
    }
}

/// Kernel and interface drop totals across pcap handle replacements. A
/// replaced handle (interface switch, snap length reopen) restarts its own
/// counters at zero, so a delta against the old handle's baseline would
/// silently swallow the new handle's first drops. This keeps process-wide
/// cumulative totals instead.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DropTotals {
    base: (u64, u64),
    last: (u64, u64),
}

impl DropTotals {
    /// Records a stats poll of the current handle; returns the process-wide
    /// `(kernel, interface)` totals.
    pub fn poll(&mut self, dropped: u32, if_dropped: u32) -> (u64, u64) {
        self.last = (u64::from(dropped), u64::from(if_dropped));
        self.totals()
    }

    /// The current handle was replaced: fold its last polled counts into
    /// the base. Drops on the old handle after its last poll are not
    /// observable and are not reported.
    pub fn handle_replaced(&mut self) {
        self.base = (self.base.0 + self.last.0, self.base.1 + self.last.1);
        self.last = (0, 0);
    }

    pub fn totals(&self) -> (u64, u64) {
        (self.base.0 + self.last.0, self.base.1 + self.last.1)
    }
}

/// Loss counters and backlog spans shared between the capture thread and
/// the emitter.
#[derive(Default)]
pub struct IoLossShared {
    pub evaluation_skipped: AtomicU64,
    backlog: Mutex<Vec<(u64, u64)>>,
}

impl IoLossShared {
    /// A live piece could not be queued (the emitter is stalled): its frames
    /// were not delivered and its span is reported as `backlog`.
    pub fn record_backlog(&self, piece: &Piece) {
        self.evaluation_skipped.fetch_add(piece.frames, Ordering::Relaxed);
        let mut spans = self.backlog.lock().unwrap();
        let full = spans.len() >= MAX_BACKLOG_SPANS;
        match spans.last_mut() {
            Some(last) if full || last.1 >= piece.covered_from_ms => {
                last.1 = last.1.max(piece.covered_to_ms);
            }
            _ => spans.push((piece.covered_from_ms, piece.covered_to_ms)),
        }
    }

    pub fn take_backlog(&self) -> Vec<(u64, u64)> {
        std::mem::take(&mut *self.backlog.lock().unwrap())
    }
}

/// Upper bound on one serialized `[startMs, packets, bytes]` entry: three
/// u64s of at most 20 digits, brackets, two inner commas, one separator.
const ENTRY_BYTES: usize = 3 * 20 + 4;
/// Upper bound on one aggregate 7-tuple: six u64s of at most 20 digits, a
/// quoted u128 sum of at most 39 digits, brackets, six commas, a separator.
const AGGREGATE_ENTRY_BYTES: usize = 6 * 20 + (39 + 2) + 9;
const SERIES_OVERHEAD_BYTES: usize = 64 + MAX_ID_LEN;
const NOT_OBSERVED_BYTES: usize = 96;
const MESSAGE_OVERHEAD_BYTES: usize = 512;

struct LineBuilder {
    msg: IoBucketsJson,
    late_scalar: Vec<u64>,
    late_maps: Vec<BTreeMap<u64, (u64, u64)>>,
    estimate: usize,
}

impl LineBuilder {
    fn new(epoch: &str, piece: &Piece, loss: IoLossJson) -> Self {
        let set_ids = piece.ids.as_slice();
        LineBuilder {
            msg: IoBucketsJson {
                revision: piece.revision,
                epoch: epoch.to_string(),
                bucket_ms: BUCKET_MS,
                covered_from_ms: piece.covered_from_ms,
                covered_to_ms: piece.covered_from_ms,
                not_observed: Vec::new(),
                loss,
                series: set_ids
                    .iter()
                    .map(|id| IoSeriesBucketsJson { id: id.clone(), late: 0, late_buckets: Vec::new(), buckets: Vec::new() })
                    .collect(),
            },
            late_scalar: vec![0; set_ids.len()],
            late_maps: vec![BTreeMap::new(); set_ids.len()],
            estimate: MESSAGE_OVERHEAD_BYTES + set_ids.len() * SERIES_OVERHEAD_BYTES,
        }
    }

    fn piece_cost(piece: &Piece) -> usize {
        piece.not_observed.len() * NOT_OBSERVED_BYTES
            + piece
                .series
                .iter()
                .map(|s| {
                    let per_bucket = if s.aggregates.is_empty() { ENTRY_BYTES } else { AGGREGATE_ENTRY_BYTES };
                    s.buckets.len() * per_bucket + s.late_buckets.len() * ENTRY_BYTES
                })
                .sum::<usize>()
    }

    fn fits(&self, piece: &Piece) -> bool {
        self.estimate + Self::piece_cost(piece) <= MAX_LINE_BYTES
    }

    fn push(&mut self, piece: Piece) {
        self.estimate += Self::piece_cost(&piece);
        self.msg.covered_to_ms = piece.covered_to_ms;
        self.msg.not_observed.extend(piece.not_observed);
        for (i, s) in piece.series.into_iter().enumerate() {
            if s.aggregates.is_empty() {
                self.msg.series[i].buckets.extend(s.buckets.into_iter().map(IoBucketJson::Plain));
            } else {
                let entries = s.buckets.into_iter().zip(s.aggregates).map(|(b, a)| IoBucketJson::Aggregate(b, a));
                self.msg.series[i].buckets.extend(entries);
            }
            for (start, (p, b)) in s.late_buckets {
                let e = self.late_maps[i].entry(start).or_insert((0, 0));
                e.0 += p;
                e.1 += b;
            }
        }
    }

    fn finish(mut self) -> String {
        for (i, map) in self.late_maps.into_iter().enumerate() {
            let s = &mut self.msg.series[i];
            for (n, (start, (p, b))) in map.into_iter().enumerate() {
                if n < MAX_LATE_BUCKETS_PER_MESSAGE {
                    s.late_buckets.push([start, p, b]);
                } else {
                    self.late_scalar[i] += p;
                }
            }
            s.late = self.late_scalar[i];
        }
        let line = crate::wire::encode_event(&crate::wire::AgentEvent::IoBuckets { buckets: Box::new(self.msg) });
        debug_assert!(line.len() <= MAX_LINE_BYTES, "io_buckets line {} bytes", line.len());
        line
    }
}

/// Turns queued pieces into `io_buckets` lines, each within
/// `MAX_LINE_BYTES` and holding one revision. `loss` and `backlog` are
/// attached to the first line. A piece is never split or dropped; a piece
/// that would not fit starts the next line. Pieces are consumed only up to
/// `MAX_LINES_PER_TICK` lines; the rest are returned for the next tick.
pub fn build_lines(
    epoch: &str,
    pieces: Vec<Piece>,
    mut loss: IoLossJson,
    backlog: Vec<(u64, u64)>,
) -> (Vec<String>, Vec<Piece>) {
    let mut lines = Vec::new();
    let mut current: Option<LineBuilder> = None;
    let mut backlog = Some(backlog);
    let mut iter = pieces.into_iter();
    while let Some(mut piece) = iter.next() {
        if let Some(spans) = backlog.take() {
            piece.not_observed.extend(spans.into_iter().map(|(from_ms, to_ms)| IoNotObservedJson {
                from_ms,
                to_ms,
                reason: "backlog",
            }));
        }
        let continues = current.as_ref().is_some_and(|b| {
            b.msg.revision == piece.revision && b.msg.covered_to_ms == piece.covered_from_ms && b.fits(&piece)
        });
        if !continues {
            if let Some(done) = current.take() {
                lines.push(done.finish());
                if lines.len() == MAX_LINES_PER_TICK {
                    let mut rest = vec![piece];
                    rest.extend(iter);
                    return (lines, rest);
                }
            }
            current = Some(LineBuilder::new(epoch, &piece, std::mem::take(&mut loss)));
        }
        current.as_mut().unwrap().push(piece);
    }
    if let Some(done) = current {
        lines.push(done.finish());
    }
    (lines, Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fields::{ByteRegion, FieldType, FieldValue};

    fn def(id: &str, filter: &str) -> IoSeriesDefJson {
        IoSeriesDefJson { id: id.into(), filter: filter.into(), aggregate: None }
    }

    fn shared() -> IoSeriesShared {
        IoSeriesShared::new("4be1a07c".into())
    }

    fn uint(path: &str, n: u64) -> Field {
        Field {
            path: path.into(),
            label: path.into(),
            group: None,
            field_type: FieldType::Uint,
            value: Some(FieldValue::Uint(n)),
            region: ByteRegion::Header,
            offset: 0,
            len: 0,
        }
    }

    // ---- compare-and-swap and validation ----

    #[test]
    fn accepts_on_matching_base_and_assigns_the_next_revision() {
        let s = shared();
        let g0 = s.generation();
        let status = s.apply("4be1a07c", 0, "c41f09aa", &[def("all", ""), def("dns", "dns")]);
        assert_eq!(status.rejected, None);
        assert_eq!(status.revision, 1);
        assert_eq!(status.request_id.as_deref(), Some("c41f09aa"));
        assert_eq!(status.series.iter().map(|e| (e.id.as_str(), e.filter.as_str(), e.ok)).collect::<Vec<_>>(),
            vec![("all", "", true), ("dns", "dns", true)]);
        assert_eq!(s.generation(), g0 + 1);
    }

    #[test]
    fn stale_revision_is_a_conflict_and_keeps_the_set() {
        let s = shared();
        s.apply("4be1a07c", 0, "aaaaaaaa", &[def("a", "tcp")]);
        let status = s.apply("4be1a07c", 0, "bbbbbbbb", &[def("b", "udp")]);
        assert_eq!(status.rejected.as_deref(), Some("conflict"));
        assert_eq!(status.revision, 1);
        assert_eq!(status.series[0].id, "a");
    }

    #[test]
    fn stale_epoch_with_a_coinciding_revision_is_a_conflict() {
        // Simulated restart: the new process has a new epoch and its revision
        // has climbed back to 1. An edit built against the old process's
        // revision 1 must not overwrite it.
        let restarted = IoSeriesShared::new("00112233".into());
        restarted.apply("00112233", 0, "aaaaaaaa", &[def("new", "tcp")]);
        let status = restarted.apply("4be1a07c", 1, "bbbbbbbb", &[def("old", "udp")]);
        assert_eq!(status.rejected.as_deref(), Some("conflict"));
        assert_eq!(status.series[0].id, "new");
    }

    #[test]
    fn concurrent_edits_from_the_same_base_accept_exactly_one() {
        let s = Arc::new(shared());
        s.apply("4be1a07c", 0, "aaaaaaaa", &[def("x", "tcp")]);
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let s = s.clone();
                std::thread::spawn(move || s.apply("4be1a07c", 1, &format!("{i:08x}"), &[def("y", "udp")]).rejected)
            })
            .collect();
        let accepted = handles.into_iter().map(|h| h.join().unwrap()).filter(Option::is_none).count();
        assert_eq!(accepted, 1);
        assert_eq!(s.status().revision, 2);
    }

    #[test]
    fn whole_request_rejections_keep_the_previous_set() {
        let s = shared();
        s.apply("4be1a07c", 0, "aaaaaaaa", &[def("keep", "tcp")]);
        let nine: Vec<_> = (0..9).map(|i| def(&format!("s{i}"), "")).collect();
        let eight: Vec<_> = (0..8).map(|i| def(&format!("s{i}"), "")).collect();
        let long = "x".repeat(MAX_FILTER_UTF16 + 1);
        let max = "x".repeat(MAX_FILTER_UTF16);
        let cases: Vec<(Vec<IoSeriesDefJson>, &str, &str, &str)> = vec![
            (nine, "4be1a07c", "aaaaaaab", "too_many_series"),
            (vec![def("a", ""), def("a", "")], "4be1a07c", "aaaaaaab", "duplicate_id"),
            (vec![def("Bad", "")], "4be1a07c", "aaaaaaab", "invalid_id"),
            (vec![def("", "")], "4be1a07c", "aaaaaaab", "invalid_id"),
            (vec![def(&"a".repeat(33), "")], "4be1a07c", "aaaaaaab", "invalid_id"),
            (vec![def("a", &long)], "4be1a07c", "aaaaaaab", "filter_too_long"),
            (vec![def("a", "")], "4be1a07c", "nothex!!", "invalid_request_id"),
            (vec![def("a", "")], "4be1a07c", "abc", "invalid_request_id"),
            (vec![def("a", "")], "not-hex", "aaaaaaab", "invalid_epoch"),
        ];
        for (series, epoch, request, reason) in cases {
            let status = s.apply(epoch, 1, request, &series);
            assert_eq!(status.rejected.as_deref(), Some(reason), "{reason}");
            assert_eq!(status.revision, 1);
            assert_eq!(status.series[0].id, "keep");
        }
        // The limits themselves are accepted.
        assert_eq!(s.apply("4be1a07c", 1, "aaaaaaac", &eight).rejected, None);
        assert_eq!(s.apply("4be1a07c", 2, "aaaaaaad", &[def(&"a".repeat(32), &max)]).rejected, None);
    }

    #[test]
    fn failing_series_are_kept_with_their_filter_and_error_but_not_countable() {
        let s = shared();
        let status = s.apply("4be1a07c", 0, "aaaaaaaa", &[def("big", "frame.len > 1000 and tcpp ==")]);
        let e = &status.series[0];
        assert!(!e.ok);
        assert_eq!(e.filter, "frame.len > 1000 and tcpp ==");
        assert_eq!(e.error.as_ref().unwrap().message, "Unexpected token");
        assert!(!s.snapshot().1.is_countable());
        let status = s.apply("4be1a07c", 1, "aaaaaaab", &[def("c", "connection.process == \"x\"")]);
        assert!(status.series[0].error.as_ref().unwrap().message.starts_with("connection fields"));
    }

    #[test]
    fn an_empty_list_turns_counting_off() {
        let s = shared();
        s.apply("4be1a07c", 0, "aaaaaaaa", &[def("a", "")]);
        let g = s.generation();
        let status = s.apply("4be1a07c", 1, "aaaaaaab", &[]);
        assert!(status.series.is_empty());
        assert_eq!(s.generation(), g + 1);
        assert!(!s.snapshot().1.is_countable());
    }

    #[test]
    fn status_serializes_as_the_spec_example() {
        let s = shared();
        s.apply("4be1a07c", 0, "c41f09aa", &[def("all", ""), def("big", "frame.len > 1000 and == 1")]);
        let line = crate::wire::encode_event(&crate::wire::AgentEvent::IoSeriesStatus { status: Box::new(s.status()) });
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["type"], "io_series_status");
        assert_eq!(v["revision"], 1);
        assert_eq!(v["epoch"], "4be1a07c");
        assert_eq!(v["replayWaiting"], false);
        assert!(v.get("requestId").is_none() && v.get("rejected").is_none());
        assert_eq!(v["series"][1]["error"]["token"], "==");
        assert_eq!(v["series"][1]["error"]["position"], 21);
    }

    // ---- replay start barrier ----

    #[test]
    fn replay_wait_parses_strictly() {
        assert_eq!(parse_replay_wait(None, true), Ok(false));
        assert_eq!(parse_replay_wait(Some(""), true), Ok(false));
        assert_eq!(parse_replay_wait(Some("1"), true), Ok(true));
        assert!(parse_replay_wait(Some("1"), false).unwrap_err().contains("REPLAY_FILE"));
        assert!(parse_replay_wait(Some("true"), true).is_err());
        assert!(parse_replay_wait(Some("0"), true).is_err());
    }

    #[test]
    fn replay_wait_blocks_until_a_countable_set_and_reports_waiting() {
        let s = Arc::new(shared());
        let waiter = {
            let s = s.clone();
            std::thread::spawn(move || s.wait_for_first_countable_set())
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !s.replay_waiting() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert!(s.status().replay_waiting);
        // A set with only failing series does not release the barrier.
        s.apply("4be1a07c", 0, "aaaaaaaa", &[def("bad", "==")]);
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!waiter.is_finished());
        let released = s.apply("4be1a07c", 1, "aaaaaaab", &[def("all", "")]);
        assert!(!released.replay_waiting, "the accepting status must not still report waiting");
        waiter.join().unwrap();
        assert!(!s.replay_waiting());
    }

    // ---- accumulator ----

    fn set_of(filters: &[&str]) -> Arc<SeriesSet> {
        Arc::new(SeriesSet {
            revision: 3,
            series: filters
                .iter()
                .enumerate()
                .map(|(i, f)| compile_series(&def(&format!("s{i}"), f)))
                .collect(),
        })
    }

    fn agg_def(id: &str, filter: &str, func: &str, field: &str) -> IoSeriesDefJson {
        IoSeriesDefJson { id: id.into(), filter: filter.into(), aggregate: Some(IoAggregateJson { func: func.into(), field: field.into() }) }
    }

    fn agg_set(defs: &[IoSeriesDefJson]) -> Arc<SeriesSet> {
        Arc::new(SeriesSet { revision: 3, series: defs.iter().map(compile_series).collect() })
    }

    // ---- numeric-field aggregates (JAM-18 Task 5, spec D10) ----

    #[test]
    fn an_aggregate_reads_the_first_occurrence_of_its_field_and_rolls_up_count_sum_min_max() {
        let mut a = Accumulator::new(1, agg_set(&[agg_def("win", "", "avg", "tcp.window_size"), def("all", "")]));
        // Two occurrences in one frame: the first (512) is the value, as in filter lookup.
        a.observe_with(us(1_000), 60, 60, || vec![uint("tcp.window_size", 512), uint("tcp.window_size", 9)]);
        a.observe_with(us(1_010), 60, 60, || vec![uint("tcp.window_size", 100)]);
        a.observe_with(us(1_020), 60, 60, Vec::new); // matches, but has no such field
        let p = a.advance(1_700).unwrap();
        assert_eq!(p.series[0].buckets, vec![[1_000, 3, 180]]);
        assert_eq!(p.series[0].aggregates, vec![IoAggregate { count: 2, sum: 612, min: Some(100), max: Some(512) }]);
        // A plain series carries no aggregates.
        assert!(p.series[1].aggregates.is_empty());
    }

    #[test]
    fn an_aggregate_counts_only_frames_its_filter_matches() {
        let mut a = Accumulator::new(1, agg_set(&[agg_def("big", "frame.len > 100", "sum", "frame.len")]));
        a.observe_with(us(2_000), 60, 60, Vec::new);
        a.observe_with(us(2_010), 1514, 1514, Vec::new);
        let p = a.advance(2_700).unwrap();
        assert_eq!(p.series[0].buckets, vec![[2_000, 1, 1514]]);
        assert_eq!(p.series[0].aggregates, vec![IoAggregate { count: 1, sum: 1514, min: Some(1514), max: Some(1514) }]);
    }

    #[test]
    fn late_frames_are_not_aggregated() {
        let mut a = Accumulator::new(1, agg_set(&[agg_def("ttl", "", "max", "ip.ttl")]));
        a.observe_with(us(5_000), 1, 1, || vec![uint("ip.ttl", 64)]);
        let first = a.advance(5_700).unwrap();
        assert_eq!(first.series[0].aggregates[0].max, Some(64));
        a.observe_with(us(5_000), 1, 1, || vec![uint("ip.ttl", 255)]); // late: its bucket already closed
        let second = a.advance(5_800).unwrap();
        assert!(second.series[0].aggregates.is_empty());
        assert_eq!(second.series[0].late_buckets.get(&5_000), Some(&(1, 1)));
    }

    #[test]
    fn a_non_uint_aggregate_field_is_a_compile_error_on_that_series_only() {
        let s = shared();
        let status = s.apply("4be1a07c", 0, "c41f09aa", &[agg_def("names", "", "sum", "dns.qry.name"), agg_def("win", "tcp", "avg", "tcp.window_size")]);
        assert_eq!(status.rejected, None);
        assert!(!status.series[0].ok);
        let err = status.series[0].error.as_ref().unwrap();
        assert_eq!((err.message.as_str(), err.token.as_str()), ("sum needs a uint field; dns.qry.name is not one", "dns.qry.name"));
        assert!(status.series[1].ok);
        // The aggregate is echoed so every tab can rebuild the editor.
        assert_eq!(status.series[1].aggregate, Some(IoAggregateJson { func: "avg".into(), field: "tcp.window_size".into() }));
    }

    #[test]
    fn a_malformed_aggregate_rejects_the_whole_request() {
        let s = shared();
        for bad in [agg_def("a", "", "median", "ip.ttl"), agg_def("a", "", "sum", ""), agg_def("a", "", "sum", "ip ttl"), agg_def("a", "", "sum", &"x".repeat(65))] {
            assert_eq!(s.apply("4be1a07c", 0, "c41f09aa", &[bad]).rejected.as_deref(), Some("invalid_aggregate"));
        }
        assert_eq!(s.status().revision, 0);
    }

    #[test]
    fn aggregate_buckets_serialize_as_7_tuples_with_an_exact_u128_sum() {
        let mut big = IoAggregate::default();
        big.add(u64::MAX);
        big.add(u64::MAX); // the sum no longer fits a u64
        let cases = [
            (IoBucketJson::Plain([1_000, 2, 20]), serde_json::json!([1_000, 2, 20])),
            (
                IoBucketJson::Aggregate([1_000, 2, 20], IoAggregate { count: 2, sum: (1 << 53) - 1, min: Some(1), max: Some(9) }),
                serde_json::json!([1_000, 2, 20, 2, 9_007_199_254_740_991u64, 1, 9]),
            ),
            (
                IoBucketJson::Aggregate([1_000, 2, 20], IoAggregate { count: 2, sum: 1 << 53, min: Some(1), max: Some(9) }),
                serde_json::json!([1_000, 2, 20, 2, "9007199254740992", 1, 9]),
            ),
            (
                IoBucketJson::Aggregate([1_000, 2, 20], big),
                serde_json::json!([1_000, 2, 20, 2, "36893488147419103230", u64::MAX, u64::MAX]),
            ),
            (IoBucketJson::Aggregate([1_000, 2, 20], IoAggregate::default()), serde_json::json!([1_000, 2, 20, 0, 0, null, null])),
        ];
        for (bucket, expected) in cases {
            assert_eq!(serde_json::to_value(&bucket).unwrap(), expected);
        }
    }

    #[test]
    fn io_buckets_lines_carry_7_tuples_for_aggregate_series_only_and_stay_bounded() {
        // From a real accumulator: 7-tuples for the aggregate series only.
        let mut a = Accumulator::new(1, agg_set(&[agg_def("win", "", "sum", "tcp.window_size"), def("all", "")]));
        a.observe_with(us(1_000_000), 60, 60, || vec![uint("tcp.window_size", 7)]);
        let (lines, _) = build_lines("4be1a07c", vec![a.finalize().unwrap()], IoLossJson::default(), Vec::new());
        let v: serde_json::Value = serde_json::from_str(lines[0].trim_end()).unwrap();
        assert_eq!(v["series"][0]["buckets"], serde_json::json!([[1_000_000, 1, 60, 1, 7, 7, 7]]));
        assert_eq!(v["series"][1]["buckets"], serde_json::json!([[1_000_000, 1, 60]]));

        // Worst-case widths (every number at its maximum, a 39-digit sum):
        // the splitter must budget the wider entry, or a line overflows.
        let max = IoAggregate { count: u64::MAX, sum: u128::MAX, min: Some(u64::MAX), max: Some(u64::MAX) };
        let ids = Arc::new(vec!["win".to_string()]);
        let pieces: Vec<Piece> = (0..200u64)
            .map(|i| Piece {
                revision: 1,
                ids: ids.clone(),
                covered_from_ms: i * 1_000,
                covered_to_ms: (i + 1) * 1_000,
                not_observed: Vec::new(),
                frames: 10,
                series: vec![SeriesPiece { buckets: vec![[u64::MAX; 3]; 10], aggregates: vec![max; 10], late_buckets: BTreeMap::new() }],
            })
            .collect();
        let (mut lines, mut rest) = build_lines("4be1a07c", pieces, IoLossJson::default(), Vec::new());
        while !rest.is_empty() {
            let (more, left) = build_lines("4be1a07c", rest, IoLossJson::default(), Vec::new());
            lines.extend(more);
            rest = left;
        }
        let mut total = 0;
        for line in &lines {
            assert!(line.len() <= MAX_LINE_BYTES, "{} bytes", line.len());
            let v: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
            total += v["series"][0]["buckets"].as_array().unwrap().len();
        }
        assert_eq!(total, 2_000);
    }

    fn us(ms: u64) -> u64 {
        ms * 1000
    }

    #[test]
    fn buckets_key_on_exact_100ms_edges_and_close_after_the_grace() {
        let mut a = Accumulator::new(1, set_of(&[""]));
        a.observe_matches(us(1_000), 60, &[true]);
        a.observe_matches(us(1_099), 40, &[true]);
        a.observe_matches(us(1_100), 10, &[true]);
        // Bucket 1000 closes once the clock reaches 1000 + 100 + 500.
        assert!(a.advance(1_599).is_none());
        let p = a.advance(1_600).unwrap();
        assert_eq!((p.covered_from_ms, p.covered_to_ms), (1_000, 1_100));
        assert_eq!(p.series[0].buckets, vec![[1_000, 2, 100]]);
        let p = a.advance(1_700).unwrap();
        assert_eq!((p.covered_from_ms, p.covered_to_ms), (1_100, 1_200));
        assert_eq!(p.series[0].buckets, vec![[1_100, 1, 10]]);
    }

    #[test]
    fn output_is_sparse_and_covered_ranges_abut() {
        let mut a = Accumulator::new(1, set_of(&["", "x == 1"]));
        a.observe_matches(us(2_000), 1, &[true, false]);
        a.observe_matches(us(2_900), 1, &[true, true]);
        let p1 = a.advance(3_000).unwrap();
        let p2 = a.advance(4_000).unwrap();
        assert_eq!(p1.covered_to_ms, p2.covered_from_ms);
        let all: Vec<_> = p1.series[0].buckets.iter().chain(&p2.series[0].buckets).copied().collect();
        assert_eq!(all, vec![[2_000, 1, 1], [2_900, 1, 1]]);
        assert_eq!(p2.series[1].buckets, vec![[2_900, 1, 1]]);
        assert!(p1.series[1].buckets.is_empty());
    }

    #[test]
    fn late_frames_are_attributed_to_their_original_bucket() {
        let mut a = Accumulator::new(1, set_of(&[""]));
        a.observe_matches(us(5_000), 10, &[true]);
        a.advance(6_000).unwrap();
        a.observe_matches(us(5_050), 7, &[true]);
        let p = a.advance(6_000).unwrap();
        assert_eq!((p.covered_from_ms, p.covered_to_ms), (5_500, 5_500));
        assert_eq!(p.series[0].late_buckets.get(&5_000), Some(&(1, 7)));
        assert!(p.series[0].buckets.is_empty());
    }

    #[test]
    fn idle_advance_keeps_covering_zero_traffic_time() {
        let mut a = Accumulator::new(1, set_of(&[""]));
        a.observe_matches(us(10_000), 1, &[true]);
        let mut covered = 0;
        for clock in (10_600..=13_600).step_by(1_000) {
            let p = a.advance(clock).unwrap();
            assert!(p.covered_to_ms > covered);
            covered = p.covered_to_ms;
        }
        assert_eq!(covered, 13_100);
    }

    #[test]
    fn high_water_never_moves_backwards() {
        let mut a = Accumulator::new(1, set_of(&[""]));
        a.observe_matches(us(9_000), 1, &[true]);
        a.observe_matches(us(1_000), 1, &[true]);
        assert_eq!(a.high_water_ms(), 9_000);
    }

    #[test]
    fn finalize_closes_every_open_bucket_for_a_stream_shorter_than_the_grace() {
        let mut a = Accumulator::new(1, set_of(&[""]));
        for ms in [100, 150, 230] {
            a.observe_matches(us(ms), 1, &[true]);
        }
        assert!(a.advance(230).is_none());
        let p = a.finalize().unwrap();
        assert_eq!((p.covered_from_ms, p.covered_to_ms), (100, 300));
        assert_eq!(p.series[0].buckets, vec![[100, 2, 2], [200, 1, 1]]);
        assert!(a.finalize().is_none());
    }

    #[test]
    fn finalize_covers_a_tail_of_frames_that_match_no_series() {
        // Only a DNS series; the replay's frames are all non-DNS.
        let mut a = Accumulator::new(1, set_of(&["dns"]));
        a.observe_with(us(1_000), 60, 60, Vec::new);
        a.observe_with(us(1_200), 60, 60, Vec::new);
        let p = a.finalize().expect("observed zero-count time must be reported");
        assert_eq!((p.covered_from_ms, p.covered_to_ms), (1_000, 1_300));
        assert!(p.series[0].buckets.is_empty());
        // A matched bucket followed by an unmatched tail covers the tail too.
        let mut b = Accumulator::new(1, set_of(&["x == 1"]));
        b.observe_with(us(2_000), 1, 1, || vec![uint("x", 1)]);
        b.observe_with(us(2_450), 1, 1, Vec::new);
        let p = b.finalize().unwrap();
        assert_eq!(p.covered_to_ms, 2_500);
        assert_eq!(p.series[0].buckets, vec![[2_000, 1, 1]]);
    }

    #[test]
    fn piece_frames_count_distinct_frames_independent_of_filters() {
        // Eight overlapping all-traffic series and one that matches nothing:
        // 100 frames are 100 frames, not 800 and not 0.
        let mut overlapping = Accumulator::new(1, set_of(&["", "", "", "", "", "", "", ""]));
        let mut none = Accumulator::new(1, set_of(&["x == 1"]));
        for i in 0..100 {
            overlapping.observe_matches(us(1_000 + i), 1, &[true; 8]);
            none.observe_matches(us(1_000 + i), 1, &[false]);
        }
        overlapping.observe_matches(us(1_000), 1, &[true; 8]); // still on time
        let p = overlapping.finalize().unwrap();
        assert_eq!(p.frames, 101);
        assert_eq!(p.packets(), 8 * 101);
        assert_eq!(none.finalize().unwrap().frames, 100);
        // Late frames count too, once each.
        let mut late = Accumulator::new(1, set_of(&["", ""]));
        late.observe_matches(us(5_000), 1, &[true, true]);
        assert_eq!(late.advance(6_000).unwrap().frames, 1);
        late.observe_matches(us(5_010), 1, &[true, true]);
        assert_eq!(late.advance(6_000).unwrap().frames, 1);
        // And the backlog counter uses them.
        let loss = IoLossShared::default();
        loss.record_backlog(&p);
        assert_eq!(loss.evaluation_skipped.load(Ordering::Relaxed), 101);
    }

    #[test]
    fn drop_totals_survive_handle_replacement() {
        let mut d = DropTotals::default();
        assert_eq!(d.poll(100, 2), (100, 2));
        d.handle_replaced();
        assert_eq!(d.totals(), (100, 2), "no drop lost or invented at the switch");
        // The new handle starts from zero; its first 3 drops are reported.
        assert_eq!(d.poll(3, 0), (103, 2));
        assert_eq!(d.poll(10, 1), (110, 3));
        d.handle_replaced();
        d.handle_replaced(); // replaced again before any poll: nothing doubles
        assert_eq!(d.poll(0, 0), (110, 3));
    }

    #[test]
    fn finalize_never_moves_coverage_backwards() {
        let mut a = Accumulator::new(1, set_of(&[""]));
        a.observe_matches(us(1_000), 1, &[true]);
        a.advance(5_000).unwrap(); // live idle clock covered through 4_500
        assert!(a.finalize().is_none());
    }

    #[test]
    fn not_observed_spans_are_reported_once() {
        let mut a = Accumulator::new(1, set_of(&[""]));
        a.observe_matches(us(1_000), 1, &[true]);
        a.mark_not_observed(1_050, 1_080, "interface_switch");
        let p = a.advance(2_000).unwrap();
        assert_eq!(p.not_observed, vec![IoNotObservedJson { from_ms: 1_050, to_ms: 1_080, reason: "interface_switch" }]);
        assert!(a.advance(2_000).is_none());
    }

    #[test]
    fn the_field_tree_is_only_built_when_an_accumulator_exists() {
        let built = std::cell::Cell::new(0);
        let mut none: Option<Accumulator> = None;
        if let Some(a) = none.as_mut() {
            a.observe_with(us(1), 1, 1, || {
                built.set(built.get() + 1);
                Vec::new()
            });
        }
        assert_eq!(built.get(), 0);
        let mut some = Some(Accumulator::new(1, set_of(&["x == 1"])));
        if let Some(a) = some.as_mut() {
            a.observe_with(us(1_000), 9, 9, || {
                built.set(built.get() + 1);
                vec![uint("x", 1)]
            });
        }
        assert_eq!(built.get(), 1);
        assert_eq!(some.unwrap().finalize().unwrap().series[0].buckets, vec![[1_000, 1, 9]]);
    }

    #[test]
    fn bytes_are_the_original_length_and_frame_len_is_the_captured_length() {
        let mut a = Accumulator::new(1, set_of(&["frame.len == 64"]));
        a.observe_with(us(1_000), 1_514, 64, Vec::new);
        assert_eq!(a.finalize().unwrap().series[0].buckets, vec![[1_000, 1, 1_514]]);
    }

    #[test]
    fn sync_finalizes_the_old_set_and_only_holds_an_accumulator_while_countable() {
        let s = shared();
        let mut acc = None;
        let mut seen = u64::MAX;
        let mut sent = Vec::new();
        sync_accumulator(&s, &mut acc, &mut seen, &mut |p| sent.push(p));
        assert!(acc.is_none(), "no accumulator while nothing is configured");
        s.apply("4be1a07c", 0, "aaaaaaaa", &[def("all", "")]);
        sync_accumulator(&s, &mut acc, &mut seen, &mut |p| sent.push(p));
        acc.as_mut().unwrap().observe_matches(us(1_000), 5, &[true]);
        // Unchanged generation: nothing happens.
        sync_accumulator(&s, &mut acc, &mut seen, &mut |p| sent.push(p));
        assert!(sent.is_empty());
        s.apply("4be1a07c", 1, "aaaaaaab", &[]);
        sync_accumulator(&s, &mut acc, &mut seen, &mut |p| sent.push(p));
        assert!(acc.is_none());
        assert_eq!(sent.len(), 1);
        assert_eq!((sent[0].revision, sent[0].series[0].buckets.clone()), (1, vec![[1_000, 1, 5]]));
        assert_eq!(sent[0].ids.as_slice(), ["all".to_string()]);
    }

    // ---- line building ----

    fn one_id() -> Arc<Vec<String>> {
        Arc::new(vec!["s0".to_string()])
    }

    fn total_buckets(lines: &[String]) -> (u64, Vec<(u64, u64)>) {
        let mut packets = 0;
        let mut covered = Vec::new();
        for line in lines {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            covered.push((v["coveredFromMs"].as_u64().unwrap(), v["coveredToMs"].as_u64().unwrap()));
            for s in v["series"].as_array().unwrap() {
                for b in s["buckets"].as_array().unwrap() {
                    packets += b[1].as_u64().unwrap();
                }
            }
        }
        (packets, covered)
    }

    #[test]
    fn lines_chunk_at_the_ceiling_without_losing_or_duplicating_buckets() {
        // 8 series with a bucket in every 100 ms for a long stretch.
        let mut a = Accumulator::new(1, set_of(&["", "", "", "", "", "", "", ""]));
        let mut pieces = Vec::new();
        for ms in (0..60_000u64).step_by(100) {
            a.observe_matches(us(1_000_000 + ms), 1, &[true; 8]);
            if let Some(p) = a.advance(1_000_000 + ms) {
                pieces.push(p);
            }
        }
        pieces.extend(a.finalize());
        let expected: u64 = pieces.iter().map(Piece::packets).sum();
        assert_eq!(expected, 8 * 600);
        let mut lines = Vec::new();
        let mut rest = pieces;
        while !rest.is_empty() {
            let (l, r) = build_lines("4be1a07c", rest, IoLossJson::default(), Vec::new());
            assert!(l.len() <= MAX_LINES_PER_TICK);
            lines.extend(l);
            rest = r;
        }
        assert!(lines.len() > 1, "expected chunking");
        for line in &lines {
            assert!(line.len() <= MAX_LINE_BYTES, "{}", line.len());
        }
        let (packets, covered) = total_buckets(&lines);
        assert_eq!(packets, expected);
        for pair in covered.windows(2) {
            assert_eq!(pair[0].1, pair[1].0, "covered ranges must abut");
        }
    }

    #[test]
    fn lines_split_on_revision_and_carry_loss_and_backlog_once() {
        let p = |revision, from, to| Piece {
            revision,
            ids: one_id(),
            covered_from_ms: from,
            covered_to_ms: to,
            not_observed: Vec::new(),
            frames: 0,
            series: vec![SeriesPiece::default()],
        };
        let loss = IoLossJson { kernel_dropped: 3, if_dropped: 0, unparseable: 2, evaluation_skipped: 1 };
        let (lines, rest) =
            build_lines("4be1a07c", vec![p(1, 0, 100), p(1, 100, 200), p(2, 200, 300)], loss, vec![(5, 6)]);
        assert!(rest.is_empty());
        assert_eq!(lines.len(), 2);
        let first: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        let second: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        assert_eq!((first["revision"].as_u64(), first["coveredToMs"].as_u64()), (Some(1), Some(200)));
        assert_eq!(first["loss"]["kernelDropped"], 3);
        assert_eq!(first["notObserved"][0]["reason"], "backlog");
        assert_eq!(second["revision"], 2);
        assert_eq!(second["loss"]["kernelDropped"], 0);
        assert!(second["notObserved"].as_array().unwrap().is_empty());
    }

    #[test]
    fn late_buckets_overflow_into_the_scalar_late_count() {
        let mut late = BTreeMap::new();
        for i in 0..(MAX_LATE_BUCKETS_PER_MESSAGE as u64 + 1) {
            late.insert(i * 100, (1, 10));
        }
        let piece = Piece {
            revision: 1,
            ids: one_id(),
            covered_from_ms: 0,
            covered_to_ms: 0,
            not_observed: Vec::new(),
            frames: 0,
            series: vec![SeriesPiece { buckets: Vec::new(), aggregates: Vec::new(), late_buckets: late }],
        };
        let (lines, _) = build_lines("4be1a07c", vec![piece], IoLossJson::default(), Vec::new());
        let v: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(v["series"][0]["lateBuckets"].as_array().unwrap().len(), MAX_LATE_BUCKETS_PER_MESSAGE);
        assert_eq!(v["series"][0]["late"], 1);
    }

    #[test]
    fn backlog_records_skipped_frames_and_bounded_spans() {
        let loss = IoLossShared::default();
        for i in 0..(MAX_BACKLOG_SPANS as u64 + 10) {
            let piece = Piece {
                revision: 1,
                ids: one_id(),
                covered_from_ms: i * 1_000,
                covered_to_ms: i * 1_000 + 100,
                not_observed: Vec::new(),
                frames: 2,
                series: vec![SeriesPiece { buckets: vec![[i * 1_000, 2, 20]], aggregates: Vec::new(), late_buckets: BTreeMap::new() }],
            };
            loss.record_backlog(&piece);
        }
        assert_eq!(loss.evaluation_skipped.load(Ordering::Relaxed), 2 * (MAX_BACKLOG_SPANS as u64 + 10));
        let spans = loss.take_backlog();
        assert_eq!(spans.len(), MAX_BACKLOG_SPANS);
        assert_eq!(spans.last().unwrap().1, (MAX_BACKLOG_SPANS as u64 + 9) * 1_000 + 100);
        assert!(loss.take_backlog().is_empty());
    }
}
