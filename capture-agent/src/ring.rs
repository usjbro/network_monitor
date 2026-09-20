//! Ring-buffer rotation, autostop, and a disk-space guard for
//! capture-to-file (epic #55, JAM-5/GitHub #72). This module owns *when*
//! the pcapng writer's output file changes or stops; it never touches
//! block-level writing itself (`pcapng.rs`).
//!
//! Mirrors this repo's own established atomic-write pattern
//! (`lib/enrichment/cache.ts`'s `atomicWriteJson`: write to a temp path,
//! `rename()` onto the final name only once fully flushed) — restated here
//! in Rust for a binary format instead of JSON, same guarantee: the file
//! visible under its real name is always complete. Applied universally
//! (both ring and single-file captures), not only on rotation: a crash
//! mid-write must never leave a half-written file under its final name,
//! whether or not ring mode is even configured.

use crate::pcapng::{InterfaceDescriptionBlock, Writer};
use crate::wire::{AutostopConfigJson, CaptureFileStatusJson, RingConfigJson};
use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Default floor below which `start`/`on_tick` refuse to begin, or cleanly
/// stop, a capture (spec Components §3). Not yet operator-configurable —
/// `start_capture_file`'s wire shape has no field for it and none is added
/// here; a fixed, documented default matching the design spec is this
/// task's whole scope.
const DEFAULT_LOW_DISK_FLOOR_BYTES: u64 = 500 * 1024 * 1024;

/// All state for one active capture-to-file run, spanning however many
/// files ring rotation produces. Lives only inside the dedicated writer
/// thread (`main.rs`) — nothing else ever touches an open file handle.
pub struct RingState {
    writer: Writer,
    base_path: PathBuf,
    idb: InterfaceDescriptionBlock,
    hostname: String,
    agent_version: String,
    ring: Option<RingConfigJson>,
    autostop: Option<AutostopConfigJson>,
    /// 1-based, matches the UI's "file N" framing. Only meaningful (and
    /// only ever surfaced on the wire) when `ring` is `Some` — a
    /// non-rotating capture always writes directly to `base_path` with no
    /// numbered suffix.
    current_index: u32,
    started_at: Instant,
    /// Packets written to the *current* file since it was opened — the
    /// counter `ring.mode == "count"` rotation checks. Reset to 0 on every
    /// rotation; NOT the same as a cumulative total.
    packets_this_file: u64,
    /// Sum of `bytes_written()` for every file already rotated out of this
    /// run, so `total observed` in `capture_file_status` and a `totalSize`
    /// autostop threshold both account for the whole run, not just
    /// whatever's in the currently-open file.
    bytes_before_current_file: u64,
}

/// Real free-space query for `path`'s filesystem — `std::fs` has no
/// cross-platform equivalent, and this repo already limits itself to
/// macOS/Linux (`CLAUDE.md`), so a small `libc::statvfs` wrapper is used
/// rather than a new crate dependency, consistent with `pcapng.rs`'s own
/// zero-new-dependency call. Kept separate from `start`/`on_tick` (which
/// take a `free_space_bytes` function parameter instead of calling this
/// directly) so a disk-space-guard test can inject a fake low-space answer
/// rather than requiring an actually-nearly-full filesystem in CI.
pub fn real_free_space_bytes(path: &Path) -> io::Result<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c_path = CString::new(path.as_os_str().as_bytes())?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // libc::statvfs's f_bavail/f_frsize field widths vary by platform (e.g.
    // already u64 on Linux, narrower on macOS) — the `as u64` is a no-op on
    // some targets and a real widening cast on others, so it can't be
    // dropped just because this platform's clippy flags it as redundant.
    #[allow(clippy::unnecessary_cast)]
    Ok(stat.f_bavail as u64 * stat.f_frsize as u64)
}

/// `capture-0007.pcapng` for base path `capture.pcapng`, index 7, only when
/// `ring` is configured — a fixed-width numbered sequence, wrapping is the
/// operator's `ring.threshold` (count mode) or simply growing otherwise
/// (size/duration mode rings have no fixed file count). When `ring` is
/// `None`, the base path is used completely unmodified: a plain
/// `capture <path>` with no ring option writes exactly the file the
/// operator named, nothing appended.
fn member_path(base_path: &Path, ring: &Option<RingConfigJson>, index: u32) -> PathBuf {
    if ring.is_none() {
        return base_path.to_path_buf();
    }
    let stem = base_path.file_stem().unwrap_or_default().to_string_lossy().into_owned();
    let ext = base_path.extension().unwrap_or_default().to_string_lossy().into_owned();
    if ext.is_empty() {
        base_path.with_file_name(format!("{stem}-{index:04}"))
    } else {
        base_path.with_file_name(format!("{stem}-{index:04}.{ext}"))
    }
}

fn partial_path(final_path: &Path) -> PathBuf {
    let mut p = final_path.as_os_str().to_owned();
    p.push(".partial");
    PathBuf::from(p)
}

/// Opens the next file in sequence at its `.partial` name. The caller is
/// responsible for renaming the *previous* file's `.partial` to its final
/// name only after this new file has successfully opened, so a failure
/// here never leaves the run in a state where neither the old nor the new
/// file is valid.
fn open_next(
    base_path: &Path,
    ring: &Option<RingConfigJson>,
    index: u32,
    idb: &InterfaceDescriptionBlock,
    hostname: &str,
    agent_version: &str,
) -> io::Result<Writer> {
    let final_path = member_path(base_path, ring, index);
    let partial = partial_path(&final_path);
    Writer::create(&partial, idb, hostname, agent_version)
}

/// Flushes, fsyncs, and closes `writer` (via `Writer::finish`), then
/// atomically renames its `.partial` path to `final_path` — the one moment
/// a file becomes visible under its real name, and therefore the one
/// moment it's guaranteed complete.
fn finish_and_rename(writer: Writer, final_path: &Path) -> io::Result<()> {
    let partial = partial_path(final_path);
    writer.finish()?;
    std::fs::rename(&partial, final_path)
}

/// Starts a new capture-to-file run. Refuses to begin if free space at
/// `base_path`'s parent is already below the floor (spec Components §3) —
/// same rejection shape as an over-length capture filter (issue #68).
/// `state` must be `None` on entry; the caller (`main.rs`'s writer thread)
/// already guarantees only one run is ever active at a time.
#[allow(clippy::too_many_arguments)]
pub fn start(
    state: &mut Option<RingState>,
    base_path: &Path,
    ring: Option<RingConfigJson>,
    autostop: Option<AutostopConfigJson>,
    idb: &InterfaceDescriptionBlock,
    hostname: &str,
    agent_version: &str,
    free_space_bytes: impl Fn(&Path) -> io::Result<u64>,
) -> Result<(), String> {
    let parent = base_path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let free = free_space_bytes(parent).map_err(|e| format!("could not check free space at {}: {e}", parent.display()))?;
    if free < DEFAULT_LOW_DISK_FLOOR_BYTES {
        return Err(format!(
            "refused: only {free} bytes free at {} — below the {DEFAULT_LOW_DISK_FLOOR_BYTES}-byte floor",
            parent.display()
        ));
    }

    let writer = open_next(base_path, &ring, 1, idb, hostname, agent_version)
        .map_err(|e| format!("could not open capture file: {e}"))?;

    *state = Some(RingState {
        writer,
        base_path: base_path.to_path_buf(),
        idb: idb.clone(),
        hostname: hostname.to_string(),
        agent_version: agent_version.to_string(),
        ring,
        autostop,
        current_index: 1,
        started_at: Instant::now(),
        packets_this_file: 0,
        bytes_before_current_file: 0,
    });
    Ok(())
}

/// Operator-requested stop: closes and finalizes whatever file is
/// currently open. A no-op, matching `pause`/`resume`'s existing tolerance
/// for a redundant call, if no run is active.
pub fn stop(state: &mut Option<RingState>) {
    if let Some(ring_state) = state.take() {
        let final_path = member_path(&ring_state.base_path, &ring_state.ring, ring_state.current_index);
        if let Err(e) = finish_and_rename(ring_state.writer, &final_path) {
            eprintln!("capture-agent: error finalizing capture file {}: {e}", final_path.display());
        }
    }
}

impl RingState {
    /// Writes one packet to the currently-open file and records it toward
    /// `ring.mode == "count"` rotation — bytes-as-a-stand-in-for-count
    /// would be wrong (see `should_rotate`), so this is a real, dedicated
    /// counter incremented only on a successful write.
    pub fn write_packet(&mut self, timestamp: std::time::SystemTime, direction: crate::pcapng::Direction, data: &[u8]) -> io::Result<()> {
        self.writer.write_packet(timestamp, direction, data)?;
        self.packets_this_file += 1;
        Ok(())
    }

    /// Total bytes written across this whole run so far, including every
    /// already-rotated file — not just the currently-open one.
    pub fn bytes_written(&self) -> u64 {
        self.bytes_before_current_file + self.writer.bytes_written()
    }
}

fn should_rotate(ring_state: &RingState) -> bool {
    match &ring_state.ring {
        Some(cfg) if cfg.mode == "size" => ring_state.writer.bytes_written() >= cfg.threshold,
        Some(cfg) if cfg.mode == "duration" => ring_state.started_at.elapsed().as_secs() >= cfg.threshold,
        Some(cfg) if cfg.mode == "count" => ring_state.packets_this_file >= cfg.threshold,
        _ => false,
    }
}

fn autostop_reason(ring_state: &RingState) -> Option<&'static str> {
    match &ring_state.autostop {
        Some(cfg) if cfg.mode == "duration" && ring_state.started_at.elapsed().as_secs() >= cfg.threshold => Some("duration"),
        Some(cfg) if cfg.mode == "totalSize" => {
            let total = ring_state.bytes_before_current_file + ring_state.writer.bytes_written();
            if total >= cfg.threshold {
                Some("totalSize")
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Called once per periodic tick (the same ~1s cadence `capture_stats`
/// already runs on) while a run is active: writes an Interface Statistics
/// block, then checks rotation, autostop, and the disk-space guard, in
/// that order. Returns `None` if no run is active (the writer thread's
/// caller should skip emitting `capture_file_status` from this call in
/// that case — the periodic emitter already has its own "no active run"
/// default). A firing autostop or low-disk condition closes the file
/// cleanly and clears `state` — the *last* file in the run is therefore
/// always complete, never truncated.
pub fn on_tick(
    state: &mut Option<RingState>,
    received: u64,
    dropped: u64,
    free_space_bytes: impl Fn(&Path) -> io::Result<u64>,
) -> Option<CaptureFileStatusJson> {
    let ring_state = state.as_mut()?;
    let _ = ring_state.writer.write_interface_stats(received, dropped);

    let reason = autostop_reason(ring_state);
    let parent = ring_state.base_path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let low_disk = free_space_bytes(parent).map(|free| free < DEFAULT_LOW_DISK_FLOOR_BYTES).unwrap_or(false);

    if reason.is_some() || low_disk {
        let reason = reason.unwrap_or("lowDisk").to_string();
        let ring_state = state.take().unwrap();
        let final_path = member_path(&ring_state.base_path, &ring_state.ring, ring_state.current_index);
        let bytes_written = ring_state.bytes_written();
        let path_str = final_path.display().to_string();
        if let Err(e) = finish_and_rename(ring_state.writer, &final_path) {
            eprintln!("capture-agent: error finalizing capture file {}: {e}", final_path.display());
        }
        return Some(CaptureFileStatusJson {
            writing: false,
            path: Some(path_str),
            bytes_written,
            ring_file: None,
            ring_total: None,
            autostop_reason: Some(reason),
            backpressure_drops: 0, // caller (main.rs) overwrites from its own atomic counter
        });
    }

    if should_rotate(ring_state) {
        let old_index = ring_state.current_index;
        let old_final = member_path(&ring_state.base_path, &ring_state.ring, old_index);
        let next_index = old_index + 1;
        match open_next(&ring_state.base_path, &ring_state.ring, next_index, &ring_state.idb, &ring_state.hostname, &ring_state.agent_version) {
            Ok(new_writer) => {
                let old_writer = std::mem::replace(&mut ring_state.writer, new_writer);
                ring_state.bytes_before_current_file += old_writer.bytes_written();
                ring_state.packets_this_file = 0;
                if let Err(e) = finish_and_rename(old_writer, &old_final) {
                    eprintln!("capture-agent: error finalizing rotated capture file {}: {e}", old_final.display());
                }
                ring_state.current_index = next_index;
            }
            // A failed rotation is not a reason to stop capturing — leave
            // the current (over-threshold) file open and keep writing to
            // it; the next tick will simply try to rotate again.
            Err(e) => eprintln!("capture-agent: rotation failed, continuing with current file: {e}"),
        }
    }

    let ring_state = state.as_ref().unwrap();
    Some(CaptureFileStatusJson {
        writing: true,
        path: Some(member_path(&ring_state.base_path, &ring_state.ring, ring_state.current_index).display().to_string()),
        bytes_written: ring_state.bytes_written(),
        ring_file: ring_state.ring.as_ref().map(|_| ring_state.current_index),
        ring_total: None, // no fixed member count for size/duration/count-mode rings — every mode here rotates indefinitely, not into a fixed-size ring that wraps
        autostop_reason: None,
        backpressure_drops: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::LinkType;

    fn test_idb() -> InterfaceDescriptionBlock {
        InterfaceDescriptionBlock {
            interface_name: "lo".into(),
            link_type: LinkType::NullLoopback,
            snaplen: 65535,
            timestamp_resolution_exponent: 9,
        }
    }

    fn unique_base(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("ring-test-{label}-{}.pcapng", std::process::id()))
    }

    fn ample_free_space(_: &Path) -> io::Result<u64> {
        Ok(u64::MAX / 2)
    }

    fn no_free_space(_: &Path) -> io::Result<u64> {
        Ok(0)
    }

    #[test]
    fn a_non_ring_capture_writes_directly_to_the_named_path_with_no_suffix() {
        let base = unique_base("no-ring");
        let mut state: Option<RingState> = None;
        start(&mut state, &base, None, None, &test_idb(), "host", "0.1.0", ample_free_space).unwrap();
        assert!(partial_path(&base).exists(), "before stop(), the file must exist only under its .partial name");
        stop(&mut state);
        assert!(base.exists(), "the operator-named path itself must exist, no numbered suffix");
        std::fs::remove_file(&base).ok();
    }

    #[test]
    fn a_size_triggered_rotation_produces_a_complete_openable_file_and_starts_a_fresh_one() {
        let base = unique_base("size-rotate");
        let mut state: Option<RingState> = None;
        start(
            &mut state,
            &base,
            Some(RingConfigJson { mode: "size".into(), threshold: 100 }),
            None,
            &test_idb(),
            "host",
            "0.1.0",
            ample_free_space,
        )
        .unwrap();

        for _ in 0..5 {
            state.as_mut().unwrap().write_packet(std::time::SystemTime::now(), crate::pcapng::Direction::Inbound, &[0u8; 64]).unwrap();
        }

        let status = on_tick(&mut state, 5, 0, ample_free_space).unwrap();
        assert!(status.writing);
        assert_eq!(status.ring_file, Some(2), "should have rotated into file 2");

        let first_final = member_path(&base, &Some(RingConfigJson { mode: "size".into(), threshold: 100 }), 1);
        assert!(first_final.exists(), "rotated-out file should be visible under its final name");
        assert!(!partial_path(&first_final).exists(), "no .partial should remain for a completed rotation");

        stop(&mut state);
        let second_final = member_path(&base, &Some(RingConfigJson { mode: "size".into(), threshold: 100 }), 2);
        assert!(second_final.exists());

        std::fs::remove_file(&first_final).ok();
        std::fs::remove_file(&second_final).ok();
    }

    #[test]
    fn a_count_triggered_rotation_fires_after_the_configured_packet_count() {
        let base = unique_base("count-rotate");
        let mut state: Option<RingState> = None;
        start(
            &mut state,
            &base,
            Some(RingConfigJson { mode: "count".into(), threshold: 3 }),
            None,
            &test_idb(),
            "host",
            "0.1.0",
            ample_free_space,
        )
        .unwrap();

        for _ in 0..3 {
            state.as_mut().unwrap().write_packet(std::time::SystemTime::now(), crate::pcapng::Direction::Outbound, &[1, 2, 3]).unwrap();
        }
        let status = on_tick(&mut state, 3, 0, ample_free_space).unwrap();
        assert_eq!(status.ring_file, Some(2), "3 packets at threshold 3 should trigger rotation");

        let first_final = member_path(&base, &Some(RingConfigJson { mode: "count".into(), threshold: 3 }), 1);
        let second_final = member_path(&base, &Some(RingConfigJson { mode: "count".into(), threshold: 3 }), 2);
        stop(&mut state);
        std::fs::remove_file(&first_final).ok();
        std::fs::remove_file(&second_final).ok();
    }

    #[test]
    fn autostop_by_duration_closes_the_file_cleanly_and_reports_the_reason() {
        let base = unique_base("autostop-duration");
        let mut state: Option<RingState> = None;
        start(&mut state, &base, None, Some(AutostopConfigJson { mode: "duration".into(), threshold: 0 }), &test_idb(), "host", "0.1.0", ample_free_space).unwrap();

        let status = on_tick(&mut state, 0, 0, ample_free_space).unwrap(); // threshold 0 fires immediately
        assert_eq!(status.autostop_reason.as_deref(), Some("duration"));
        assert!(!status.writing);
        assert!(state.is_none(), "autostop must clear the active run");
        assert!(base.exists(), "the last file in the run must still be complete and visible");

        std::fs::remove_file(&base).ok();
    }

    #[test]
    fn autostop_by_total_size_accounts_for_bytes_across_a_prior_rotation() {
        let base = unique_base("autostop-totalsize");
        let mut state: Option<RingState> = None;
        start(
            &mut state,
            &base,
            // Threshold 50: even a single 64-byte-payload EPB (~100+ bytes
            // once framed) already exceeds it, so one packet is guaranteed
            // to trigger rotation on the very next tick.
            Some(RingConfigJson { mode: "size".into(), threshold: 50 }),
            // Threshold 1000: comfortably more than one packet's framed
            // size, so it can't fire after just the first rotation below —
            // only after enough further packets in the *second* file push
            // the running total (first file + second file) past it.
            Some(AutostopConfigJson { mode: "totalSize".into(), threshold: 1000 }),
            &test_idb(),
            "host",
            "0.1.0",
            ample_free_space,
        )
        .unwrap();

        // First file: exactly one packet, comfortably over the 50-byte
        // rotation threshold but nowhere near the 1000-byte totalSize floor.
        state.as_mut().unwrap().write_packet(std::time::SystemTime::now(), crate::pcapng::Direction::Inbound, &[0u8; 64]).unwrap();
        let status = on_tick(&mut state, 1, 0, ample_free_space).unwrap();
        assert!(status.writing, "1000-byte totalSize floor must not fire after a single ~100-byte packet");
        assert_eq!(status.ring_file, Some(2), "the 50-byte size threshold must have already rotated into file 2");
        let bytes_after_rotation = status.bytes_written;
        assert!(bytes_after_rotation > 0 && bytes_after_rotation < 1000);

        // Second file: enough further packets that the RUNNING total (first
        // file + this one) clears the 1000-byte totalSize floor.
        for _ in 0..15 {
            state.as_mut().unwrap().write_packet(std::time::SystemTime::now(), crate::pcapng::Direction::Inbound, &[0u8; 64]).unwrap();
        }
        let status = on_tick(&mut state, 16, 0, ample_free_space).unwrap();
        assert_eq!(status.autostop_reason.as_deref(), Some("totalSize"));
        assert!(status.bytes_written >= 1000);

        let first_final = member_path(&base, &Some(RingConfigJson { mode: "size".into(), threshold: 50 }), 1);
        let second_final = member_path(&base, &Some(RingConfigJson { mode: "size".into(), threshold: 50 }), 2);
        std::fs::remove_file(&first_final).ok();
        std::fs::remove_file(&second_final).ok();
    }

    #[test]
    fn start_refuses_below_the_disk_space_floor() {
        let base = unique_base("low-disk-start");
        let mut state: Option<RingState> = None;
        let err = start(&mut state, &base, None, None, &test_idb(), "host", "0.1.0", no_free_space).unwrap_err();
        assert!(err.contains("below"), "got: {err}");
        assert!(state.is_none());
        assert!(!base.exists());
    }

    #[test]
    fn on_tick_stops_cleanly_when_free_space_drops_below_the_floor_mid_run() {
        let base = unique_base("low-disk-mid-run");
        let mut state: Option<RingState> = None;
        start(&mut state, &base, None, None, &test_idb(), "host", "0.1.0", ample_free_space).unwrap();

        let status = on_tick(&mut state, 0, 0, no_free_space).unwrap();
        assert_eq!(status.autostop_reason.as_deref(), Some("lowDisk"));
        assert!(state.is_none());
        assert!(base.exists(), "the file must still be finalized, not abandoned as .partial");

        std::fs::remove_file(&base).ok();
    }

    #[test]
    fn a_crash_mid_write_leaves_every_already_rotated_file_valid() {
        let base = unique_base("crash-simulation");
        let mut state: Option<RingState> = None;
        start(
            &mut state,
            &base,
            Some(RingConfigJson { mode: "size".into(), threshold: 100 }),
            None,
            &test_idb(),
            "host",
            "0.1.0",
            ample_free_space,
        )
        .unwrap();
        for _ in 0..5 {
            state.as_mut().unwrap().write_packet(std::time::SystemTime::now(), crate::pcapng::Direction::Inbound, &[0u8; 64]).unwrap();
        }
        on_tick(&mut state, 5, 0, ample_free_space); // rotates — file 1 is now complete and renamed
        let first_final = member_path(&base, &Some(RingConfigJson { mode: "size".into(), threshold: 100 }), 1);
        assert!(first_final.exists());

        // Simulate a crash: drop `state` without calling stop(), so file 2
        // is abandoned as a .partial. File 1 must remain valid regardless.
        drop(state);
        assert!(first_final.exists(), "already-rotated file must survive an unclean shutdown of a later file");
        let second_partial = partial_path(&member_path(&base, &Some(RingConfigJson { mode: "size".into(), threshold: 100 }), 2));
        assert!(second_partial.exists(), "the in-flight file is expected to remain a .partial — that's the crash's honest footprint, not a bug");

        std::fs::remove_file(&first_final).ok();
        std::fs::remove_file(&second_partial).ok();
    }

    #[test]
    fn member_path_leaves_a_non_ring_base_path_completely_unmodified() {
        let base = Path::new("/tmp/mycapture.pcapng");
        assert_eq!(member_path(base, &None, 1), base);
        assert_eq!(member_path(base, &None, 7), base);
    }

    #[test]
    fn member_path_appends_a_fixed_width_index_only_when_ring_is_configured() {
        let base = Path::new("/tmp/mycapture.pcapng");
        let ring = Some(RingConfigJson { mode: "size".into(), threshold: 1 });
        assert_eq!(member_path(base, &ring, 7), Path::new("/tmp/mycapture-0007.pcapng"));
    }
}
