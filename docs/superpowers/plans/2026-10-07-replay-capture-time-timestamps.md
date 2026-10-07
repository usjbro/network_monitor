# Replay Capture-Time Timestamps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make replay packet and finding timestamps describe capture time, while keeping request matching and expiration speed-independent.

**Architecture:** The current capture loop already calls `TransactionTracker::observe_frame` and `expire` with each frame's capture timestamp, and replay disables wall-clock timeout sweeps. Do not add a second analysis clock or change transaction expiry. Instead, pass the expiry timestamp into unanswered-finding emission, stamp packet-triggered findings and packet events from the frame timestamp, and keep the live timeout path on wall time. `ReplayClock` remains the relative timer used by reassembly and flow aging; its far-future outlier behavior stays with JAM-190.

**Tech Stack:** Rust, Tokio broadcast channels, existing capture-agent replay fixtures, Markdown wire-protocol documentation.

**Spec:** JAM-203 Linear acceptance criteria; replay clock semantics in `docs/superpowers/specs/2026-09-28-stream-reassembly-design.md`.

## Global Constraints

- Preserve live packet stamping and wall-clock idle timeout behavior.
- Replay transaction matching and expiry remain driven by the capture timestamps already passed to the tracker.
- Keep packet-event `relative_time_ms` on agent elapsed time and do not change wire field shapes.
- Keep packet-triggered finding timestamps equal to the triggering frame's raw capture timestamp; unanswered findings use the timestamp at which expiry is evaluated.
- Do not add a second corrupt-future clamp. Document that reassembly/flow timer outlier handling remains JAM-190.
- Audit non-test `SystemTime::now()` and `Instant::now()` calls in `capture-agent/src/` and annotate the intended wall-clock use.

## Review Focus

- Replayed malformed frames: test the finding carries the triggering frame's timestamp; verify the connection-reset finding uses the same frame timestamp at its emission site.
- Unanswered requests expiring during replay: test the finding uses the capture time that caused expiry, not the process wall clock.
- Fast and realtime replay of the same fixture: compare finding timestamps and matched/unanswered outcomes exactly; packet-event rate limiting can sample different frames, so verify an emitted packet event against its fixture timestamp.
- Live idle capture timeout: retain the wall-clock expiration path and its existing behavior.
- Outlier timestamps: state clearly that packet observations keep raw capture time and the JAM-190 timer-safety behavior is separate.

---

### Task 1: Use capture timestamps at replay event boundaries

**Files:**
- Modify: `capture-agent/src/main.rs`
- Modify: other `capture-agent/src/` files only where a non-test `now()` call lacks an intentional-clock comment
- Test: `capture-agent/src/main.rs` unit tests and focused binary replay coverage under `capture-agent/tests/`
- Modify: `docs/wire-protocol.md`
- Modify: `.ai/CURRENT_TASK.md`, `.ai/TEST_STATUS.md`, `.ai/HANDOFF.md`

**Interfaces:**
- Consume the existing `SourceFrame::Bytes.timestamp` and `TransactionTracker::expire(now_us)` values.
- Add no clock wire field or API; pass the already-computed expiry time into `emit_unanswered_findings`.

- [x] **Step 1: Write failing tests.** Verify the unanswered-finding helper uses its supplied expiration time; a binary replay fixture at `fast` and `realtime` emits identical finding timestamps and transaction outcomes; verify an emitted packet event and malformed-frame finding use their fixture timestamps and that timestamp-based IDs remain unique. `relativeTimeMs` remains agent elapsed time and is intentionally excluded from equivalence checks.
- [x] **Step 2: Run the focused tests and confirm they fail because replay events currently call `SystemTime::now()`.**
- [x] **Step 3: Implement the smallest change.** Use frame timestamps for packet events, malformed-frame findings, and connection-reset findings; pass replay expiry time to unanswered findings; retain wall time for live idle expiry.
- [x] **Step 4: Audit and annotate remaining non-test `SystemTime::now()` / `Instant::now()` calls in `capture-agent/src/`.** Explain which are intentionally wall-clock scheduling, elapsed-time, live-capture, or file-writing uses.
- [x] **Step 5: Document packet, finding, and `relative_time_ms` timestamp semantics for replay in `docs/wire-protocol.md`; note that JAM-190 owns far-future timer clamping.**
- [x] **Step 6: Run the focused Rust tests, then `cargo build --release --locked`, `cargo test --locked`, and `cargo clippy --all-targets --locked -- -D warnings`.**
- [x] **Step 7: Review the diff and update `.ai/TEST_STATUS.md` and `.ai/HANDOFF.md` with verified results.**
