# Capture Files and Offline Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the product a file format. The capture agent gains the ability to write a live capture to a real pcapng file (operator-triggered, ring-buffered, autostopped) and to replay a pcapng or classic-pcap file through the exact same event pipeline live capture uses. Every hard-coded buffer cap in the product becomes visible and adjustable. The browser gains client-side export of the current view. `docs/security.md` gains the capture-handling guidance this epic's own text says must land first.

**Architecture:** A new `capture-agent/src/pcapng.rs` module owns both directions of a hand-rolled pcapng codec (Section Header, Interface Description, Enhanced Packet, and — added by the design spec, not named in the source issue — Interface Statistics blocks). The capture loop in `main.rs` is refactored behind a `PacketSource` enum (`Live`, `ReplayPcapng`, `ReplayClassic`) so `parse::parse_packet` onward is completely unaware of where bytes came from. A new `capture-agent/src/ring.rs` owns rotation/autostop/disk-space-guard policy on top of the writer. Six new/changed wire-protocol surfaces (two control messages, one new event, two new fields on an existing event, and one revived-from-dead event) carry all of this to the relay unchanged in shape; the relay does no transformation, matching every prior sub-project's precedent. Export is pure browser-side `Blob` generation, no new route.

**Tech Stack:** Rust (capture-agent — `std::io`/`std::fs` only for the pcapng codec, no new crate; `pcap::Capture::from_file()` for classic-pcap read, using the existing `pcap` dependency), TypeScript/Next.js (React state, command-bar verbs, `Blob`/`URL.createObjectURL`, zero new npm dependencies), `cargo test` + the existing `cargo-fuzz` target, Vitest, and the `capture-agent/tests/live_loopback.rs` integration harness epic JAM-57 already built.

**Spec:** `docs/superpowers/specs/2026-09-19-capture-files-design.md` — read it before starting; this plan assumes familiarity with its Components §0–§5, Wire/control-message changes, Security model table, and Error handling & lifecycle sections. Concrete field names and defaults are restated below for convenience but the spec is the source of truth for *why*.

## Global Constraints

- **Never write to disk by default.** Capture-to-file only ever starts on an explicit `start_capture_file` control message (spec Components §1) — no task in this plan wires it to fire automatically.
- **Decrypted TLS content never becomes reachable from the writer or from export.** `pcapng.rs` never imports or references `DecryptedRingBuffer`/`DecryptState`; the browser's CSV/JSON exporters never read `decryptedSegments`. This is structural (the code path doesn't exist), not a runtime check — every task touching either surface must preserve that by construction, and Task 13 adds a regression test on both sides.
- **Output path discipline:** `start_capture_file`'s `path` is always operator-supplied, `0600` on creation, and rejected outright if it resolves inside the repo working tree or `.data/` (spec Components §1).
- **Live vs. replay is a startup-only choice.** `REPLAY_FILE` (mutually exclusive with `CAPTURE_INTERFACE`) is read once in `main()`; no task adds a runtime control message that switches `PacketSource` after startup (spec Components §2's explicit resolution of the source issue's open question).
- **Unknown beats a confident wrong answer.** A replayed capture with no derivable local-address information reports `"unknown"` direction; a replayed capture reports `processName: "unknown"`, `pid: null` for every connection — never falls back to this machine's own `local_addrs` or `process_lookup` table (spec Components §2).
- **Report zero/absent rather than invent a number** — the house style `docs/wire-protocol.md` already documents. Applies here to: a per-packet EPB error-flags bit this agent can't actually classify (left unset, not guessed), timestamp resolution (recorded honestly per platform, never claimed as nanosecond if the clock doesn't support it), and every new cumulative counter (starts at zero, never backfilled).
- **Field names on the wire are `camelCase`**, matching every existing event's convention exactly; Rust-side structs stay `snake_case` with `#[serde(rename_all = "camelCase")]`, matching every existing `*Json` struct in `wire.rs`.
- **No live network calls or live filesystem races in any test.** pcapng round-trip tests read/write to `std::env::temp_dir()` fixtures cleaned up per-test (matching `no_disk_write_invariant.rs`'s existing `unique_dir` helper pattern); the one genuinely live check in this whole plan is Task 14's `live_loopback.rs` extension, which already has an established `#[ignore]`-gated, CI-privileged pattern from epic JAM-57 to reuse rather than reinvent.
- **Every new Rust dependency gets the extra-scrutiny review `docs/security.md` calls for** — moot for this plan specifically, since Components §1/§2 (Dependency hygiene) commit to zero new crates for the codec itself.

---

## File Structure

**New — `capture-agent/src/`:**
- `pcapng.rs` — the codec: block framing shared by both directions, `Writer` (Tasks 2–3), `Reader` (Task 6)
- `ring.rs` — rotation, autostop, disk-space guard (Task 5)

**Modified — `capture-agent/src/`:**
- `wire.rs` — `ControlMessage::StartCaptureFile`/`StopCaptureFile`; `AgentEvent::CaptureFileStatus`; `AgentEvent::AgentStatus`'s payload gains `mode`/`replay_source`; `CaptureStatsJson` gains `total_connections_observed`/`capacity_evictions`/`idle_evictions` (Tasks 4, 9)
- `main.rs` — `PacketSource` enum and startup dispatch (Task 7); writer/ring wiring (Tasks 3–5); `agent_status`/`capture_file_status` emission on the existing per-tick loop (Tasks 4, 9); `MAX_FLOWS` env var (Task 12)
- `flow.rs` — `total_flows_observed`, `capacity_evictions`, `idle_evictions` counters on `FlowTable` (Task 9)
- `process_lookup.rs` — no code change, but Task 8's replay path deliberately never calls `refresh()`
- `lib.rs` — `pub mod pcapng;` `pub mod ring;`

**New — `capture-agent/tests/`:**
- `fixtures/pcapng/` — hand-built and real-tool-captured (`tcpdump`) fixture files for round-trip and classic-pcap interop tests
- `pcapng_roundtrip.rs` — Task 6
- `fuzz/fuzz_targets/pcapng_reader.rs` — Task 6

**New — relay + UI:**
- `docs/geoip-protocol.md` sibling: none needed — `capture_file_status`/`agent_status` are agent-originated, documented in `docs/wire-protocol.md` directly (Task 10)
- `lib/export.ts` — `connectionsToCsv`, `packetsToJson`, both taking already-filtered/already-in-memory arrays only (Task 13)
- `lib/__tests__/export.test.ts`, `lib/__tests__/pcapng-mode-banner.test.tsx` (or equivalent `page-*` test file, matching this repo's existing naming convention), `lib/__tests__/decrypted-export-exclusion.test.ts`

**Modified — relay + UI:**
- `lib/types.ts` — `CaptureFileStatus`, `AgentMode` types; `CaptureStats` gains three fields
- `lib/agent-mapping.ts` — `mapCaptureFileStatusEvent`, `mapAgentStatusEvent`; `mapCaptureStatsEvent` extended
- `app/page.tsx` — three-state mode derivation, `capture_file_status`/`agent_status` handling, command-bar verbs, buffer-limit state (Tasks 11–12)
- `components/HeaderBar.tsx` — active-capture-file indicator, mode banner
- `components/CommandLineBar.tsx` — help text for `capture ...`/`buffer ...`
- `components/ConnectionsView.tsx` — export-CSV action (Task 13)
- `components/PacketStreamView.tsx` — export-JSON action, hex-dump copy (Task 13)
- `docs/wire-protocol.md` — every new/changed event and control message (Task 10)
- `docs/security.md` — capture-handling section (Task 1, this plan's Task 1 is the spec's Component 0)
- `docs/architecture.md` — resource-model documentation (Task 14)
- `CONTRIBUTING.md` — `live_loopback.rs`'s extended coverage noted alongside its existing entry (Task 14)

---

### Task 1: `docs/security.md` capture-handling section

**Files:**
- Modify: `docs/security.md`

**Interfaces:** none — documentation only. This task has no code dependents in the strict compiler sense, but Tasks 2–4 (the writer) and Task 13 (export) must not ship until this section exists, per the spec's explicit "#75 blocks #70 and #74" instruction — treat this as a hard merge-order dependency even though nothing enforces it mechanically.

This is the epic's own "do first" task (spec Components §0). No spike, no code — just the six points the spec already specifies, added as a new section between the existing "What's explicitly NOT done yet" and "Dependency hygiene" sections.

- [ ] **Step 1: Add the section**

Insert into `docs/security.md`, after the "What's explicitly NOT done yet" section's closing bullet and before "## Dependency hygiene":

```markdown
## Capture files (epic #55)

Writing a live capture to disk, or replaying one, is the point at which this tool's output stops being "whatever is currently in one browser tab" and becomes a durable, portable file — everything the live UI already shows, at rest, for as long as that file exists.

- **What a capture file contains:** every process's connections, remote IPs, DNS queries, TLS SNI hostnames, and raw packet bytes this agent observed while writing — the same sensitivity this document's opening line already assigns to the live tool, now true of a file rather than only a running process.
- **What it never contains:** decrypted TLS content. The pcapng writer (`capture-agent/src/pcapng.rs`) has no code path that can reach `DecryptedRingBuffer` or any decrypted byte — writes ciphertext frames only, by construction, not by a runtime check. Export (below) holds the same guarantee on the browser side.
- **Storage discipline:** written only to an operator-named path, `0600` on creation, never `.data/`, never this repo's working tree — the agent refuses the request otherwise. Matches the same discipline `bin/osi-inspect.js` already applies to its ephemeral key-log files.
- **Retention is the operator's responsibility.** Ring-buffer rotation bounds disk use *while a capture is actively being written* (size, duration, or packet-count triggered, oldest file overwritten); nothing in this tool deletes a file once capture stops or a session ends. This is a bounded rolling window, not a retention feature or a storage tier.
- **Legal note:** a capture may include other devices' traffic on a shared network segment — most obviously a home Wi-Fi network. Be mindful of who else's traffic you're capturing and for how long you keep it, same caution any packet-capture tool carries, restated here for an audience (a home/SMB operator) who may not already know it.
- **Export crosses a narrower boundary than the live view.** A CSV/JSON/hex-dump export (below) becomes a downloaded file on whatever device did the downloading — outside the mTLS layer, the loopback bind, and every other protection the live SSE stream has. No additional runtime mitigation is proposed beyond redaction (already applied before data ever reaches the browser) and the same decrypted-content exclusion the writer holds — export is inherently "the operator asked for a copy," the same trust already extended to the operator's own browser tab.
```

- [ ] **Step 2: Commit**

```bash
git add docs/security.md
git commit -m "docs(security): add capture-file sensitivity, storage, and legal guidance (#75)"
```

---

### Task 2: `pcapng.rs` — block framing primitives and the writer's SHB/IDB half

**Files:**
- Create: `capture-agent/src/pcapng.rs`
- Modify: `capture-agent/src/lib.rs` (`pub mod pcapng;`)

**Interfaces:**
- Produces: `pub mod block` (or free functions — implementer's choice, shown here as free functions for brevity) that write a generic block's framing, plus `SectionHeaderBlock`/`InterfaceDescriptionBlock` structs with a `write_to(&mut impl Write) -> io::Result<()>` method each.
- Consumed by: Task 3 (EPB/ISB — same file, same `Writer` type), Task 6 (the reader round-trips against this exact byte layout).

Every pcapng block shares one shape: a 4-byte little-endian block type, a 4-byte little-endian total length, a body (padded to a 4-byte boundary), and the total length repeated at the end — this repetition is what lets a reader seek backward through a file, and it's also the property Task 6's round-trip test checks first (`length_prefix == length_suffix` for every block).

- [ ] **Step 1: Generic block writer**

```rust
// capture-agent/src/pcapng.rs
//
// A hand-rolled pcapng encoder and decoder (issue #70/#71, JAM-132/JAM-133).
// Deliberately narrow: four block types (Section Header, Interface
// Description, Enhanced Packet, Interface Statistics), no Name Resolution
// or Decryption Secrets blocks, no per-packet comments. See
// docs/superpowers/specs/2026-09-19-capture-files-design.md Components §1
// for why this is hand-rolled rather than a new crate dependency.
use std::io::{self, Read, Write};

const BYTE_ORDER_MAGIC: u32 = 0x1A2B3C4D;
const BT_SECTION_HEADER: u32 = 0x0A0D0D0A;
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
/// block type below, since pcapng's option encoding is identical regardless
/// of which block or which option code is being written.
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

/// Writes one full block: type, length, body (already padded by the
/// caller), length repeated. `body` must already end on a 4-byte boundary —
/// every block-body builder below (`shb_body`, `idb_body`, etc.) guarantees
/// this by construction (every option is padded, and the fixed-width
/// fields before the options are all already multiples of 4).
fn write_block(w: &mut impl Write, block_type: u32, body: &[u8]) -> io::Result<()> {
    let total_len = 12 + body.len() as u32; // type + len + body + len
    w.write_all(&block_type.to_le_bytes())?;
    w.write_all(&total_len.to_le_bytes())?;
    w.write_all(body)?;
    w.write_all(&total_len.to_le_bytes())
}
```

- [ ] **Step 2: Section Header Block**

```rust
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
```

- [ ] **Step 3: Interface Description Block**

```rust
/// pcapng LINKTYPE_* values this agent can produce — a small, closed
/// mapping from `parse::LinkType` (the agent's own internal link-type enum,
/// already resolved once at startup by `main.rs::resolve_link_type`), not a
/// general-purpose pcapng linktype table.
fn pcapng_linktype(link_type: crate::parse::LinkType) -> u16 {
    match link_type {
        crate::parse::LinkType::Ethernet => 1,     // LINKTYPE_ETHERNET
        crate::parse::LinkType::NullLoopback => 0, // LINKTYPE_NULL
        crate::parse::LinkType::Raw => 101,        // LINKTYPE_RAW
    }
}

pub struct InterfaceDescriptionBlock {
    pub interface_name: String,
    pub link_type: crate::parse::LinkType,
    pub snaplen: u32,
    /// Honest per the platform clock's actual resolution — see Global
    /// Constraints. `9` means nanosecond (10^-9); pcapng's `if_tsresol`
    /// encodes resolution as a power-of-ten exponent with the high bit
    /// clear, so a plain byte value of the exponent is correct here.
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
```

- [ ] **Step 4: Unit tests — framing invariants**

```rust
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
        SectionHeaderBlock { hostname: "test-host".into(), agent_version: "0.1.0".into() }
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
            interface_name: "en0x".into(), // 4 bytes — also test an odd one below
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
}
```

- [ ] **Step 5: Build and commit**

```bash
cd capture-agent && cargo build --locked && cargo test --locked pcapng
git add src/pcapng.rs src/lib.rs
git commit -m "feat(capture-agent): pcapng block framing + Section Header/Interface Description writer (#70)"
```

---

### Task 3: `pcapng.rs` — Enhanced Packet/Interface Statistics blocks, the `Writer` type, and backpressure

**Files:**
- Modify: `capture-agent/src/pcapng.rs`

**Interfaces:**
- Produces:
  ```rust
  pub struct Writer { /* opaque: open file handle + interface metadata already written */ }
  impl Writer {
      pub fn create(path: &Path, idb: &InterfaceDescriptionBlock, hostname: &str, agent_version: &str) -> io::Result<Self>;
      pub fn write_packet(&mut self, timestamp: SystemTime, direction: Direction, data: &[u8]) -> io::Result<()>;
      pub fn write_interface_stats(&mut self, received: u64, dropped: u64) -> io::Result<()>;
      pub fn bytes_written(&self) -> u64;
      pub fn finish(self) -> io::Result<()>; // flush + close — see ring.rs (Task 5) for the rename-on-finish step
  }
  pub enum Direction { Inbound, Outbound, Unknown }
  ```
- Consumed by: `main.rs`'s writer thread (this task, Step 4) and `ring.rs` (Task 5, which owns *when* a `Writer` is created/finished, not the block-level writing itself).

- [ ] **Step 1: Enhanced Packet Block**

```rust
pub enum Direction {
    Inbound,
    Outbound,
    Unknown,
}

impl Direction {
    /// epb_flags is a 32-bit field; bits 0-1 encode direction per the
    /// pcapng spec (00 = unknown/not available, 01 = inbound, 10 =
    /// outbound). No other bits are set by this agent — see Global
    /// Constraints on not inventing per-packet error flags this agent
    /// can't actually classify.
    fn epb_flags_bits(&self) -> u32 {
        match self {
            Direction::Unknown => 0b00,
            Direction::Inbound => 0b01,
            Direction::Outbound => 0b10,
        }
    }
}

fn write_enhanced_packet_block(
    w: &mut impl Write,
    interface_id: u32,
    timestamp: SystemTime,
    direction: Direction,
    data: &[u8],
) -> io::Result<()> {
    let since_epoch = timestamp
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    // pcapng's EPB timestamp is a 64-bit value split into two 32-bit
    // halves, in whatever unit the owning IDB's if_tsresol declared —
    // this agent always declares resolution in Step 3 of Task 2 as
    // nanoseconds where the platform clock supports it, so this encodes
    // nanoseconds-since-epoch split high/low.
    let ts_ns = since_epoch.as_nanos() as u64;
    let ts_high = (ts_ns >> 32) as u32;
    let ts_low = (ts_ns & 0xFFFF_FFFF) as u32;

    let mut body = Vec::new();
    body.extend_from_slice(&interface_id.to_le_bytes());
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
```

- [ ] **Step 2: Interface Statistics Block**

```rust
fn write_interface_statistics_block(
    w: &mut impl Write,
    interface_id: u32,
    timestamp: SystemTime,
    received: u64,
    dropped: u64,
) -> io::Result<()> {
    let since_epoch = timestamp.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let ts_ns = since_epoch.as_nanos() as u64;

    let mut body = Vec::new();
    body.extend_from_slice(&interface_id.to_le_bytes());
    body.extend_from_slice(&((ts_ns >> 32) as u32).to_le_bytes());
    body.extend_from_slice(&((ts_ns & 0xFFFF_FFFF) as u32).to_le_bytes());

    write_option(&mut body, ISB_IFRECV, &received.to_le_bytes())?;
    write_option(&mut body, ISB_IFDROP, &dropped.to_le_bytes())?;
    write_end_of_opt(&mut body)?;

    write_block(w, BT_INTERFACE_STATISTICS, &body)
}
```

- [ ] **Step 3: The `Writer` type — ties SHB/IDB/EPB/ISB to an open file**

```rust
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt; // mode() — Unix-only, matching this repo's existing macOS/Linux-only posture
use std::path::Path;
use std::time::SystemTime;

pub struct Writer {
    file: File,
    bytes_written: u64,
}

impl Writer {
    /// Opens `path` fresh (`0600`, matching Global Constraints), writes the
    /// Section Header and Interface Description blocks immediately (both
    /// are written exactly once, at file open — spec Components §1's
    /// table), and returns a `Writer` ready for `write_packet` calls.
    /// Interface ID is always `0` — this agent ever writes exactly one
    /// interface's traffic per file, so pcapng's multi-interface support
    /// (interface IDs beyond 0) is unused, deliberately, matching the
    /// spec's narrow scope.
    pub fn create(
        path: &Path,
        idb: &InterfaceDescriptionBlock,
        hostname: &str,
        agent_version: &str,
    ) -> io::Result<Self> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true) // never silently overwrite an existing file at this path
            .mode(0o600)
            .open(path)?;
        SectionHeaderBlock { hostname: hostname.to_string(), agent_version: agent_version.to_string() }
            .write_to(&mut file)?;
        idb.write_to(&mut file)?;
        file.flush()?;
        Ok(Self { file, bytes_written: 0 })
    }

    pub fn write_packet(&mut self, timestamp: SystemTime, direction: Direction, data: &[u8]) -> io::Result<()> {
        let before = self.bytes_written;
        write_enhanced_packet_block(&mut self.file, 0, timestamp, direction, data)?;
        // Recomputed from the block's own total length rather than tracked
        // incrementally elsewhere, so bytes_written can never drift from
        // what was actually written to the file handle.
        self.bytes_written = before + (12 + pad4(data.len()) + 4/*epb_flags option header*/ + 4/*epb_flags value*/ + 4/*end-of-opt*/ + 16/*fixed EPB fields*/) as u64;
        Ok(())
    }

    pub fn write_interface_stats(&mut self, received: u64, dropped: u64) -> io::Result<()> {
        write_interface_statistics_block(&mut self.file, 0, SystemTime::now(), received, dropped)
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Flushes and closes the handle. Does NOT rename the file — Task 5's
    /// `ring.rs` owns the write-to-`.partial`-then-rename sequence, since
    /// that policy belongs to rotation, not to the codec itself (a caller
    /// that only ever writes one file, never rotating, still wants a
    /// correctly-closed file without needing to know about `.partial`
    /// naming at all).
    pub fn finish(mut self) -> io::Result<()> {
        self.file.flush()?;
        self.file.sync_all()
    }
}
```

**Note on `bytes_written`'s arithmetic**: the inline recomputation above is intentionally explicit (not hidden behind a second call into the block-writing function that also happens to return a length) so the length math is visible for review — an implementer should replace this with `write_enhanced_packet_block` itself returning the byte count it wrote, avoiding two sources of truth for the same number. Flagged here rather than silently done right, since getting this wrong only manifests as a slowly-drifting `capture_file_status.bytesWritten` in the UI — the kind of bug a code reviewer should be pointed at explicitly.

- [ ] **Step 4: Writer thread and backpressure, wired into `main.rs`**

A dedicated OS thread owns the `Writer`, fed by a bounded `mpsc::sync_channel` from the capture loop — never a direct call from the hot per-packet path, per spec Components §1's "the writer must not be able to stall or drop the live stream."

```rust
// In main.rs, alongside the other Arc<Mutex<...>>/channel setup near the
// top of main():
enum WriterCommand {
    Packet { timestamp: std::time::SystemTime, direction: pcapng::Direction, data: Vec<u8> },
    Stats { received: u64, dropped: u64 },
}
// Bounded at 4096 — generous relative to this agent's existing 100/sec
// discrete-event rate limits elsewhere, sized so a brief disk hiccup
// doesn't immediately start dropping, while still bounding memory if the
// disk stalls for longer than that.
const WRITER_QUEUE_CAPACITY: usize = 4096;
let (writer_tx, writer_rx) = std::sync::mpsc::sync_channel::<WriterCommand>(WRITER_QUEUE_CAPACITY);
// Cumulative count of packets the capture loop wanted to write but the
// queue was full for — surfaced via capture_file_status (Task 4), never
// silently dropped from the operator's view even though the frame itself
// is gone.
let writer_backpressure_drops = Arc::new(AtomicU64::new(0));
```

In the capture loop's per-packet path, a `try_send` (never a blocking `send`, which would stall packet processing exactly as the spec forbids):

```rust
if let Some(tx) = active_writer_tx.as_ref() {
    if tx
        .try_send(WriterCommand::Packet {
            timestamp: std::time::SystemTime::now(),
            direction: local_direction, // computed from the same is_local check FlowTable already does
            data: frame_bytes.to_vec(),
        })
        .is_err()
    {
        writer_backpressure_drops.fetch_add(1, Ordering::Relaxed);
    }
}
```

The writer thread itself is a simple drain loop — `ring.rs` (Task 5) is what decides when to call `Writer::create`/`finish` in response to rotation/autostop, so this thread's job is narrowly "hand each queued command to whichever `Writer` is currently open":

```rust
std::thread::spawn(move || {
    // current_writer is Option<pcapng::Writer>, behind the same kind of
    // Arc<Mutex<...>> ring.rs (Task 5) already needs for its own rotation
    // bookkeeping — shown here as a local for clarity; Task 5 wires the
    // real shared handle.
    while let Ok(cmd) = writer_rx.recv() {
        match cmd {
            WriterCommand::Packet { timestamp, direction, data } => {
                if let Some(w) = current_writer.as_mut() {
                    let _ = w.write_packet(timestamp, direction, &data); // I/O errors surfaced via capture_file_status's next tick, not panicked on
                }
            }
            WriterCommand::Stats { received, dropped } => {
                if let Some(w) = current_writer.as_mut() {
                    let _ = w.write_interface_stats(received, dropped);
                }
            }
        }
    }
});
```

- [ ] **Step 5: Tests**

```rust
#[cfg(test)]
mod writer_tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    fn temp_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("pcapng-writer-test-{label}-{}.pcapng", std::process::id()))
    }

    #[test]
    fn creates_a_file_with_0600_permissions() {
        let path = temp_path("perms");
        let idb = InterfaceDescriptionBlock {
            interface_name: "lo".into(),
            link_type: crate::parse::LinkType::NullLoopback,
            snaplen: 65535,
            timestamp_resolution_exponent: 9,
        };
        let writer = Writer::create(&path, &idb, "test-host", "0.1.0").unwrap();
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
        let idb = InterfaceDescriptionBlock {
            interface_name: "lo".into(),
            link_type: crate::parse::LinkType::NullLoopback,
            snaplen: 65535,
            timestamp_resolution_exponent: 9,
        };
        let result = Writer::create(&path, &idb, "test-host", "0.1.0");
        assert!(result.is_err(), "create_new should refuse an existing path");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn bytes_written_matches_actual_file_size_after_several_packets() {
        let path = temp_path("byte-count");
        let idb = InterfaceDescriptionBlock {
            interface_name: "lo".into(),
            link_type: crate::parse::LinkType::NullLoopback,
            snaplen: 65535,
            timestamp_resolution_exponent: 9,
        };
        let mut writer = Writer::create(&path, &idb, "test-host", "0.1.0").unwrap();
        let header_size = std::fs::metadata(&path).unwrap().len();

        for _ in 0..5 {
            writer
                .write_packet(SystemTime::now(), Direction::Inbound, &[0u8; 64])
                .unwrap();
        }
        let bytes_after = writer.bytes_written();
        writer.finish().unwrap();

        let actual_file_size = std::fs::metadata(&path).unwrap().len();
        assert_eq!(actual_file_size, header_size + bytes_after);
        std::fs::remove_file(&path).ok();
    }
}
```

- [ ] **Step 6: Build, test, commit**

```bash
cd capture-agent && cargo build --locked && cargo test --locked pcapng
git add src/pcapng.rs src/main.rs
git commit -m "feat(capture-agent): Enhanced Packet/Interface Statistics blocks, Writer, backpressure-counted writer thread (#70)"
```

---

### Task 4: `start_capture_file`/`stop_capture_file` control messages and the `capture_file_status` event

**Files:**
- Modify: `capture-agent/src/wire.rs`, `capture-agent/src/main.rs`

**Interfaces:**
- Consumes: Task 3's `pcapng::Writer`/`Direction`.
- Produces: the `ControlMessage::StartCaptureFile`/`StopCaptureFile` variants and `AgentEvent::CaptureFileStatus` — the shape Task 10 (relay-side mapping) and Task 11 (`docs/wire-protocol.md`) both depend on.

- [ ] **Step 1: Wire types**

```rust
// wire.rs — added to the existing ControlMessage enum, same file, same
// #[serde(tag = "type", rename_all = "snake_case")] the enum already uses.
StartCaptureFile {
    path: String,
    ring: Option<RingConfigJson>,
    autostop: Option<AutostopConfigJson>,
},
StopCaptureFile,
```
```rust
#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RingConfigJson {
    pub mode: String, // "size" | "duration" | "count" — validated in main.rs, not here (matches SetSnaplen's existing precedent of deserializing permissively and validating at the call site)
    pub threshold: u64,
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AutostopConfigJson {
    pub mode: String, // "duration" | "totalSize" | "fileCount"
    pub threshold: u64,
}
```

```rust
// Added to AgentEvent:
CaptureFileStatus { status: CaptureFileStatusJson },
```
```rust
#[derive(Serialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CaptureFileStatusJson {
    pub writing: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub bytes_written: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ring_file: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ring_total: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autostop_reason: Option<String>,
    /// Cumulative count of packets the writer's bounded queue couldn't
    /// accept (Task 3, Step 4) — distinct from capture_stats' existing
    /// dropped/unparseableFrames counters, since this is specifically the
    /// writer falling behind, not the kernel or the parser.
    pub backpressure_drops: u64,
}
```

- [ ] **Step 2: `main.rs` dispatch**

```rust
// In the existing async control-message-handling task (the same one that
// already matches on ControlMessage::Pause/SetCaptureFilter/etc.):
ControlMessage::StartCaptureFile { path, ring, autostop } => {
    // Validation mirrors SetCaptureFilter's existing rejected-request shape
    // (issue #68): a bad request gets a named error event, not a panic and
    // not a silent no-op.
    let resolved = std::path::Path::new(&path);
    let rejected = resolved.starts_with(std::env::current_dir().unwrap_or_default())
        || path.contains(".data/")
        || active_writer_state.lock().unwrap().is_some(); // Task-5's ring.rs owns the actual state; shown inline here for the dispatch shape
    if rejected {
        let _ = tx.send(wire::encode_event(&wire::AgentEvent::CaptureConfigError {
            message: "refused: capture path must not be inside the repo working tree, .data/, or already active".to_string(),
        }));
    } else {
        // Task 5's ring.rs::start(...) does the real work — opening the
        // first Writer, recording ring/autostop config, checking the
        // disk-space guard. Sketched here as a single call so this task's
        // diff stays reviewable independent of Task 5's internals.
        ring::start(&path, ring, autostop, /* ...shared state... */);
    }
}
ControlMessage::StopCaptureFile => {
    ring::stop(/* ...shared state... */, None); // None = operator-requested, not an autostop reason
}
```

- [ ] **Step 3: Emit `capture_file_status` every tick**

Alongside the existing per-tick `capture_stats`/`system_stats`/`capture_config` emission in the periodic emitter:

```rust
let status = ring::current_status(/* ...shared state... */); // Task 5
let _ = tx.send(wire::encode_event(&wire::AgentEvent::CaptureFileStatus { status }));
```

- [ ] **Step 4: Wire-layer tests**

```rust
// wire.rs's existing #[cfg(test)] mod tests
#[test]
fn decodes_start_capture_file_with_ring_and_autostop() {
    let json = r#"{"type":"start_capture_file","path":"/Users/me/captures/run1.pcapng","ring":{"mode":"size","threshold":104857600},"autostop":{"mode":"duration","threshold":3600}}"#;
    match decode_control(json) {
        Some(ControlMessage::StartCaptureFile { path, ring, autostop }) => {
            assert_eq!(path, "/Users/me/captures/run1.pcapng");
            assert_eq!(ring.unwrap(), RingConfigJson { mode: "size".into(), threshold: 104_857_600 });
            assert_eq!(autostop.unwrap(), AutostopConfigJson { mode: "duration".into(), threshold: 3600 });
        }
        other => panic!("expected StartCaptureFile, got {other:?}"),
    }
}

#[test]
fn decodes_start_capture_file_with_no_ring_or_autostop() {
    let json = r#"{"type":"start_capture_file","path":"/tmp/one-shot.pcapng"}"#;
    match decode_control(json) {
        Some(ControlMessage::StartCaptureFile { ring, autostop, .. }) => {
            assert!(ring.is_none());
            assert!(autostop.is_none());
        }
        other => panic!("expected StartCaptureFile, got {other:?}"),
    }
}

#[test]
fn decodes_stop_capture_file() {
    assert!(matches!(decode_control(r#"{"type":"stop_capture_file"}"#), Some(ControlMessage::StopCaptureFile)));
}

#[test]
fn encodes_capture_file_status_camel_case_omitting_absent_fields() {
    let event = AgentEvent::CaptureFileStatus {
        status: CaptureFileStatusJson {
            writing: false,
            path: None,
            bytes_written: 0,
            ring_file: None,
            ring_total: None,
            autostop_reason: None,
            backpressure_drops: 0,
        },
    };
    let line = encode_event(&event);
    assert!(line.contains(r#""writing":false"#));
    assert!(!line.contains("\"path\""), "absent Option fields must be omitted, not null");
}
```

- [ ] **Step 5: Build, test, commit**

```bash
cd capture-agent && cargo build --locked && cargo test --locked
git add src/wire.rs src/main.rs
git commit -m "feat(capture-agent): start_capture_file/stop_capture_file control messages, capture_file_status event (#70)"
```

---

### Task 5: `ring.rs` — atomic rotation across N files

**Files:**
- Create: `capture-agent/src/ring.rs`
- Modify: `capture-agent/src/lib.rs` (`pub mod ring;`)

**Interfaces:**
- Consumes: Task 3's `pcapng::Writer`/`InterfaceDescriptionBlock`.
- Produces:
  ```rust
  pub struct RingState { /* current Writer, ring config, file index, autostop config, disk-guard floor */ }
  pub fn start(base_path: &Path, ring: Option<RingConfigJson>, autostop: Option<AutostopConfigJson>, state: &Mutex<Option<RingState>>) -> Result<(), String>;
  pub fn stop(state: &Mutex<Option<RingState>>, autostop_reason: Option<&str>);
  pub fn on_tick(state: &Mutex<Option<RingState>>) -> CaptureFileStatusJson; // checks rotation/autostop/disk-guard thresholds, called once per periodic-emitter tick
  ```

Mirrors this repo's own established atomic-write pattern (`lib/enrichment/cache.ts`'s `atomicWriteJson`: write to a temp path, `rename()` onto the final name only once fully flushed) — restated here in Rust for a binary format instead of JSON, same guarantee: the file visible under its real name is always complete.

- [ ] **Step 1: Ring file naming and rotation**

```rust
// capture-agent/src/ring.rs
use crate::pcapng::{self, InterfaceDescriptionBlock, Writer};
use crate::wire::{AutostopConfigJson, CaptureFileStatusJson, RingConfigJson};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

pub struct RingState {
    writer: Writer,
    base_path: PathBuf,
    idb: InterfaceDescriptionBlock,
    hostname: String,
    agent_version: String,
    ring: Option<RingConfigJson>,
    autostop: Option<AutostopConfigJson>,
    current_index: u32, // 1-based, matches the UI's "file N of M" framing
    started_at: Instant,
    total_bytes_across_ring: u64,
}

/// `capture-0007.pcapng` for base path `capture.pcapng`, index 7 — a fixed-
/// width numbered sequence per the spec, wrapping once `ring.threshold`
/// (count mode) or an implicit ring size is reached. Non-ring (single-file)
/// captures use the base path unmodified.
fn ring_member_path(base_path: &Path, index: u32) -> PathBuf {
    let stem = base_path.file_stem().unwrap_or_default().to_string_lossy();
    let ext = base_path.extension().unwrap_or_default().to_string_lossy();
    base_path.with_file_name(format!("{stem}-{index:04}.{ext}"))
}

fn partial_path(final_path: &Path) -> PathBuf {
    let mut p = final_path.as_os_str().to_owned();
    p.push(".partial");
    PathBuf::from(p)
}

/// Opens the next file in sequence at its `.partial` name — the caller
/// (rotate_if_needed, Step 2) is responsible for renaming the PREVIOUS
/// file's `.partial` to its final name only after this new file has
/// successfully opened, so a failure here never leaves the ring in a state
/// where neither the old nor the new file is valid.
fn open_next(
    base_path: &Path,
    index: u32,
    idb: &InterfaceDescriptionBlock,
    hostname: &str,
    agent_version: &str,
) -> io::Result<Writer> {
    let final_path = ring_member_path(base_path, index);
    let partial = partial_path(&final_path);
    Writer::create(&partial, idb, hostname, agent_version)
}
```

- [ ] **Step 2: `start`/`stop` and the disk-space guard**

```rust
const DEFAULT_LOW_DISK_FLOOR_BYTES: u64 = 500 * 1024 * 1024; // 500MB default, spec Components §3

fn free_space_bytes(path: &Path) -> io::Result<u64> {
    // std::fs has no cross-platform free-space query; this repo already
    // limits itself to macOS/Linux (CLAUDE.md), so a small libc statvfs
    // wrapper (libc is already a normal dependency) is used rather than a
    // new crate — consistent with pcapng.rs's own zero-new-dependency call.
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat.f_bavail as u64 * stat.f_frsize as u64)
}

pub fn start(
    base_path: &Path,
    ring: Option<RingConfigJson>,
    autostop: Option<AutostopConfigJson>,
    idb: &InterfaceDescriptionBlock,
    hostname: &str,
    agent_version: &str,
    state: &Mutex<Option<RingState>>,
) -> Result<(), String> {
    let parent = base_path.parent().unwrap_or_else(|| Path::new("."));
    let free = free_space_bytes(parent).map_err(|e| format!("could not check free space: {e}"))?;
    if free < DEFAULT_LOW_DISK_FLOOR_BYTES {
        return Err(format!(
            "refused: only {free} bytes free at {}, below the {DEFAULT_LOW_DISK_FLOOR_BYTES}-byte floor",
            parent.display()
        ));
    }

    let writer = open_next(base_path, 1, idb, hostname, agent_version)
        .map_err(|e| format!("could not open capture file: {e}"))?;

    *state.lock().unwrap() = Some(RingState {
        writer,
        base_path: base_path.to_path_buf(),
        idb: idb.clone(),
        hostname: hostname.to_string(),
        agent_version: agent_version.to_string(),
        ring,
        autostop,
        current_index: 1,
        started_at: Instant::now(),
        total_bytes_across_ring: 0,
    });
    Ok(())
}

/// Closes the currently-open `.partial` file and renames it to its final
/// name — the one moment a ring member becomes visible under its real
/// name, and therefore the one moment it's guaranteed complete. Called by
/// both a normal rotation (Step 3) and by `stop`/autostop (so the LAST file
/// in a run is never left as a dangling `.partial`).
fn finish_and_rename(writer: Writer, final_path: &Path) -> io::Result<()> {
    let partial = partial_path(final_path);
    writer.finish()?; // flush + sync_all, Task 3
    std::fs::rename(&partial, final_path) // atomic on the same filesystem
}

pub fn stop(state: &Mutex<Option<RingState>>, autostop_reason: Option<&str>) {
    let mut guard = state.lock().unwrap();
    if let Some(ring_state) = guard.take() {
        let final_path = ring_member_path(&ring_state.base_path, ring_state.current_index);
        let _ = finish_and_rename(ring_state.writer, &final_path); // I/O error here is unusual enough to not need its own wire event beyond the next tick's capture_file_status simply reporting writing: false
        let _ = autostop_reason; // surfaced by on_tick's caller before this runs — see Step 3
    }
}
```

- [ ] **Step 3: `on_tick` — rotation, autostop, and the low-disk clean-stop path**

```rust
pub fn on_tick(state: &Mutex<Option<RingState>>, received: u64, dropped: u64, backpressure_drops: u64) -> CaptureFileStatusJson {
    let mut guard = state.lock().unwrap();
    let Some(ring_state) = guard.as_mut() else {
        return CaptureFileStatusJson {
            writing: false,
            path: None,
            bytes_written: 0,
            ring_file: None,
            ring_total: None,
            autostop_reason: None,
            backpressure_drops: 0,
        };
    };

    let _ = ring_state.writer.write_interface_stats(received, dropped);

    // Rotation check — size/duration/count, whichever mode is configured.
    let should_rotate = match &ring_state.ring {
        Some(cfg) if cfg.mode == "size" => ring_state.writer.bytes_written() >= cfg.threshold,
        Some(cfg) if cfg.mode == "duration" => ring_state.started_at.elapsed().as_secs() >= cfg.threshold,
        // "count" mode rotates by packet count — tracked via bytes_written
        // as a proxy is wrong; an implementer should add a packet counter
        // to RingState alongside bytes_written for this mode specifically.
        _ => false,
    };

    // Autostop check — duration/totalSize/fileCount.
    let autostop_reason = match &ring_state.autostop {
        Some(cfg) if cfg.mode == "duration" && ring_state.started_at.elapsed().as_secs() >= cfg.threshold => Some("duration"),
        Some(cfg) if cfg.mode == "totalSize" && ring_state.total_bytes_across_ring >= cfg.threshold => Some("totalSize"),
        _ => None,
    };

    let low_disk = ring_state
        .base_path
        .parent()
        .and_then(|p| free_space_bytes(p).ok())
        .map(|free| free < DEFAULT_LOW_DISK_FLOOR_BYTES)
        .unwrap_or(false);

    if autostop_reason.is_some() || low_disk {
        let reason = autostop_reason.unwrap_or("lowDisk").to_string();
        let ring_state = guard.take().unwrap();
        let final_path = ring_member_path(&ring_state.base_path, ring_state.current_index);
        let _ = finish_and_rename(ring_state.writer, &final_path);
        return CaptureFileStatusJson {
            writing: false,
            path: Some(final_path.display().to_string()),
            bytes_written: 0,
            ring_file: None,
            ring_total: None,
            autostop_reason: Some(reason),
            backpressure_drops,
        };
    }

    if should_rotate {
        let old_index = ring_state.current_index;
        let old_final = ring_member_path(&ring_state.base_path, old_index);
        let next_index = old_index + 1;
        match open_next(&ring_state.base_path, next_index, &ring_state.idb, &ring_state.hostname, &ring_state.agent_version) {
            Ok(new_writer) => {
                let old_writer = std::mem::replace(&mut ring_state.writer, new_writer);
                ring_state.total_bytes_across_ring += old_writer.bytes_written();
                let _ = finish_and_rename(old_writer, &old_final); // old file becomes visible under its real name only now — never a half-written file
                ring_state.current_index = next_index;
            }
            Err(_) => { /* leave the current file open and keep writing to it — a failed rotation is not a reason to stop capturing */ }
        }
    }

    CaptureFileStatusJson {
        writing: true,
        path: Some(ring_member_path(&ring_state.base_path, ring_state.current_index).display().to_string()),
        bytes_written: ring_state.writer.bytes_written(),
        ring_file: Some(ring_state.current_index),
        ring_total: None, // "count" ring mode's total; None for size/duration-mode rings, which have no fixed file count
        autostop_reason: None,
        backpressure_drops,
    }
}
```

- [ ] **Step 4: Tests — rotation, autostop, disk guard, atomicity**

```rust
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

    fn unique_base(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("ring-test-{label}-{}.pcapng", std::process::id()))
    }

    #[test]
    fn a_size_triggered_rotation_produces_a_complete_openable_file_and_starts_a_fresh_one() {
        let base = unique_base("size-rotate");
        let state: Mutex<Option<RingState>> = Mutex::new(None);
        start(&base, Some(RingConfigJson { mode: "size".into(), threshold: 100 }), None, &test_idb(), "host", "0.1.0", &state).unwrap();

        // Write enough to exceed the 100-byte threshold, then tick.
        {
            let mut guard = state.lock().unwrap();
            let rs = guard.as_mut().unwrap();
            for _ in 0..5 {
                rs.writer.write_packet(std::time::SystemTime::now(), pcapng::Direction::Inbound, &[0u8; 64]).unwrap();
            }
        }
        on_tick(&state, 5, 0, 0);

        let first_final = ring_member_path(&base, 1);
        assert!(first_final.exists(), "rotated-out file should be visible under its final name");
        assert!(!partial_path(&first_final).exists(), "no .partial should remain for a completed rotation");

        stop(&state, None);
        let second_final = ring_member_path(&base, 2);
        assert!(second_final.exists());

        std::fs::remove_file(&first_final).ok();
        std::fs::remove_file(&second_final).ok();
    }

    #[test]
    fn autostop_by_duration_closes_the_file_cleanly_and_reports_the_reason() {
        let base = unique_base("autostop-duration");
        let state: Mutex<Option<RingState>> = Mutex::new(None);
        start(&base, None, Some(AutostopConfigJson { mode: "duration".into(), threshold: 0 }), &test_idb(), "host", "0.1.0", &state).unwrap();

        let status = on_tick(&state, 0, 0, 0); // threshold 0 fires immediately
        assert_eq!(status.autostop_reason.as_deref(), Some("duration"));
        assert!(!status.writing);
        assert!(state.lock().unwrap().is_none(), "autostop must clear the active ring state");

        std::fs::remove_file(ring_member_path(&base, 1)).ok();
    }

    #[test]
    fn start_refuses_below_the_disk_space_floor() {
        // Dependency-injecting free_space_bytes would need a trait
        // indirection this sketch omits for brevity — an implementer
        // should extract free_space_bytes behind a small trait so this
        // test can inject a fake low-space answer rather than requiring an
        // actually-nearly-full filesystem in CI. Sketched here as the
        // test's *intent*; Task 5's real diff must include the
        // indirection, not skip this test.
    }

    #[test]
    fn a_crash_mid_write_leaves_every_already_rotated_file_valid() {
        let base = unique_base("crash-simulation");
        let state: Mutex<Option<RingState>> = Mutex::new(None);
        start(&base, Some(RingConfigJson { mode: "size".into(), threshold: 100 }), None, &test_idb(), "host", "0.1.0", &state).unwrap();
        {
            let mut guard = state.lock().unwrap();
            let rs = guard.as_mut().unwrap();
            for _ in 0..5 {
                rs.writer.write_packet(std::time::SystemTime::now(), pcapng::Direction::Inbound, &[0u8; 64]).unwrap();
            }
        }
        on_tick(&state, 5, 0, 0); // rotates — file 1 is now complete and renamed
        let first_final = ring_member_path(&base, 1);
        assert!(first_final.exists());

        // Simulate a crash: drop `state` without calling stop(), so file 2
        // is abandoned as a .partial. File 1 must remain valid regardless.
        drop(state);
        assert!(first_final.exists(), "already-rotated file must survive an unclean shutdown of a later file");
        let second_partial = partial_path(&ring_member_path(&base, 2));
        assert!(second_partial.exists(), "the in-flight file is expected to remain a .partial — that's the crash's honest footprint, not a bug");

        std::fs::remove_file(&first_final).ok();
        std::fs::remove_file(&second_partial).ok();
    }
}
```

- [ ] **Step 5: Real multi-hour-equivalent verification (manual, not `cargo test`)**

Per the spec's explicit acceptance criterion ("verify with a real multi-hour run, not just a unit test") and JAM-5's own acceptance criteria — run the agent against `lo` with a small size-mode ring (e.g. 1MB, 5 files) and `nc`/`curl` generating steady traffic for at least an hour; confirm total disk use under the capture directory never exceeds the configured ring size (5MB), and that every file present at the end opens cleanly in `capinfos`. Document the result inline in this task's PR description — this is a one-time verification, not a repeatable CI gate (an accelerated tick-rate override for CI is a legitimate follow-up but not required to close this task).

- [ ] **Step 6: Build, test, commit**

```bash
cd capture-agent && cargo build --locked && cargo test --locked ring
git add src/ring.rs src/lib.rs
git commit -m "feat(capture-agent): ring-buffer rotation, autostop, disk-space guard (#72)"
```

---

### Task 6: `pcapng.rs` — the reader, a round-trip test, and fuzz coverage

**Files:**
- Modify: `capture-agent/src/pcapng.rs`
- Create: `capture-agent/tests/pcapng_roundtrip.rs`, `capture-agent/fuzz/fuzz_targets/pcapng_reader.rs`, `capture-agent/tests/fixtures/pcapng/`

**Interfaces:**
- Produces:
  ```rust
  pub struct ParsedInterface { pub name: Option<String>, pub link_type: Option<crate::parse::LinkType>, pub snaplen: u32 }
  pub struct ParsedPacket { pub timestamp: std::time::SystemTime, pub data: Vec<u8> }
  pub struct Reader<R: Read> { /* opaque */ }
  impl<R: Read> Reader<R> {
      pub fn new(inner: R) -> io::Result<(Self, ParsedInterface)>; // consumes SHB + IDB, returns interface metadata immediately
      pub fn next_packet(&mut self) -> io::Result<Option<ParsedPacket>>; // None at EOF; skips ISB/unknown blocks transparently
  }
  ```
- Consumed by: Task 7's `PacketSource::ReplayPcapng` variant.

Untrusted-input-adjacent, per the spec's Security model table — a file handed to this tool, however it arrived, is not implicitly trustworthy. Every read here returns `Option`/`Result`, never panics, matching `parse.rs`'s existing discipline exactly.

- [ ] **Step 1: Generic block reader**

```rust
fn read_block<R: Read>(r: &mut R) -> io::Result<Option<(u32, Vec<u8>)>> {
    let mut type_and_len = [0u8; 8];
    match r.read_exact(&mut type_and_len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None), // clean EOF between blocks
        Err(e) => return Err(e),
    }
    let block_type = u32::from_le_bytes(type_and_len[0..4].try_into().unwrap());
    let total_len = u32::from_le_bytes(type_and_len[4..8].try_into().unwrap());
    // A block shorter than its own fixed 12-byte overhead (type + len +
    // len) is malformed by definition — reject rather than underflow the
    // body-length subtraction below.
    if total_len < 12 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "block length smaller than minimum block overhead"));
    }
    let body_len = total_len as usize - 12;
    let mut body = vec![0u8; body_len];
    r.read_exact(&mut body)?;
    let mut suffix = [0u8; 4];
    r.read_exact(&mut suffix)?;
    let suffix_len = u32::from_le_bytes(suffix);
    if suffix_len != total_len {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "block length prefix/suffix mismatch"));
    }
    Ok(Some((block_type, body)))
}

/// Walks an option TLV list, calling `on_option(code, value)` for each one
/// until opt_endofopt or the body is exhausted — used by both the IDB and
/// EPB readers below. Malformed option framing (a length that runs past
/// the body's end) is reported as an error, not a panic.
fn for_each_option(body: &[u8], mut on_option: impl FnMut(u16, &[u8])) -> io::Result<()> {
    let mut i = 0;
    while i + 4 <= body.len() {
        let code = u16::from_le_bytes(body[i..i + 2].try_into().unwrap());
        let len = u16::from_le_bytes(body[i + 2..i + 4].try_into().unwrap()) as usize;
        if code == OPT_END_OF_OPT {
            break;
        }
        let value_start = i + 4;
        let value_end = value_start + len;
        if value_end > body.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "option value runs past block body"));
        }
        on_option(code, &body[value_start..value_end]);
        i = value_start + pad4(len);
    }
    Ok(())
}
```

- [ ] **Step 2: `Reader::new` — consumes SHB + IDB**

```rust
pub struct ParsedInterface {
    pub name: Option<String>,
    pub link_type: Option<crate::parse::LinkType>,
    pub snaplen: u32,
}

pub struct Reader<R: Read> {
    inner: R,
}

fn linktype_from_pcapng(value: u16) -> Option<crate::parse::LinkType> {
    match value {
        1 => Some(crate::parse::LinkType::Ethernet),
        0 => Some(crate::parse::LinkType::NullLoopback),
        101 => Some(crate::parse::LinkType::Raw),
        _ => None, // an unsupported link type is reported, not guessed — Task 7 surfaces this as a startup failure, matching resolve_link_type's existing loud-failure precedent for live capture
    }
}

impl<R: Read> Reader<R> {
    pub fn new(mut inner: R) -> io::Result<(Self, ParsedInterface)> {
        let (block_type, _body) = read_block(&mut inner)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty file: no Section Header block"))?;
        if block_type != BT_SECTION_HEADER {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "first block is not a Section Header"));
        }

        let (block_type, body) = read_block(&mut inner)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "file ends after Section Header — no Interface Description block"))?;
        if block_type != BT_INTERFACE_DESCRIPTION {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "second block is not an Interface Description block"));
        }
        if body.len() < 8 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Interface Description block body too short"));
        }
        let link_type_raw = u16::from_le_bytes(body[0..2].try_into().unwrap());
        let snaplen = u32::from_le_bytes(body[4..8].try_into().unwrap());
        let mut name = None;
        for_each_option(&body[8..], |code, value| {
            if code == IF_NAME {
                name = Some(String::from_utf8_lossy(value).into_owned());
            }
        })?;

        Ok((
            Reader { inner },
            ParsedInterface { name, link_type: linktype_from_pcapng(link_type_raw), snaplen },
        ))
    }

    /// Returns the next captured frame, transparently skipping any
    /// Interface Statistics (or other/unrecognized) block in between —
    /// callers only ever want packets, and ISB's own drop/receive counters
    /// aren't meaningful to a replay consumer the way they are live.
    pub fn next_packet(&mut self) -> io::Result<Option<ParsedPacket>> {
        loop {
            let Some((block_type, body)) = read_block(&mut self.inner)? else {
                return Ok(None);
            };
            if block_type != BT_ENHANCED_PACKET {
                continue; // ISB or anything else in scope — skip, don't fail
            }
            if body.len() < 20 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Enhanced Packet block body too short"));
            }
            let ts_high = u32::from_le_bytes(body[4..8].try_into().unwrap()) as u64;
            let ts_low = u32::from_le_bytes(body[8..12].try_into().unwrap()) as u64;
            let captured_len = u32::from_le_bytes(body[12..16].try_into().unwrap()) as usize;
            let data_start = 20;
            let data_end = data_start + captured_len;
            if data_end > body.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Enhanced Packet block's declared length exceeds its own body"));
            }
            let ts_ns = (ts_high << 32) | ts_low;
            let timestamp = std::time::UNIX_EPOCH + std::time::Duration::from_nanos(ts_ns);
            return Ok(Some(ParsedPacket { timestamp, data: body[data_start..data_end].to_vec() }));
        }
    }
}
```

- [ ] **Step 3: Round-trip integration test**

```rust
// capture-agent/tests/pcapng_roundtrip.rs
//
// The most direct correctness check available for this codec (spec
// Testing section, and JAM-132's own acceptance criteria): write a file
// with the real Writer, read it back with the real Reader, and assert
// every packet survives byte-for-byte.
use capture_agent::pcapng::{Direction, InterfaceDescriptionBlock, Reader, Writer};
use capture_agent::parse::LinkType;
use std::io::Cursor;
use std::time::SystemTime;

#[test]
fn a_file_written_by_writer_reads_back_identically_via_reader() {
    let path = std::env::temp_dir().join(format!("pcapng-roundtrip-{}.pcapng", std::process::id()));
    let idb = InterfaceDescriptionBlock {
        interface_name: "lo".into(),
        link_type: LinkType::NullLoopback,
        snaplen: 65535,
        timestamp_resolution_exponent: 9,
    };
    let mut writer = Writer::create(&path, &idb, "test-host", "0.1.0").unwrap();
    let frames: Vec<Vec<u8>> = vec![vec![1, 2, 3, 4], vec![0u8; 128], (0..255u8).collect()];
    for frame in &frames {
        writer.write_packet(SystemTime::now(), Direction::Inbound, frame).unwrap();
    }
    writer.finish().unwrap();

    let file = std::fs::File::open(&path).unwrap();
    let (mut reader, interface) = Reader::new(file).unwrap();
    assert_eq!(interface.name.as_deref(), Some("lo"));
    assert_eq!(interface.link_type, Some(LinkType::NullLoopback));
    assert_eq!(interface.snaplen, 65535);

    for expected in &frames {
        let packet = reader.next_packet().unwrap().expect("expected a packet, got EOF early");
        assert_eq!(&packet.data, expected);
    }
    assert!(reader.next_packet().unwrap().is_none(), "no extra packets beyond what was written");

    std::fs::remove_file(&path).ok();
}

#[test]
fn interface_statistics_blocks_are_skipped_transparently_by_next_packet() {
    let path = std::env::temp_dir().join(format!("pcapng-isb-skip-{}.pcapng", std::process::id()));
    let idb = InterfaceDescriptionBlock {
        interface_name: "lo".into(),
        link_type: LinkType::NullLoopback,
        snaplen: 65535,
        timestamp_resolution_exponent: 9,
    };
    let mut writer = Writer::create(&path, &idb, "test-host", "0.1.0").unwrap();
    writer.write_packet(SystemTime::now(), Direction::Outbound, &[9, 9, 9]).unwrap();
    writer.write_interface_stats(100, 2).unwrap(); // an ISB written in between
    writer.write_packet(SystemTime::now(), Direction::Outbound, &[8, 8, 8]).unwrap();
    writer.finish().unwrap();

    let file = std::fs::File::open(&path).unwrap();
    let (mut reader, _interface) = Reader::new(file).unwrap();
    assert_eq!(reader.next_packet().unwrap().unwrap().data, vec![9, 9, 9]);
    assert_eq!(reader.next_packet().unwrap().unwrap().data, vec![8, 8, 8]);
    assert!(reader.next_packet().unwrap().is_none());

    std::fs::remove_file(&path).ok();
}

#[test]
fn truncated_file_reports_an_error_not_a_panic() {
    let mut buf = Vec::new();
    InterfaceDescriptionBlock {
        interface_name: "lo".into(),
        link_type: LinkType::NullLoopback,
        snaplen: 65535,
        timestamp_resolution_exponent: 9,
    };
    // A file with only a Section Header, nothing else.
    capture_agent::pcapng::SectionHeaderBlock { hostname: "h".into(), agent_version: "0.1.0".into() }
        .write_to(&mut buf)
        .unwrap();
    let result = Reader::new(Cursor::new(buf));
    assert!(result.is_err(), "a file missing its Interface Description block must error, not panic");
}
```

- [ ] **Step 4: Fuzz target**

```rust
// capture-agent/fuzz/fuzz_targets/pcapng_reader.rs
//
// Same untrusted-bytes posture as the existing parse_packet/http2_reassembly
// targets (issue #66) — a pcapng file is untrusted input the moment it can
// come from anywhere other than this agent's own writer (a third-party
// tool, a corrupted download, a deliberately hostile file someone hands to
// "replay this capture").
#![no_main]
use libfuzzer_sys::fuzz_target;
use capture_agent::pcapng::Reader;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    if let Ok((mut reader, _interface)) = Reader::new(Cursor::new(data)) {
        // Drain packets until EOF or the first error — must never panic,
        // whatever garbage follows a valid-looking header.
        while let Ok(Some(_packet)) = reader.next_packet() {}
    }
});
```

Add to `capture-agent/fuzz/Cargo.toml`'s `[[bin]]` list, matching `parse_packet`'s/`http2_reassembly`'s existing entries exactly. Wire into `.github/workflows/ci.yml`'s existing path-filtered fuzz job (Task 15 covers the CI-config diff itself, alongside `docs/architecture.md`'s resource-model pass, so both land together).

- [ ] **Step 5: Build, test, commit**

```bash
cd capture-agent && cargo build --locked && cargo test --locked
cargo +nightly fuzz run pcapng_reader -- -max_total_time=30 # local smoke run before relying on CI
git add src/pcapng.rs tests/pcapng_roundtrip.rs fuzz/fuzz_targets/pcapng_reader.rs fuzz/Cargo.toml
git commit -m "feat(capture-agent): pcapng reader, round-trip test, fuzz coverage (#71)"
```

---

### Task 7: `PacketSource` abstraction and `REPLAY_FILE` startup dispatch

**Files:**
- Modify: `capture-agent/src/main.rs`

**Interfaces:**
- Consumes: Task 6's `pcapng::Reader`.
- Produces: `enum PacketSource`, consumed by the capture loop's existing per-packet body (unmodified from this point onward — `parse::parse_packet` and everything after it never sees which variant is active).

This is the mechanism that makes "the same wire events, no special cases downstream" (spec Components §2's stated goal) actually true.

- [ ] **Step 1: The enum and its next-frame method**

```rust
enum PacketSource {
    Live(pcap::Capture<pcap::Active>),
    ReplayPcapng(pcapng::Reader<std::fs::File>),
    ReplayClassic(pcap::Capture<pcap::Offline>),
}

enum SourceFrame {
    Bytes { data: Vec<u8>, timestamp: std::time::SystemTime },
    Timeout, // Live mode's existing pcap read-timeout case — the capture loop already handles this today for control-message polling between packets
    Eof,     // replay-only: the file has been fully consumed
}

impl PacketSource {
    fn next_frame(&mut self) -> SourceFrame {
        match self {
            PacketSource::Live(cap) => match cap.next_packet() {
                Ok(packet) => SourceFrame::Bytes {
                    data: packet.data.to_vec(),
                    timestamp: std::time::SystemTime::now(), // live mode's existing behavior — unchanged
                },
                Err(pcap::Error::TimeoutExpired) => SourceFrame::Timeout,
                Err(_) => SourceFrame::Eof, // a live device closing is treated the same as replay EOF — both mean "no more frames"
            },
            PacketSource::ReplayPcapng(reader) => match reader.next_packet() {
                Ok(Some(packet)) => SourceFrame::Bytes { data: packet.data, timestamp: packet.timestamp },
                Ok(None) => SourceFrame::Eof,
                Err(_) => SourceFrame::Eof, // a malformed trailing block ends replay early rather than looping forever on the same error
            },
            PacketSource::ReplayClassic(cap) => match cap.next_packet() {
                Ok(packet) => SourceFrame::Bytes {
                    data: packet.data.to_vec(),
                    timestamp: std::time::UNIX_EPOCH
                        + std::time::Duration::new(packet.header.ts.tv_sec as u64, (packet.header.ts.tv_usec * 1000) as u32),
                },
                Err(_) => SourceFrame::Eof,
            },
        }
    }
}
```

- [ ] **Step 2: Startup dispatch — `REPLAY_FILE`, mutual exclusion with `CAPTURE_INTERFACE`, `REPLAY_LOCAL_ADDRS`, `REPLAY_SPEED`**

```rust
/// Mirrors detect_interface()'s existing fail-loud posture exactly: an
/// unparseable or self-contradictory startup configuration panics with a
/// specific message naming what's wrong, never silently falls back.
fn resolve_packet_source() -> (PacketSource, String /* interface_name */, Vec<String> /* local_addrs */, parse::LinkType, &'static str /* mode: "live" | "replay" */, Option<String> /* replay_source */) {
    let replay_file = std::env::var("REPLAY_FILE").ok().filter(|s| !s.trim().is_empty());
    let capture_interface_set = std::env::var_os("CAPTURE_INTERFACE")
        .map(|v| !v.to_string_lossy().trim().is_empty())
        .unwrap_or(false);

    if let Some(path) = replay_file {
        if capture_interface_set {
            panic!("both CAPTURE_INTERFACE and REPLAY_FILE are set — these are mutually exclusive; unset one");
        }
        let file = std::fs::File::open(&path)
            .unwrap_or_else(|e| panic!("REPLAY_FILE={path} could not be opened: {e}"));

        // Try pcapng first (this agent's own writer always produces it, and
        // it's the richer format); fall back to classic pcap via libpcap's
        // own file-open support, per spec Components §2's two-path design.
        match pcapng::Reader::new(file) {
            Ok((reader, interface)) => {
                let link_type = interface.link_type.unwrap_or_else(|| {
                    panic!("REPLAY_FILE={path} uses a link type this agent cannot decode")
                });
                let interface_name = interface.name.unwrap_or_else(|| "unknown (replayed pcapng, no if_name recorded)".to_string());
                let local_addrs = replay_local_addrs();
                (
                    PacketSource::ReplayPcapng(pcapng::Reader::new(std::fs::File::open(&path).unwrap()).unwrap().0),
                    interface_name,
                    local_addrs,
                    link_type,
                    "replay",
                    Some(path.clone()),
                )
            }
            Err(_) => {
                // Not a valid pcapng file — try classic pcap via the
                // existing `pcap` dependency's own file-open support.
                let cap = pcap::Capture::from_file(&path)
                    .unwrap_or_else(|e| panic!("REPLAY_FILE={path} is neither valid pcapng nor classic pcap: {e}"));
                let link_type = resolve_link_type(cap.get_datalink(), &path);
                let local_addrs = replay_local_addrs();
                (
                    PacketSource::ReplayClassic(cap),
                    "unknown (replayed classic pcap)".to_string(),
                    local_addrs,
                    link_type,
                    "replay",
                    Some(path),
                )
            }
        }
    } else {
        // Existing live-mode startup path — device already resolved by
        // detect_interface() earlier in main(), unchanged by this task.
        let device = detect_interface();
        let interface_name = device.name.clone();
        let local_addrs = local_addrs_for(&device);
        let cap = /* ...existing live Capture::from_device/.open() chain, unchanged... */ todo!();
        let link_type = resolve_link_type(cap.get_datalink(), &interface_name);
        (PacketSource::Live(cap), interface_name, local_addrs, link_type, "live", None)
    }
}

/// REPLAY_LOCAL_ADDRS, comma-separated — spec Components §2's resolution
/// for "FlowTable::new's local_addrs cannot come from this machine's
/// interfaces when replaying someone else's capture." Empty (never
/// guessed) if unset; Task 8 covers the pcapng-IDB-address fallback and the
/// "unknown direction" degradation this produces.
fn replay_local_addrs() -> Vec<String> {
    std::env::var("REPLAY_LOCAL_ADDRS")
        .ok()
        .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default()
}

enum ReplaySpeed {
    Fast,
    Realtime,
}

fn replay_speed() -> ReplaySpeed {
    match std::env::var("REPLAY_SPEED").as_deref() {
        Ok("realtime") => ReplaySpeed::Realtime,
        _ => ReplaySpeed::Fast, // default, and the only meaningful value in live mode (ignored there)
    }
}
```

- [ ] **Step 3: Realtime pacing in the capture loop**

```rust
// In the capture loop, only when mode == "replay" and ReplaySpeed::Realtime:
// sleep for the delta between this frame's timestamp and the previous
// one before processing it, capped at some sane maximum (e.g. 5s) so a
// capture with a multi-hour gap in it doesn't stall replay for that long.
if let (ReplaySpeed::Realtime, Some(prev_ts)) = (&replay_speed, previous_frame_timestamp) {
    if let Ok(delta) = frame_timestamp.duration_since(prev_ts) {
        std::thread::sleep(delta.min(Duration::from_secs(5)));
    }
}
previous_frame_timestamp = Some(frame_timestamp);
```

`pause`/`resume` (existing `AtomicBool`) are checked in the same loop iteration exactly as they already are for live mode — no new code needed for those two control messages to "just work" against a replay, per the spec's explicit claim.

- [ ] **Step 4: Tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_local_addrs_parses_comma_separated_list() {
        std::env::set_var("REPLAY_LOCAL_ADDRS", "192.168.1.10, 10.0.0.5,");
        let addrs = replay_local_addrs();
        assert_eq!(addrs, vec!["192.168.1.10".to_string(), "10.0.0.5".to_string()]);
        std::env::remove_var("REPLAY_LOCAL_ADDRS");
    }

    #[test]
    fn replay_local_addrs_is_empty_when_unset() {
        std::env::remove_var("REPLAY_LOCAL_ADDRS");
        assert!(replay_local_addrs().is_empty());
    }

    #[test]
    #[should_panic(expected = "mutually exclusive")]
    fn refuses_both_capture_interface_and_replay_file_set() {
        std::env::set_var("CAPTURE_INTERFACE", "lo");
        std::env::set_var("REPLAY_FILE", "/tmp/whatever.pcapng");
        let _ = resolve_packet_source(); // panics — this test asserts the message, not the return value
        std::env::remove_var("CAPTURE_INTERFACE");
        std::env::remove_var("REPLAY_FILE");
    }
}
```

**Note for the implementer:** `resolve_packet_source`'s live-mode branch above elides the existing `Capture::from_device(...).and_then(|c| c.promisc(true)...open())` chain with `todo!()` deliberately — that logic is untouched by this task and should be moved into this function verbatim from its current location in `main()`, not rewritten. The diff for this task should read as "wrap the existing live-open logic in a match arm, add two new arms," not a rewrite of working code.

- [ ] **Step 5: Build, test, commit**

```bash
cd capture-agent && cargo build --locked && cargo test --locked
git add src/main.rs
git commit -m "feat(capture-agent): PacketSource abstraction, REPLAY_FILE/REPLAY_LOCAL_ADDRS/REPLAY_SPEED startup dispatch (#71)"
```

---

### Task 8: Direction attribution and process-lookup degradation for replay

**Files:**
- Modify: `capture-agent/src/flow.rs`, `capture-agent/src/main.rs`, `capture-agent/src/wire.rs`

**Interfaces:**
- Consumes: Task 7's `local_addrs` (possibly empty, in replay mode with no `REPLAY_LOCAL_ADDRS` and no IDB address option).
- Produces: `FlowTable`'s existing `key_for` gains a documented fallback path; `AgentEvent::AgentStatus` gains a `direction_attribution_unavailable: bool` field.

**A gap found while planning this task, not in the spec as written:** `FlowTable::is_local`/`key_for` currently return `false`/`None` for *every* packet when `local_addrs` is empty — meaning an empty local-address list doesn't produce "unknown-direction flows," it produces **zero flows at all** (`key_for` returning `None` means `observe()` no-ops silently for that packet). That's a worse outcome than the spec's stated "every flow... attributed 'unknown' direction" — it would fail JAM-133's own acceptance criterion that a replayed capture "populate[s] connections, packets and layer stats" at all. This task fixes that, and the spec's Components §2/Wire-changes sections should be read as amended by this task's resolution: the "one-time capture_file_status note" the spec describes is moved to the already-being-revived `agent_status` event instead (Task 9), since it's a property of the whole replay session, not of file-writing status — `capture_file_status` is about the writer, not replay, and conflating the two would be confusing on the wire.

- [ ] **Step 1: `FlowTable` positional fallback when `local_addrs` is empty**

```rust
// flow.rs — key_for's existing body, with a fallback branch added. The
// existing two branches (is_local(src) / is_local(dst)) are unchanged;
// only the final "neither matched" case changes.
fn key_for(&self, packet: &ParsedPacket) -> Option<(FlowKey, bool)> {
    let (src_port, dst_port) = (packet.src_port?, packet.dst_port?);
    if self.is_local(&packet.src_ip) {
        // ...existing branch, unchanged...
    } else if self.is_local(&packet.dst_ip) {
        // ...existing branch, unchanged...
    } else if self.local_addrs.is_empty() {
        // No known local address at all (replay with no REPLAY_LOCAL_ADDRS
        // and no IDB address option — Task 7) — rather than silently
        // dropping this packet from the flow table entirely, fall back to
        // a fixed positional convention: the packet's source is always
        // treated as "local" for FlowKey construction. This is explicitly
        // NOT a claim that the source actually was the local side — every
        // consumer of this flow's direction is told so via
        // agent_status.directionAttributionUnavailable (Task 9), sent once
        // per replay session, not silently per-flow.
        Some((
            FlowKey {
                protocol: packet.protocol,
                local_addr: packet.src_ip.clone(),
                local_port: src_port,
                remote_addr: packet.dst_ip.clone(),
                remote_port: dst_port,
            },
            true,
        ))
    } else {
        // local_addrs is non-empty but matched neither side — e.g. a
        // capture containing third-party-to-third-party traffic captured
        // in promiscuous mode. Unchanged existing behavior: this packet
        // isn't part of any flow this table tracks.
        None
    }
}
```

- [ ] **Step 2: `main.rs` — never populate `process_map` in replay mode**

```rust
// In main(), where the existing process_map background-refresh thread is
// spawned (see main.rs's "Background: refresh the process-attribution map
// every 3s" comment) — gated on mode:
let process_map = Arc::new(Mutex::new(if mode == "live" {
    process_lookup::refresh()
} else {
    HashMap::new() // never populated for the life of a replay process
}));
if mode == "live" {
    let process_map = process_map.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(3));
        let fresh = process_lookup::refresh();
        *process_map.lock().unwrap() = fresh;
    });
}
```

No change needed to the connection-emission code itself (`process_name: proc_info.map(...).unwrap_or_else(|| "unknown".to_string())`, `pid: proc_info.map(...).unwrap_or(0)`) — an empty, never-populated `process_map` already produces exactly `"unknown"`/`0` for every connection via the existing fallback, which is the correct replay behavior for free. This is why Task 8 has no wire-schema change for process attribution: the existing schema's "no match" sentinel already means what replay needs it to mean.

- [ ] **Step 3: Wire field for the one-time direction-attribution note**

```rust
// wire.rs — AgentEvent::AgentStatus's payload, extended by Task 9 for
// mode/replay_source; this task adds the third field to that same struct:
pub struct AgentStatusJson {
    pub interface: String,
    pub capturing: bool,
    pub mode: String, // "live" | "replay" — Task 9
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay_source: Option<String>, // Task 9
    pub direction_attribution_unavailable: bool, // this task — true only when local_addrs was empty at startup
}
```

- [ ] **Step 4: Tests**

```rust
// flow.rs's existing #[cfg(test)] mod tests
#[test]
fn with_no_local_addrs_a_packet_still_produces_a_flow_using_positional_fallback() {
    let mut table = FlowTable::new(vec![]); // empty — the replay-with-no-hint case
    let packet = /* ...build a ParsedPacket with src_ip "203.0.113.5", dst_ip "198.51.100.9"... */;
    table.observe(&packet);
    let flows = table.snapshot(0);
    assert_eq!(flows.len(), 1, "an empty local_addrs list must not silently drop every packet");
    assert_eq!(flows[0].key.local_addr, "203.0.113.5", "positional fallback treats source as local");
}

#[test]
fn with_local_addrs_set_but_not_matching_either_side_the_packet_is_still_dropped() {
    let mut table = FlowTable::new(vec!["10.0.0.1".to_string()]); // non-empty, but doesn't match this packet
    let packet = /* src "203.0.113.5", dst "198.51.100.9" — neither is 10.0.0.1 */;
    table.observe(&packet);
    assert_eq!(table.snapshot(0).len(), 0, "a non-empty, non-matching local_addrs list keeps its existing drop behavior — only the EMPTY case gets the new fallback");
}
```

- [ ] **Step 5: Build, test, commit**

```bash
cd capture-agent && cargo build --locked && cargo test --locked flow
git add src/flow.rs src/main.rs src/wire.rs
git commit -m "fix(capture-agent): positional direction fallback and process-lookup degradation for replay (#71)"
```

---

### Task 9: Revive `agent_status`; add `totalConnectionsObserved`/`capacityEvictions`/`idleEvictions` to `capture_stats`

**Files:**
- Modify: `capture-agent/src/wire.rs`, `capture-agent/src/main.rs`, `capture-agent/src/flow.rs`

**Interfaces:**
- Produces: `AgentStatusJson` (Task 8, Step 3, extended here with `mode`/`replay_source`); three new fields on the existing `CaptureStatsJson`.
- Modifies an existing signature: `FlowTable::evict_stale`'s return type changes from `Vec<FlowKey>` to a small struct distinguishing *why* each key was evicted — every existing call site and test that touches this function needs updating, called out explicitly here since it's the one signature-breaking change in this whole plan.

- [ ] **Step 1: `FlowTable` gains three cumulative counters**

```rust
// flow.rs — new fields on FlowTable itself (alongside the existing
// `flows`/`local_addrs`/`max_flows`):
pub struct FlowTable {
    // ...existing fields...
    total_flows_observed: u64,
    capacity_evictions: u64,
    idle_evictions: u64,
}
```

`observe`'s existing `self.flows.entry(key).or_default()` line becomes entry-aware so first-sight can be counted:

```rust
use std::collections::hash_map::Entry;

let is_new = matches!(self.flows.entry(key.clone()), Entry::Vacant(_));
if is_new {
    self.total_flows_observed += 1;
}
let state = self.flows.entry(key).or_default();
```

(Two `entry()` calls on the same key is slightly wasteful but keeps the diff minimal and obviously correct; an implementer may collapse this into one `match` on a single `entry()` call if preferred — either is fine, this is not a hot-path-sensitive count relative to the packet-parsing work already happening per packet.)

`evict_stale`'s return type changes to distinguish eviction reason — **every existing caller and test of this function must be updated**:

```rust
pub struct EvictedFlows {
    pub idle: Vec<FlowKey>,
    pub capacity: Vec<FlowKey>,
}

pub fn evict_stale(&mut self, now_ms: u64) -> EvictedFlows {
    // ...existing idle-eviction retain() loop, unchanged, but pushing into
    // `idle` instead of a single shared `evicted` Vec...
    let mut idle = Vec::new();
    self.flows.retain(|key, state| {
        // ...unchanged threshold logic...
        if stale { idle.push(key.clone()); }
        !stale
    });
    self.idle_evictions += idle.len() as u64;

    // ...existing capacity-eviction loop, unchanged, but pushing into
    // `capacity` instead...
    let mut capacity = Vec::new();
    if self.flows.len() > self.max_flows {
        // ...unchanged by_age sort/take(excess) logic, pushing into `capacity`...
    }
    self.capacity_evictions += capacity.len() as u64;

    EvictedFlows { idle, capacity }
}

pub fn total_flows_observed(&self) -> u64 { self.total_flows_observed }
pub fn capacity_evictions(&self) -> u64 { self.capacity_evictions }
pub fn idle_evictions(&self) -> u64 { self.idle_evictions }
```

**Call sites to update** (grep `evict_stale` in `main.rs` — the periodic emitter's existing per-tick call, and any place that currently does `evicted.len()` or iterates the old flat `Vec<FlowKey>` to emit `connection_closed` events): the existing `connection_closed` emission logic must now iterate `evicted.idle.iter().chain(evicted.capacity.iter())` to preserve its current behavior of closing both kinds of eviction identically on the wire — only the *counting*, not the `connection_closed` event itself, is reason-aware. `connection_closed`'s own wire shape (`{ id: String }`) is unchanged.

- [ ] **Step 2: `CaptureStatsJson` gains the three new fields**

```rust
// wire.rs
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureStatsJson {
    // ...existing fields (received, dropped, if_dropped, relay_lagged_events, unparseable_frames)...
    pub total_connections_observed: u64,
    pub capacity_evictions: u64,
    pub idle_evictions: u64,
}
```

Populated each tick from `flow_table.lock().unwrap()`'s three new accessor methods, alongside wherever `CaptureStatsJson` is currently constructed in the periodic emitter.

- [ ] **Step 3: `AgentStatusJson` completed and actually emitted**

```rust
// wire.rs — AgentStatusJson now fully specified (interface/capturing
// already existed; mode/replay_source from Task 7's resolve_packet_source,
// direction_attribution_unavailable from Task 8):
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentStatusJson {
    pub interface: String,
    pub capturing: bool,
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay_source: Option<String>,
    pub direction_attribution_unavailable: bool,
}
```

```rust
// AgentEvent::AgentStatus's existing variant shape ({interface: String,
// capturing: bool}) is replaced with the struct above, matching how every
// other multi-field event in this enum is already boxed/structured:
AgentStatus { status: AgentStatusJson },
```

Emitted every tick, alongside `capture_stats`/`system_stats`/`capture_config`/`capture_file_status` in the periodic emitter — resolving `docs/wire-protocol.md`'s own "defined but never actually sent... a future task should wire it up" note (Task 11 updates that doc).

- [ ] **Step 4: Tests**

```rust
// flow.rs
#[test]
fn total_flows_observed_counts_distinct_flows_not_packets() {
    let mut table = FlowTable::new(vec!["10.0.0.1".to_string()]);
    let packet = /* src 10.0.0.1:1234, dst 8.8.8.8:443 */;
    table.observe(&packet, &L7Info::None, 0);
    table.observe(&packet, &L7Info::None, 100); // same flow, second packet
    table.observe(&packet, &L7Info::None, 200); // same flow, third packet
    assert_eq!(table.total_flows_observed(), 1, "repeated packets on the same flow must not inflate the observed count");
}

#[test]
fn capacity_and_idle_evictions_are_counted_separately() {
    let mut table = FlowTable::new_with_capacity(vec!["10.0.0.1".to_string()], 1);
    let a = /* flow A packet */;
    let b = /* flow B packet, distinct key */;
    table.observe(&a, &L7Info::None, 0);
    table.observe(&b, &L7Info::None, 0); // exceeds capacity 1 — evicts A
    let evicted = table.evict_stale(0);
    assert_eq!(evicted.capacity.len(), 1);
    assert_eq!(evicted.idle.len(), 0);
    assert_eq!(table.capacity_evictions(), 1);
    assert_eq!(table.idle_evictions(), 0);
}
```

```rust
// wire.rs
#[test]
fn encodes_agent_status_with_mode_and_direction_flag() {
    let event = AgentEvent::AgentStatus {
        status: AgentStatusJson {
            interface: "lo".into(),
            capturing: true,
            mode: "replay".into(),
            replay_source: Some("/tmp/test.pcapng".into()),
            direction_attribution_unavailable: true,
        },
    };
    let line = encode_event(&event);
    assert!(line.contains(r#""mode":"replay""#));
    assert!(line.contains(r#""directionAttributionUnavailable":true"#));
}
```

- [ ] **Step 5: Build, test, commit**

```bash
cd capture-agent && cargo build --locked && cargo test --locked
git add src/wire.rs src/main.rs src/flow.rs
git commit -m "feat(capture-agent): revive agent_status (mode/replay indicator), capture_stats horizon/eviction counters (#73)"
```

---

### Task 10: `docs/wire-protocol.md`, `lib/agent-mapping.ts`, `lib/types.ts`

**Files:**
- Modify: `docs/wire-protocol.md`, `lib/agent-mapping.ts`, `lib/types.ts`

**Interfaces:**
- Consumes: every wire change from Tasks 4 and 9.
- Produces: `mapAgentStatusEvent`, `mapCaptureFileStatusEvent`; `mapCaptureStatsEvent` extended; new `AgentMode`, `CaptureFileStatus` types — consumed by Task 11 (`app/page.tsx`).

Per this repo's standing rule (`CLAUDE.md`, `CONTRIBUTING.md`): any wire change updates the doc and both TS files together, in the same commit.

- [ ] **Step 1: `docs/wire-protocol.md`**

Replace the existing `### agent_status` section (currently: *"Defined in the wire protocol... but never actually sent... dead wire protocol surface"*) with its real, now-live contract:

```markdown
### `agent_status`

Sent once per tick, alongside `capture_stats`/`system_stats`/`capture_config` — previously defined but never sent (see git history); wired up by epic #55 to carry the live/replay mode indicator JAM-133 needs.

\`\`\`json
{
  "type": "agent_status",
  "interface": "lo",
  "capturing": true,
  "mode": "replay",
  "replaySource": "/Users/me/captures/incident.pcapng",
  "directionAttributionUnavailable": false
}
\`\`\`

Field notes:
- `mode` — `"live"` or `"replay"`, fixed for the life of the agent process (see `REPLAY_FILE`, below) — never changes mid-session.
- `replaySource` — present only when `mode` is `"replay"`; the file path passed via `REPLAY_FILE`.
- `directionAttributionUnavailable` — `true` for the whole session when replay had no derivable local-address information (`REPLAY_LOCAL_ADDRS` unset and the file's own Interface Description block carried no address option) — every connection in that session used a positional fallback (source treated as local) rather than a real determination. See `capture-agent/src/flow.rs`'s `key_for`.
```

Add new sections for `capture_file_status` and the two new control messages, following the existing `capture_config`/`set_capture_filter` sections' format exactly (JSON example, field notes, note on how a client should treat an absent optional field). Extend the existing `capture_stats` section's field notes with `totalConnectionsObserved`/`capacityEvictions`/`idleEvictions`, following the same per-field bullet style already used there for `received`/`dropped`/etc.

Add a `REPLAY_FILE`/`REPLAY_LOCAL_ADDRS`/`REPLAY_SPEED` subsection near wherever `CAPTURE_INTERFACE` is currently documented (if it is — check `docs/troubleshooting.md` and `docs/getting-started.md` too, since `CAPTURE_INTERFACE`'s own docs may live there rather than in `wire-protocol.md`; place the new env vars' documentation in whichever file `CAPTURE_INTERFACE`'s already lives in, not a new location).

- [ ] **Step 2: `lib/types.ts`**

```typescript
// lib/types.ts
export type AgentMode = 'live' | 'replay';

export interface AgentStatus {
  interface: string;
  capturing: boolean;
  mode: AgentMode;
  replaySource?: string;
  directionAttributionUnavailable: boolean;
}

export interface CaptureFileStatus {
  writing: boolean;
  path?: string;
  bytesWritten: number;
  ringFile?: number;
  ringTotal?: number;
  autostopReason?: string;
  backpressureDrops: number;
}

// CaptureStats — existing interface, three fields added:
export interface CaptureStats {
  received: number;
  dropped: number;
  ifDropped: number;
  relayLaggedEvents: number;
  unparseableFrames: number;
  totalConnectionsObserved: number;
  capacityEvictions: number;
  idleEvictions: number;
}
```

- [ ] **Step 3: `lib/agent-mapping.ts`**

```typescript
// lib/agent-mapping.ts
export function mapAgentStatusEvent(json: unknown): AgentStatus {
  const w = json as Record<string, unknown>;
  return {
    interface: requireField(w, 'interface'),
    capturing: requireField(w, 'capturing'),
    mode: requireField(w, 'mode'),
    replaySource: w.replaySource as string | undefined,
    directionAttributionUnavailable: requireField(w, 'directionAttributionUnavailable'),
  };
}

export function mapCaptureFileStatusEvent(json: unknown): CaptureFileStatus {
  // Same nested-envelope shape as mapCaptureStatsEvent/mapTracerouteHopEvent
  // — the full event carries a `status` key.
  const w = json as { status?: Record<string, unknown> };
  const status = w.status;
  if (!status) {
    throw new Error('malformed capture_file_status event: missing "status" field');
  }
  return {
    writing: requireField(status, 'writing'),
    path: status.path as string | undefined,
    bytesWritten: requireField(status, 'bytesWritten'),
    ringFile: status.ringFile as number | undefined,
    ringTotal: status.ringTotal as number | undefined,
    autostopReason: status.autostopReason as string | undefined,
    backpressureDrops: requireField(status, 'backpressureDrops'),
  };
}

// mapCaptureStatsEvent — existing function, extended:
export function mapCaptureStatsEvent(json: unknown): CaptureStats {
  const w = json as { stats?: Record<string, unknown> };
  const stats = w.stats;
  if (!stats) {
    throw new Error('malformed capture_stats event: missing "stats" field');
  }
  return {
    received: requireField(stats, 'received'),
    dropped: requireField(stats, 'dropped'),
    ifDropped: requireField(stats, 'ifDropped'),
    relayLaggedEvents: requireField(stats, 'relayLaggedEvents'),
    unparseableFrames: requireField(stats, 'unparseableFrames'),
    totalConnectionsObserved: requireField(stats, 'totalConnectionsObserved'),
    capacityEvictions: requireField(stats, 'capacityEvictions'),
    idleEvictions: requireField(stats, 'idleEvictions'),
  };
}
```

- [ ] **Step 4: Tests**

```typescript
// lib/__tests__/agent-mapping.test.ts — new cases alongside the existing ones
describe('mapAgentStatusEvent', () => {
  it('maps a live-mode status with directionAttributionUnavailable false', () => {
    const event = { type: 'agent_status', interface: 'en0', capturing: true, mode: 'live', directionAttributionUnavailable: false };
    expect(mapAgentStatusEvent(event)).toEqual({
      interface: 'en0', capturing: true, mode: 'live', replaySource: undefined, directionAttributionUnavailable: false,
    });
  });

  it('maps a replay-mode status including replaySource', () => {
    const event = { type: 'agent_status', interface: 'unknown (replayed pcapng, no if_name recorded)', capturing: true, mode: 'replay', replaySource: '/tmp/x.pcapng', directionAttributionUnavailable: true };
    const mapped = mapAgentStatusEvent(event);
    expect(mapped.mode).toBe('replay');
    expect(mapped.replaySource).toBe('/tmp/x.pcapng');
    expect(mapped.directionAttributionUnavailable).toBe(true);
  });
});

describe('mapCaptureFileStatusEvent', () => {
  it('maps an active-writing status', () => {
    const event = { type: 'capture_file_status', status: { writing: true, path: '/tmp/capture-0001.pcapng', bytesWritten: 4096, ringFile: 1, backpressureDrops: 0 } };
    const mapped = mapCaptureFileStatusEvent(event);
    expect(mapped.writing).toBe(true);
    expect(mapped.ringFile).toBe(1);
    expect(mapped.autostopReason).toBeUndefined();
  });

  it('throws on a missing status field, matching every other envelope mapper', () => {
    expect(() => mapCaptureFileStatusEvent({ type: 'capture_file_status' })).toThrow();
  });
});

describe('mapCaptureStatsEvent (extended)', () => {
  it('carries the three new horizon/eviction counters', () => {
    const event = { type: 'capture_stats', stats: { received: 100, dropped: 0, ifDropped: 0, relayLaggedEvents: 0, unparseableFrames: 0, totalConnectionsObserved: 42, capacityEvictions: 3, idleEvictions: 7 } };
    const mapped = mapCaptureStatsEvent(event);
    expect(mapped.totalConnectionsObserved).toBe(42);
    expect(mapped.capacityEvictions).toBe(3);
    expect(mapped.idleEvictions).toBe(7);
  });
});
```

- [ ] **Step 5: Type-check, test, commit**

```bash
npx tsc --noEmit && npx vitest run
git add docs/wire-protocol.md lib/types.ts lib/agent-mapping.ts lib/__tests__/agent-mapping.test.ts
git commit -m "docs+feat: document and map agent_status/capture_file_status, extend capture_stats (#70 #71 #73)"
```

---

### Task 11: `app/page.tsx` — three-state mode banner and `capture_file_status` display

**Files:**
- Modify: `app/page.tsx`, `components/HeaderBar.tsx`

**Interfaces:**
- Consumes: Task 10's `mapAgentStatusEvent`/`mapCaptureFileStatusEvent`.
- Produces: new `agentMode`/`captureFileStatus` state in `app/page.tsx`, passed down to `HeaderBar`.

Today's banner is a single boolean (`agentConnected`, driven by the relay-synthesized `connection_status` event). This task makes it a three-state derivation — live / replaying `<source>` / disconnected — per JAM-133's explicit requirement, without removing `connection_status`'s existing role (it still answers "is the TCP socket to the agent up at all," which is orthogonal to "what mode is the agent in").

- [ ] **Step 1: New state and SSE handling**

```typescript
// app/page.tsx — new state alongside the existing agentConnected/captureStats/etc.
const [agentMode, setAgentMode] = useState<AgentStatus | null>(null); // null until the first agent_status tick
const [captureFileStatus, setCaptureFileStatus] = useState<CaptureFileStatus | null>(null);
```

```typescript
// In the existing SSE onmessage handler, alongside the other `if (data.type === '...')` branches:
if (data.type === 'agent_status') {
  setAgentMode(mapAgentStatusEvent(data));
}
if (data.type === 'capture_file_status') {
  setCaptureFileStatus(mapCaptureFileStatusEvent(data));
}
```

- [ ] **Step 2: Three-state banner derivation**

```typescript
// Replaces the existing single `{!agentConnected && (...)}` banner block.
// Order matters: disconnected (no TCP socket at all) always wins over
// whatever mode was last known, since a disconnected agent's last-known
// mode is stale information.
const bannerState: 'disconnected' | 'live' | 'replaying' = !agentConnected
  ? 'disconnected'
  : agentMode?.mode === 'replay'
    ? 'replaying'
    : 'live';
```

```tsx
{bannerState === 'disconnected' && (
  <div className="w-full bg-red-900/40 border-b border-red-700 text-red-200 text-sm px-4 py-2">
    capture agent not connected — run <code>./capture-agent</code> in <code>capture-agent/</code> (see capture-agent/README.md)
  </div>
)}
{bannerState === 'replaying' && (
  <div className="w-full bg-sky-900/40 border-b border-sky-700 text-sky-200 text-sm px-4 py-2">
    replaying <code>{agentMode?.replaySource ?? 'unknown file'}</code> — not a live capture
    {agentMode?.directionAttributionUnavailable && ' — direction (rx/tx) could not be determined for this file and is shown positionally, not authoritatively'}
  </div>
)}
```

`bannerState === 'live'` renders no banner, matching today's existing "no banner when connected" behavior exactly — this task only adds two new informative states, it doesn't make the healthy case any noisier.

- [ ] **Step 3: `HeaderBar` — active capture-file indicator**

```typescript
// components/HeaderBar.tsx — new prop, following the existing `captureConfig: CaptureConfig | null` prop's exact pattern (always rendered once known, never placeholder'd):
captureFileStatus: CaptureFileStatus | null;
```

```tsx
{captureFileStatus?.writing && (
  <span className="text-xs text-amber-400" title={`${captureFileStatus.bytesWritten} bytes written${captureFileStatus.ringFile ? `, file ${captureFileStatus.ringFile}` : ''}`}>
    ● recording {captureFileStatus.path?.split('/').pop()}
  </span>
)}
```

- [ ] **Step 4: Tests**

Follow this repo's existing `page-capture-config-handling.test.tsx`/`page-capture-stats-handling.test.tsx` pattern exactly (a `FakeEventSource`, dispatch a raw wire-shaped message, assert on rendered DOM) — new file `lib/__tests__/page-agent-mode-handling.test.tsx`:

```typescript
import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
// ...same FakeEventSource/render-TerminalApp scaffolding page-capture-stats-handling.test.tsx already uses...

describe('agent mode banner', () => {
  it('shows the disconnected banner when connection_status reports disconnected, regardless of last-known mode', async () => {
    // dispatch agent_status{mode:"live"} then connection_status{connected:false}
    // assert the disconnected banner text is present, not a stale "live" state
  });

  it('shows the replaying banner with the source file once agent_status reports replay mode', async () => {
    // dispatch connection_status{connected:true} then agent_status{mode:"replay", replaySource:"/tmp/incident.pcapng", directionAttributionUnavailable:false}
    // assert screen.getByText(/replaying/i) and the file path both render
  });

  it('appends the direction-attribution caveat only when directionAttributionUnavailable is true', async () => {
    // two variants of the replay dispatch above, asserting the caveat text's presence/absence
  });

  it('shows no banner at all once connected in live mode', async () => {
    // dispatch connection_status{connected:true}, agent_status{mode:"live"}
    // assert neither the disconnected nor replaying banner text is present
  });
});
```

- [ ] **Step 5: Type-check, test, commit**

```bash
npx tsc --noEmit && npx vitest run
git add app/page.tsx components/HeaderBar.tsx lib/__tests__/page-agent-mode-handling.test.tsx
git commit -m "feat(web): three-state live/replaying/disconnected banner, active-capture-file indicator (#71 #70)"
```

---

### Task 12: Command-bar verbs (`capture`, `buffer`) and the `MAX_FLOWS` env var

**Files:**
- Modify: `app/page.tsx`, `components/CommandLineBar.tsx`, `capture-agent/src/main.rs`

**Interfaces:**
- Consumes: Task 4's `start_capture_file`/`stop_capture_file` control messages (sent via the existing `/api/control` POST route — no new API route needed, same as `pause`/`filter`/`snaplen` today).
- Produces: `buffer packets/connections/decrypted <n>` client-side state; `capture <path> [ring <mode> <n>] [autostop <mode> <n>]` / `capture stop`.

- [ ] **Step 1: `capture ...` command bar verb**

```typescript
// app/page.tsx's handleExecuteCommand — new branches, following the
// existing `filter <expr>`'s exact precedent for preserving case in a
// path/expression argument (see its own comment: "sliced off the ORIGINAL
// cmdStr, not the lowercased `parts`").
} else if (mainCmd === 'capture' && arg1 === 'stop') {
  fetch('/api/control', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'stop_capture_file' }),
  });
} else if (mainCmd === 'capture' && arg1) {
  // `capture /Users/me/captures/Run1.pcapng ring size 104857600 autostop duration 3600`
  // Path case must survive — sliced from the ORIGINAL cmdStr, matching
  // `filter <expr>`'s established precedent immediately above.
  const rest = cmdStr.slice(cmdStr.indexOf(' ') + 1).trim();
  const tokens = rest.split(' ');
  const path = tokens[0];
  const ringIdx = tokens.indexOf('ring');
  const autostopIdx = tokens.indexOf('autostop');
  const ring = ringIdx !== -1 ? { mode: tokens[ringIdx + 1], threshold: Number(tokens[ringIdx + 2]) } : undefined;
  const autostop = autostopIdx !== -1 ? { mode: tokens[autostopIdx + 1], threshold: Number(tokens[autostopIdx + 2]) } : undefined;
  fetch('/api/control', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'start_capture_file', path, ring, autostop }),
  });
}
```

- [ ] **Step 2: `buffer ...` command bar verb — purely client-side**

```typescript
// New state alongside the existing hard-coded slice(0, 100)/slice(0, 200) limits:
const [packetBufferLimit, setPacketBufferLimit] = useState(100);
const [connectionBufferLimit, setConnectionBufferLimit] = useState(200);
const [decryptedBufferLimit, setDecryptedBufferLimit] = useState(100);
```

```typescript
} else if (mainCmd === 'buffer' && arg1 === 'packets' && parts[2]) {
  const n = parseInt(parts[2], 10);
  if (n > 0) setPacketBufferLimit(n);
} else if (mainCmd === 'buffer' && arg1 === 'connections' && parts[2]) {
  const n = parseInt(parts[2], 10);
  if (n > 0) setConnectionBufferLimit(n);
} else if (mainCmd === 'buffer' && arg1 === 'decrypted' && parts[2]) {
  const n = parseInt(parts[2], 10);
  if (n > 0) setDecryptedBufferLimit(n);
}
```

Every existing `.slice(0, 100)`/`.slice(0, 200)`/`.slice(0, 100)` call site in the SSE handler (packets, connections, decrypted segments respectively) is updated to read `packetBufferLimit`/`connectionBufferLimit`/`decryptedBufferLimit` instead of the hard-coded literal — this is the only change those call sites need; the values themselves are unaffected until a `buffer ...` command changes them.

- [ ] **Step 3: The horizon text, using Task 9's new counters**

```tsx
// PacketStreamView / ConnectionsView — new prop `totalObserved: number`,
// passed from app/page.tsx as `captureStats?.received` (packets) or
// `captureStats?.totalConnectionsObserved` (connections):
<div className="text-xs text-slate-500">
  showing last {packets.length} of {captureStats?.received ?? packets.length} observed
</div>
```

Connections view additionally surfaces capacity-vs-idle eviction distinctly, per JAM-6's acceptance criterion:

```tsx
{captureStats && captureStats.capacityEvictions > 0 && (
  <div className="text-xs text-amber-500">
    {captureStats.capacityEvictions} connection(s) evicted for capacity — the flow table may be missing recent activity (a port scan or a burst can do this)
  </div>
)}
```

- [ ] **Step 4: `MAX_FLOWS` env var (agent-side)**

```rust
// main.rs, alongside detect_interface()'s call in main() — same
// env-var-override, fail-loud-if-unparseable precedent CAPTURE_INTERFACE
// already sets:
fn resolve_max_flows() -> usize {
    match std::env::var("MAX_FLOWS") {
        Ok(raw) => raw
            .parse::<usize>()
            .unwrap_or_else(|_| panic!("MAX_FLOWS={raw} is not a valid positive integer")),
        Err(_) => flow::DEFAULT_MAX_FLOWS,
    }
}
// ...
let flow_table = Arc::new(Mutex::new(FlowTable::new_with_capacity(local_addrs, resolve_max_flows())));
```

- [ ] **Step 5: `CommandLineBar` help text**

```tsx
<div><strong className="text-emerald-400">capture &lt;path&gt; [ring size|duration|count &lt;n&gt;] [autostop duration|totalSize &lt;n&gt;]</strong>: Start writing a live capture to a pcapng file</div>
<div><strong className="text-emerald-400">capture stop</strong>: Stop the active capture-to-file</div>
<div><strong className="text-emerald-400">buffer packets|connections|decrypted &lt;n&gt;</strong>: Adjust how many recent items this browser tab keeps</div>
```

- [ ] **Step 6: Tests**

```typescript
// lib/__tests__/page-capture-config-handling.test.tsx-style new file,
// lib/__tests__/page-command-bar-capture.test.tsx:
it('sends start_capture_file with the path case preserved and parsed ring/autostop', async () => {
  // type "capture /Users/Me/Captures/Run1.pcapng ring size 104857600 autostop duration 3600" into the command bar
  // assert the mocked fetch('/api/control', ...) body matches
  // { type: 'start_capture_file', path: '/Users/Me/Captures/Run1.pcapng', ring: {mode:'size',threshold:104857600}, autostop:{mode:'duration',threshold:3600} }
  // — path case specifically must NOT be lowercased, the one thing most likely to regress here
});

it('buffer packets 500 changes how many packets the view keeps without an agent round-trip', async () => {
  // dispatch more than 100 packet events, confirm only 100 render by default,
  // run the buffer command, dispatch more, confirm up to 500 now render
});
```

```rust
// main.rs
#[test]
fn resolve_max_flows_falls_back_to_default_when_unset() {
    std::env::remove_var("MAX_FLOWS");
    assert_eq!(resolve_max_flows(), flow::DEFAULT_MAX_FLOWS);
}

#[test]
#[should_panic(expected = "not a valid positive integer")]
fn resolve_max_flows_panics_loudly_on_garbage() {
    std::env::set_var("MAX_FLOWS", "not-a-number");
    let _ = resolve_max_flows();
    std::env::remove_var("MAX_FLOWS");
}
```

- [ ] **Step 7: Build, type-check, test, commit**

```bash
cd capture-agent && cargo build --locked && cargo test --locked
cd .. && npx tsc --noEmit && npx vitest run
git add app/page.tsx components/CommandLineBar.tsx components/ConnectionsView.tsx components/PacketStreamView.tsx capture-agent/src/main.rs lib/__tests__/
git commit -m "feat: capture/buffer command-bar verbs, MAX_FLOWS env var, honest horizon text (#72 #73)"
```

---

### Task 13: Export (CSV/JSON/hex) and decrypted-content exclusion regression tests

**Files:**
- Create: `lib/export.ts`, `lib/__tests__/export.test.ts`, `lib/__tests__/decrypted-export-exclusion.test.ts`
- Modify: `components/ConnectionsView.tsx`, `components/PacketStreamView.tsx`

**Interfaces:**
- Produces: `connectionsToCsv(connections: NetworkConnection[]): string`, `packetsToJson(packets: PacketFrame[]): string`, `downloadBlob(content: string, filename: string, mimeType: string): void` — pure functions taking already-filtered/already-in-memory arrays, no fetch, no server involvement.

Per the spec's explicit rule and this task's own regression test: **the exporter's input type signature never includes `DecryptedPayloadSegment`** — not filtered out inside the function, structurally absent from what it can even be called with.

- [ ] **Step 1: `lib/export.ts`**

```typescript
// lib/export.ts
//
// Pure, browser-side export — no new API route, nothing written
// server-side (spec Components §5). Every function here takes only the
// data type it's meant to export; DecryptedPayloadSegment never appears in
// any signature in this file, which is the structural half of "decrypted
// content is never exportable" (the other half is
// decrypted-export-exclusion.test.ts, Step 4).
import { NetworkConnection, PacketFrame } from './types';

const CSV_COLUMNS: Array<{ header: string; get: (c: NetworkConnection) => string | number }> = [
  { header: 'Protocol', get: (c) => c.protocol },
  { header: 'Local', get: (c) => `${c.localAddr}:${c.localPort}` },
  { header: 'Remote', get: (c) => `${c.remoteAddr}:${c.remotePort}` },
  { header: 'Process', get: (c) => c.processName },
  { header: 'PID', get: (c) => c.pid },
  { header: 'RX Bytes', get: (c) => c.rxBytesTotal },
  { header: 'TX Bytes', get: (c) => c.txBytesTotal },
  { header: 'Status', get: (c) => c.status },
];

function csvEscape(value: string | number): string {
  const s = String(value);
  // RFC 4180: a field containing a comma, quote, or newline must be
  // quoted, with internal quotes doubled. Network-sourced strings
  // (processName, in particular) are exactly the kind of untrusted text
  // this matters for — the same "never trust a network-sourced string to
  // be well-behaved" posture no-dangerous-html.test.ts already applies to
  // rendering, applied here to a different output format.
  if (/[",\n]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

export function connectionsToCsv(connections: NetworkConnection[], totalObserved: number): string {
  const header = `# showing ${connections.length} of ${totalObserved} observed\n` + CSV_COLUMNS.map((c) => c.header).join(',');
  const rows = connections.map((c) => CSV_COLUMNS.map((col) => csvEscape(col.get(c))).join(','));
  return [header, ...rows].join('\n');
}

export function packetsToJson(packets: PacketFrame[]): string {
  return JSON.stringify(packets, null, 2);
}

export function downloadBlob(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
```

- [ ] **Step 2: `ConnectionsView` — export button**

```tsx
// components/ConnectionsView.tsx — new prop `totalObserved: number` (Task
// 12's captureStats.totalConnectionsObserved), a button beside the
// existing search/filter controls:
<button
  onClick={() => downloadBlob(connectionsToCsv(filtered, totalObserved), `connections-${Date.now()}.csv`, 'text/csv')}
  className="..."
>
  Export CSV
</button>
```

Exports `filtered` — the same array the table itself renders (Scope's own explicit requirement: "the current *filtered* table"), never the unfiltered `connections` prop.

- [ ] **Step 3: `PacketStreamView` — export button and hex-dump copy**

```tsx
// components/PacketStreamView.tsx
<button onClick={() => downloadBlob(packetsToJson(packets), `packets-${Date.now()}.json`, 'application/json')}>
  Export JSON
</button>
```

```tsx
// In the packet detail panel, beside the existing hex dump rendering:
<button onClick={() => navigator.clipboard.writeText(selectedPacket.hexDump)}>
  Copy hex dump
</button>
```

- [ ] **Step 4: Decrypted-content exclusion — the regression test that matters most in this task**

```typescript
// lib/__tests__/decrypted-export-exclusion.test.ts
import { describe, expect, it } from 'vitest';
import * as exportModule from '../export';

describe('decrypted content is structurally unreachable from export', () => {
  it('lib/export.ts has no function whose parameter type could accept a DecryptedPayloadSegment array', () => {
    // A compile-time property is what actually matters here (Step 1's
    // signatures never mention DecryptedPayloadSegment) — this test is a
    // runtime tripwire for the case someone adds a new exported function
    // later without updating this file: it asserts the exported surface
    // is exactly the closed set expected, so a new export function is a
    // visible diff here, not a silent addition.
    expect(Object.keys(exportModule).sort()).toEqual(['connectionsToCsv', 'downloadBlob', 'packetsToJson']);
  });

  it('connectionsToCsv output never contains a decrypted-payload-shaped field even if a caller mistakenly spreads one into a connection object', () => {
    // Defense in depth against a future refactor accidentally widening
    // NetworkConnection to carry decrypted content: CSV columns are a
    // fixed, explicit allowlist (CSV_COLUMNS), not "every field on the
    // object" — so even a widened type can't leak a new column for free.
    const conn = {
      protocol: 'HTTPS/TLS', localAddr: '10.0.0.1', localPort: 1, remoteAddr: '1.1.1.1', remotePort: 443,
      processName: 'test', pid: 1, rxBytesTotal: 0, txBytesTotal: 0, status: 'ESTABLISHED',
      decryptedPayload: 'THIS MUST NEVER APPEAR IN CSV OUTPUT', // simulating an accidentally-widened type
    } as any;
    const csv = exportModule.connectionsToCsv([conn], 1);
    expect(csv).not.toContain('THIS MUST NEVER APPEAR IN CSV OUTPUT');
  });
});
```

- [ ] **Step 5: Round-trip and formatting tests**

```typescript
// lib/__tests__/export.test.ts
describe('connectionsToCsv', () => {
  it('quotes a field containing a comma per RFC 4180', () => {
    const conn = { /* ...processName: 'Chrome, Helper' ... */ } as any;
    const csv = connectionsToCsv([conn], 1);
    expect(csv).toContain('"Chrome, Helper"');
  });

  it('includes the observed-vs-shown horizon as a leading comment line', () => {
    const csv = connectionsToCsv([], 41207);
    expect(csv.split('\n')[0]).toBe('# showing 0 of 41207 observed');
  });
});

describe('packetsToJson', () => {
  it('round-trips through JSON.parse with headerBreakdown intact', () => {
    const packets = [{ /* ...a full PacketFrame fixture with headerBreakdown... */ }] as any;
    const parsed = JSON.parse(packetsToJson(packets));
    expect(parsed).toEqual(packets);
  });
});
```

- [ ] **Step 6: Type-check, test, commit**

```bash
npx tsc --noEmit && npx vitest run
git add lib/export.ts lib/__tests__/export.test.ts lib/__tests__/decrypted-export-exclusion.test.ts components/ConnectionsView.tsx components/PacketStreamView.tsx
git commit -m "feat(web): export connections to CSV, packets to JSON, hex-dump copy — decrypted content structurally excluded (#74)"
```

---

### Task 14: `live_loopback.rs` extension, `docs/architecture.md` resource model, CI wiring, final pass

**Files:**
- Modify: `capture-agent/tests/live_loopback.rs`, `docs/architecture.md`, `.github/workflows/ci.yml`, `CONTRIBUTING.md`

**Interfaces:**
- Consumes: everything from Tasks 1–13.
- Produces: no new public interfaces — closes out the spec's Testing section items not yet exercised by earlier tasks' own tests, and the plan's remaining documentation debt.

- [ ] **Step 1: Extend the live-loopback integration test to cover capture-to-file**

`capture-agent/tests/live_loopback.rs` (epic JAM-57) already spawns the real binary against real `lo` traffic under `#[ignore]` + CI-granted capability — the natural place to add one more assertion rather than a parallel harness:

```rust
// A second #[ignore]d test in the same file, reusing the same
// spawn-agent/generate-traffic helpers already defined there.
#[test]
#[ignore = "requires CAP_NET_RAW/CAP_NET_ADMIN (or root) to open a live capture on `lo`; same CI step as captures_real_loopback_traffic_and_emits_matching_wire_events"]
fn a_live_capture_written_to_file_opens_cleanly_afterward() {
    // 1. Spawn the agent against `lo`, as the existing test does.
    // 2. Connect as a wire client, send {"type":"start_capture_file","path":"<temp path>"}.
    // 3. Generate the same known traffic the existing test uses.
    // 4. Poll for a capture_file_status event with writing: true and bytes_written > 0.
    // 5. Send {"type":"stop_capture_file"}, poll for writing: false.
    // 6. Assert the file at <temp path> is non-empty and its first 4 bytes
    //    are the Section Header block's byte-order magic — a real
    //    "did a real file actually get written" check, not just a wire
    //    status assertion.
    // 7. AgentGuard (existing) tears the process down; clean up the temp file.
}
```

- [ ] **Step 2: `docs/architecture.md` — the resource model, in one place**

Per JAM-6's own acceptance criterion ("states the resource model and the defaults"), add a table covering every cap this epic touches or that already existed, so an operator/contributor never has to reconstruct it from source:

```markdown
## Resource limits

| Limit | Default | Configurable via | What happens at the limit |
| --- | --- | --- | --- |
| Packet buffer (browser) | 100 | `buffer packets <n>` | Oldest entries drop; "showing N of M observed" states the true total |
| Connection list (browser) | 200 | `buffer connections <n>` | Same |
| Decrypted-segment buffer (browser) | 100 | `buffer decrypted <n>` | Same |
| Flow table capacity (agent) | 10,000 | `MAX_FLOWS` env var, startup-only | Oldest-by-last-seen flow evicted; counted separately from idle eviction via `capture_stats.capacityEvictions` |
| Flow idle eviction | 30s (SYN_SENT) / 60s (UDP) / 120s (closing) / 1800s (ceiling) | not configurable in this epic | Flow removed; counted via `capture_stats.idleEvictions` |
| Capture-to-file ring | operator-configured (`ring` in the `capture` command), no default (single-file if omitted) | `capture <path> ring <mode> <n>` | Oldest ring file overwritten |
| Capture-to-file low-disk floor | 500MB | not configurable in this epic | Capture refuses to start / stops cleanly, `autostopReason: "lowDisk"` |
```

- [ ] **Step 3: Fold `pcapng_reader` into CI's existing fuzz path filter**

`.github/workflows/ci.yml`'s `fuzz` job currently triggers on PRs touching `capture-agent/(src/parse\.rs|src/http2\.rs|fuzz/)` — `src/pcapng.rs` is a third file in the same "parses untrusted bytes" class and belongs in that same filter:

```yaml
# .github/workflows/ci.yml — the existing regex, extended:
if echo "$changed" | grep -qE '^capture-agent/(src/parse\.rs|src/http2\.rs|src/pcapng\.rs|fuzz/)'; then
```

Add a new step running `cargo +nightly fuzz run pcapng_reader -- -max_total_time=30`, mirroring the existing `parse_packet`/`http2_reassembly` steps exactly (same job, same `if:` gate).

- [ ] **Step 4: `CONTRIBUTING.md`**

Add `REPLAY_FILE`/`REPLAY_LOCAL_ADDRS`/`REPLAY_SPEED`/`MAX_FLOWS` to whichever section already documents `CAPTURE_INTERFACE` (check `docs/troubleshooting.md` and `docs/getting-started.md` first per Task 10's own note — env vars may live there rather than in `CONTRIBUTING.md`; place these four alongside wherever the existing one already is, not a new location).

- [ ] **Step 5: Full verification sweep**

```bash
cd capture-agent
cargo build --release --locked
cargo test --locked
cargo test --locked --test live_loopback --no-run
sudo setcap cap_net_raw,cap_net_admin=eip target/debug/capture-agent
cargo test --locked --test live_loopback -- --ignored --test-threads=1
cargo clippy --all-targets --locked -- -D warnings
cargo audit
cd ..
npx vitest run
npx tsc --noEmit
npm run lint
npm run build
npx playwright test
```

Per this plan's own Global Constraints and every prior epic's closing pattern: also do the "break it on purpose" verification this repo's acceptance criteria consistently demand — pick at least one regression per major surface (e.g., temporarily corrupt an EPB's length field and confirm the reader errors rather than panicking; temporarily skip the disk-space check and confirm the new ring test would have caught it) and confirm the relevant new test catches it, then revert, exactly as epics JAM-52/53/54/55 already did for their own scope.

- [ ] **Step 6: Commit**

```bash
git add capture-agent/tests/live_loopback.rs docs/architecture.md .github/workflows/ci.yml CONTRIBUTING.md
git commit -m "test+docs: capture-to-file live-loopback coverage, resource-model docs, fuzz CI wiring (#55)"
```

---

## Self-Review Notes (for the plan author, not the implementer)

- **Spec coverage:** Components §0 (security docs) → Task 1. Components §1 (pcapng writer: framing, SHB/IDB, EPB/ISB, Writer, backpressure) → Tasks 2–4. Components §3 (ring/autostop/disk-guard) → Task 5. Components §2 (reader, round-trip, fuzz, `PacketSource`, `REPLAY_FILE` dispatch, direction/process degradation) → Tasks 6–8. Components §4 (buffer horizon, eviction-reason counters, `agent_status` revival) → Task 9, surfaced in Tasks 11–12. Wire/control-message changes (consolidated) → Task 10. UI mode banner → Task 11. Command-bar verbs → Task 12. Components §5 (export) → Task 13. Testing section's remaining items (live-loopback extension, resource-model docs, fuzz CI wiring) → Task 14.
- **Known gap found and resolved during planning, not silently carried forward:** the spec's Components §2 states "every flow in that replay is attributed 'unknown' direction" without checking `FlowTable::key_for`'s actual behavior when `local_addrs` is empty — it currently drops the packet entirely (`None`), not "unknown-tags" it. Task 8 designs and implements the actual fix (a positional fallback), and reassigns the spec's "one-time capture_file_status note" to the more semantically correct `agent_status` event instead (Task 9) — flagged inline in Task 8 rather than implemented silently differently from what the spec says.
- **One signature-breaking change, called out explicitly:** `FlowTable::evict_stale`'s return type changes from `Vec<FlowKey>` to `EvictedFlows { idle, capacity }` (Task 9) — every existing caller and test must be updated in the same commit; this is the only pre-existing public-ish interface this plan modifies rather than purely extends.
- **Deliberately not built, per the spec's own Scope:** seek-to-arbitrary-offset and single-step replay controls, runtime live↔replay switching, pcapng Decryption Secrets/Name Resolution blocks, per-packet comments, long-term retention/archival. No task above attempts any of these.
- **Sequencing:** Tasks 1 (security docs) must land before Tasks 2–4 (writer) and Task 13 (export) merge, matching the spec's explicit "#75 blocks #70 and #74" instruction — everything else can proceed in numeric order, with Tasks 9–13 each independently reviewable once Tasks 2–8 (the writer/reader/replay core) are in place. Tasks 5 and 6–8 are independent of each other and may be developed in parallel by different implementers if desired, since ring.rs (Task 5) depends only on pcapng::Writer (Tasks 2–3), not on the reader (Task 6) or PacketSource (Tasks 7–8).
