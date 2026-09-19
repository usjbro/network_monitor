# Capture Files and Offline Analysis — Design Spec

**Sub-project:** Phase 2, epic B (Linear JAM-125 / GitHub #55)
**Status:** Approved by usjbro (jamesmbrownjr@gmail.com) on 2026-09-19
**Date:** 2026-09-19
**Resolves:** JAM-125 (epic) and its six constituent tasks — JAM-8/#75 (capture-handling security guidance), JAM-132/#70 (pcapng writer), JAM-133/#71 (file replay), JAM-5/#72 (ring-buffer rotation and autostop), JAM-6/#73 (configurable buffer limits and an honest horizon), JAM-7/#74 (export)

## Purpose

Give the product a file format. Today nothing reads or writes a capture: the agent streams JSON to whoever is connected on `127.0.0.1:9990`, the browser keeps the last 100 packets and 200 connections, and everything else is gone the moment it scrolls off — a relay restart loses the lot. This is the largest single item in the phase-2 packet-analysis foundation (Linear: Size XL) and, per JAM-31's roadmap, the biggest multiplier in it: it is what turns "here are the packets, right now, in this one browser tab" into offline analysis, handing a capture to a second person, answering "what happened twenty minutes ago" without re-running the agent, deterministic fixture-driven tests for every analysis surface epic #57 already built, and — later, once decryption-breadth (epic JAM-128) exists — portable decryption via pcapng's own Decryption Secrets Block mechanism.

This spec covers all six constituent tasks together, in one document, because they share one architectural decision (write real pcapng, not classic pcap, and read both) and a strict dependency order the epic's own issue text already states: the security-guidance task blocks the writer and the export task; the writer and reader are a matched pair; ring-buffer rotation hard-depends on the writer existing. Buffer limits and export are independent of the file format and can land in either order, or in parallel with the rest.

## Scope

**In scope:**
- `docs/security.md` gains a capture-handling section — sensitivity, storage, retention, legal considerations of exporting network contents as files (JAM-8/#75).
- The capture agent gains the ability to write a live capture to a real pcapng file: Section Header, Interface Description, and Enhanced Packet blocks, operator-triggered only, output path always operator-named (JAM-132/#70).
- The capture agent gains a second startup mode — file replay — that reads a pcapng or classic-pcap file and emits the *same* wire events a live capture would, so every existing consumer (`lib/agent-mapping.ts`, every React view) needs no special case for "this data came from a file" (JAM-133/#71).
- Ring-buffer rotation across N files (by size, duration, or packet count) plus autostop (by duration, size, or file count), both surfaced live in the UI, both fail-safe on low disk (JAM-5/#72).
- Every hard-coded buffer cap in the product (packet buffer, connection list, decrypted-segment buffer, flow-table capacity) becomes visible and adjustable, and every view that truncates says so ("showing last 100 of 41,207 observed") rather than implying completeness (JAM-6/#73).
- Browser-side export: the current filtered connections table to CSV, the packet buffer to JSON, one frame's hex dump to the clipboard — no new server-side surface, nothing written to disk by the relay (JAM-7/#74).

**Explicitly not in scope** (carried forward from the epic issue and JAM-31's roadmap-level non-goals, restated here so this spec doesn't quietly relitigate them):
- The baseline design document's ~30 foreign read formats (Sniffer, NetMon, snoop, ERF, K12, …). pcapng write, plus pcapng *and* classic-pcap read, is the whole ask.
- Long-term retention at scale. This is a bounded rolling window on local disk, not a storage tier — no cloud upload, no database, no indexing service.
- pcapng's Name Resolution Block and Decryption Secrets Block, and per-packet comments. Deliberately deferred (JAM-132's own text) — Decryption Secrets specifically belongs to epic JAM-128's decryption-breadth work, once there is portable key material worth attaching to a file at all.
- Runtime switching between live capture and file replay within one running agent process. See Components §2's "one design decision this spec resolves" — mode is chosen once, at startup.
- Seek-to-arbitrary-offset and single-step replay controls. Replay speed (as-fast-as-possible vs. original-timing) plus the existing `pause`/`resume` control messages are the core; seek/step are named as a follow-up in "Deferred," not attempted here.

## Architecture

```
CAPTURE-AGENT PROCESS (one running mode, chosen at startup — never both)
┌────────────────────────────────────────────────────────────────────┐
│  LIVE MODE (existing)          │  REPLAY MODE (new, JAM-133)        │
│  pcap::Capture::from_device     │  pcapng.rs reader (new, native)    │
│  (unchanged capture loop)       │   or pcap::Capture::from_file      │
│                                 │   (classic-pcap fallback)          │
│         │                      │         │                          │
│         ▼                      │         ▼                          │
│  same packet-processing pipeline: parse.rs → l7.rs → FlowTable        │
│  → wire::AgentEvent (connection_update / packet / layer_update / …)  │
│         │                                                             │
│         ├──────────────► TCP broadcast to relay (unchanged, :9990)   │
│         │                                                             │
│         ▼ (LIVE MODE only, operator-triggered — JAM-132)             │
│   pcapng.rs writer: SHB + IDB once, EPB per packet                    │
│   ring.rs: rotates across N files, autostop, disk-space guard (JAM-5) │
│   → operator-named directory, 0600, never .data/, never the repo     │
└────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
                    Next.js relay — unchanged wire consumption
                    (lib/agent-mapping.ts sees the same event shapes
                     whether the source was a live interface or a file)
                                  │
                                  ▼
                    Browser — a new mode indicator (live/replaying/
                    disconnected) plus buffer-limit controls (JAM-6)
                    and export actions (JAM-7, client-side only)
```

No new listening port and no new relay↔agent transport: replay reuses the existing TCP wire protocol exactly (same events, same control channel for `pause`/`resume`/the new capture-file controls), matching the precedent every prior sub-project in this repo has followed (traceroute, enrichment, TLS visibility all added event/control types on the existing channel rather than a new one).

## Components

### 0. `docs/security.md` capture-handling section (JAM-8/#75) — do first

Not a code change. Adds a section to `docs/security.md`, alongside its existing bullet-list posture statements, covering:
- **What a capture file contains**: everything the live UI already shows, at rest, portable — every process's connections, remote IPs, DNS queries, TLS SNI hostnames, and raw packet bytes (the same sensitivity statement `docs/security.md`'s own opening line already makes about the live tool, now true of a file too, and now true for as long as that file exists rather than only while the agent runs).
- **What it never contains**: decrypted TLS content. This is the one line every other component in this spec depends on being true — see Components §1's Security model row.
- **Storage discipline**: written only to an operator-named location (never `.data/`, never the repo working tree — Components §1), `0600` permissions matching every other sensitive artifact this repo already creates (`bin/osi-inspect.js`'s key-log files, `.data/enrichment/`'s cache).
- **Retention is the operator's responsibility**, not this tool's. Ring-buffer rotation (Components §3) bounds how much accumulates *while capture is running*; nothing in this design auto-deletes a file once capture stops. Stated plainly, matching JAM-31's roadmap-level "long-term storage and packet retention remain bounded and privacy-conscious" convention without overclaiming a retention *feature* this spec doesn't build.
- **Legal guidance**: a capture may include other people's traffic on a shared network segment (a home Wi-Fi network, in particular) — the same one-line caution most packet-capture tools carry, pointed at this repo's actual audience (a home/SMB operator, not a network professional who already knows this).
- **Export's narrower boundary** (Components §5): an export additionally crosses the mTLS/loopback security boundary the live SSE stream is subject to, since it becomes a downloaded file on whatever device did the downloading — covered as its own line so it isn't conflated with the agent-side writer above.

This section must exist before Components §1 and §5 ship (JAM-132's and JAM-7's own text both say so); it does not block Components §2, §3, or §4, which don't create new on-disk artifacts.

### 1. pcapng writer (`capture-agent/src/pcapng.rs`, new module) — JAM-132/#70

**Format decision: hand-roll a minimal pcapng encoder, not a new crate dependency.** The scope here is deliberately narrow — three block types (Section Header, Interface Description, Enhanced Packet), no options beyond what's listed below, no Name Resolution or Decryption Secrets blocks. pcapng's block framing is simple, well-specified, and small enough to implement and fuzz directly (a block is a 32-bit type, a 32-bit length, a payload, and the length repeated at the end for backward seeking — that's the entire general shape every block in scope here uses). This repo's own dependency-hygiene rule (`docs/security.md`: "no new dependency for something you can reasonably build with what's already in the tree") points the same direction a general-purpose pcapng crate would cost: one more third-party parser touching untrusted-shaped output, for a feature whose entire spec is three block types. `serde`/`serde_json` (already a dependency) are not used here — this is raw binary framing, not JSON.

Blocks written, per the epic issue's own table:

| Block | Written | Contents |
|---|---|---|
| Section Header (SHB) | once, at file open | byte-order magic, hostname + `capture-agent` version as the `shb_userappl` option |
| Interface Description (IDB) | once, at file open | interface name (`if_name`), link type (from the already-resolved `parse::LinkType` → pcapng `LINKTYPE_*`), snap length (issue #68's active value), timestamp resolution (`if_tsresol`, nanosecond where the platform clock supports it — recorded honestly, never claimed if it isn't) |
| Enhanced Packet (EPB) | once per captured frame | the raw frame bytes, nanosecond timestamp, and — cheap to include since `FlowTable`'s direction check (`is_local`) already computes it per packet — the `epb_flags` option's inbound/outbound direction bits. Per-packet *error* flags are not set: nothing in this agent classifies an individual frame as errored at that granularity, and inventing a value would violate this codebase's "report zero/absent rather than fabricate" convention (`docs/wire-protocol.md`'s own stated discipline). |
| **Interface Statistics (ISB) — added by this spec, not named in the issue's table** | once per file-rotation tick (same ~1s cadence as `capture_stats`) | `isb_ifrecv`/`isb_ifdrop` mirroring issue #61's `capture_stats.received`/`.dropped` counters. The issue's own text asks for "per-packet flags **and drop counts**" on the Enhanced Packet block, but drop counts are cumulative interface-level statistics, not a property of any one packet — pcapng has a dedicated block for exactly this. Writing them into ISB rather than stretching EPB's semantics is a correction to the issue's table, not a scope addition: the same information ships, in the block type the format actually defines for it. |

**Trigger and lifecycle**: two new control messages on the existing TCP channel, `start_capture_file { path, ring, autostop }` and `stop_capture_file` — never on by default, never inferred, matching every other opt-in feature this repo has shipped (ownership enrichment, geoIP, TLS decrypt-eligibility all require an explicit control message or command-bar verb; capture-to-disk is no different). While active, `capture_file_status` (new agent→relay event, same "sent every tick, always current" pattern as `capture_stats`/`capture_config`) reports the currently-open file path, bytes written, and ring/autostop state — see Components §3 for the rotation-specific fields.

**Backpressure**: the writer's queue (a bounded `mpsc` channel between the capture thread and a dedicated writer thread, so a slow disk never blocks packet processing) has a fixed capacity; a full queue means the writer can't keep up, and the shortfall is counted and surfaced through the same `capture_file_status` event — never silently dropped, matching issue #61's precedent that any form of "this data didn't make it" gets a counter and a UI signal rather than nothing.

**Output location** (per JAM-132's explicit instruction): always an operator-supplied path in `start_capture_file`'s `path` field, `0600` permissions on creation. The agent refuses the request outright (`capture_config_error`-style rejection, reusing the existing pattern issue #68 established for a rejected filter/snaplen change) if the resolved path falls inside the repo working tree or `.data/` — those are for this tool's own small, ephemeral metadata, not multi-gigabyte capture artifacts an operator explicitly asked to keep.

### 2. File replay (`capture-agent/src/pcapng.rs` reader half + startup-mode dispatch in `main.rs`) — JAM-133/#71

**One design decision this spec resolves that the issue text left open**: the issue proposes replay mode be "driven by a control message or a CLI flag." This spec picks **CLI/env flag only, resolved once at process startup, never runtime-switchable** — the same shape `CAPTURE_INTERFACE` already uses. Reasoning: live mode already has its own runtime-reconfiguration surface (issue #68's filter/snaplen, issue #69's interface switch), all of it built assuming an open `pcap::Capture` device handle that can be reopened against a new device. Interleaving that with "also might need to become a file reader mid-session" roughly doubles the state space of `main.rs`'s capture loop for a capability (switching a *running* agent from live to replay or back) nothing in the acceptance criteria actually asks for. A new environment variable, `REPLAY_FILE`, mutually exclusive with normal live-mode startup (set alongside `CAPTURE_INTERFACE` is a startup-time error, same fail-loud posture `detect_interface()` already applies to a bad `CAPTURE_INTERFACE` value) keeps every existing runtime-reconfiguration code path completely unaware replay mode exists at all — it only ever reads from a different `PacketSource` (see below), which does not care how it's used afterward.

**Reading pcapng vs. classic pcap — two different code paths, not one:**
- **pcapng** (our own writer's output, and any modern tool's): read with the `pcapng.rs` reader from Components §1, which the writer already needs — a matched pair over the same three-plus-one block types, tested against each other directly (Testing, below). This path yields the *rich* metadata JAM-133 needs: the file's own Interface Description block gives the real original interface name and link type, so a replayed capture reports the interface it was actually taken on, not this machine's.
- **Classic pcap** (a legacy Wireshark/`tcpdump` capture): read via the existing `pcap` crate's `Capture::from_file()` — libpcap already opens classic pcap natively, and the existing `pcap` dependency (already used for live capture) covers this with no new code and no new crate. This path is coarser by nature: classic pcap carries only a global link-type and per-packet timestamps, no embedded interface name — for a replayed classic-pcap file, `interface_name` in every emitted event honestly reports `"unknown (replayed classic pcap)"` rather than fabricating one, consistent with `local_addrs` handling below.

**The subtle part, called out explicitly per the issue's own warning**: `FlowTable::new`'s `local_addrs` — the list this machine's own interface addresses that decides which side of every packet is "local" — cannot come from this machine's interfaces when replaying someone else's capture; getting it wrong silently flips every flow's direction and every rx/tx byte split. Resolution: `REPLAY_FILE` accepts an optional companion, `REPLAY_LOCAL_ADDRS` (comma-separated), naming the addresses that were local *in that capture*. If unset, the agent falls back to whatever addresses the file's own Interface Description block names (pcapng only — an IDB can carry an `if_ipv4addr`/`if_ipv6addr` option, though not every capture tool populates it) and, failing that, refuses to guess: every flow in that replay is attributed `"unknown"` direction rather than silently wrong, with a one-time `capture_file_status` note that direction attribution is unavailable. This mirrors JAM-133's own acceptance criterion for `process_lookup` (below) — "unknown" beats a confident wrong answer.

**Process attribution**: `process_lookup::refresh()` walks *this* machine's live socket table — meaningless for a replayed capture (the processes that owned those flows may never have run on this machine at all, or have long since exited if it's an old capture of this same machine). In replay mode, `process_map` is never populated; every connection reports `processName: "unknown"`, `pid: null` rather than mis-attributing to whatever unrelated process happens to hold a matching local port today. This is a real, named limitation, not a bug to work around later.

**Replay speed**: two modes, both requested via `REPLAY_FILE`'s companion `REPLAY_SPEED` (`fast` default, or `realtime`) — `fast` reads and emits every frame back-to-back as quickly as the pipeline can process them (what CI fixture tests and "reproduce this bug quickly" want), `realtime` sleeps between frames to reproduce the file's own inter-packet timing (what a demo or a "watch it happen again" review wants). The existing `pause`/`resume` control messages work unchanged in either mode — pausing a replay simply stops the reader thread from advancing, exactly like pausing a live capture already stops packet processing.

**`PacketSource` abstraction**: the capture loop in `main.rs` is refactored behind a small enum, `enum PacketSource { Live(pcap::Capture<Active>), ReplayPcapng(pcapng::Reader), ReplayClassic(pcap::Capture<Offline>) }`, each yielding the same `(bytes, timestamp)` shape the existing loop already consumes from `cap.next_packet()`. This is the mechanism that makes "the same wire events, no special cases downstream" (the issue's stated goal) actually true — everything from `parse::parse_packet` onward is unmodified code, reading from whichever source was selected once at startup.

### 3. Ring-buffer rotation and autostop (`capture-agent/src/ring.rs`, new module) — JAM-5/#72

Hard-depends on Components §1 (the writer) existing — this module owns *when* the writer's output file changes or stops, not the block-level writing itself.

**Ring buffer**: `start_capture_file`'s `ring` parameter names a mode (`size`, `duration`, or `count`) and its threshold. Rotation opens the next file in a fixed-width numbered sequence (`capture-0001.pcapng`, `capture-0002.pcapng`, …, wrapping after N), overwriting the oldest once the ring is full. **Atomicity, mirroring this repo's own established pattern** (`lib/enrichment/cache.ts`'s `atomicWriteJson`: write to a temp path, `rename()` onto the final name only once fully flushed): each file in the ring is written to `<name>.partial` and renamed to its final `.pcapng` name only after its Section Header/Interface Description/every Enhanced Packet block already written to it is flushed and the handle closed cleanly — the rotated-out file that becomes visible under its real name is therefore always a complete, independently-openable pcapng file, never a half-written one a parser would choke on. A crash or kill mid-rotation leaves at most one `.partial` file behind (the one actively being written) plus every already-rotated file intact and valid — the same failure-mode shape `atomicWriteJson`'s own test (`"a write interrupted before rename leaves the previous file intact"`) already proves for the TS-side cache.

**Autostop**: a duration, total size across the whole ring, or file count, checked on the same tick the writer already runs on; firing it cleanly closes and rotates-in the current file (so the last file is complete, not truncated) and reports the reason (`"duration"` / `"totalSize"` / `"fileCount"`) via `capture_file_status`, rather than the capture simply going quiet with no explanation — the exact failure mode the issue calls out by name.

**Disk-space guard**: `start_capture_file` refuses to begin (same rejection shape as an over-length capture filter, issue #68) if free space on the target volume is already below a floor — default 500MB, operator-configurable in the same request — and, while running, the writer thread checks free space each rotation tick and stops cleanly (same clean-stop path as autostop, reason `"lowDisk"`) rather than running the volume to zero. "The failure mode to avoid is a monitoring tool taking the machine down" (the issue's own words) is the test this guard has to pass, not just a unit test against a mocked filesystem — see Testing, below.

### 4. Configurable buffer limits and an honest horizon — JAM-6/#73

Splits cleanly into a relay/browser-side half and an agent-side half; neither depends on Components §1–§3.

**Browser-side caps** (packet buffer 100, connection list 200, decrypted-segment buffer 100 — all today hard-coded in `app/page.tsx`): become `useState` values seeded from constants but adjustable via new command-bar verbs (`buffer packets <n>`, `buffer connections <n>`, `buffer decrypted <n>`), following `CommandLineBar`'s existing verb-dispatch and help-text pattern exactly (the same shape `theme`/`layer`/`filter` already use). Purely client-side state — no wire protocol change, no agent involvement, and nothing persisted across a page reload (matching this repo's existing "opt-in never persists" precedent for enrichment/geoIP mode, applied here to a UI preference rather than a privacy-sensitive toggle, but the same "explicit every session" shape).

**The horizon, made honest**: every truncated view states what it isn't showing.
- **Packets**: `capture_stats.received` (issue #61's existing cumulative frame counter) is already the correct "total observed" number — every captured frame is a would-be packet event before the 100/sec delivery rate-limit or the 100-item buffer cap trims it, so no new counter is needed. The packet view renders "showing last {buffer.length} of {captureStats.received} observed."
- **Connections**: no existing counter answers "how many distinct flows has this agent ever seen," only "how many are live right now." `FlowTable` gains a cumulative `total_flows_observed: u64`, incremented once the first time a given `FlowKey` is ever seen (not on every `observe()` call), exposed as a new `totalConnectionsObserved` field on the existing `capture_stats` event (its natural home — already "capture health," already sent every tick, already the field this repo reaches for when a new cumulative counter is needed, per issue #61's own precedent).
- **Flow-table pressure, capacity vs. idle**: `FlowTable`'s eviction code already distinguishes *why* a flow left the table internally (`enforces_max_flow_capacity_by_evicting_oldest` vs. its three idle-timeout paths — both already unit-tested, per the file's existing test names) but exposes neither reason on the wire today. Two new cumulative counters, `capacityEvictions`/`idleEvictions`, added to `capture_stats` alongside `totalConnectionsObserved` above — a connections view that's missing rows because the table hit its capacity ceiling (a port scan or a DDoS, as the issue notes, does this immediately) is a materially different, more urgent situation than one that's missing rows because they'd simply gone idle, and the UI should be able to say which.

**Agent-side flow-table capacity** (`DEFAULT_MAX_FLOWS` = 10,000): made configurable via a new `MAX_FLOWS` environment variable, following the exact precedent `CAPTURE_INTERFACE` already set (env-var override, validated and fail-loud at startup if unparseable, not a runtime control message) — runtime-shrinking a live flow table would force an immediate eviction storm with no natural trigger to explain it to the operator, a sharper-edged problem than this issue's acceptance criteria ask for solving. Startup-only, like `CAPTURE_INTERFACE` and (Components §2) `REPLAY_FILE`, is the deliberate, consistent answer this repo already gives to "should this be adjustable while running."

**Documentation**: `docs/architecture.md` (or a new subsection of it) states the full resource model in one place — every cap, its default, and what happens when it's hit — rather than leaving an operator to reconstruct it from source, per the issue's own acceptance criterion.

### 5. Export — JAM-7/#74

Entirely browser-side, no wire protocol change, no new API route — a `Blob` plus a synthetic download link, matching the issue's own proposed mechanism exactly. Independent of every other component in this spec; can ship whenever convenient once Components §0's security-doc section exists.

- **Connections → CSV**: the *currently filtered* `ConnectionsView` table (its existing search term and protocol filter already narrow the row set client-side — export reads the same filtered array the table itself renders, not the unfiltered `connections` prop) — one row per visible connection, one column per visible field, plus the JAM-6 horizon note (total observed vs. exported) as a leading comment line.
- **Packets → JSON**: the current packet buffer, each entry's full `headerBreakdown` included (already present on every `PacketFrame` per `docs/wire-protocol.md`'s `packet` event) — round-trips through `jq` by construction, since it's a direct `JSON.stringify` of exactly what the UI already holds in React state.
- **One frame → hex dump**: `navigator.clipboard.writeText` of the selected frame's existing `hexDump` field, formatted for pasting into a ticket (the issue's own stated use case) — no export UI beyond a copy button already implicit in the packet detail view.
- **The one hard rule, and the reason Components §0 blocks this**: decrypted TLS content (`decryptedSegments` state, sourced from `decrypted_payload` events, gated on transport by `lib/decrypted-payload-gate.ts`) is never included in any export, full stop — not filtered out at render time, *excluded from the exporter's input entirely*, so a future change to what the packet/connection exporters read can't accidentally reintroduce it. The ring buffer it lives in is `mlock`'d and never written to disk by design (`capture-agent/src/ring_buffer.rs`); an export path that could write it to a downloaded file would be exactly the "back door around that guarantee" Components §1 already refuses to become for the pcapng writer, applied here to the relay/browser side instead of the agent side.
- **Redaction**: exported packet JSON is read from the same in-memory `PacketFrame` state the UI already renders, which already reflects `capture-agent/src/redact.rs`'s header-stripping pass (redaction happens agent-side, before the event ever reaches the browser) — export therefore inherits redaction for free rather than needing its own pass, but this inheritance is exactly why "read from the same state the UI renders, not a separate un-redacted path" is load-bearing, not incidental.

## Wire/control-message changes (consolidated)

New agent → relay events (all following `docs/wire-protocol.md`'s existing `#[serde(tag = "type", rename_all = "snake_case")]` convention):
- `capture_file_status` — `{ writing: bool, path: string | null, bytesWritten: number, ringFile: number | null, ringTotal: number | null, autostopReason: string | null }` (Components §1, §3).
- `capture_stats` gains three new fields on the existing event rather than a new one: `totalConnectionsObserved`, `capacityEvictions`, `idleEvictions` (Components §4).
- The existing, currently-dead `agent_status { interface, capturing }` event (flagged in `docs/wire-protocol.md` today as "defined but never actually sent... a future task should either wire it up... or remove it") is wired up by this spec: sent every tick alongside `capture_stats`/`capture_config`, gaining a `mode: "live" | "replay"` field and (replay only) `replaySource: string`. This directly answers JAM-133's "the UI must say 'replaying `<file>`' rather than implying live capture" requirement, and resolves a piece of named-dead wire protocol surface rather than adding a parallel one.

New relay → agent control messages (same channel, same framing `pause`/`resume`/`set_capture_filter` already use):
- `start_capture_file { path, ring: { mode, threshold }, autostop: { mode, threshold } | null }`, `stop_capture_file` (Components §1, §3).

`app/page.tsx`'s SSE handler gains cases for `capture_file_status` and the now-live `agent_status`; its "agent not connected" banner logic becomes a three-state derivation (live / replaying `<source>` / disconnected) rather than the current boolean, per JAM-133's explicit requirement.

`docs/wire-protocol.md` and `lib/agent-mapping.ts`/`lib/types.ts` are updated together, field-for-field, per this repo's own standing rule for any wire change (`CLAUDE.md`, `CONTRIBUTING.md`).

## Setup & operations

**Writing a capture**: `capture <path> [ring <mode> <n>] [autostop <mode> <n>]` in the command bar (or the equivalent `start_capture_file` request if driven programmatically) — never automatic, never on by default. `capture stop` ends it cleanly. The active file, ring position, and bytes written are visible in the header bar the entire time a capture is open, matching every other "state that must never be silently invisible" precedent in this app (the capture-degraded banner, the decrypting banner).

**Replaying a file**: `CAPTURE_INTERFACE` is unset, `REPLAY_FILE=/path/to/capture.pcapng` (optionally with `REPLAY_LOCAL_ADDRS=...` and `REPLAY_SPEED=realtime`) is set, and the agent is started normally — from the relay/browser's point of view it behaves exactly like a live agent, except the header bar reads "replaying `capture.pcapng`" instead of an interface name, and `pause`/`resume`/replay-speed are the only controls that make sense against it (the filter/snaplen/interface-switch controls from issues #68/#69 are silently no-ops in replay mode — there is no live device to reconfigure — reported via the existing `capture_config_error`/`interface_error` rejection paths rather than crashing).

**Buffer limits**: `buffer packets <n>`, `buffer connections <n>`, `buffer decrypted <n>` in the command bar; `MAX_FLOWS` env var for the agent-side flow table, alongside `CAPTURE_INTERFACE` at startup.

**Export**: existing UI affordances in `ConnectionsView` (export-CSV) and `PacketStreamView` (export-JSON, copy-hex-dump) — no new page, no new route.

## Security model summary

| Threat | Mitigation |
|---|---|
| A capture file becomes a durable, portable copy of everything the live tool already shows — the point this whole epic exists to reach, and the point at which it needs guardrails | `docs/security.md`'s new capture-handling section (Components §0) ships before the writer or export do; operator-named output path only, `0600` permissions, no default location. |
| The pcapng writer becomes a back door around Tier B's "decrypted content never touches disk" guarantee | Writes ciphertext frames only — `pcapng.rs` never has a reference to `DecryptedRingBuffer` or any decrypted byte at all, by construction, not by a runtime check that could be bypassed. Same guarantee, same mechanism (no code path exists), as the export side (Components §5). |
| Export becomes a second back door around the same guarantee | The exporter's input is the browser's own React state, which never contains decrypted content outside the gated `decryptedSegments` array — the connections/packets exporters simply never read that array. A regression test asserts it (Testing, below). |
| A malformed or hostile pcapng/classic-pcap file crashes the agent or corrupts its state during replay | `pcapng.rs`'s reader is untrusted-input-adjacent the same way `parse.rs` already is (a file handed to this tool, however it arrived, is not implicitly trustworthy) — every block read returns `Option`/`Result`, never panics, and is added to the existing `cargo-fuzz` corpus (Testing, below) rather than getting a separate, less-scrutinized test posture. |
| An unbounded capture-to-disk fills the operator's disk | Ring-buffer rotation bounds total size by construction once configured; the disk-space guard (Components §3) refuses to start, and stops cleanly, below a floor — "the failure mode to avoid is a monitoring tool taking the machine down." |
| A half-written, corrupted file is worse than no file (Wireshark/`capinfos` reject it, the operator can't tell why) | Atomic write-then-rename on every rotation (Components §3), mirroring this repo's own established `atomicWriteJson` pattern. |
| Replaying a foreign capture silently mis-attributes flow direction or process identity | Both fail toward "unknown," never toward a confident wrong answer (Components §2) — the same posture this repo already applies everywhere else data can't be honestly derived (`docs/wire-protocol.md`'s "report zero/absent rather than invent a number" convention, cited by name). |
| Export crosses the existing mTLS/loopback security boundary — it becomes a file on whatever device downloaded it, outside every protection the live SSE stream has | Named explicitly in `docs/security.md`'s new section (Components §0); no additional runtime mitigation is proposed here beyond what redaction and the decrypted-content exclusion already provide, since export is inherently "the operator asked for a copy" — the same trust boundary this app already extends to the operator's own browser tab. |

## Error handling & lifecycle

- **Disk fills mid-capture despite the guard** (a burst faster than the once-per-rotation-tick check catches): the writer's bounded queue fills, backpressure is counted and reported (Components §1) rather than blocking the live stream; the next rotation-tick disk check stops the capture cleanly once it observes the low-space condition.
- **`stop_capture_file` with no capture active**: a no-op, reported success (idempotent, matching `pause`/`resume`'s existing tolerance for a redundant call).
- **`start_capture_file` while one is already active**: rejected (`capture_config_error`-shaped response) rather than silently switching files out from under an in-flight write — the operator must `stop` first.
- **Agent killed mid-write**: the currently-open `.partial` file is abandoned incomplete (expected, not a bug — the atomic rename never happened, so it's simply not visible under its final name); every already-rotated file in the ring remains valid and complete.
- **Replay reaches end-of-file**: the agent reports `capture_file_status`-equivalent completion (reusing the now-live `agent_status`'s `capturing: false` transition) rather than the connection simply going quiet — the same "always say why, never just stop" discipline autostop already applies to live capture.
- **`REPLAY_FILE` set to a path that isn't a valid pcapng or classic-pcap file**: fails loudly at startup, naming the file and the parse failure, matching `detect_interface()`'s existing fail-loud posture for a bad `CAPTURE_INTERFACE` value — never silently falls back to live auto-detection.
- **Both `CAPTURE_INTERFACE` and `REPLAY_FILE` set**: startup error, naming both conflicting values — mutually exclusive by design (Components §2).

## Dependency hygiene

- `capture-agent/src/pcapng.rs`: zero new crates — hand-rolled block encode/decode over `std::io`, per Components §1's explicit reasoning. The one crate this component leans on, `pcap` (already a dependency), is used only for its existing `Capture::from_file()` classic-pcap read path (Components §2) — no version bump, no new feature flags.
- No new npm dependency for Components §4 or §5 — both are existing React state, `Blob`, and `URL.createObjectURL`, all browser built-ins.
- `npm ci`/`cargo build --locked`, `ignore-scripts=true`, exact pinning — unchanged, repo-wide policy, restated here only because this epic is the first to touch on-disk artifacts at any real size and it's worth being explicit that doing so introduced no new supply-chain surface.

## Testing

- **pcapng block framing**: round-trip tests, `pcapng.rs`'s own writer output read back by its own reader, for every block type in scope (SHB, IDB, EPB, ISB) — the most direct correctness check available, and the one JAM-132's acceptance criteria calls for explicitly ("Rust tests cover block framing and a round-trip against the reader").
- **Real-tool interop**: a written file opens cleanly in Wireshark and reports correctly via `capinfos` — a manual verification step (not a `cargo test`, since neither tool is assumed present in CI), documented as part of the implementation plan's task for Components §1, mirroring how the path-visualization spec's privilege spike was verified manually rather than in CI.
- **Fuzzing**: `pcapng.rs`'s reader is added to the existing `cargo-fuzz` corpus (a new target or an extension of `parse_packet`'s, decided at implementation-plan time) — same untrusted-bytes posture as `parse.rs`, per the Security model table.
- **Ring/autostop**: unit tests for each rotation trigger (size, duration, packet count) and each autostop condition, plus a real multi-hour-equivalent run (accelerated via a test-only tick-rate override, not an actual multi-hour CI job) verifying total disk use stays bounded by the configured ring size — JAM-5's own acceptance criteria explicitly asks for more than a unit test here.
- **Disk-space guard**: a test harness that fakes low free space (dependency-injected disk-space check, not a real near-full filesystem) asserts refuse-to-start and clean-stop both fire correctly.
- **Replay correctness**: a capture written by Components §1 and one captured by real `tcpdump`/Wireshark both replay and populate connections/packets/layer stats identically to how a live capture would — JAM-133's explicit acceptance criterion. Flow-direction correctness on a capture taken on a different host, and `process_lookup` degrading to "unknown" rather than mis-attributing, both get dedicated tests.
- **Decrypted-content exclusion**: a regression test (Rust, for the writer; TypeScript, for export) asserting that decrypted payload data is unreachable from either code path — not merely absent from a sample run, but structurally excluded (Security model table).
- **Buffer horizon honesty**: TS tests asserting every truncated view's "showing N of M" text matches the underlying counters, and that capacity vs. idle eviction render as visibly distinct states.
- **Export round-trip**: CSV output matches the filtered table exactly (JAM-7's own criterion); JSON output round-trips through `jq`; hex-dump clipboard content matches `hexDump` verbatim.
- **Live-loopback integration** (epic JAM-57's now-established pattern, `capture-agent/tests/live_loopback.rs`): extended to cover a real capture-to-file run against `lo`, verifying the written file is non-empty and opens cleanly — the natural next use of the fake-traffic/real-agent-binary harness that epic already built, rather than a parallel one.

## Deferred to later sub-projects / follow-ups

- **Seek-to-arbitrary-offset and single-step replay controls** — named in the issue's proposed scope but not attempted here (Scope); `pause`/`resume` plus the two speed modes cover the acceptance criteria as written.
- **Runtime live↔replay switching within one running agent** — explicitly resolved against in Components §2; would need its own design pass if ever wanted, not a small extension of this one.
- **pcapng Decryption Secrets Block** — belongs to epic JAM-128 (decryption breadth), once TLS 1.2/QUIC key material exists in a form worth attaching portably to a file; named here only so it isn't rediscovered from scratch.
- **Name Resolution Block, per-packet comments** — deliberately out of scope per the issue's own text; no identified need for either yet.
- **Long-term retention / archival tier** — explicit roadmap-level non-goal (JAM-31); this epic bounds disk use *while capturing*, nothing more.

## Spec self-review

- **Placeholder scan**: no TBD/TODO markers. The one open design question the source issues left ambiguous (Components §2's live-vs-replay switching mechanism) is resolved explicitly, with reasoning, rather than carried forward as an open question — matching the standard this repo's other specs (e.g. path-visualization's privilege-mechanism question) set for genuinely open items: state the resolution and why, or state it's a spike if it truly can't be resolved on paper.
- **Internal consistency**: the "never a back door around the decrypted-content-never-touches-disk guarantee" rule is stated once (Components §1) and then applied identically to export (Components §5, Security model table) rather than restated with different wording that could drift. The "unknown beats a confident wrong answer" posture (Components §2's direction/process attribution) is the same posture Components §4 applies to eviction-reason reporting and the same one `docs/wire-protocol.md` already documents as this repo's house style — cited, not reinvented.
- **Scope check**: six constituent tasks in one spec is larger than this repo's prior single-feature sub-projects, but matches the epic's own "Size: XL" label and its issue text's explicit statement that this is "the largest single item in the phase-2 analysis" — splitting it into six separate specs would have hidden the one architectural decision (pcapng format, `PacketSource` abstraction) all six tasks actually share.
- **Ambiguity check**: "drop counts on the Enhanced Packet block" (JAM-132's table) was ambiguous against pcapng's actual block vocabulary — resolved explicitly in Components §1 by naming the correct block (ISB) and explaining why, rather than either silently reinterpreting the issue or stretching EPB's semantics to fit a description that doesn't quite match the format.
- **Dependency check**: the "no new dependency for something you can reasonably build with what's already in the tree" call (Components §1) is a real tradeoff, not a free win — a hand-rolled encoder/decoder is more code this repo maintains itself versus a maintained crate. Named explicitly rather than asserted as costless, and scoped tightly enough (three-plus-one block types, no optional extensions beyond what's listed) that the maintenance burden should stay small.
