# Third-party pcapng Replay Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans for the approved bounded fix, with independent reader implementation and final review.

**Goal:** Replay supported packets from third-party pcapng sections and interfaces without confusing malformed files with EOF.

**Architecture:** Keep the Rust reader and libpcap classic-pcap paths. Reader tracks section byte order/version and bounded interface metadata; each packet carries its own link type. Replay dispatch distinguishes read failure from clean EOF. No writer or wire contract changes.

**Tech Stack:** Existing Rust, std::io, pcap and etherparse dependencies.

**Spec:** `docs/superpowers/specs/2026-09-19-capture-files-design.md` §2; JAM-194 acceptance criteria and chat-approved gate `coordination/gates/jam-194__third-party-pcapng-replay.md`; draft-ietf-opsawg-pcapng-06.

## Constraints

Keep 127.0.0.1 binds, 16 MiB block cap, framing/data/options validation, and JAM-174 captured/original length attribution. Skip DSB without importing secrets. No dependencies, wire changes, timestamp offsets, FCS stripping or local-address fallback. Explicitly reject Simple Packet and obsolete Packet blocks rather than inventing missing timestamps or silently losing packets.

## Reader

- [x] Add failing independent endian/interface/unknown-block/section fixtures and malformed input regressions.
- [x] Detect SHB byte order before lengths; validate SHB/version; skip incompatible sections and reset interfaces.
- [x] Bound retained metadata, resolve EPB interface IDs, preserve lengths and carry per-packet link type/timestamp units.
- [x] Keep validated unknown-block skipping and explicit unsupported packet-block diagnostics; run reader tests and fuzz.

## Replay pipeline

- [x] Demonstrate native RAW mapping failure and malformed-tail EOF failure.
- [x] Map native RAW via libpcap identity; pass per-packet link type into packet parsing and fields.
- [x] Distinguish replay errors in startup and loop diagnostics from successful EOF.
- [x] Verify mixed-endian multi-interface packet decoding/timestamps through PacketSource and actual binary; rerun JAM-174 binary tests.

## Publication

- [x] Run locked Rust tests, release build, clippy and reader fuzz; record evidence in .ai state.
- [x] Review final diff independently for correctness and security; resolve findings.
- [ ] Commit, push, open PR, update Linear and required Slack posts. Merge only after review and green CI/clean merge state, then mark Done and clean worktree.
