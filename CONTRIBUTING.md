# Contributing

## Project structure

See [docs/architecture.md](docs/architecture.md) for how the pieces fit together before making changes. Broadly:

- `capture-agent/` — Rust, the privileged capture agent. Own `Cargo.toml`, own test suite (`cargo test`), two fuzz targets (`cargo fuzz run parse_packet`, `cargo fuzz run http2_reassembly`) — CI now runs both (30s each) on every push to `main` and on any PR touching `capture-agent/src/parse.rs`, `capture-agent/src/http2.rs`, or `capture-agent/fuzz/**` (issue #66).
- `app/`, `components/`, `lib/` — Next.js/React/TypeScript, the relay and UI. Own test suite (`npx vitest run` / `npm test`).
- `docs/` — user-facing documentation (this file's sibling).
- `docs/superpowers/specs/` and `docs/superpowers/plans/` — design specs and implementation plans for each sub-project, written before implementation. If you're planning substantial new work, look at the existing ones for the expected shape and level of detail.

## Running tests

```bash
# Rust
cd capture-agent
cargo test
cargo fuzz run parse_packet -- -max_total_time=30      # if touching parse.rs
cargo fuzz run http2_reassembly -- -max_total_time=30  # if touching http2.rs
cargo audit                                            # checks Cargo.lock against RustSec advisory-db

# TypeScript
npm audit --audit-level=high  # checks package-lock.json against the npm advisory database
npx vitest run        # or: npm test
npx tsc --noEmit
npm run lint
npm run build
npx playwright test   # real-browser smoke test — see e2e/smoke.spec.ts
```

All checks above should pass before opening a PR. CI enforces the two `cargo fuzz` commands, `cargo audit`, and `npm audit` above itself now (issues #66, #111, #112) — it's no longer only the honour system — so a PR that touches `parse.rs`, `http2.rs`, or `capture-agent/fuzz/**` will fail CI if either fuzz target finds a crash, and any PR at all will fail CI if `Cargo.lock`/`package-lock.json` carries a dependency with a known advisory (RustSec for Rust, `high` severity or above for npm), same as running these locally would show.

### Live-loopback packet-capture integration test (issue #114)

`cargo test` above never opens a real `pcap::Capture` handle — every existing Rust test (including the fixture corpus in `tests/protocol_regression.rs`) passes fixture bytes straight to `parse_packet`/`sniff_l7`. `tests/live_loopback.rs` closes that gap: it spawns the actual compiled `capture-agent` binary against the real `lo` interface, drives real TCP traffic across it, and asserts on the resulting wire events.

Opening a live capture needs `CAP_NET_RAW`/`CAP_NET_ADMIN` (or root), so this test is `#[ignore]`d by default — a plain `cargo test` never needs elevated privilege, and neither does any other check in this list. To run it locally:

```bash
cd capture-agent
cargo test --locked --test live_loopback --no-run        # build only, no privilege needed yet
sudo setcap cap_net_raw,cap_net_admin=eip target/debug/capture-agent
cargo test --locked --test live_loopback -- --ignored --test-threads=1
```

CI runs the same three steps (`.github/workflows/ci.yml`'s `rust` job) — granting the capability to the built test binary via `setcap` rather than running all of `cargo test` under `sudo`, so the elevated privilege stays scoped to exactly the one binary that needs it.

## Project roadmap

Full roadmap, epics, and individual tasks are tracked as GitHub issues in this repo, not in a separate project-management tool:

- Issue #26 — top-level roadmap, links every epic
- Epic #13 — Live Capture Core (done)
- Epic #22 — Secure LAN Access (mTLS, reverse proxy, native app) — done (see `deploy/`, `macos-app/`, `docs/security.md`)
- Epic #23 — Ownership Enrichment (WHOIS/RDAP) — done (see `lib/enrichment/`, `docs/enrichment-protocol.md`)
- Epic #24 — Network Path Visualization (traceroute + geoIP) — done (see `capture-agent/src/traceroute.rs`, `docs/geoip-protocol.md`)
- Epic #25 — TLS Visibility (JA3 fingerprinting + opt-in per-process decryption) — done. Landed as a narrower, lower-risk design than originally scoped: not a MITM proxy — no CA install, no traffic redirection, no certificate pinning broken. Decryption only happens for a process explicitly launched via `bin/osi-inspect.js`, which points `SSLKEYLOGFILE` at a fresh ephemeral file and registers that one PID as decrypt-eligible with the agent. See `docs/superpowers/specs/2026-08-29-tls-interception-design.md`.
- Issues #27, #28, #29 — done (fixed via PR #34): the packet-event stream is capped and `Lagged` no longer disconnects a slow client, `FlowTable` expires idle flows and emits `connection_closed`, and `headerBreakdown` reaches the wire.

Labels: `epic` (tracking issues), `rust`, `web`, `security`, `not-speced` (blocked on a design pass before it can be broken into real tasks — none of the current epics carry this label).

## Design process for new work

This project uses a spec-then-plan-then-implement workflow for anything nontrivial, rather than jumping straight to code:

1. **Design spec** (`docs/superpowers/specs/YYYY-MM-DD-<topic>-design.md`) — architecture, components, data flow, security model, explicitly out-of-scope items.
2. **Implementation plan** (`docs/superpowers/plans/YYYY-MM-DD-<topic>.md`) — task-by-task breakdown with concrete file paths, interfaces, and (for TDD-suited work) the actual test code, so each task is independently reviewable.
3. Implementation, with a review after each task and a final whole-branch review before merge.

You don't have to follow this exact process for a small fix, but for anything that changes the architecture (a new wire event type, a new privileged capability, a new external dependency touching security) — write the spec first. The existing specs under `docs/superpowers/specs/` show the expected depth: what problem is being solved, what alternatives were considered and why they were rejected, what the security model is, and what's explicitly deferred.

## Wire protocol changes

If you change anything in `capture-agent/src/wire.rs`, you must also update `lib/agent-mapping.ts` and `lib/types.ts` to match, field-for-field, in `camelCase`. There's no compiler check across this language boundary — see [docs/wire-protocol.md](docs/wire-protocol.md) for the full contract and the "adding a new field" checklist.

## Security-sensitive changes

Anything touching the capture agent's privilege model, the network binding of either process, authentication, or dependency additions in security-adjacent areas should be treated with extra scrutiny — see [docs/security.md](docs/security.md) for the current posture, including the residual risks called out for the mTLS/LAN-access design (epic #22) and the newer TLS-visibility and ownership-enrichment opt-in features. Do not casually expose either process beyond loopback.

## Commit and PR conventions

- Commit messages: imperative mood, explain *why* not just *what* where the reasoning isn't obvious from the diff.
- If a change fixes a defect found during review (yours or someone else's), say so in the commit message — this repo's history deliberately preserves that trail rather than squashing it away, so future readers can see what was tried and why it changed.
- PRs should list what was verified (tests run, manual checks performed) — see recent PR descriptions in this repo for the expected format.
