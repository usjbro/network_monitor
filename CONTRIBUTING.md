# Contributing

## Project structure

See [docs/architecture.md](docs/architecture.md) for how the pieces fit together before making changes. Broadly:

- `capture-agent/` — Rust, the privileged capture agent. Own `Cargo.toml`, own test suite (`cargo test`), own fuzz target (`cargo fuzz run parse_packet`).
- `app/`, `components/`, `lib/` — Next.js/React/TypeScript, the relay and UI. Own test suite (`npx vitest run` / `npm test`).
- `docs/` — user-facing documentation (this file's sibling).
- `docs/superpowers/specs/` and `docs/superpowers/plans/` — design specs and implementation plans for each sub-project, written before implementation. If you're planning substantial new work, look at the existing ones for the expected shape and level of detail.

## Running tests

```bash
# Rust
cd capture-agent
cargo test
cargo fuzz run parse_packet -- -max_total_time=30   # if touching parse.rs

# TypeScript
npx vitest run        # or: npm test
npx tsc --noEmit
npm run lint
npm run build
```

All four TypeScript checks and both Rust checks should pass before opening a PR.

## Project roadmap

Full roadmap, epics, and individual tasks are tracked as GitHub issues in this repo, not in a separate project-management tool:

- Issue #26 — top-level roadmap, links every epic
- Epic #13 — Live Capture Core (done)
- Epic #22 — Secure LAN Access (mTLS, reverse proxy, native app) — speced, not yet planned in detail
- Epic #23 — Ownership Enrichment (WHOIS/RDAP) — not yet speced
- Epic #24 — Network Path Visualization (traceroute + geoIP) — not yet speced
- Epic #25 — TLS Interception / MITM Proxy — not yet speced, deliberately treated as the highest-risk piece, needs its own dedicated design pass before any code
- Issues #27, #28, #29 — known, real gaps in the current implementation (uncapped packet stream, flows never expiring, `headerBreakdown` never reaching the wire)

Labels: `epic` (tracking issues), `rust`, `web`, `security`, `not-speced` (blocked on a design pass before it can be broken into real tasks).

## Design process for new work

This project uses a spec-then-plan-then-implement workflow for anything nontrivial, rather than jumping straight to code:

1. **Design spec** (`docs/superpowers/specs/YYYY-MM-DD-<topic>-design.md`) — architecture, components, data flow, security model, explicitly out-of-scope items.
2. **Implementation plan** (`docs/superpowers/plans/YYYY-MM-DD-<topic>.md`) — task-by-task breakdown with concrete file paths, interfaces, and (for TDD-suited work) the actual test code, so each task is independently reviewable.
3. Implementation, with a review after each task and a final whole-branch review before merge.

You don't have to follow this exact process for a small fix, but for anything that changes the architecture (a new wire event type, a new privileged capability, a new external dependency touching security) — write the spec first. The existing specs under `docs/superpowers/specs/` show the expected depth: what problem is being solved, what alternatives were considered and why they were rejected, what the security model is, and what's explicitly deferred.

## Wire protocol changes

If you change anything in `capture-agent/src/wire.rs`, you must also update `lib/agent-mapping.ts` and `lib/types.ts` to match, field-for-field, in `camelCase`. There's no compiler check across this language boundary — see [docs/wire-protocol.md](docs/wire-protocol.md) for the full contract and the "adding a new field" checklist.

## Security-sensitive changes

Anything touching the capture agent's privilege model, the network binding of either process, authentication, or dependency additions in security-adjacent areas should be treated with extra scrutiny — see [docs/security.md](docs/security.md) for the current posture and what's explicitly out of scope until epic #22 lands. Do not casually expose either process beyond loopback.

## Commit and PR conventions

- Commit messages: imperative mood, explain *why* not just *what* where the reasoning isn't obvious from the diff.
- If a change fixes a defect found during review (yours or someone else's), say so in the commit message — this repo's history deliberately preserves that trail rather than squashing it away, so future readers can see what was tried and why it changed.
- PRs should list what was verified (tests run, manual checks performed) — see recent PR descriptions in this repo for the expected format.
