# Network Monitor — Claude Code Instructions

## Mission

Build and maintain Network Monitor according to repository code, approved requirements, architecture, and tracked work. Treat source and tests as evidence; inspect before editing and keep changes scoped.

## Start Here

1. Read `.ai/CURRENT_TASK.md`.
2. Read `.ai/HANDOFF.md` only when continuing previous work.
3. Inspect relevant code and tests; read subsystem docs only as needed.
4. Do not load all of `docs/` or the repository by default.

`AGENTS.md` is the cross-agent source of truth for the newer operational conventions shared by every coding agent in this repo — project structure, boundaries, git/commit conventions, multi-agent coordination, and testing expectations. This file stays the detailed architecture and Claude-Code-specific guidance. Some older sections (Mission, Sources of Truth, Required Workflow, Model Routing, Context Discipline, Session Completion) still exist independently in both files rather than being deduplicated — read both, and if you edit one of those overlapping sections, check whether the other needs the same change.

## Commands

```sh
npm install
npm run dev       # Next.js; loopback only
npm run build
npm run start     # loopback only
npm run lint
npm run clean
npm test          # Vitest
npx vitest run
```

TypeScript/React specs are in `lib/__tests__/`. The Rust agent has its own tests and commands:

```sh
cd capture-agent
cargo build --release
cargo test
cargo run --release
```

See `CONTRIBUTING.md` for broader CI checks, fuzzing, audit, and integration-test requirements. Do not run the full suite just to fill in `.ai/TEST_STATUS.md`.

## Sources of Truth

- Repository/GitHub code: implementation, tests, CI, and commits.
- Linear: tracked task/work status where connected; do not treat `Done` as proof of correct implementation.
- Notion: specifications/documentation where available; docs do not prove implementation exists.
- `.ai/PROJECT_STATE.md`: short, verified project orientation.
- `.ai/CURRENT_TASK.md`: active unit of work.
- `.ai/HANDOFF.md`: minimal continuation state.
- `.ai/DECISIONS.md`: durable technical decisions.
- `.ai/TEST_STATUS.md`: latest verified test condition.

Surface disagreements among sources explicitly. The current epic-cycle skill uses Linear (and optional Notion tracking), while `CONTRIBUTING.md` describes a GitHub issue roadmap; follow the active task's tracker and do not silently rewrite tracker policy.

## Required Development Workflow

1. Read `CURRENT_TASK.md`; inspect relevant implementation, tests, and architecture.
2. Post the 🟡 `started` message to `#network-monitor` (after the approval gate is approved, if the task has one).
3. Read the relevant spec/protocol docs and confirm acceptance criteria.
4. Use test-first development where practical; show the changed test fails for the missing behavior.
5. Implement the smallest correct change; run relevant tests, fix failures, then broader applicable checks.
6. Review `git diff`; update applicable state files and `HANDOFF.md` with verified facts.
7. Commit only verified work and only when the user explicitly requests a commit.
8. Post to Slack when you open a PR (`pr-opened`), whenever you ask for review or feedback (`feedback`), and when the task ends (`review`, `done`, or `blocked`).

The Slack posts in steps 2 and 8 are required on every task — ad hoc or Linear-tracked, small or large — not only when the user asks for Slack coordination. Telling the user in chat does not replace them. See `AGENTS.md` "Slack Status Posts" for the message format and how to post from a cloud session with no webhook.

Tests, not compilation, a rendered screen, a file's existence, or tracker status, establish behavior. Never claim completion without evidence.

## Architecture Summary

The Next.js 16 / React 19 UI displays real traffic. The Rust `capture-agent` captures and parses it in a separate process. Its loopback NDJSON socket feeds the relay (`lib/agent-client.ts`); `app/api/stream/route.ts` sends SSE to the browser and `app/api/control/route.ts` forwards controls. `app/page.tsx` owns main client state; `lib/agent-mapping.ts` maps wire events; `lib/types.ts` defines domain types; `components/` are primarily presentational. `lib/osi-engine.ts` contains static OSI descriptions, not live measurements.

Read `docs/architecture.md` for the component map. Do not infer behavior from this summary alone — and note `.ai/PROJECT_STATE.md`'s "Known Source Disagreements" flags that `docs/architecture.md` itself contains stale/self-contradictory system-stats claims; current code and tests take precedence over that doc for those fields.

User-facing docs also live under `docs/`: [getting-started.md](docs/getting-started.md), [usage.md](docs/usage.md), [troubleshooting.md](docs/troubleshooting.md), plus the protocol/security docs referenced below.

## Critical Invariants

- Preserve `next.config.ts`'s deliberate Webpack/file-watching behavior and `--webpack` flags in `package.json`; do not casually remove or “fix” them.
- Next.js and the capture agent bind to `127.0.0.1`. Never expose them by widening their bind. LAN access goes through the existing Caddy/mTLS front door; its LAN-facing change is deliberate/manual and must follow `deploy/README.md`.
- Before changing `deploy/Caddyfile`, read `docs/security.md` and `deploy/README.md`; rerun `deploy/test-mtls-rejection.sh` after the change.
- Startup `CAPTURE_INTERFACE` selection and runtime `set_interface` switching are distinct paths. Preserve their separate semantics.
- TLS decryption is explicit, per-process opt-in via `bin/osi-inspect.js`; this is passive visibility, not a blanket MITM. Keep key material and decrypted payloads ephemeral/in-memory, redacted, zeroed on eviction, and gated to loopback or mTLS as implemented.
- Ownership enrichment and GeoIP enrichment are opt-in; traceroute probes are on demand and bounded.
- Do not invent host metrics or interface properties. The agent emits system/interface identity and traffic counters; it does not emit CPU, memory, uptime, interface speed, or duplex. Add displayed data only with a real producer.
- Do not mistake static OSI metadata for live values. Do not reintroduce simulated traffic or metrics.
- A filename, type, issue, UI placeholder, spec, or comment alone does not prove functionality. Check source, tests, and current wire behavior.
- `macos-app`: build/test with `CODE_SIGNING_ALLOWED=NO`; use a clean build after changing `NavigationLockDelegate` because optional delegate signature mismatches can evade incremental builds. The client key is Secure-Enclave-backed; the app does not read the CA private key. `deploy/sign-native-app-csr.sh` signs its CSR out of band.

## Read Before Modifying

- Capture-agent wire messages or `lib/agent-mapping.ts`: `docs/wire-protocol.md`; update Rust and TypeScript contract together.
- Ownership enrichment: `docs/enrichment-protocol.md` and `docs/superpowers/specs/2026-08-28-ownership-enrichment-design.md`.
- Traceroute/GeoIP: `docs/geoip-protocol.md` and `docs/superpowers/specs/2026-09-01-path-visualization-design.md`.
- Deployment or mTLS: `docs/security.md` and `deploy/README.md`.
- macOS navigation/client certificate security: `macos-app/README.md` and `docs/security.md`.
- Significant architecture: relevant `docs/superpowers/specs/` entry, then follow the spec → plan process in `CONTRIBUTING.md`.
- TLS visibility or capture files: find and read the relevant design spec and plan under `docs/superpowers/` before extending them.

## Model Routing

- **Opus:** architecture, cross-subsystem design, ambiguous/conflicting requirements, difficult root-cause analysis, security-sensitive design, major data-model or performance work, and competing technical approaches.
- **Sonnet:** normal implementation, tests, approved designs, bug fixes, refactoring, integrations, docs, and review.
- **Haiku:** formatting, renaming, simple documentation/mechanical changes, and tiny well-defined fixes.

Escalate Haiku → Sonnet → Opus based on actual complexity. A test failure alone is not a reason to escalate; first check whether its cause is straightforward. Use the least expensive model that can reliably complete the task; return to a cheaper model for mechanical follow-up.

## Context and Orchestration Cost Control

Load only the state and docs the task needs. Do not repeatedly reread unchanged large docs. Conversation history is not project state; persist durable facts in Git, the active tracker, approved specs, tests, and concise `.ai/` files. Start fresh at meaningful task boundaries.

Do not spawn agents just because roles exist. Delegate only when work is genuinely parallel, independent verification has material value, specialization helps, or isolation saves context. Give narrow scopes; do not make every role inspect the whole repository. A simple task usually needs one developer; agent count should follow complexity, not a fixed pipeline.

## Session Completion

For substantial work: test → review → update `TEST_STATUS` and `PROJECT_STATE` when applicable → record durable decisions → update `HANDOFF` → commit verified work only if explicitly requested. Keep handoffs short; do not store transcripts or logs.
