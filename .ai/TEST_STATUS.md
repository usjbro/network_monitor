# Test Status

## JAM-164 — verified 2026-09-28

All local commands ran in `.worktrees/live-pcap-per-packet-layer-field-is-hardcoded-to-4-breaking`.

| Command | Result |
|---|---|
| `cargo test --locked packet_osi_layer` | 2 targeted Rust tests passed. |
| `cargo test --locked` | Passed: 202 library tests, 53 binary tests, 6 integration tests; 2 privileged live-loopback tests ignored by default. |
| `cargo clippy --all-targets --locked -- -D warnings` | Passed. |
| `cargo build --release --locked` | Passed. |
| `npx vitest run lib/__tests__/packet-stream-layer-filter.test.tsx` | 1 component test passed. |
| `npx vitest run` | 498 tests passed across 73 files. |
| `npm run lint` | Passed. |
| `npx tsc --noEmit` | Passed. |
| `git diff --check` | Passed. |
| `codex review --uncommitted` and `codex review --commit 8257fca` | No actionable findings. |

PR #240's CI also passed Rust, Web, Playwright E2E, fuzz targets, and all CodeQL analyses. Verify the live checks again before merge.
