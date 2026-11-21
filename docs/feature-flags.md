# Feature Flags

Standing Rule 6 (`CLAUDE.md` / `AGENTS.md`): new features start behind a flag that is **off by default**. Add a row here in the same PR that adds the flag. There's no flag registry in code yet; this list is the registry *(code registry and CI check: planned, not enforced yet)*.

| Feature | How it's enabled | Default | Where | Status |
|---|---|---|---|---|
| Follow Stream (KAN-110) | `FOLLOW_STREAM=1` env var for the capture agent | off | `capture-agent/src/follow_config.rs`, `main.rs` | in progress; agent side merged in parts, relay route (Task 4) not yet |
| TLS decrypted-content visibility | launch a process via `npx osi-inspect <cmd>` (`bin/osi-inspect.js`); a browser needs `--yes-decrypt-entire-browser` | off (per process, explicit) | `bin/osi-inspect.js`, `capture-agent/src/tls_decrypt.rs` | shipped |
| Ownership enrichment (WHOIS/RDAP) | `enrich on` / background mode via `app/api/enrichment/control` | off (`mode = 'off'`) | `lib/enrichment.ts` | shipped |
| GeoIP for traceroute hops | `geoip enable` via `app/api/geoip/control` | off (`mode = 'off'`) | `lib/geoip.ts` | shipped |
| Traceroute probe | on demand, per connection | not run until requested | `capture-agent/src/traceroute.rs` | shipped |
| Capture replay | `REPLAY_FILE=<path>` (with `REPLAY_SPEED`, `REPLAY_LOCAL_ADDRS`) | off (live capture) | `capture-agent/src/main.rs` | shipped (a mode, not a feature flag) |
| Dev HMR disable | `DISABLE_HMR=true` | HMR on | `next.config.ts` | dev-only, from AI Studio scaffold |

Configuration values that aren't features (`CAPTURE_INTERFACE`, `RELAY_PORT`, `FRONT_DOOR_PORT`, `MAX_FLOWS`, `MAX_OBSERVED_DNS_NAMES`, `AGENT_TOKEN_FILE`, `ALLOWED_HOSTS`, `OSI_INSPECT_RELAY_URL`) are listed by name in `.env.example`.

## Planned (not built)

| Feature | Intended flag | Default |
|---|---|---|
| Fleet uplink (separate process, outbound to ingest) | TBD | off |
| Device blocking | TBD; also needs a Standing Rule 1 plan per action | off |
