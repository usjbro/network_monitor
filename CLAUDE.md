# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm install      # install dependencies
npm run dev       # start dev server (Next.js)
npm run build     # production build
npm run start     # run production build
npm run lint      # eslint .
npm run clean     # next clean
```

TypeScript/React tests run via Vitest (`npm test`, or `npx vitest run`); specs live in `lib/__tests__/`. The Rust capture agent has its own `cargo test` suite plus a `cargo-fuzz` target — see `capture-agent/` commands below.

```bash
cd capture-agent
cargo build --release   # build the capture agent
cargo test               # run its test suite
cargo run --release      # run it (listens on 127.0.0.1:9990)
```

## Architecture

This is a Next.js 15 (App Router) + React 19 + Tailwind v4 terminal-style UI ("OSI NetStriker") that visualizes **real** network traffic captured on the local machine, broken down across the 7 OSI layers. It was originally scaffolded via Google AI Studio (see `metadata.json`, `README.md`) as a client-side simulation and was later converted to a real live-capture pipeline; some Google AI Studio scaffolding artifacts (e.g. `GEMINI_API_KEY` in `.env.example`, `majorCapabilities` in `metadata.json`, an empty `app/api/gemini/analyze/` directory) are leftover and not wired to anything — there is no Gemini API call anywhere in the code.

Real traffic flows through three pieces:

1. **`capture-agent/`** — a standalone Rust binary (not started by `npm run dev`; run it separately) that opens a live packet capture on the default network interface via `pcap`, parses frames (`src/parse.rs`), sniffs application-layer protocols (`src/l7.rs`), attributes flows to local processes (`src/process_lookup.rs`), and aggregates them into a flow table (`src/flow.rs`). It listens on a TCP socket bound to `127.0.0.1:9990` and streams newline-delimited JSON events (`src/wire.rs` defines the wire format: `Packet`, `ConnectionUpdate`, `LayerUpdate`) to whatever connects — normally the Next.js relay below. It also accepts `pause`/`resume` control messages on the same connection. See `capture-agent/README.md` for one-time macOS `access_bpf` setup (no `sudo` needed at runtime once configured).
2. **`lib/agent-client.ts`** — a Node `net.Socket`-based client (`AgentClient`, a singleton stashed on `global.__agentClient`) that connects to the capture agent, parses its newline-delimited JSON stream, and re-emits `'event'`/`'status'` on a Node `EventEmitter`. It auto-reconnects with a fixed delay on disconnect.
3. **`app/api/stream/route.ts`** — an SSE (`text/event-stream`) API route that subscribes to the shared `AgentClient` singleton and forwards every event to the connected browser tab. `app/api/control/route.ts` is the corresponding POST endpoint the browser uses to send `pause`/`resume` back through the same `AgentClient`.

On the client:

- `app/page.tsx` — the entire application lives in one client component (`'use client'`). It opens an `EventSource('/api/stream')` in a `useEffect` and folds incoming events into React state: `connection_update` events upsert into `connections`, `packet` events prepend into a capped `packets` buffer, `layer_update` events merge into `liveLayers` (via `mergeLayerStats` from `lib/agent-mapping.ts`), and a `connection_status` event drives the "agent not connected" banner. There is no simulation loop — all metrics originate from the capture agent. Tab switching, layer selection, and a Unix-style command bar (`handleExecuteCommand`) are handled here rather than via routing — there's only one route. Note: no wire event currently carries system-level stats (hostname, CPU/mem, aggregate interface throughput) — `SystemStats` in `app/page.tsx` is seeded mostly at zero/placeholder values pending a future task to wire that up; don't assume those fields are live.
- `lib/agent-mapping.ts` — translates raw agent wire JSON into the app's domain types: `mapConnectionEvent`, `mapPacketEvent`, and `mergeLayerStats` (merges live per-layer stats from the agent onto the static per-layer metadata below, sorted descending 7→1 to match display order).
- `lib/osi-engine.ts` — `THEMES` (terminal color schemes), `STATIC_LAYER_INFO` (per-layer metadata: name, PDU, protocol list, badge colors — NOT live values), and formatting helpers (`formatSpeed`, `formatBytes`). It no longer generates fake traffic.
- `lib/types.ts` — all domain types (`OSILayerInfo`, `NetworkConnection`, `PacketFrame`, `SystemStats`, `ThemeConfig`, `TerminalTheme`). Add new fields here first when extending what's displayed.
- `components/` — one component per view/tab (`DashboardView`, `LayerDetailView`, `ConnectionsView`, `PacketStreamView`, `ProtocolMatrixView`), plus chrome (`HeaderBar`, `CommandLineBar`, `InstallModal`). All are presentational — they receive `theme: ThemeConfig` plus view-specific data as props from `app/page.tsx`; there's no separate client-side data fetching or state management library. (The old `ScenarioLabView` was removed along with the simulation it drove.)
- `app/api/install/route.ts` — a single API route that serves a generated bash installer script (`GET`), which itself writes a standalone Node CLI script to the user's machine mimicking the terminal UI. Self-contained; not connected to the rest of the app.
- Theming: `TerminalTheme` (10 variants defined in `THEMES`) drives Tailwind class strings passed down as a `theme` prop — there's no CSS-in-JS or theme context, just plain prop drilling.
- `next.config.ts` has `eslint.ignoreDuringBuilds: true` and a webpack tweak that disables file watching when `DISABLE_HMR=true` (used by the AI Studio agent environment to avoid flicker during automated edits) — don't rely on lint failing the build, and don't "fix" the watchOptions block.
- `npm run dev`/`npm run start` bind Next.js to `127.0.0.1` only (`-H 127.0.0.1`), matching the capture agent's loopback-only bind — don't remove that flag, it's a deliberate security boundary until the separate mTLS/Caddy LAN-access plan lands.

## Further documentation

User-facing docs live under `docs/`: [architecture.md](docs/architecture.md), [getting-started.md](docs/getting-started.md), [usage.md](docs/usage.md), [wire-protocol.md](docs/wire-protocol.md) (the full agent↔relay JSON contract — read this before touching `capture-agent/src/wire.rs` or `lib/agent-mapping.ts`), [troubleshooting.md](docs/troubleshooting.md), [security.md](docs/security.md). Design specs and implementation plans for each sub-project live under `docs/superpowers/specs/` and `docs/superpowers/plans/` — read the relevant spec before extending a sub-project, and follow that same spec-then-plan process for new architectural work (see `CONTRIBUTING.md`).
