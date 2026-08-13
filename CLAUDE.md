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

There is no test suite configured in this repo (no test runner, no `*.test.*` files).

## Architecture

This is a Next.js 15 (App Router) + React 19 + Tailwind v4 single-page terminal-style UI ("OSI NetStriker") that visualizes simulated network traffic across the 7 OSI layers. It was scaffolded via Google AI Studio (see `metadata.json`, `README.md`).

**All state and data are simulated client-side — there is no real network capture and no live Gemini API call anywhere in the code**, despite `GEMINI_API_KEY` in `.env.example` and `majorCapabilities` in `metadata.json` declaring server-side Gemini use. Treat any "live" numbers (throughput, packets, connections) as procedurally generated, not real telemetry.

- `app/page.tsx` — the entire application lives in one client component (`'use client'`). It owns all state (active tab, theme, scenario, stats, layers, connections, packet buffer) and runs a single `setInterval` loop that regenerates all simulated metrics on every tick. Tab switching, layer selection, and a Unix-style command bar (`handleExecuteCommand`) are all handled here rather than via routing — there's only one route.
- `lib/osi-engine.ts` — the simulation engine: `THEMES` (terminal color schemes), `INITIAL_OSI_LAYERS`/`INITIAL_CONNECTIONS` seed data, `generateRandomPacket()` (fabricates packet frames with per-layer header breakdowns), and formatting helpers (`formatSpeed`, `formatBytes`). Changing simulated traffic behavior (scenario multipliers, layer values, packet content) means editing this file and/or the interval loop in `app/page.tsx`.
- `lib/types.ts` — all domain types (`OSILayerInfo`, `NetworkConnection`, `PacketFrame`, `SystemStats`, `ThemeConfig`, `TerminalTheme`, `TrafficScenario`). Add new fields here first when extending the simulation.
- `components/` — one component per view/tab (`DashboardView`, `LayerDetailView`, `ConnectionsView`, `PacketStreamView`, `ProtocolMatrixView`, `ScenarioLabView`), plus chrome (`HeaderBar`, `CommandLineBar`, `InstallModal`). All are presentational — they receive `theme: ThemeConfig` plus view-specific data as props from `app/page.tsx`; there's no separate client-side data fetching or state management library.
- `app/api/install/route.ts` — a single API route that serves a generated bash installer script (`GET`), which itself writes a standalone Node CLI script to the user's machine mimicking the terminal UI. Self-contained; not connected to the rest of the app's simulation state.
- Theming: `TerminalTheme` (10 variants defined in `THEMES`) drives Tailwind class strings passed down as a `theme` prop — there's no CSS-in-JS or theme context, just plain prop drilling.
- `next.config.ts` has `eslint.ignoreDuringBuilds: true` and a webpack tweak that disables file watching when `DISABLE_HMR=true` (used by the AI Studio agent environment to avoid flicker during automated edits) — don't rely on lint failing the build, and don't "fix" the watchOptions block.

This directory is not currently a git repository.
