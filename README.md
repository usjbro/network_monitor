# OSI Traffic Terminal Monitor

A terminal-style single-page app that visualizes simulated network traffic across all 7 layers of the OSI model — throughput, active connections, a live packet stream with per-layer header breakdowns, a protocol matrix, and traffic-scenario presets (web-heavy, video streaming, SYN flood, IoT mesh, DNS storm, etc.).

> **All data is simulated client-side.** There is no real packet capture and no live network access — every number (throughput, packets, connections, latency) is procedurally generated in the browser on a timer. There is also no live Gemini API call anywhere in the code, despite `GEMINI_API_KEY` appearing in `.env.example`.

Built with Next.js 15 (App Router), React 19, and Tailwind v4. Originally scaffolded via [Google AI Studio](https://ai.studio/apps/9315112a-9298-4e9c-82e9-59ed03d07fcc).

## Features

- **Dashboard** — real-time system stats (CPU, memory, interface throughput) and per-layer sparklines
- **Layer detail view** — drill into any of the 7 OSI layers for protocol breakdowns and health status
- **Connections view** — simulated active socket table (TCP/UDP/QUIC/SCTP/ICMP) with per-connection speed, latency, and encryption info
- **Packet stream** — a scrolling feed of fabricated packets with full L1–L7 header breakdowns and hex dumps
- **Protocol matrix / topology view**
- **Scenario lab** — switch traffic patterns (normal, web-heavy, video stream, SYN flood, IoT mesh, DNS storm) to see how stats and error rates react
- **10 terminal color themes** (sophisticated, macOS Pro, macOS Homebrew, iTerm Snazzy, Matrix, Dracula, Amber, Cyberpunk, Catppuccin, Nord)
- **Unix-style command bar** — e.g. `dash`, `layer <1-7>`, `conn`, `pcap`, `matrix`, `lab`, `theme <name>`, `pause`, `resume`, `reset`
- **Install modal** — install as a PWA, or download a bash-generated standalone Node CLI script that mimics the terminal UI

## Run Locally

**Prerequisites:** Node.js

```bash
npm install      # install dependencies
npm run dev       # start dev server
```

Then open the printed local URL in your browser.

## Other Commands

```bash
npm run build     # production build
npm run start      # run production build
npm run lint       # eslint .
npm run clean      # next clean
```

There is no test suite configured in this repo.
