# OSI Traffic Terminal Monitor

A terminal-style app that visualizes **real, live-captured** network traffic on your machine across all 7 layers of the OSI model — throughput, active connections, a live packet stream with per-layer header breakdowns, and a protocol matrix.

Traffic is captured by a small Rust agent (`capture-agent/`) using `pcap`, streamed to a Next.js relay over a loopback-only TCP socket, and pushed to the browser over Server-Sent Events. No numbers are fabricated: layers the agent can't independently measure (L1/L2/L5/L6) are shown at zero rather than a made-up value, and there is no live Gemini API call anywhere in the code despite `GEMINI_API_KEY` appearing in `.env.example` (a leftover from the original Google AI Studio scaffold).

Built with Next.js 15 (App Router), React 19, and Tailwind v4 on the frontend, and Rust (tokio + pcap) for the capture agent. Originally scaffolded via [Google AI Studio](https://ai.studio/apps/9315112a-9298-4e9c-82e9-59ed03d07fcc) as a client-side simulation, then converted to a real live-capture pipeline.

## Features

- **Dashboard** — per-layer throughput and active-connection counts, sourced from the capture agent's flow table
- **Layer detail view** — drill into any of the 7 OSI layers for protocol breakdowns and health status
- **Connections view** — live active socket table (TCP/UDP) with per-connection speed, latency, process attribution, and encryption info
- **Packet stream** — a scrolling feed of real captured packets with header breakdowns and hex dumps
- **Protocol matrix / topology view**
- **10 terminal color themes** (sophisticated, macOS Pro, macOS Homebrew, iTerm Snazzy, Matrix, Dracula, Amber, Cyberpunk, Catppuccin, Nord)
- **Unix-style command bar** — e.g. `dash`, `layer <1-7>`, `conn`, `pcap`, `matrix`, `theme <name>`, `pause`, `resume`, `reset`
- **Install modal** — install as a PWA, or download a bash-generated standalone Node CLI script that mimics the terminal UI

System-level stats (hostname, CPU/memory, aggregate interface throughput) aren't wired to real data yet — that's tracked as separate follow-up work and shown as placeholder/zero values in the meantime, not "LIVE".

## Run Locally

**Prerequisites:** Node.js, Rust (for the capture agent), and macOS `access_bpf` group membership (see `capture-agent/README.md`).

Run the capture agent and the web app in two terminals:

```bash
cd capture-agent
cargo run --release      # listens on 127.0.0.1:9990
```

```bash
npm install
npm run dev               # binds to 127.0.0.1 only; open the printed local URL
```

Without the agent running, the app still loads and shows an "agent not connected" banner instead of live data.

## Other Commands

```bash
npm run build     # production build
npm run start      # run production build (also binds to 127.0.0.1 only)
npm run lint       # eslint .
npm run clean      # next clean
npm test           # vitest run — lib/__tests__/
```

The Rust capture agent has its own test suite and a `cargo-fuzz` target:

```bash
cd capture-agent
cargo test
```
