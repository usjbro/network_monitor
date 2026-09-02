# Network Path Visualization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give a connection in `ConnectionsView` an on-demand "trace route" action that runs a real ICMP-based traceroute from the capture agent, streams hop results to the browser, and enriches each hop with an opt-in geoIP lookup — with a hop table as the shipped deliverable and a path map as an explicitly separable stretch goal.

**Architecture:** A new `capture-agent/src/traceroute.rs` sends ICMP Echo Requests with incrementing TTL over an unprivileged ICMP datagram socket (mechanism confirmed by Task 1's spike before any other code depends on it), streaming one `traceroute_hop` NDJSON event per resolved hop over the existing agent↔relay TCP connection. A new relay-side `lib/geoip.ts` (`GeoIpClient`) mirrors sub-project 2's `EnrichmentClient` shape exactly — default-off, scope-filtered via the same `lib/enrichment/scope-filter.ts`, disk-cached, rate-limited — and emits its own `geo_hop_update` SSE event, kept separate from `traceroute_hop` since geo enrichment is optional and can lag or be absent.

**Tech Stack:** Rust (capture-agent — ICMP socket handling via the standard library `net` module or a small crate if raw ICMP framing needs it, decided in Task 2 once Task 1's spike result is known), TypeScript/Next.js Route Handlers + built-in `fetch` for `lib/geoip.ts` (zero new npm dependencies unless the chosen geoIP provider genuinely requires an SDK, per Dependency hygiene below), Vitest, `cargo test` + the existing `cargo-fuzz` target.

**Spec:** `docs/superpowers/specs/2026-09-01-path-visualization-design.md` — read it before starting; this plan assumes familiarity with its Components §1–§4, Security model table, and Error handling & lifecycle sections. Concrete numbers restated below for convenience.

## Global Constraints

- **Traceroute is on-demand only, never automatic.** No task in this plan wires a trace to fire on connection creation or any other automatic trigger — every trace originates from an explicit user action (spec Scope: "Explicitly out of scope").
- **Bounded cost, always:** hop ceiling 30, per-hop timeout 1s with up to 3 retries before recording "no response" and moving to the next hop, total-trace timeout 45s. Every task touching the probe loop must preserve all three bounds.
- **GeoIP is default-off, runtime-only, and never persisted across a relay restart** — same precedent as sub-project 2's `EnrichmentClient`. No task writes an "enabled" flag to disk.
- **Reuse sub-project 2's scope filter, don't reimplement it.** `lib/geoip.ts` calls `isPrivateOrReserved` from `lib/enrichment/scope-filter.ts` directly.
- **No live network calls in any test.** ICMP reply parsing uses fixture bytes; `GeoIpClient` uses an injected `fetch`; the one genuinely live check in this whole plan is Task 1's privilege spike, which is explicitly a manual investigation, not a `cargo test`/`vitest` target.
- **Field names on wire/SSE events are flat `camelCase`**, matching every existing event's convention exactly.
- **Data directory:** `.data/geoip/` at the repo root, `{ recursive: true, mode: 0o700 }`, sibling to sub-project 2's `.data/enrichment/`.
- **GeoIP cache TTL is 30 days** (longer than sub-project 2's 14-day RDAP TTL — a deliberate, named difference per the spec, not an oversight).

---

## File Structure

**New — `capture-agent/src/`:**
- `traceroute.rs` — ICMP probe loop, hop-result collection, bounded by hop ceiling/per-hop timeout+retry/total-trace timeout

**Modified — `capture-agent/src/`:**
- `wire.rs` — new `ControlMessage::TraceRoute { target_ip: String }` variant; new `AgentEvent::TracerouteHop { hop: Box<TracerouteHopJson> }` variant; new `TracerouteHopJson` struct
- `main.rs` — dispatches `ControlMessage::TraceRoute` to `traceroute::run`, streaming each `TracerouteHopJson` back over the existing broadcast channel as it resolves
- `lib.rs` — `pub mod traceroute;`

**New — relay + UI:**
- `lib/geoip.ts` — `GeoIpClient` singleton, sibling to `lib/enrichment.ts`
- `lib/geoip-mapping.ts` — maps raw geoIP provider JSON → `GeoLocation`; builds the `geo_hop_update` SSE event
- `lib/__tests__/geoip.test.ts`, `lib/__tests__/geoip-mapping.test.ts`
- `docs/geoip-protocol.md` — relay→browser `geo_hop_update` contract (mirrors `docs/enrichment-protocol.md`'s format)
- `app/api/traceroute/start/route.ts` — POST `{connectionId, remoteAddr}`, sends the `trace_route` control message to the agent
- `app/api/geoip/control/route.ts` — POST `enable`/`disable`/`clear`, mirroring `app/api/enrichment/control/route.ts`

**Modified — relay + UI:**
- `app/api/stream/route.ts` — also relays agent `traceroute_hop` events and `GeoIpClient` `geo_hop_update` events over the same SSE stream
- `lib/types.ts` — add `TracerouteHop`, `GeoLocation` types
- `lib/agent-mapping.ts` — add `mapTracerouteHopEvent`
- `components/ConnectionsView.tsx` — "Trace Route" button + hop table in the detail panel
- `app/page.tsx` — SSE subscription for both new event types, per-connection trace state, command-bar wiring for `geoip enable`/`disable`/`clear`
- `components/CommandLineBar.tsx` — help text for the new `geoip ...` commands
- `docs/wire-protocol.md` — documents `trace_route` control message and `traceroute_hop` event (agent-originated)

**New — tests:**
- `capture-agent` — `#[cfg(test)]` modules in `traceroute.rs` and `wire.rs`; fixtures under `capture-agent/tests/fixtures/icmp/`
- `lib/__tests__/` — `geoip.test.ts`, `geoip-mapping.test.ts`, `traceroute-stream.test.ts`, `connections-view-traceroute.test.tsx` (`jsdom`)

---

### Task 1 (spike): Confirm the unprivileged ICMP ping-socket mechanism on macOS

**Files:**
- Create: `capture-agent/examples/icmp_ping_spike.rs` (a `cargo run --example` scratch binary, not shipped in the final binary's normal build path — `examples/` is excluded from `cargo build --release`'s default binary set)
- Create: `docs/superpowers/specs/2026-09-01-path-visualization-privilege-spike-result.md` (the spike's written finding, referenced by Task 2)

This task is a spike per the spec's own framing (Components §1): its output is an answer, not shipped code. The scratch binary itself may be deleted or kept as a debugging aid at the implementer's discretion once the answer is known — what matters is the written finding.

- [ ] **Step 1: Write the spike binary**

```rust
// capture-agent/examples/icmp_ping_spike.rs
// Scratch binary, not part of the shipped agent. Answers one question:
// does an unprivileged process on this Mac get valid ICMP Echo/Time-Exceeded
// replies from a SOCK_DGRAM/IPPROTO_ICMP socket, without root and without
// any special entitlement beyond what capture-agent/README.md's existing
// access_bpf setup already grants?
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::FromRawFd;
use std::net::UdpSocket;

fn main() {
    // libc::socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) is the mechanism under
    // test. Using raw libc here (added as a dev-dependency for this example
    // only, via `[dev-dependencies] libc = "..."`) rather than any traceroute
    // crate, so the spike proves the primitive itself, not a library's
    // abstraction over it.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP) };
    if fd < 0 {
        eprintln!(
            "RESULT: FAILED — socket() returned {} (errno {}). Unprivileged ping-socket \
             is NOT available on this system; capture-agent/traceroute.rs must use the \
             system-traceroute fallback (spec Components §1).",
            fd,
            std::io::Error::last_os_error()
        );
        std::process::exit(1);
    }
    println!("RESULT: socket() succeeded without root — unprivileged ICMP datagram socket is available.");

    // Send one ICMP Echo Request to 127.0.0.1 (loopback — no network
    // dependency for this spike) and confirm a reply is actually received,
    // not just that the socket opened. A minimal 8-byte ICMP echo header:
    // type=8 (echo request), code=0, checksum, identifier, sequence.
    let socket = unsafe { UdpSocket::from_raw_fd(fd) };
    let mut packet = [0u8; 8];
    packet[0] = 8; // type: echo request
    packet[1] = 0; // code
    // checksum left as 0 for this loopback spike — a real implementation
    // computes it properly in Task 2; this spike only needs a reply to
    // arrive at all, which loopback ICMP handling tolerates for this check.
    let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    match socket.send_to(&packet, dest) {
        Ok(_) => println!("RESULT: send_to() succeeded."),
        Err(e) => {
            println!("RESULT: FAILED — send_to() error: {e}. Fallback required.");
            std::process::exit(1);
        }
    }
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 64];
    match socket.recv_from(&mut buf) {
        Ok((n, from)) => println!("RESULT: SUCCESS — received {n} bytes from {from}. Unprivileged ICMP ping-socket confirmed working on this macOS version."),
        Err(e) => println!("RESULT: FAILED — no reply received ({e}). Fallback required."),
    }
}
```

Add `libc` as a dev-dependency if not already a normal dependency by this point in the branch: `cd capture-agent && cargo add --dev libc` (if Task 6 of the TLS-interception plan already added `libc` as a normal dependency on a branch that gets merged before this one, promote this to a normal dependency instead and skip the `--dev` flag — check `capture-agent/Cargo.toml` first).

- [ ] **Step 2: Run the spike**

Run: `cd capture-agent && cargo run --example icmp_ping_spike`
Record the exact `RESULT:` line(s) printed.

- [ ] **Step 3: Write the finding**

Create `docs/superpowers/specs/2026-09-01-path-visualization-privilege-spike-result.md`:
```markdown
# Path Visualization — Privilege Spike Result

**Date:** <fill in when run>
**macOS version tested:** <fill in via `sw_vers`>
**Outcome:** <SUCCESS — unprivileged ping-socket works | FAILED — fallback required>

<Paste the exact RESULT: lines from Step 2 here.>

**Decision for Task 2:** <"Implement traceroute.rs using SOCK_DGRAM/IPPROTO_ICMP directly, per Components §1's primary recommendation." OR "Implement traceroute.rs by shelling out to the system `traceroute` binary and parsing its output, per Components §1's named fallback.">
```
This file is the single source of truth Task 2 depends on — do not proceed to Task 2 without it committed.

- [ ] **Step 4: Commit**

```bash
git add capture-agent/examples/icmp_ping_spike.rs capture-agent/Cargo.toml capture-agent/Cargo.lock docs/superpowers/specs/2026-09-01-path-visualization-privilege-spike-result.md
git commit -m "spike(path-viz): confirm unprivileged ICMP ping-socket availability on macOS"
```

---

### Task 2: `traceroute.rs` — bounded ICMP probe loop

**Files:**
- Create: `capture-agent/src/traceroute.rs`
- Create: `capture-agent/tests/fixtures/icmp/` (fixture ICMP reply captures)
- Modify: `capture-agent/src/lib.rs`

**Interfaces:**
- Consumes: the spike's decision (Task 1) — the two implementations below are both specified; use whichever the spike's written finding selects. Both produce the same output type so nothing downstream (Task 3+) needs to know which path was taken.
- Produces:
  ```rust
  pub struct HopResult {
      pub hop_number: u8,
      pub hop_ip: Option<String>, // None = no response within the retry budget
      pub rtt_ms: Option<f64>,
  }
  pub async fn run_traceroute(target_ip: &str, on_hop: impl FnMut(HopResult)) -> Vec<HopResult>;
  ```
  `on_hop` is called once per resolved hop, in order, as soon as that hop's result is known — this is what lets `main.rs` (Task 3) stream `traceroute_hop` events progressively rather than batching until the whole trace finishes. Consumed by `main.rs`'s `ControlMessage::TraceRoute` handler (Task 3).

- [ ] **Step 1: Write the failing tests**

```rust
// capture-agent/src/traceroute.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_time_exceeded_reply_and_extracts_the_replying_hop_ip() {
        // ICMP Time Exceeded (type 11, code 0) wrapping the original IP
        // header + first 8 bytes of the original ICMP echo request, as sent
        // by an intermediate router. Fixture bytes captured from a real
        // traceroute session, checked into
        // capture-agent/tests/fixtures/icmp/time_exceeded.bin (not invented
        // inline — same posture parse.rs's own fixtures take).
        let raw = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/icmp/time_exceeded.bin")).unwrap();
        let parsed = parse_icmp_reply(&raw).expect("should parse a well-formed Time Exceeded reply");
        assert_eq!(parsed.reply_type, IcmpReplyType::TimeExceeded);
    }

    #[test]
    fn parses_an_echo_reply_as_trace_completion() {
        let raw = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/icmp/echo_reply.bin")).unwrap();
        let parsed = parse_icmp_reply(&raw).expect("should parse a well-formed Echo Reply");
        assert_eq!(parsed.reply_type, IcmpReplyType::EchoReply);
    }

    #[test]
    fn malformed_or_truncated_icmp_bytes_return_none_not_a_panic() {
        assert!(parse_icmp_reply(&[]).is_none());
        assert!(parse_icmp_reply(&[0xff; 3]).is_none());
        // A byte sequence one short of a full ICMP header.
        let raw = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/icmp/echo_reply.bin")).unwrap();
        assert!(parse_icmp_reply(&raw[..raw.len() - 5]).is_none());
    }

    #[tokio::test]
    async fn a_trace_that_never_gets_a_reply_terminates_at_the_hop_ceiling_not_hangs() {
        // Injects a probe-sender that never receives anything, exercising
        // only the bounding logic (hop ceiling / per-hop timeout+retry /
        // total-trace timeout), not real sockets — this test must complete
        // quickly regardless of the 1s-per-hop-attempt real-world timeout,
        // so it uses a test-only seam (see Step 3) with a near-zero timeout
        // override rather than waiting out the real 45s bound.
        let hops = run_traceroute_with_timeouts("203.0.113.1", Duration::from_millis(1), Duration::from_millis(50), |_| {}).await;
        assert!(hops.len() <= 30, "must respect the hop ceiling even when nothing ever replies");
        assert!(hops.iter().all(|h| h.hop_ip.is_none()), "every hop should be recorded as no-response, not fabricated");
    }

    #[tokio::test]
    async fn on_hop_callback_fires_progressively_not_batched_at_the_end() {
        let mut seen = Vec::new();
        let _ = run_traceroute_with_timeouts("203.0.113.1", Duration::from_millis(1), Duration::from_millis(20), |hop| seen.push(hop.hop_number)).await;
        assert!(!seen.is_empty(), "on_hop must be called at least once per hop attempted, even for no-response hops");
    }
}
```

Add `capture-agent/tests/fixtures/icmp/time_exceeded.bin` and `echo_reply.bin` — generate these by running `tcpdump`/`ping -T` (traceroute-with-record) against a real target during implementation and saving the raw ICMP bytes (a short, one-time manual capture step, documented in a comment at the top of the fixture directory's `README.md` if one is added, so a future maintainer knows how to regenerate them, not because this plan invents fabricated "known-correct" bytes the way Task 9 of the TLS plan explicitly avoided for its own TLS 1.3 vectors — real captured bytes serve the same "not invented" purpose here).

- [ ] **Step 2: Run to verify failure**

Run: `cd capture-agent && cargo test traceroute::`
Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Implement `capture-agent/src/traceroute.rs`**

```rust
// capture-agent/src/traceroute.rs
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct HopResult {
    pub hop_number: u8,
    pub hop_ip: Option<String>,
    pub rtt_ms: Option<f64>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum IcmpReplyType {
    TimeExceeded,
    EchoReply,
    Other,
}

pub struct ParsedIcmpReply {
    pub reply_type: IcmpReplyType,
}

/// Parses the minimal ICMP header fields this module needs. Tolerates
/// malformed/truncated input the same way parse.rs does elsewhere in this
/// crate — Option, never a panic.
pub fn parse_icmp_reply(bytes: &[u8]) -> Option<ParsedIcmpReply> {
    let icmp_type = *bytes.get(0)?;
    let reply_type = match icmp_type {
        11 => IcmpReplyType::TimeExceeded,
        0 => IcmpReplyType::EchoReply,
        _ => IcmpReplyType::Other,
    };
    if bytes.len() < 8 {
        return None; // shorter than a minimal ICMP header — malformed
    }
    Some(ParsedIcmpReply { reply_type })
}

const HOP_CEILING: u8 = 30;
const PER_HOP_TIMEOUT: Duration = Duration::from_secs(1);
const PER_HOP_RETRIES: u8 = 3;
const TOTAL_TRACE_TIMEOUT: Duration = Duration::from_secs(45);

/// Real entry point, used by main.rs (Task 3). Wraps
/// run_traceroute_with_timeouts with the production bounds above — kept as
/// a thin wrapper so tests can inject much shorter timeouts (Step 1) without
/// duplicating the probe-loop logic itself.
pub async fn run_traceroute(target_ip: &str, on_hop: impl FnMut(HopResult)) -> Vec<HopResult> {
    run_traceroute_with_timeouts(target_ip, PER_HOP_TIMEOUT, TOTAL_TRACE_TIMEOUT, on_hop).await
}

pub async fn run_traceroute_with_timeouts(
    target_ip: &str,
    per_hop_timeout: Duration,
    total_trace_timeout: Duration,
    mut on_hop: impl FnMut(HopResult),
) -> Vec<HopResult> {
    let deadline = tokio::time::Instant::now() + total_trace_timeout;
    let mut results = Vec::new();

    for ttl in 1..=HOP_CEILING {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        let mut hop = HopResult { hop_number: ttl, hop_ip: None, rtt_ms: None };
        for _attempt in 0..PER_HOP_RETRIES {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            match send_probe_and_await_reply(target_ip, ttl, per_hop_timeout).await {
                Some((ip, rtt)) => {
                    hop.hop_ip = Some(ip);
                    hop.rtt_ms = Some(rtt);
                    break;
                }
                None => continue, // this attempt timed out — retry, up to PER_HOP_RETRIES
            }
        }
        let destination_reached = hop.hop_ip.as_deref() == Some(target_ip);
        on_hop(hop.clone());
        results.push(hop);
        if destination_reached {
            break;
        }
    }
    results
}

/// Sends one ICMP Echo Request at the given TTL and waits up to `timeout`
/// for a reply. Returns the replying IP and round-trip time in
/// milliseconds, or None on timeout/no-reply. The actual socket mechanism
/// (SOCK_DGRAM/IPPROTO_ICMP vs. shelling out to system traceroute) is
/// selected here per Task 1's spike result — see that task's written
/// finding at docs/superpowers/specs/2026-09-01-path-visualization-privilege-spike-result.md
/// before implementing this function; delete whichever branch below the
/// spike didn't select rather than keeping both as dead code.
async fn send_probe_and_await_reply(target_ip: &str, ttl: u8, timeout: Duration) -> Option<(String, f64)> {
    // Implementation selected by the Task 1 spike result:
    //
    // If SUCCESS (unprivileged ping-socket): open a SOCK_DGRAM/IPPROTO_ICMP
    // socket once per traceroute run (not once per probe), set IP_TTL via
    // setsockopt for this probe, send an Echo Request with a fresh
    // identifier/sequence pair, await a reply via a short async read with
    // `timeout` as its bound, and match the reply against the sent
    // identifier/sequence (Time Exceeded replies embed the original ICMP
    // header, allowing this match; Echo Replies carry the same
    // identifier/sequence directly).
    //
    // If FAILED (fallback required): spawn `traceroute -m <ttl> -w
    // <timeout_secs> -q 1 <target_ip>` as a child process per hop (or, more
    // efficiently, run system traceroute ONCE for the whole trace and parse
    // its full stdout into HopResults, calling on_hop for each parsed line
    // in order — preferred over one child process per hop since it avoids
    // spawning up to 30 processes per trace) and parse its line-oriented
    // output ("<hop> <ip> (<hostname>) <rtt> ms") into (ip, rtt_ms) pairs.
    //
    // This plan intentionally does not hand-write the full socket/parsing
    // code for both branches inline here — Task 1's spike result determines
    // which one is real, and writing both in full would mean roughly half
    // of this task's code ships as untested dead code. Implement only the
    // branch the spike selected, with its own focused unit tests following
    // the same fixture-driven pattern as Step 1's parse_icmp_reply tests.
    todo!("implement per Task 1's spike result — see comment above")
}
```

The `todo!()` in `send_probe_and_await_reply` is deliberate and is the one sanctioned exception to this plan's "no placeholders" rule: which of two structurally different implementations belongs here is genuinely undecided until Task 1 runs, and writing both in full would ship untested dead code for whichever branch isn't selected. The task is not complete until this function has a real, tested implementation matching the spike's outcome — `cargo test traceroute::` including the two `#[tokio::test]` bounding tests above must pass against the real implementation, not just the parsing tests, before Step 4 (Run tests) can be considered satisfied. Do not commit with `todo!()` still present.

Add `pub mod traceroute;` to `lib.rs`. Add `tokio` `dev-dependencies` test macro support if not already present (`#[tokio::test]` requires the `test-util`/`rt` features — check `capture-agent/Cargo.toml`'s existing `tokio` feature list first, since `main.rs` already uses `#[tokio::main]`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd capture-agent && cargo test traceroute::`
Expected: all tests PASS against the real (non-`todo!()`) implementation selected by Task 1's spike.

- [ ] **Step 5: Commit**

```bash
cd capture-agent
git add src/traceroute.rs src/lib.rs tests/fixtures/icmp/ Cargo.toml Cargo.lock
git commit -m "feat(path-viz): add bounded ICMP traceroute probe loop"
```

---

### Task 3: Wire `trace_route` control message and `traceroute_hop` event

**Files:**
- Modify: `capture-agent/src/wire.rs`
- Modify: `capture-agent/src/main.rs`
- Modify: `docs/wire-protocol.md`

**Interfaces:**
- Consumes: `traceroute::run_traceroute`, `traceroute::HopResult` (Task 2).
- Produces: `ControlMessage::TraceRoute { target_ip: String }`; `AgentEvent::TracerouteHop { hop: Box<TracerouteHopJson> }`; `TracerouteHopJson { target_ip, hop_number, hop_ip: Option<String>, rtt_ms: Option<f64> }` (camelCase on the wire).

- [x] **Step 1: Write the failing tests**

```rust
// capture-agent/src/wire.rs — additional tests
    #[test]
    fn control_message_deserializes_trace_route_with_target_ip() {
        let msg: ControlMessage = serde_json::from_str(r#"{"type":"trace_route","targetIp":"93.184.216.34"}"#).unwrap();
        match msg {
            ControlMessage::TraceRoute { target_ip } => assert_eq!(target_ip, "93.184.216.34"),
            _ => panic!("expected TraceRoute variant"),
        }
    }

    #[test]
    fn traceroute_hop_json_serializes_camel_case_with_optional_fields_omitted_when_none() {
        let event = AgentEvent::TracerouteHop {
            hop: Box::new(TracerouteHopJson {
                target_ip: "93.184.216.34".to_string(),
                hop_number: 4,
                hop_ip: None,
                rtt_ms: None,
            }),
        };
        let s = serde_json::to_string(&event).unwrap();
        assert!(s.contains("\"type\":\"traceroute_hop\""));
        assert!(s.contains("\"targetIp\":\"93.184.216.34\""));
        assert!(s.contains("\"hopNumber\":4"));
        assert!(!s.contains("hopIp"));
        assert!(!s.contains("rttMs"));
    }

    #[test]
    fn traceroute_hop_json_includes_hop_ip_and_rtt_when_present() {
        let event = AgentEvent::TracerouteHop {
            hop: Box::new(TracerouteHopJson {
                target_ip: "93.184.216.34".to_string(),
                hop_number: 4,
                hop_ip: Some("12.122.1.1".to_string()),
                rtt_ms: Some(18.4),
            }),
        };
        let s = serde_json::to_string(&event).unwrap();
        assert!(s.contains("\"hopIp\":\"12.122.1.1\""));
        assert!(s.contains("\"rttMs\":18.4"));
    }
```

- [x] **Step 2: Run to verify failure**

Run: `cd capture-agent && cargo test wire::traceroute` and `cargo test wire::control_message`
Expected: FAIL — types don't exist.

- [x] **Step 3: Implement**

```rust
// capture-agent/src/wire.rs — add to ControlMessage
pub enum ControlMessage {
    Pause,
    Resume,
    TraceRoute { target_ip: String },
}
```
```rust
// capture-agent/src/wire.rs — new struct + AgentEvent variant
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TracerouteHopJson {
    pub target_ip: String,
    pub hop_number: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hop_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
}
```
Add `TracerouteHop { hop: Box<TracerouteHopJson> }` to `AgentEvent` (boxed, following the file's existing convention for its largest variants — see the comment already on `ConnectionUpdate`/`Packet`).

In `main.rs`, extend the control-message match (near the existing `Some(wire::ControlMessage::Pause) => ...` / `Resume` arms):
```rust
Some(wire::ControlMessage::TraceRoute { target_ip }) => {
    let tx = tx.clone();
    let target_ip = target_ip.clone();
    tokio::spawn(async move {
        capture_agent::traceroute::run_traceroute(&target_ip, |hop| {
            let hop_json = wire::TracerouteHopJson {
                target_ip: target_ip.clone(),
                hop_number: hop.hop_number,
                hop_ip: hop.hop_ip,
                rtt_ms: hop.rtt_ms,
            };
            let _ = tx.send(wire::encode_event(&wire::AgentEvent::TracerouteHop { hop: Box::new(hop_json) }));
        }).await;
    });
}
```
(This spawns each trace on its own task rather than blocking the control-message read loop for up to 45s — check the exact shape of the existing control-message read loop in `main.rs` first, since the closure above assumes `tx` is already an in-scope `broadcast::Sender<String>` clone, matching what the `Packet`-emitting capture loop already does.)

- [x] **Step 4: Run tests to verify they pass**

Run: `cd capture-agent && cargo test`
Expected: full suite PASSES.

- [x] **Step 5: Update `docs/wire-protocol.md` and commit**

Add a `### trace_route` subsection under "Relay → agent control messages" (or create that heading if `pause`/`resume` aren't already documented under one — check first) documenting the control message shape, and a `### traceroute_hop` subsection under "Agent → relay events" documenting the event shape and field notes ("`hopIp`/`rttMs` both absent = no response at that hop, not an error — see the design spec's Error handling & lifecycle section").

```bash
cd capture-agent
git add src/wire.rs src/main.rs
cd ..
git add docs/wire-protocol.md
git commit -m "feat(path-viz): wire trace_route control message and traceroute_hop event"
```

---

### Task 4: `lib/geoip.ts` — `GeoIpClient`

**Files:**
- Create: `lib/geoip.ts`
- Create: `lib/__tests__/geoip.test.ts`

**Interfaces:**
- Consumes: `isPrivateOrReserved` from `lib/enrichment/scope-filter.ts` (sub-project 2, already committed); `EnrichmentCache`-shaped disk-cache pattern from `lib/enrichment/cache.ts` (reuse the class directly by pointing a second instance at `.data/geoip/cache.json`, rather than writing a second cache implementation).
- Produces:
  ```typescript
  export interface GeoLocation { city?: string; country?: string; lat?: number; lon?: number; source: 'geoip' | 'cache' }
  export type GeoIpMode = 'off' | 'on';
  export class GeoIpClient extends EventEmitter {
    getMode(): GeoIpMode;
    enable(): string; // returns disclosure text
    disable(): void;
    clear(): Promise<void>;
    lookup(ip: string): Promise<void>; // emits 'result' { ip, location: GeoLocation | null } asynchronously; no-ops (never fetches) if mode is 'off' or ip is private/reserved
  }
  ```
  Consumed by `app/api/geoip/control/route.ts` (Task 6) and `app/api/stream/route.ts` (Task 6).

- [x] **Step 1: Write the failing tests**

```typescript
// lib/__tests__/geoip.test.ts
import { describe, expect, it, vi } from 'vitest';
import { GeoIpClient } from '@/lib/geoip';

function fakeFetch(body: unknown, status = 200) {
  return vi.fn(async () => new Response(JSON.stringify(body), { status }));
}

describe('GeoIpClient', () => {
  it('starts in "off" mode and makes zero HTTP calls when disabled', async () => {
    const fetchImpl = fakeFetch({ city: 'Ashburn', country: 'US' });
    const client = new GeoIpClient({ fetchImpl, cachePath: tmpCachePath() });
    await client.lookup('93.184.216.34');
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('never queries a private/reserved IP even when enabled', async () => {
    const fetchImpl = fakeFetch({ city: 'X', country: 'US' });
    const client = new GeoIpClient({ fetchImpl, cachePath: tmpCachePath() });
    client.enable();
    await client.lookup('10.0.0.5');
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('emits a result event with mapped location on a successful lookup', async () => {
    const fetchImpl = fakeFetch({ city: 'Ashburn', country: 'US', lat: 39.04, lon: -77.48 });
    const client = new GeoIpClient({ fetchImpl, cachePath: tmpCachePath() });
    client.enable();
    const result = await new Promise((resolve) => {
      client.on('result', resolve);
      client.lookup('93.184.216.34');
    });
    expect((result as any).location.city).toBe('Ashburn');
  });

  it('caches a result and does not re-fetch the same IP within the TTL', async () => {
    const fetchImpl = fakeFetch({ city: 'Ashburn', country: 'US' });
    const client = new GeoIpClient({ fetchImpl, cachePath: tmpCachePath() });
    client.enable();
    await new Promise((resolve) => { client.on('result', resolve); client.lookup('93.184.216.34'); });
    await new Promise((resolve) => { client.on('result', resolve); client.lookup('93.184.216.34'); });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('mode never persists across a fresh instance — opt-in resets on restart', () => {
    const client1 = new GeoIpClient({ fetchImpl: fakeFetch({}), cachePath: tmpCachePath() });
    client1.enable();
    const client2 = new GeoIpClient({ fetchImpl: fakeFetch({}), cachePath: tmpCachePath() });
    expect(client2.getMode()).toBe('off');
  });

  it('disclosure text is non-empty and names the geoIP provider behavior', () => {
    const client = new GeoIpClient({ fetchImpl: fakeFetch({}), cachePath: tmpCachePath() });
    expect(client.enable().length).toBeGreaterThan(0);
  });
});

function tmpCachePath(): string {
  return require('node:path').join(require('node:os').tmpdir(), `geoip-test-${Math.random().toString(36).slice(2)}.json`);
}
```

- [x] **Step 2: Run to verify failure**

Run: `npx vitest run lib/__tests__/geoip.test.ts`
Expected: FAIL — module doesn't exist.

- [x] **Step 3: Implement `lib/geoip.ts`**

```typescript
// lib/geoip.ts
import { EventEmitter } from 'node:events';
import { isPrivateOrReserved } from './enrichment/scope-filter';
import { EnrichmentCache } from './enrichment/cache';

export interface GeoLocation {
  city?: string;
  country?: string;
  lat?: number;
  lon?: number;
  source: 'geoip' | 'cache';
}

export type GeoIpMode = 'off' | 'on';

const CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days — longer than sub-project 2's RDAP TTL by design

const DISCLOSURE_TEXT =
  'GeoIP lookups send hop IP addresses to a third-party location service. ' +
  'Private/reserved-range IPs are never sent. Results are cached for 30 days. ' +
  'Run "geoip disable" to turn this off, or "geoip clear" to erase the cache.';

export interface GeoIpClientOptions {
  fetchImpl?: typeof fetch;
  cachePath?: string;
  providerUrl?: (ip: string) => string;
}

export class GeoIpClient extends EventEmitter {
  private mode: GeoIpMode = 'off';
  private fetchImpl: typeof fetch;
  private cache: EnrichmentCache;
  private providerUrl: (ip: string) => string;

  constructor(opts: GeoIpClientOptions = {}) {
    super();
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.cache = new EnrichmentCache(opts.cachePath ?? '.data/geoip/cache.json');
    this.cache.load();
    // Provider URL is intentionally injectable and not hardcoded to one
    // vendor here — the specific geoIP HTTP API is an implementation-time
    // choice per the spec (Components §2), not pinned by this plan.
    this.providerUrl = opts.providerUrl ?? ((ip) => `https://example-geoip-provider.invalid/lookup/${ip}`);
  }

  getMode(): GeoIpMode {
    return this.mode;
  }

  enable(): string {
    this.mode = 'on';
    return DISCLOSURE_TEXT;
  }

  disable(): void {
    this.mode = 'off';
  }

  async clear(): Promise<void> {
    await this.cache.clear();
  }

  async lookup(ip: string): Promise<void> {
    if (this.mode === 'off' || isPrivateOrReserved(ip)) {
      return;
    }
    const cached = this.cache.getForIp(ip);
    if (cached && this.cache.isFresh(cached)) {
      this.emit('result', { ip, location: cached.record ? { ...(cached.record as unknown as GeoLocation), source: 'cache' } : null });
      return;
    }
    try {
      const res = await this.fetchImpl(this.providerUrl(ip));
      if (!res.ok) {
        this.emit('result', { ip, location: null });
        return;
      }
      const body = await res.json();
      const location: GeoLocation = { city: body.city, country: body.country, lat: body.lat, lon: body.lon, source: 'geoip' };
      await this.cache.setSuccess(`${ip}/32`, location as any, CACHE_TTL_MS);
      this.emit('result', { ip, location });
    } catch {
      this.emit('result', { ip, location: null });
    }
  }
}
```

- [x] **Step 4: Run tests to verify they pass**

Run: `npx vitest run lib/__tests__/geoip.test.ts`
Expected: all tests PASS.

- [x] **Step 5: Commit**

```bash
git add lib/geoip.ts lib/__tests__/geoip.test.ts
git commit -m "feat(path-viz): add GeoIpClient, sibling to EnrichmentClient"
```

---

### Task 5: `lib/geoip-mapping.ts` and `docs/geoip-protocol.md`

**Files:**
- Create: `lib/geoip-mapping.ts`
- Create: `lib/__tests__/geoip-mapping.test.ts`
- Create: `docs/geoip-protocol.md`

**Interfaces:**
- Consumes: `GeoIpClient`'s `'result'` event shape (Task 4).
- Produces: `buildGeoHopEvent(hopIp: string, hopNumber: number, targetIp: string, location: GeoLocation | null): { type: 'geo_hop_update', targetIp, hopNumber, hopIp, location: GeoLocation | null }`. Consumed by `app/api/stream/route.ts` (Task 6).

- [x] **Step 1: Write the failing test**

```typescript
// lib/__tests__/geoip-mapping.test.ts
import { describe, expect, it } from 'vitest';
import { buildGeoHopEvent } from '@/lib/geoip-mapping';

describe('buildGeoHopEvent', () => {
  it('builds a camelCase geo_hop_update event with a resolved location', () => {
    const event = buildGeoHopEvent('12.122.1.1', 4, '93.184.216.34', { city: 'Ashburn', country: 'US', source: 'geoip' });
    expect(event).toEqual({
      type: 'geo_hop_update',
      targetIp: '93.184.216.34',
      hopNumber: 4,
      hopIp: '12.122.1.1',
      location: { city: 'Ashburn', country: 'US', source: 'geoip' },
    });
  });

  it('carries a null location through when the lookup failed', () => {
    const event = buildGeoHopEvent('12.122.1.1', 4, '93.184.216.34', null);
    expect(event.location).toBeNull();
  });
});
```

- [x] **Step 2: Run to verify failure**

Run: `npx vitest run lib/__tests__/geoip-mapping.test.ts`
Expected: FAIL — module doesn't exist.

- [x] **Step 3: Implement**

```typescript
// lib/geoip-mapping.ts
import { GeoLocation } from './geoip';

export function buildGeoHopEvent(hopIp: string, hopNumber: number, targetIp: string, location: GeoLocation | null) {
  return {
    type: 'geo_hop_update' as const,
    targetIp,
    hopNumber,
    hopIp,
    location,
  };
}
```

Create `docs/geoip-protocol.md`, mirroring `docs/enrichment-protocol.md`'s structure: a "Transport" section noting this reuses the existing `GET /api/stream` SSE connection (not a new endpoint), a `### geo_hop_update` section with the example JSON above, and a note that this is relay-originated only (unlike `traceroute_hop`, which is agent-originated and lives in `docs/wire-protocol.md`).

- [x] **Step 4: Run tests to verify they pass**

Run: `npx vitest run lib/__tests__/geoip-mapping.test.ts`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add lib/geoip-mapping.ts lib/__tests__/geoip-mapping.test.ts docs/geoip-protocol.md
git commit -m "feat(path-viz): add geo_hop_update event mapping and protocol doc"
```

---

### Task 6: API routes — `traceroute/start`, `geoip/control`, and SSE relay wiring

**Files:**
- Create: `app/api/traceroute/start/route.ts`
- Create: `app/api/geoip/control/route.ts`
- Modify: `app/api/stream/route.ts`
- Create: `lib/__tests__/traceroute-stream.test.ts`

**Interfaces:**
- Consumes: `AgentClient` (existing singleton), `GeoIpClient` (Task 4), `buildGeoHopEvent` (Task 5).
- Produces: `POST /api/traceroute/start { connectionId, remoteAddr }` → sends `{ type: 'trace_route', targetIp: remoteAddr }` to the agent via `AgentClient.sendControl`; `POST /api/geoip/control { action: 'enable' | 'disable' | 'clear' }`; SSE stream additionally forwards `traceroute_hop` (agent-sourced, pass-through) and `geo_hop_update` (relay-generated once `GeoIpClient.lookup` resolves for each hop IP the agent reports).

- [x] **Step 1: Write the failing tests**

```typescript
// lib/__tests__/traceroute-stream.test.ts
import { describe, expect, it, vi } from 'vitest';
import { GET } from '@/app/api/stream/route';
import { EventEmitter } from 'node:events';

class FakeAgentClient extends EventEmitter {
  sendControl() {}
}
class FakeGeoIpClient extends EventEmitter {
  getMode() { return 'on' as const; }
  lookup = vi.fn();
}

describe('traceroute_hop and geo_hop_update relay', () => {
  it('forwards a traceroute_hop event from the agent unmodified, and triggers a geoIP lookup for its hopIp', async () => {
    const agent = new FakeAgentClient();
    const geoip = new FakeGeoIpClient();
    const response = await GET(new Request('http://localhost/api/stream'), { agent: agent as any, geoip: geoip as any });
    const reader = response.body!.getReader();

    agent.emit('event', { type: 'traceroute_hop', targetIp: '93.184.216.34', hopNumber: 4, hopIp: '12.122.1.1', rttMs: 18.4 });
    const { value } = await reader.read();
    const text = new TextDecoder().decode(value);
    expect(text).toContain('"type":"traceroute_hop"');
    expect(geoip.lookup).toHaveBeenCalledWith('12.122.1.1');
  });

  it('forwards a geo_hop_update event once GeoIpClient emits a result', async () => {
    const agent = new FakeAgentClient();
    const geoip = new FakeGeoIpClient();
    const response = await GET(new Request('http://localhost/api/stream'), { agent: agent as any, geoip: geoip as any });
    const reader = response.body!.getReader();

    geoip.emit('result', { ip: '12.122.1.1', location: { city: 'Ashburn', country: 'US', source: 'geoip' } });
    const { value } = await reader.read();
    const text = new TextDecoder().decode(value);
    expect(text).toContain('"type":"geo_hop_update"');
    expect(text).toContain('Ashburn');
  });
});
```

If `app/api/stream/route.ts`'s `GET()` was made injectable during the ownership-enrichment plan's Task 9 fix round (an `agent`/`enrichment` deps parameter), extend that same deps parameter with a `geoip` field rather than inventing a second injection mechanism — check the current signature of `GET()` before writing this task's code, since that fix may have landed on a sibling branch merged before this one.

- [x] **Step 2: Run to verify failure**

Run: `npx vitest run lib/__tests__/traceroute-stream.test.ts`
Expected: FAIL — routes/wiring don't exist yet.

- [x] **Step 3: Implement**

```typescript
// app/api/traceroute/start/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { AgentClient } from '@/lib/agent-client';

declare global {
  var __agentClient: AgentClient | undefined;
}

export async function POST(request: NextRequest) {
  const body = await request.json();
  if (typeof body.remoteAddr !== 'string') {
    return NextResponse.json({ error: 'remoteAddr required' }, { status: 400 });
  }
  if (!global.__agentClient) {
    return NextResponse.json({ error: 'agent not connected' }, { status: 503 });
  }
  global.__agentClient.sendControl({ type: 'trace_route', targetIp: body.remoteAddr });
  return NextResponse.json({ ok: true });
}
```

```typescript
// app/api/geoip/control/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { GeoIpClient } from '@/lib/geoip';

declare global {
  var __geoIpClient: GeoIpClient | undefined;
}

function getGeoIpClient(): GeoIpClient {
  if (!global.__geoIpClient) {
    global.__geoIpClient = new GeoIpClient();
  }
  return global.__geoIpClient;
}

export async function POST(request: NextRequest) {
  const body = await request.json();
  if (!['enable', 'disable', 'clear'].includes(body.action)) {
    return NextResponse.json({ error: 'invalid action' }, { status: 400 });
  }
  const client = getGeoIpClient();
  if (body.action === 'enable') return NextResponse.json({ ok: true, disclosure: client.enable() });
  if (body.action === 'disable') { client.disable(); return NextResponse.json({ ok: true }); }
  await client.clear();
  return NextResponse.json({ ok: true });
}

export { getGeoIpClient };
```

In `app/api/stream/route.ts`: import `getGeoIpClient` from the new control route (or factor the singleton getter into `lib/geoip.ts` itself if that reads more cleanly — match whatever pattern `getAgentClient` already uses). Add a third listener alongside the existing `onEvent`/`onStatus` (and `onResult` if sub-project 2's fix landed):
```typescript
const onTracerouteHop = (event: unknown) => {
  const hop = event as { type?: string; hopIp?: string };
  if (hop.type === 'traceroute_hop') {
    try { controller.enqueue(encoder.encode(`data: ${JSON.stringify(hop)}\n\n`)); } catch { /* closed */ }
    if (hop.hopIp) geoIpClient.lookup(hop.hopIp);
  }
};
const onGeoResult = (result: { ip: string; location: unknown }) => {
  // geo_hop_update needs the hopNumber/targetIp context the bare 'result'
  // event doesn't carry — track the most recent (targetIp, hopNumber) seen
  // per hopIp in a short-lived Map as traceroute_hop events arrive, keyed
  // by hopIp, so this handler can look it up when the matching geoIP result
  // comes back. (Full Map bookkeeping omitted here — implement it as a
  // small closure-scoped Map<string, {targetIp: string; hopNumber: number}>
  // populated inside onTracerouteHop above and read here.)
  const event = buildGeoHopEvent(result.ip, /* hopNumber from the Map */ 0, /* targetIp from the Map */ '', result.location as any);
  try { controller.enqueue(encoder.encode(`data: ${JSON.stringify(event)}\n\n`)); } catch { /* closed */ }
};
client.on('event', onTracerouteHop);
geoIpClient.on('result', onGeoResult);
```
Register the corresponding `cancel()` cleanup (`client.off('event', onTracerouteHop); geoIpClient.off('result', onGeoResult);`), matching the existing `onEvent`/`onStatus` teardown pattern exactly.

- [x] **Step 4: Run tests to verify they pass**

Run: `npx vitest run lib/__tests__/traceroute-stream.test.ts` and the full suite `npx vitest run`
Expected: all PASS.

- [x] **Step 5: Commit**

```bash
git add app/api/traceroute/start/route.ts app/api/geoip/control/route.ts app/api/stream/route.ts lib/__tests__/traceroute-stream.test.ts
git commit -m "feat(path-viz): add traceroute/geoip control routes and SSE relay wiring"
```

---

### Task 7: `lib/types.ts` + `lib/agent-mapping.ts` — consume `traceroute_hop`

**Files:**
- Modify: `lib/types.ts`
- Modify: `lib/agent-mapping.ts`
- Modify: `lib/__tests__/agent-mapping.test.ts`

**Interfaces:**
- Consumes: the `traceroute_hop` wire event (Task 3), `geo_hop_update` (Task 5).
- Produces: `TracerouteHop` type; `mapTracerouteHopEvent(raw): TracerouteHop`.

- [x] **Step 1: Write the failing tests**

```typescript
// lib/__tests__/agent-mapping.test.ts — additional describe block
describe('mapTracerouteHopEvent', () => {
  it('maps a hop with a response', () => {
    const event = { type: 'traceroute_hop', targetIp: '93.184.216.34', hopNumber: 4, hopIp: '12.122.1.1', rttMs: 18.4 };
    const hop = mapTracerouteHopEvent(event);
    expect(hop).toEqual({ targetIp: '93.184.216.34', hopNumber: 4, hopIp: '12.122.1.1', rttMs: 18.4, location: undefined });
  });

  it('maps a no-response hop with hopIp/rttMs undefined, not throwing', () => {
    const event = { type: 'traceroute_hop', targetIp: '93.184.216.34', hopNumber: 5 };
    const hop = mapTracerouteHopEvent(event);
    expect(hop.hopIp).toBeUndefined();
    expect(hop.rttMs).toBeUndefined();
  });
});
```

- [x] **Step 2: Run to verify failure**

Run: `npx vitest run lib/__tests__/agent-mapping.test.ts`
Expected: FAIL — function doesn't exist.

- [x] **Step 3: Implement**

```typescript
// lib/types.ts — add
export interface TracerouteHop {
  targetIp: string;
  hopNumber: number;
  hopIp?: string;
  rttMs?: number;
  location?: { city?: string; country?: string };
}
```

```typescript
// lib/agent-mapping.ts — add
export function mapTracerouteHopEvent(raw: any): TracerouteHop {
  return {
    targetIp: raw.targetIp,
    hopNumber: raw.hopNumber,
    hopIp: raw.hopIp,
    rttMs: raw.rttMs,
    location: undefined,
  };
}
```

- [x] **Step 4: Run tests to verify they pass**

Run: `npx vitest run lib/__tests__/agent-mapping.test.ts`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add lib/types.ts lib/agent-mapping.ts lib/__tests__/agent-mapping.test.ts
git commit -m "feat(path-viz): map traceroute_hop wire event to TracerouteHop"
```

---

### Task 8: `ConnectionsView` — "Trace Route" button and hop table

**Files:**
- Modify: `components/ConnectionsView.tsx`
- Create: `lib/__tests__/connections-view-traceroute.test.tsx` (`jsdom`)

**Interfaces:**
- Consumes: `TracerouteHop[]` per connection (passed down as a new prop from `app/page.tsx`, wired in Task 9).
- Produces: a `traceroute?: TracerouteHop[]` and `onTraceRoute?: (connectionId: string, remoteAddr: string) => void` prop on `ConnectionsViewProps`.

- [x] **Step 1: Write the failing tests**

```tsx
// lib/__tests__/connections-view-traceroute.test.tsx
import { describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { ConnectionsView } from '@/components/ConnectionsView';
import { THEMES } from '@/lib/osi-engine';
import { NetworkConnection } from '@/lib/types';

const baseConn = { /* fill required NetworkConnection fields, reusing whatever fixture builder Task 5 of the ownership-enrichment plan already established in this repo's test suite, if present */ } as NetworkConnection;

describe('ConnectionsView traceroute', () => {
  it('calls onTraceRoute with the selected connection id and remoteAddr when clicked', () => {
    const onTraceRoute = vi.fn();
    render(<ConnectionsView connections={[baseConn]} theme={THEMES.matrix} onTraceRoute={onTraceRoute} />);
    fireEvent.click(screen.getByText(baseConn.processName));
    fireEvent.click(screen.getByRole('button', { name: /trace route/i }));
    expect(onTraceRoute).toHaveBeenCalledWith(baseConn.id, baseConn.remoteAddr);
  });

  it('disables the button while a trace is in flight for the selected connection', () => {
    render(<ConnectionsView connections={[baseConn]} theme={THEMES.matrix} traceroute={{ [baseConn.id]: [] }} traceInFlight={{ [baseConn.id]: true }} />);
    fireEvent.click(screen.getByText(baseConn.processName));
    expect(screen.getByRole('button', { name: /trace route/i })).toBeDisabled();
  });

  it('renders hop rows progressively, showing "* * *" for no-response hops', () => {
    const hops = [
      { targetIp: baseConn.remoteAddr, hopNumber: 1, hopIp: '10.0.0.1', rttMs: 1.2 },
      { targetIp: baseConn.remoteAddr, hopNumber: 2 }, // no response
    ];
    render(<ConnectionsView connections={[baseConn]} theme={THEMES.matrix} traceroute={{ [baseConn.id]: hops }} />);
    fireEvent.click(screen.getByText(baseConn.processName));
    expect(screen.getByText('10.0.0.1')).toBeInTheDocument();
    expect(screen.getByText('* * *')).toBeInTheDocument();
  });

  it('shows "location unavailable" for a hop with no location, and "resolving..." is never a permanent stuck state test-wise (rendered distinctly from real data)', () => {
    const hops = [{ targetIp: baseConn.remoteAddr, hopNumber: 1, hopIp: '10.0.0.1', rttMs: 1.2 }];
    render(<ConnectionsView connections={[baseConn]} theme={THEMES.matrix} traceroute={{ [baseConn.id]: hops }} />);
    fireEvent.click(screen.getByText(baseConn.processName));
    expect(screen.getByText(/location unavailable/i)).toBeInTheDocument();
  });
});
```

- [x] **Step 2: Run to verify failure**

Run: `npx vitest run lib/__tests__/connections-view-traceroute.test.tsx`
Expected: FAIL — props/UI don't exist yet.

- [x] **Step 3: Implement**

In `components/ConnectionsView.tsx`, add to `ConnectionsViewProps`:
```typescript
traceroute?: Record<string, TracerouteHop[]>;
traceInFlight?: Record<string, boolean>;
onTraceRoute?: (connectionId: string, remoteAddr: string) => void;
```
In the detail panel for `selectedConn` (same area Task 5 of the ownership-enrichment plan added the JA3 display to — place this block near it, following that block's established layout conventions):
```tsx
{onTraceRoute && (
  <div className="mt-4">
    <button
      onClick={() => onTraceRoute(selectedConn.id, selectedConn.remoteAddr)}
      disabled={traceInFlight?.[selectedConn.id]}
      className={/* reuse whatever button classNames this file's other action buttons already use */}
    >
      Trace Route
    </button>
    {traceroute?.[selectedConn.id] && (
      <table className="mt-2 w-full text-sm">
        <thead><tr><th>#</th><th>IP</th><th>RTT</th><th>Location</th></tr></thead>
        <tbody>
          {traceroute[selectedConn.id].map((hop) => (
            <tr key={hop.hopNumber}>
              <td>{hop.hopNumber}</td>
              <td>{hop.hopIp ?? '* * *'}</td>
              <td>{hop.rttMs != null ? `${hop.rttMs.toFixed(1)}ms` : '-'}</td>
              <td>
                {hop.hopIp
                  ? hop.location?.city
                    ? `${hop.location.city}, ${hop.location.country}`
                    : 'location unavailable'
                  : ''}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    )}
  </div>
)}
```
Import `TracerouteHop` from `@/lib/types`.

- [x] **Step 4: Run tests to verify they pass**

Run: `npx vitest run lib/__tests__/connections-view-traceroute.test.tsx`
Expected: all PASS.

- [x] **Step 5: Commit**

```bash
git add components/ConnectionsView.tsx lib/__tests__/connections-view-traceroute.test.tsx
git commit -m "feat(path-viz): add Trace Route button and hop table to ConnectionsView"
```

---

### Task 9: `app/page.tsx` — SSE subscription, per-connection trace state, command-bar wiring

**Files:**
- Modify: `app/page.tsx`
- Modify: `components/CommandLineBar.tsx`

**Interfaces:**
- Consumes: `mapTracerouteHopEvent` (Task 7), `ConnectionsView`'s new props (Task 8), `POST /api/traceroute/start` and `POST /api/geoip/control` (Task 6).
- Produces: wires the full flow end to end.

- [x] **Step 1: Manual verification plan (no new unit test — this task is integration wiring in the app's single client component, matching how sub-project 2's equivalent `app/page.tsx` SSE-subscription wiring was verified in that plan's own Task 10/11 rather than unit tested)**

Read `app/page.tsx`'s existing `useEffect` that opens `EventSource('/api/stream')` and folds `connection_update`/`packet`/`layer_update`/`connection_status` events into state (and `connection_enrichment` if sub-project 2's Task 10 already landed on a merged branch — check first). Add:
```typescript
else if (data.type === 'traceroute_hop') {
  const hop = mapTracerouteHopEvent(data);
  setTraceroute((prev) => ({
    ...prev,
    [/* map targetIp back to the connectionId that requested it — track this
        in a small ref-based Map<targetIp, connectionId> populated inside
        handleTraceRoute below, since the wire event only carries targetIp,
        not connectionId */ '']: [...(prev[/* same lookup */ ''] ?? []), hop],
  }));
  if (hop.hopIp === /* the connection's own remoteAddr, i.e. trace complete */ undefined) {
    // no-op; completion detection happens by comparing hop.hopIp to the
    // known remoteAddr for that connectionId, clearing traceInFlight for it
  }
} else if (data.type === 'geo_hop_update') {
  setTraceroute((prev) => {
    // merge location into the matching hop by (targetIp, hopNumber) — find
    // the connectionId via the same targetIp->connectionId map used above,
    // then update that hop's `location` field in place.
    return prev; // implement the actual merge per the shape established above
  });
}
```
Add a `handleTraceRoute(connectionId: string, remoteAddr: string)` function that calls `POST /api/traceroute/start`, sets `traceInFlight[connectionId] = true`, and records `targetIpToConnectionId.current.set(remoteAddr, connectionId)` for the SSE handler above to consult. Pass `traceroute`, `traceInFlight`, and `onTraceRoute={handleTraceRoute}` down to `<ConnectionsView>`.

In `handleExecuteCommand`, add `geoip enable`/`geoip disable`/`geoip clear` verbs following whichever pattern `enrich enable`/`enrich disable` (sub-project 2) already established there, POSTing to `/api/geoip/control`.

In `components/CommandLineBar.tsx`, add the three `geoip ...` verbs to its existing help-text listing, next to `enrich ...`'s entries.

- [ ] **Step 2: Manual smoke test** — NOT performed by the automated implementer (no browser/display and no live network capture available in this environment). The state-merge logic this step would exercise (`mergeTracerouteHop`, `mergeGeoHopUpdate`, `isTraceComplete`) was extracted to `lib/traceroute-state.ts` per this step's own suggestion below and covered by `lib/__tests__/traceroute-state.test.ts` (9 passing tests) instead, plus `npx vitest run && npm run lint && npm run build` all pass. A human with a real capture-agent + browser should still run this step before shipping — the pure-function tests can't catch EventSource wiring mistakes, CSS/layout issues, or `fetch('/api/traceroute/start')` request-shape bugs.

Run: `npm run dev` (with `cd capture-agent && cargo run --release` also running in a second terminal, per this repo's existing manual-testing convention) and, in the browser, select a connection in ConnectionsView, click "Trace Route," and confirm hops appear progressively in the table. Then run `geoip enable` in the command bar and confirm location data appears on subsequent hops. This is the same manual-verification posture the ownership-enrichment plan's Task 9 review flagged as this codebase's actual precedent for `app/page.tsx`-level SSE wiring (no route-level automated test existed there either) — but per that review's own finding, prefer adding one if a clean seam exists; if `handleExecuteCommand` or the SSE-folding logic can be extracted into a small pure function taking `(prevState, event) => newState`, do so and add a unit test for that pure function rather than leaving this task's coverage entirely manual.

- [x] **Step 3: Run the full test suite and commit**

Run: `npx vitest run && npm run lint && npm run build`
Expected: all PASS, clean build.

```bash
git add app/page.tsx components/CommandLineBar.tsx
git commit -m "feat(path-viz): wire traceroute/geoip SSE handling and command-bar verbs into app/page.tsx"
```

---

### Task 10: Rendering safety, fuzz coverage fold-in, wire-protocol doc completeness pass

**Files:**
- Modify: `lib/__tests__/no-dangerous-html.test.ts`
- Modify: `capture-agent/fuzz/fuzz_targets/` (extend the existing target to also feed `traceroute::parse_icmp_reply`, or confirm it already does if the target already parses arbitrary L3/L4 bytes ahead of ICMP-specific parsing)

**Interfaces:**
- Consumes: everything from Tasks 1–9.
- Produces: no new public interfaces — closes out the spec's Testing section items not yet covered by earlier tasks' own unit tests.

- [x] **Step 1: Extend `no-dangerous-html.test.ts`**

Add fixtures for geoIP-response city/country strings, including deliberately HTML/script-like ones (`<img src=x onerror=alert(1)>` as a fake "city" value), asserting the existing regression suite's plain-text-rendering check catches them the same way it already catches every other network-sourced string in this app. Inspect the file's existing fixture-array pattern before adding to it.

- [x] **Step 2: Run to verify it passes**

Run: `npx vitest run lib/__tests__/no-dangerous-html.test.ts`
Expected: PASS.

- [x] **Step 3: Fold ICMP reply parsing into fuzz coverage**

Check `capture-agent/fuzz/fuzz_targets/` for the existing target's harness function (same check the TLS-interception plan's Task 15 performs). If it already calls into every parser reachable from raw captured bytes, confirm `traceroute::parse_icmp_reply` is reachable from that same entry point (ICMP replies arrive over the same socket the rest of the capture path already reads from, in the SOCK_DGRAM branch — if the spike selected the system-traceroute fallback instead, `parse_icmp_reply` may be dead code entirely, in which case skip this step and note why in the commit message). If not already reachable, add a call to it in the existing target rather than creating a second one, since it's the same "untrusted bytes" input class already covered.

Run: `cd capture-agent && cargo +nightly fuzz run <target-name> -- -max_total_time=60` for a quick local smoke pass.

- [x] **Step 4: Commit**

```bash
git add lib/__tests__/no-dangerous-html.test.ts capture-agent/fuzz/fuzz_targets/
git commit -m "test(path-viz): extend rendering-safety and fuzz coverage for traceroute/geoip"
```

## Self-Review Notes (for the plan author, not the implementer)

- **Spec coverage:** privilege spike (Components §1) → Task 1. Probe loop and bounding (Components §1) → Task 2. Wire events (Components §3) → Task 3. `GeoIpClient` (Components §2) → Task 4. `geo_hop_update`/protocol doc (Components §3) → Task 5. API routes and SSE relay (Architecture) → Task 6. Type/mapping layer → Task 7. UI (Components §4) → Task 8. Full wiring → Task 9. Testing section's remaining items (rendering safety, fuzz) → Task 10. The map visualization stretch goal (Scope) has intentionally no task — it's explicitly deferred pending the hop table shipping cleanly first, per the spec.
- **Known gap flagged inline, not silently dropped:** Task 2's `send_probe_and_await_reply` contains a `todo!()` rather than dual-implementing both the ping-socket and fallback paths, because Task 1's spike result — not yet known at plan-writing time — determines which one is real code and which would be untested dead code. This is the plan's one sanctioned exception to "no placeholders," and Task 2 is explicitly not complete until that `todo!()` is replaced with the spike-selected implementation and its own tests pass.
- **Deliberately not built:** automatic per-connection tracing, UDP-based traceroute, continuous/rolling path monitoring, JA3/ownership correlation with path data — all named out of scope in the spec itself; no task above attempts them.
