# Live Capture Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the simulated traffic engine with a real capture pipeline — a Rust agent that captures and parses this Mac's own traffic, and a Next.js relay/UI that displays it — working end-to-end on `localhost`, unencrypted, for local development.

**Architecture:** A standalone Rust binary (`capture-agent/`) opens the primary network interface via libpcap, parses packets itself (never trusting a black-box dissector), aggregates them into a flow table, and serves the results as newline-delimited JSON over a loopback TCP socket that it listens on. The Next.js app connects to that socket as a client, relays events to the browser over Server-Sent Events, and the existing presentational components render real data instead of `setInterval`-generated fake data.

**Tech Stack:** Rust (`pcap` 2.5, `etherparse` 0.20, `tokio` 1, `serde`/`serde_json` 1) for the agent; Next.js 15 Route Handlers (SSE) and Vitest for the relay/mapping layer.

**Spec:** `docs/superpowers/specs/2026-08-26-live-capture-ingestion-design.md`

## Global Constraints

- This plan covers the **unsecured local pipeline only** — real capture, real data, working on `localhost`. mTLS, the Caddy reverse proxy, and the native macOS app are a separate follow-on plan (`docs/superpowers/plans/2026-08-26-secure-lan-access.md`, not yet written) built on top of this one, per the spec's sub-project sequencing.
- The capture agent must never `sudo`/run as root at runtime. It relies on macOS `access_bpf` group membership, granted once outside this plan (`sudo dseditgroup -o edit -a $(whoami) -t user access_bpf`, documented in `capture-agent/README.md`, not automated by code).
- The agent must never panic on malformed or malicious packet bytes — every parse function returns `Result`/`Option` and the capture loop logs and skips on error, per the spec's hardening requirement.
- Wire protocol field names are `camelCase` on the wire (via `#[serde(rename_all = "camelCase")]` on the Rust side) so they match `lib/types.ts` field names exactly with no translation layer.
- `NetworkConnection`, `PacketFrame`, and `OSILayerInfo` (from `lib/types.ts`) are reused as-is — this plan does not change their shape, only how they're populated.
- Exact crate/library API calls (especially `pcap` and `etherparse`) should be checked against `cargo doc --open` for the installed version if a step's code doesn't compile as written — versions may have shifted since this plan was written; the TDD steps (`cargo build`/`cargo test`) are how that gets caught.

---

## File Structure

**New — Rust capture agent (`capture-agent/`, a new Cargo project at the repo root):**
- `capture-agent/Cargo.toml` — dependencies
- `capture-agent/README.md` — one-time `access_bpf` setup instructions
- `capture-agent/src/main.rs` — entrypoint: interface detection, capture thread, TCP server, wiring
- `capture-agent/src/parse.rs` — Ethernet/IP/TCP/UDP parsing (`parse_packet`)
- `capture-agent/src/l7.rs` — plaintext L7 sniffing: HTTP request line, DNS query name, TLS ClientHello SNI
- `capture-agent/src/flow.rs` — flow table: byte counters, TCP-state-derived `status`, RTT, retransmission-based loss
- `capture-agent/src/process_lookup.rs` — `lsof`-based local-port → process name/PID map
- `capture-agent/src/wire.rs` — `AgentEvent`/`ControlMessage` serde types, newline-delimited JSON framing, TCP server
- `capture-agent/fuzz/fuzz_targets/parse_packet.rs` — `cargo-fuzz` target for `parse::parse_packet`

**Modified/new — Next.js app:**
- Modify: `lib/types.ts` — remove `TrafficScenario`
- Modify: `lib/osi-engine.ts` — remove `generateRandomPacket`, `INITIAL_CONNECTIONS`; replace `INITIAL_OSI_LAYERS` with a trimmed `STATIC_LAYER_INFO` (descriptive fields only — name, shortName, pdu, protocols, color, badgeBg, badgeText); keep `THEMES`, `formatSpeed`, `formatBytes`
- Create: `lib/agent-mapping.ts` — pure functions mapping agent wire JSON to `NetworkConnection`/`PacketFrame`/`OSILayerInfo`
- Create: `lib/agent-client.ts` — TCP client managing the persistent connection to the agent, with reconnect/backoff, exposed as an async event emitter
- Create: `app/api/stream/route.ts` — SSE endpoint forwarding agent events to the browser
- Create: `app/api/control/route.ts` — POST endpoint forwarding pause/resume to the agent
- Modify: `app/page.tsx` — replace the `setInterval` simulation loop with `EventSource` consumption; remove `ScenarioLabView`/`scenario` state/`lab`+`scenario` commands; repurpose `pause`/`resume`/`reset`
- Delete: `components/ScenarioLabView.tsx`
- Create: `vitest.config.ts`, `lib/__tests__/agent-mapping.test.ts`

---

### Task 1: Rust agent scaffold + interface detection + bare TCP server

**Files:**
- Create: `capture-agent/Cargo.toml`
- Create: `capture-agent/README.md`
- Create: `capture-agent/src/main.rs`

**Interfaces:**
- Produces: a binary that, on `cargo run`, prints the auto-detected capture interface name and listens on `127.0.0.1:9990`, accepting and immediately closing connections (proves the process starts and binds before any capture logic is added).

- [ ] **Step 1: Create the Cargo project**

```bash
cd /Users/jamesbrown/code/osi-traffic-terminal-monitor
cargo new capture-agent --bin
```

- [ ] **Step 2: Write `Cargo.toml` dependencies**

```toml
[package]
name = "capture-agent"
version = "0.1.0"
edition = "2021"

[dependencies]
pcap = "2.5"
etherparse = "0.20"
tokio = { version = "1", features = ["rt-multi-thread", "net", "io-util", "sync", "macros"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"

[dev-dependencies]
etherparse = { version = "0.20", features = ["std"] }
```

- [ ] **Step 3: Write `capture-agent/README.md` with the one-time setup instructions**

```markdown
# capture-agent

Real packet capture agent for the OSI Traffic Terminal Monitor. Runs as
your normal user — no `sudo` needed at runtime — once you've done the
one-time setup below.

## One-time setup

Add your user to macOS's `access_bpf` group so this binary can open
`/dev/bpf*` without elevated privileges:

    sudo dseditgroup -o edit -a $(whoami) -t user access_bpf

Log out and back in (or reboot) for the group membership to take effect.

## Running

    cargo run --release

Listens on `127.0.0.1:9990` for the Next.js relay to connect to.
```

- [ ] **Step 4: Write the interface-detection + bare TCP server in `main.rs`**

```rust
use tokio::net::TcpListener;

fn detect_interface() -> String {
    match pcap::Device::lookup() {
        Ok(Some(device)) => device.name,
        Ok(None) => panic!("no capture-capable network interface found"),
        Err(e) => panic!("failed to look up default capture device: {e}"),
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let interface = detect_interface();
    println!("capture-agent: using interface {interface}");

    let listener = TcpListener::bind("127.0.0.1:9990").await?;
    println!("capture-agent: listening on 127.0.0.1:9990");

    loop {
        let (socket, _addr) = listener.accept().await?;
        drop(socket);
    }
}
```

- [ ] **Step 5: Verify it builds and runs**

Run: `cd capture-agent && cargo build`
Expected: builds with no errors (network/library API names may need adjusting against the installed crate versions — see Global Constraints).

Run: `cargo run &` then `nc -z 127.0.0.1 9990; echo $?`
Expected: prints the detected interface name, and `nc` connects successfully (exit code `0`). Stop the background process afterward (`kill %1`).

- [ ] **Step 6: Commit**

```bash
git add capture-agent/Cargo.toml capture-agent/Cargo.lock capture-agent/README.md capture-agent/src/main.rs capture-agent/.gitignore
git commit -m "feat(agent): scaffold capture-agent with interface detection and bare TCP listener"
```

---

### Task 2: Ethernet/IP/TCP/UDP packet parsing

**Files:**
- Create: `capture-agent/src/parse.rs`
- Modify: `capture-agent/src/main.rs:1` (add `mod parse;`)

**Interfaces:**
- Produces:
  ```rust
  pub struct ParsedPacket {
      pub src_mac: String,
      pub dst_mac: String,
      pub src_ip: String,
      pub dst_ip: String,
      pub protocol: TransportProtocol, // Tcp | Udp | Icmp | Other
      pub src_port: Option<u16>,
      pub dst_port: Option<u16>,
      pub tcp_flags: Option<TcpFlags>, // syn, ack, fin, rst
      pub seq: Option<u32>,
      pub ttl: u8,
      pub total_len: u16,
      pub payload: Vec<u8>,
  }
  pub fn parse_packet(data: &[u8]) -> Option<ParsedPacket>
  ```
  Later tasks (`flow.rs`, `l7.rs`, `main.rs`) consume `ParsedPacket` and never touch raw bytes or `etherparse` types directly.

- [ ] **Step 1: Write the failing test**

```rust
// capture-agent/src/parse.rs (bottom of file, #[cfg(test)] mod tests)
#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;

    #[test]
    fn parses_a_tcp_syn_packet() {
        let builder = PacketBuilder::ethernet2([0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11])
            .ipv4([192, 168, 1, 10], [93, 184, 216, 34], 64)
            .tcp(51000, 443, 1000, 65535)
            .syn();
        let payload: &[u8] = &[];
        let mut data = Vec::new();
        builder.write(&mut data, payload).unwrap();

        let parsed = parse_packet(&data).expect("should parse a valid TCP/IP packet");

        assert_eq!(parsed.src_ip, "192.168.1.10");
        assert_eq!(parsed.dst_ip, "93.184.216.34");
        assert_eq!(parsed.protocol, TransportProtocol::Tcp);
        assert_eq!(parsed.src_port, Some(51000));
        assert_eq!(parsed.dst_port, Some(443));
        assert_eq!(parsed.tcp_flags.unwrap().syn, true);
        assert_eq!(parsed.ttl, 64);
    }

    #[test]
    fn returns_none_for_garbage_bytes() {
        let garbage = [0u8, 1, 2, 3, 4];
        assert!(parse_packet(&garbage).is_none());
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test parses_a_tcp_syn_packet`
Expected: FAIL — `parse_packet` and `ParsedPacket`/`TransportProtocol` don't exist yet.

- [ ] **Step 3: Implement `parse.rs`**

```rust
use etherparse::{SlicedPacket, IpSlice, TransportSlice};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Icmp,
    Other,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
}

#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub src_mac: String,
    pub dst_mac: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: TransportProtocol,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: Option<TcpFlags>,
    pub seq: Option<u32>,
    pub ttl: u8,
    pub total_len: u16,
    pub payload: Vec<u8>,
}

fn mac_to_string(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Never panics on malformed input — returns None instead. This function
/// is exercised by the cargo-fuzz target in `fuzz/fuzz_targets/parse_packet.rs`
/// specifically because it runs on untrusted, attacker-reachable bytes.
pub fn parse_packet(data: &[u8]) -> Option<ParsedPacket> {
    let sliced = SlicedPacket::from_ethernet(data).ok()?;

    let (src_mac, dst_mac) = match &sliced.link {
        Some(etherparse::LinkSlice::Ethernet2(eth)) => {
            (mac_to_string(eth.source()), mac_to_string(eth.destination()))
        }
        _ => return None,
    };

    let (src_ip, dst_ip, ttl) = match &sliced.net {
        Some(IpSlice::Ipv4(ipv4)) => (
            ipv4.header().source_addr().to_string(),
            ipv4.header().destination_addr().to_string(),
            ipv4.header().ttl(),
        ),
        Some(IpSlice::Ipv6(ipv6)) => (
            ipv6.header().source_addr().to_string(),
            ipv6.header().destination_addr().to_string(),
            ipv6.header().hop_limit(),
        ),
        None => return None,
    };

    let (protocol, src_port, dst_port, tcp_flags, seq) = match &sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => (
            TransportProtocol::Tcp,
            Some(tcp.source_port()),
            Some(tcp.destination_port()),
            Some(TcpFlags {
                syn: tcp.syn(),
                ack: tcp.ack(),
                fin: tcp.fin(),
                rst: tcp.rst(),
            }),
            Some(tcp.sequence_number()),
        ),
        Some(TransportSlice::Udp(udp)) => (
            TransportProtocol::Udp,
            Some(udp.source_port()),
            Some(udp.destination_port()),
            None,
            None,
        ),
        Some(TransportSlice::Icmpv4(_)) | Some(TransportSlice::Icmpv6(_)) => {
            (TransportProtocol::Icmp, None, None, None, None)
        }
        None => (TransportProtocol::Other, None, None, None, None),
    };

    let payload = sliced.payload.to_vec();

    Some(ParsedPacket {
        src_mac,
        dst_mac,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        tcp_flags,
        seq,
        ttl,
        total_len: data.len() as u16,
        payload,
    })
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test parse::`
Expected: both `parses_a_tcp_syn_packet` and `returns_none_for_garbage_bytes` PASS. If `SlicedPacket`/`IpSlice`/`TransportSlice` field/method names don't match the installed `etherparse` 0.20 API exactly, run `cargo doc -p etherparse --open` and adjust — the shape (link/net/transport slices) has been stable across etherparse's 0.x line, but exact accessor names can shift between minor versions.

- [ ] **Step 5: Add `mod parse;` to `main.rs` and commit**

```bash
# add `mod parse;` near the top of capture-agent/src/main.rs
git add capture-agent/src/parse.rs capture-agent/src/main.rs
git commit -m "feat(agent): parse Ethernet/IP/TCP/UDP headers with etherparse"
```

---

### Task 3: Plaintext L7 sniffing (HTTP, DNS, TLS SNI)

**Files:**
- Create: `capture-agent/src/l7.rs`
- Modify: `capture-agent/src/main.rs` (add `mod l7;`)

**Interfaces:**
- Consumes: `ParsedPacket.payload: Vec<u8>`, `ParsedPacket.dst_port: Option<u16>` from Task 2
- Produces:
  ```rust
  pub enum L7Info {
      Http { method: String, path: String },
      Dns { query_name: String },
      TlsClientHello { sni: String },
      None,
  }
  pub fn sniff_l7(payload: &[u8], dst_port: Option<u16>) -> L7Info
  ```
  Consumed by `flow.rs` (Task 4, for `appLayerProtocol`/`encryption`) and by `main.rs` when building `PacketFrame.headerBreakdown.layer7`/`layer6`.

- [ ] **Step 1: Write the failing tests**

```rust
// capture-agent/src/l7.rs, #[cfg(test)] mod tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_http_get_request() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        match sniff_l7(payload, Some(80)) {
            L7Info::Http { method, path } => {
                assert_eq!(method, "GET");
                assert_eq!(path, "/index.html");
            }
            other => panic!("expected Http, got {other:?}"),
        }
    }

    #[test]
    fn detects_dns_query() {
        // Minimal DNS query for "a.com": header (12 bytes) + QNAME "a" "com" + QTYPE/QCLASS
        let mut payload = vec![
            0x12, 0x34, // transaction id
            0x01, 0x00, // flags: standard query
            0x00, 0x01, // qdcount = 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // an/ns/ar counts = 0
        ];
        payload.push(1);
        payload.extend_from_slice(b"a");
        payload.push(3);
        payload.extend_from_slice(b"com");
        payload.push(0); // root label
        payload.extend_from_slice(&[0x00, 0x01]); // QTYPE A
        payload.extend_from_slice(&[0x00, 0x01]); // QCLASS IN

        match sniff_l7(&payload, Some(53)) {
            L7Info::Dns { query_name } => assert_eq!(query_name, "a.com"),
            other => panic!("expected Dns, got {other:?}"),
        }
    }

    #[test]
    fn returns_none_for_unrecognized_payload_on_unrelated_port() {
        let payload = b"not a known protocol";
        assert!(matches!(sniff_l7(payload, Some(9999)), L7Info::None));
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test l7::`
Expected: FAIL — `l7` module doesn't exist yet.

- [ ] **Step 3: Implement `l7.rs`**

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L7Info {
    Http { method: String, path: String },
    Dns { query_name: String },
    TlsClientHello { sni: String },
    None,
}

fn sniff_http(payload: &[u8]) -> Option<L7Info> {
    let text = std::str::from_utf8(payload).ok()?;
    let first_line = text.lines().next()?;
    let mut parts = first_line.split_whitespace();
    let method = parts.next()?;
    let path = parts.next()?;
    let known_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"];
    if known_methods.contains(&method) && path.starts_with('/') {
        Some(L7Info::Http {
            method: method.to_string(),
            path: path.to_string(),
        })
    } else {
        None
    }
}

fn sniff_dns(payload: &[u8]) -> Option<L7Info> {
    if payload.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut idx = 12;
    let mut labels = Vec::new();
    loop {
        let len = *payload.get(idx)? as usize;
        if len == 0 {
            break;
        }
        idx += 1;
        let label = payload.get(idx..idx + len)?;
        labels.push(std::str::from_utf8(label).ok()?.to_string());
        idx += len;
        if idx > payload.len() {
            return None;
        }
    }
    if labels.is_empty() {
        return None;
    }
    Some(L7Info::Dns {
        query_name: labels.join("."),
    })
}

fn sniff_tls_client_hello(payload: &[u8]) -> Option<L7Info> {
    // TLS record header (5 bytes): type=0x16 (handshake), version, length
    if payload.len() < 6 || payload[0] != 0x16 {
        return None;
    }
    // Handshake header: type=0x01 (ClientHello) at offset 5
    if payload[5] != 0x01 {
        return None;
    }
    // Walk forward past session id, cipher suites, compression methods to find
    // the extensions block, then find the SNI extension (type 0x0000).
    let mut idx = 43usize; // fixed portion: record(5) + handshake(4) + version(2) + random(32)
    let session_id_len = *payload.get(idx)? as usize;
    idx += 1 + session_id_len;
    let cipher_suites_len = u16::from_be_bytes([*payload.get(idx)?, *payload.get(idx + 1)?]) as usize;
    idx += 2 + cipher_suites_len;
    let compression_len = *payload.get(idx)? as usize;
    idx += 1 + compression_len;
    if idx + 2 > payload.len() {
        return None;
    }
    idx += 2; // extensions total length
    while idx + 4 <= payload.len() {
        let ext_type = u16::from_be_bytes([payload[idx], payload[idx + 1]]);
        let ext_len = u16::from_be_bytes([payload[idx + 2], payload[idx + 3]]) as usize;
        let ext_start = idx + 4;
        if ext_type == 0x0000 {
            // server_name extension: skip list length(2) + type(1) to reach name length(2)
            let name_len_idx = ext_start + 3;
            let name_len = u16::from_be_bytes([
                *payload.get(name_len_idx)?,
                *payload.get(name_len_idx + 1)?,
            ]) as usize;
            let name_start = name_len_idx + 2;
            let name_bytes = payload.get(name_start..name_start + name_len)?;
            let sni = std::str::from_utf8(name_bytes).ok()?.to_string();
            return Some(L7Info::TlsClientHello { sni });
        }
        idx = ext_start + ext_len;
    }
    None
}

pub fn sniff_l7(payload: &[u8], dst_port: Option<u16>) -> L7Info {
    let info = match dst_port {
        Some(53) => sniff_dns(payload),
        Some(443) => sniff_tls_client_hello(payload),
        _ => sniff_http(payload).or_else(|| sniff_dns(payload)).or_else(|| sniff_tls_client_hello(payload)),
    };
    info.unwrap_or(L7Info::None)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test l7::`
Expected: all three tests PASS.

- [ ] **Step 5: Add `mod l7;` to `main.rs` and commit**

```bash
git add capture-agent/src/l7.rs capture-agent/src/main.rs
git commit -m "feat(agent): sniff plaintext HTTP/DNS and TLS SNI from packet payloads"
```

---

### Task 4: Flow table — byte counters, speed, and TCP-state-derived status

**Files:**
- Create: `capture-agent/src/flow.rs`
- Modify: `capture-agent/src/main.rs` (add `mod flow;`)

**Interfaces:**
- Consumes: `ParsedPacket` (Task 2), `L7Info` (Task 3)
- Produces:
  ```rust
  #[derive(Debug, Clone, Hash, Eq, PartialEq)]
  pub struct FlowKey {
      pub protocol: parse::TransportProtocol,
      pub local_addr: String,
      pub local_port: u16,
      pub remote_addr: String,
      pub remote_port: u16,
  }
  pub struct FlowTable {
      pub fn new(local_addrs: Vec<String>) -> Self
      pub fn observe(&mut self, packet: &parse::ParsedPacket, l7: &l7::L7Info, now_ms: u64)
      pub fn snapshot(&mut self, now_ms: u64) -> Vec<FlowSnapshot> // also resets per-tick byte counters used for speed
  }
  pub struct FlowSnapshot {
      pub key: FlowKey,
      pub app_layer_protocol: String,
      pub status: String, // "SYN_SENT" | "ESTABLISHED" | "TIME_WAIT" | "CLOSE_WAIT"
      pub encryption: String,
      pub rx_speed: f64,
      pub tx_speed: f64,
      pub rx_bytes_total: u64,
      pub tx_bytes_total: u64,
      pub latency_ms: f64,
      pub packet_loss: f64,
  }
  ```
  Consumed by `main.rs`'s periodic emitter (Task 8) and by `wire.rs`'s `AgentEvent::ConnectionUpdate` (Task 7).

- [ ] **Step 1: Write the failing tests**

```rust
// capture-agent/src/flow.rs, #[cfg(test)] mod tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{ParsedPacket, TransportProtocol, TcpFlags};
    use crate::l7::L7Info;

    fn tcp_packet(local_is_src: bool, flags: TcpFlags, len: u16) -> ParsedPacket {
        let (src_ip, dst_ip, src_port, dst_port) = if local_is_src {
            ("192.168.1.10".to_string(), "93.184.216.34".to_string(), 51000u16, 443u16)
        } else {
            ("93.184.216.34".to_string(), "192.168.1.10".to_string(), 443u16, 51000u16)
        };
        ParsedPacket {
            src_mac: "aa:aa:aa:aa:aa:aa".into(),
            dst_mac: "bb:bb:bb:bb:bb:bb".into(),
            src_ip,
            dst_ip,
            protocol: TransportProtocol::Tcp,
            src_port: Some(src_port),
            dst_port: Some(dst_port),
            tcp_flags: Some(flags),
            seq: Some(1000),
            ttl: 64,
            total_len: len,
            payload: vec![],
        }
    }

    #[test]
    fn derives_syn_sent_then_established() {
        let mut table = FlowTable::new(vec!["192.168.1.10".to_string()]);

        let syn = tcp_packet(true, TcpFlags { syn: true, ack: false, fin: false, rst: false }, 60);
        table.observe(&syn, &L7Info::None, 0);
        let snap = table.snapshot(0);
        assert_eq!(snap[0].status, "SYN_SENT");

        let synack = tcp_packet(false, TcpFlags { syn: true, ack: true, fin: false, rst: false }, 60);
        table.observe(&synack, &L7Info::None, 20);
        let ack = tcp_packet(true, TcpFlags { syn: false, ack: true, fin: false, rst: false }, 60);
        table.observe(&ack, &L7Info::None, 25);

        let snap = table.snapshot(25);
        assert_eq!(snap[0].status, "ESTABLISHED");
        assert!((snap[0].latency_ms - 20.0).abs() < 0.01, "expected ~20ms RTT, got {}", snap[0].latency_ms);
    }

    #[test]
    fn accumulates_byte_totals_by_direction() {
        let mut table = FlowTable::new(vec!["192.168.1.10".to_string()]);
        let out = tcp_packet(true, TcpFlags::default(), 100);
        let inb = tcp_packet(false, TcpFlags::default(), 250);
        table.observe(&out, &L7Info::None, 0);
        table.observe(&inb, &L7Info::None, 0);

        let snap = table.snapshot(1000);
        assert_eq!(snap[0].tx_bytes_total, 100);
        assert_eq!(snap[0].rx_bytes_total, 250);
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test flow::`
Expected: FAIL — `flow` module doesn't exist.

- [ ] **Step 3: Implement `flow.rs`**

```rust
use crate::l7::L7Info;
use crate::parse::{ParsedPacket, TransportProtocol};
use std::collections::HashMap;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FlowKey {
    pub protocol: TransportProtocol,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
}

struct FlowState {
    app_layer_protocol: String,
    encryption: String,
    established: bool,
    fin_seen: bool,
    syn_sent_at_ms: Option<u64>,
    rtt_ms: Option<f64>,
    rx_bytes_total: u64,
    tx_bytes_total: u64,
    rx_bytes_this_tick: u64,
    tx_bytes_this_tick: u64,
    max_seq_seen: HashMap<bool /* local_is_sender */, u32>,
    retransmits: u64,
    segments: u64,
}

impl Default for FlowState {
    fn default() -> Self {
        FlowState {
            app_layer_protocol: "Unknown".to_string(),
            encryption: "None".to_string(),
            established: false,
            fin_seen: false,
            syn_sent_at_ms: None,
            rtt_ms: None,
            rx_bytes_total: 0,
            tx_bytes_total: 0,
            rx_bytes_this_tick: 0,
            tx_bytes_this_tick: 0,
            max_seq_seen: HashMap::new(),
            retransmits: 0,
            segments: 0,
        }
    }
}

pub struct FlowSnapshot {
    pub key: FlowKey,
    pub app_layer_protocol: String,
    pub status: String,
    pub encryption: String,
    pub rx_speed: f64,
    pub tx_speed: f64,
    pub rx_bytes_total: u64,
    pub tx_bytes_total: u64,
    pub latency_ms: f64,
    pub packet_loss: f64,
}

pub struct FlowTable {
    local_addrs: Vec<String>,
    flows: HashMap<FlowKey, FlowState>,
    last_snapshot_ms: u64,
}

fn well_known_protocol(port: u16) -> Option<&'static str> {
    match port {
        80 => Some("HTTP"),
        443 => Some("HTTPS/TLS"),
        53 => Some("DNS"),
        22 => Some("SSH"),
        _ => None,
    }
}

impl FlowTable {
    pub fn new(local_addrs: Vec<String>) -> Self {
        FlowTable {
            local_addrs,
            flows: HashMap::new(),
            last_snapshot_ms: 0,
        }
    }

    fn is_local(&self, addr: &str) -> bool {
        self.local_addrs.iter().any(|a| a == addr)
    }

    /// `key_for` always orders (local, remote) so both packet directions of
    /// one connection map to the same FlowKey.
    fn key_for(&self, packet: &ParsedPacket) -> Option<(FlowKey, bool /* is_outbound */)> {
        let (src_port, dst_port) = (packet.src_port?, packet.dst_port?);
        if self.is_local(&packet.src_ip) {
            Some((
                FlowKey {
                    protocol: packet.protocol,
                    local_addr: packet.src_ip.clone(),
                    local_port: src_port,
                    remote_addr: packet.dst_ip.clone(),
                    remote_port: dst_port,
                },
                true,
            ))
        } else if self.is_local(&packet.dst_ip) {
            Some((
                FlowKey {
                    protocol: packet.protocol,
                    local_addr: packet.dst_ip.clone(),
                    local_port: dst_port,
                    remote_addr: packet.src_ip.clone(),
                    remote_port: src_port,
                },
                false,
            ))
        } else {
            None
        }
    }

    pub fn observe(&mut self, packet: &ParsedPacket, l7: &L7Info, now_ms: u64) {
        let Some((key, is_outbound)) = self.key_for(packet) else { return };
        let remote_port = key.remote_port;
        let state = self.flows.entry(key).or_default();

        if is_outbound {
            state.tx_bytes_total += packet.total_len as u64;
            state.tx_bytes_this_tick += packet.total_len as u64;
        } else {
            state.rx_bytes_total += packet.total_len as u64;
            state.rx_bytes_this_tick += packet.total_len as u64;
        }

        match l7 {
            L7Info::Http { .. } => state.app_layer_protocol = "HTTP".to_string(),
            L7Info::Dns { .. } => state.app_layer_protocol = "DNS".to_string(),
            L7Info::TlsClientHello { .. } => {
                state.app_layer_protocol = "HTTPS/TLS".to_string();
                state.encryption = "TLS".to_string();
            }
            L7Info::None => {
                if state.app_layer_protocol == "Unknown" {
                    if let Some(name) = well_known_protocol(remote_port) {
                        state.app_layer_protocol = name.to_string();
                    }
                }
            }
        }

        if let Some(flags) = packet.tcp_flags {
            if flags.syn && !flags.ack {
                state.syn_sent_at_ms = Some(now_ms);
            }
            if flags.syn && flags.ack && !is_outbound {
                if let Some(sent_at) = state.syn_sent_at_ms {
                    state.rtt_ms = Some((now_ms.saturating_sub(sent_at)) as f64);
                }
            }
            if flags.ack {
                state.established = true;
            }
            if flags.fin {
                state.fin_seen = true;
            }
            if flags.rst {
                state.established = false;
            }

            if let Some(seq) = packet.seq {
                state.segments += 1;
                let max_seen = state.max_seq_seen.entry(is_outbound).or_insert(seq);
                if seq <= *max_seen && state.segments > 1 {
                    state.retransmits += 1;
                } else {
                    *max_seen = seq;
                }
            }
        }
    }

    pub fn snapshot(&mut self, now_ms: u64) -> Vec<FlowSnapshot> {
        let elapsed_s = ((now_ms.saturating_sub(self.last_snapshot_ms)).max(1)) as f64 / 1000.0;
        self.last_snapshot_ms = now_ms;

        let mut result = Vec::with_capacity(self.flows.len());
        for (key, state) in self.flows.iter_mut() {
            let status = if state.fin_seen {
                "TIME_WAIT"
            } else if state.established {
                "ESTABLISHED"
            } else if state.syn_sent_at_ms.is_some() {
                "SYN_SENT"
            } else {
                "CLOSE_WAIT"
            };

            let packet_loss = if state.segments > 0 {
                (state.retransmits as f64 / state.segments as f64) * 100.0
            } else {
                0.0
            };

            result.push(FlowSnapshot {
                key: key.clone(),
                app_layer_protocol: state.app_layer_protocol.clone(),
                status: status.to_string(),
                encryption: state.encryption.clone(),
                rx_speed: state.rx_bytes_this_tick as f64 / elapsed_s,
                tx_speed: state.tx_bytes_this_tick as f64 / elapsed_s,
                rx_bytes_total: state.rx_bytes_total,
                tx_bytes_total: state.tx_bytes_total,
                latency_ms: state.rtt_ms.unwrap_or(0.0),
                packet_loss: packet_loss.min(100.0),
            });

            state.rx_bytes_this_tick = 0;
            state.tx_bytes_this_tick = 0;
        }
        result
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test flow::`
Expected: both tests PASS.

- [ ] **Step 5: Add `mod flow;` to `main.rs` and commit**

```bash
git add capture-agent/src/flow.rs capture-agent/src/main.rs
git commit -m "feat(agent): aggregate packets into a flow table with status/RTT/loss derivation"
```

---

### Task 5: Process attribution via `lsof`

**Files:**
- Create: `capture-agent/src/process_lookup.rs`
- Modify: `capture-agent/src/main.rs` (add `mod process_lookup;`)

**Interfaces:**
- Produces:
  ```rust
  pub struct ProcessInfo { pub name: String, pub pid: u32 }
  pub fn parse_lsof_output(output: &str) -> std::collections::HashMap<u16, ProcessInfo> // keyed by local port
  pub fn refresh() -> std::collections::HashMap<u16, ProcessInfo> // shells out to `lsof -i -n -P`
  ```
  Consumed by `main.rs`'s periodic emitter (Task 8), merged into `FlowSnapshot`-derived connection records before they're sent as `AgentEvent::ConnectionUpdate`.

- [ ] **Step 1: Write the failing test**

```rust
// capture-agent/src/process_lookup.rs, #[cfg(test)] mod tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lsof_output_into_port_map() {
        let sample = "\
COMMAND   PID   USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
Safari   1234 jamesb   45u  IPv4 0x123      0t0  TCP 192.168.1.10:51000->93.184.216.34:443 (ESTABLISHED)
Slack    5678 jamesb   12u  IPv4 0x456      0t0  UDP 192.168.1.10:60123->8.8.8.8:53
";
        let map = parse_lsof_output(sample);
        assert_eq!(map.get(&51000).unwrap().name, "Safari");
        assert_eq!(map.get(&51000).unwrap().pid, 1234);
        assert_eq!(map.get(&60123).unwrap().name, "Slack");
        assert_eq!(map.get(&60123).unwrap().pid, 5678);
    }

    #[test]
    fn ignores_unparseable_lines() {
        let sample = "COMMAND   PID   USER   FD   TYPE\nnot a real line at all\n";
        let map = parse_lsof_output(sample);
        assert!(map.is_empty());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test process_lookup::`
Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Implement `process_lookup.rs`**

```rust
use std::collections::HashMap;
use std::process::Command;

pub struct ProcessInfo {
    pub name: String,
    pub pid: u32,
}

/// Parses `lsof -i -n -P` output. Lines look like:
///   Safari   1234 jamesb   45u  IPv4 0x123   0t0  TCP 192.168.1.10:51000->93.184.216.34:443 (ESTABLISHED)
/// Keyed by the *local* port (the number before "->").
pub fn parse_lsof_output(output: &str) -> HashMap<u16, ProcessInfo> {
    let mut map = HashMap::new();
    for line in output.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 9 {
            continue;
        }
        let name = fields[0].to_string();
        let Ok(pid) = fields[1].parse::<u32>() else { continue };
        let name_field = fields[8];
        let Some(local_part) = name_field.split("->").next() else { continue };
        let Some(port_str) = local_part.rsplit(':').next() else { continue };
        let Ok(port) = port_str.parse::<u16>() else { continue };
        map.insert(port, ProcessInfo { name, pid });
    }
    map
}

pub fn refresh() -> HashMap<u16, ProcessInfo> {
    match Command::new("lsof").args(["-i", "-n", "-P"]).output() {
        Ok(output) => {
            let text = String::from_utf8_lossy(&output.stdout);
            parse_lsof_output(&text)
        }
        Err(_) => HashMap::new(),
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test process_lookup::`
Expected: both tests PASS.

- [ ] **Step 5: Add `mod process_lookup;` to `main.rs` and commit**

```bash
git add capture-agent/src/process_lookup.rs capture-agent/src/main.rs
git commit -m "feat(agent): attribute connections to a process name/PID via lsof"
```

---

### Task 6: Wire protocol types and newline-delimited JSON framing

**Files:**
- Create: `capture-agent/src/wire.rs`
- Modify: `capture-agent/src/main.rs` (add `mod wire;`)

**Interfaces:**
- Consumes: `flow::FlowKey`/`FlowSnapshot` (Task 4), `process_lookup::ProcessInfo` (Task 5)
- Produces:
  ```rust
  #[derive(Serialize)]
  #[serde(tag = "type", rename_all = "snake_case")]
  pub enum AgentEvent {
      ConnectionUpdate { connection: ConnectionJson },
      Packet { packet: PacketJson },
      LayerUpdate { layers: Vec<LayerStatsJson> },
      AgentStatus { interface: String, capturing: bool },
  }
  #[derive(Deserialize)]
  #[serde(tag = "type", rename_all = "snake_case")]
  pub enum ControlMessage { Pause, Resume }
  pub fn encode_event(event: &AgentEvent) -> String // one line, newline-terminated
  pub fn decode_control(line: &str) -> Option<ControlMessage>
  ```
  Consumed by `main.rs`'s TCP server loop (Task 8) and mirrored exactly by `lib/agent-mapping.ts` on the TypeScript side (Task 10) — field names must match `camelCase`.

- [ ] **Step 1: Write the failing test**

```rust
// capture-agent/src/wire.rs, #[cfg(test)] mod tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_connection_update_as_one_json_line_camel_case() {
        let event = AgentEvent::ConnectionUpdate {
            connection: ConnectionJson {
                id: "tcp-192.168.1.10:51000-93.184.216.34:443".to_string(),
                protocol: "TCP".to_string(),
                app_layer_protocol: "HTTPS/TLS".to_string(),
                transport_protocol: "TCP".to_string(),
                osi_stack: "L4:TCP -> L3:IPv4".to_string(),
                local_addr: "192.168.1.10".to_string(),
                local_port: 51000,
                remote_addr: "93.184.216.34".to_string(),
                remote_port: 443,
                process_name: "Safari".to_string(),
                pid: 1234,
                rx_speed: 1024.0,
                tx_speed: 512.0,
                rx_bytes_total: 4096,
                tx_bytes_total: 2048,
                latency_ms: 20.0,
                packet_loss: 0.0,
                status: "ESTABLISHED".to_string(),
                encryption: "TLS".to_string(),
                sparkline: vec![1, 2, 3],
            },
        };
        let line = encode_event(&event);
        assert!(line.ends_with('\n'));
        assert!(line.contains("\"appLayerProtocol\":\"HTTPS/TLS\""));
        assert!(line.contains("\"processName\":\"Safari\""));
        assert!(line.contains("\"type\":\"connection_update\""));
    }

    #[test]
    fn decodes_pause_and_resume() {
        assert!(matches!(decode_control("{\"type\":\"pause\"}"), Some(ControlMessage::Pause)));
        assert!(matches!(decode_control("{\"type\":\"resume\"}"), Some(ControlMessage::Resume)));
        assert!(decode_control("not json").is_none());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test wire::`
Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Implement `wire.rs`**

```rust
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionJson {
    pub id: String,
    pub protocol: String,
    pub app_layer_protocol: String,
    pub transport_protocol: String,
    pub osi_stack: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub process_name: String,
    pub pid: u32,
    pub rx_speed: f64,
    pub tx_speed: f64,
    pub rx_bytes_total: u64,
    pub tx_bytes_total: u64,
    pub latency_ms: f64,
    pub packet_loss: f64,
    pub status: String,
    pub encryption: String,
    pub sparkline: Vec<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LayerStatsJson {
    pub layer: u8,
    pub rx_speed: f64,
    pub tx_speed: f64,
    pub rx_packets_per_sec: f64,
    pub tx_packets_per_sec: f64,
    pub total_bytes: u64,
    pub error_rate: f64,
    pub active_sockets: u32,
    pub sparkline: Vec<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketJson {
    pub id: String,
    pub timestamp: String,
    pub relative_time_ms: u64,
    pub layer: u8,
    pub protocol: String,
    pub src: String,
    pub dst: String,
    pub length: u32,
    pub summary: String,
    pub hex_dump: String,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentEvent {
    ConnectionUpdate { connection: ConnectionJson },
    Packet { packet: PacketJson },
    LayerUpdate { layers: Vec<LayerStatsJson> },
    AgentStatus { interface: String, capturing: bool },
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlMessage {
    Pause,
    Resume,
}

pub fn encode_event(event: &AgentEvent) -> String {
    let mut line = serde_json::to_string(event).expect("AgentEvent serialization cannot fail");
    line.push('\n');
    line
}

pub fn decode_control(line: &str) -> Option<ControlMessage> {
    serde_json::from_str(line.trim()).ok()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test wire::`
Expected: both tests PASS.

- [ ] **Step 5: Add `mod wire;` to `main.rs` and commit**

```bash
git add capture-agent/src/wire.rs capture-agent/src/main.rs
git commit -m "feat(agent): define wire protocol types and newline-delimited JSON framing"
```

---

### Task 7: `cargo-fuzz` target for the packet parser

**Files:**
- Create: `capture-agent/fuzz/Cargo.toml`
- Create: `capture-agent/fuzz/fuzz_targets/parse_packet.rs`

**Interfaces:**
- Consumes: `parse::parse_packet` (Task 2) — this task adds no new interface, it only exercises the existing one against arbitrary bytes.

- [ ] **Step 1: Install `cargo-fuzz` and initialize the fuzz directory**

```bash
cd capture-agent
cargo install cargo-fuzz
cargo fuzz init
```

- [ ] **Step 2: Write the fuzz target**

```rust
// capture-agent/fuzz/fuzz_targets/parse_packet.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use capture_agent::parse::parse_packet;

fuzz_target!(|data: &[u8]| {
    // The only property under test: arbitrary bytes must never panic.
    // A None/Some result are both acceptable outcomes.
    let _ = parse_packet(data);
});
```

- [ ] **Step 3: Expose `parse` as a library so the fuzz crate can import it**

Add a `capture-agent/src/lib.rs`:

```rust
pub mod parse;
pub mod l7;
pub mod flow;
pub mod process_lookup;
pub mod wire;
```

Change `main.rs`'s `mod parse;` etc. lines to `use capture_agent::{parse, l7, flow, process_lookup, wire};` instead, and add to `Cargo.toml`:

```toml
[lib]
name = "capture_agent"
path = "src/lib.rs"

[[bin]]
name = "capture-agent"
path = "src/main.rs"
```

- [ ] **Step 4: Run the fuzzer briefly to confirm the harness works**

Run: `cargo fuzz run parse_packet -- -max_total_time=30`
Expected: runs for 30 seconds exercising `parse_packet` with random/mutated byte sequences and exits without finding a crash. If it finds one, fix the panic in `parse.rs` (a bounds-check or `.unwrap()` that should be a `?`/`.ok()?`) before proceeding — this is the hardening requirement from the spec, not optional.

- [ ] **Step 5: Commit**

```bash
git add capture-agent/src/lib.rs capture-agent/src/main.rs capture-agent/Cargo.toml capture-agent/fuzz/
git commit -m "feat(agent): add cargo-fuzz target for the packet parser"
```

---

### Task 8: Wire it together — capture loop, periodic emitter, TCP server, pause/resume

**Files:**
- Modify: `capture-agent/src/main.rs`

**Interfaces:**
- Consumes: everything from Tasks 1–7
- Produces: the complete running agent — no further Rust interfaces are exposed beyond the wire protocol already defined in Task 6, which is what Task 10 (TypeScript) consumes.

- [ ] **Step 1: Replace `main.rs` with the full wiring**

```rust
use capture_agent::{flow::FlowTable, l7, parse, process_lookup, wire};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::broadcast;

fn detect_interface() -> pcap::Device {
    match pcap::Device::lookup() {
        Ok(Some(device)) => device,
        Ok(None) => panic!("no capture-capable network interface found"),
        Err(e) => panic!("failed to look up default capture device: {e}"),
    }
}

fn local_addrs_for(device: &pcap::Device) -> Vec<String> {
    device
        .addresses
        .iter()
        .map(|a| a.addr.to_string())
        .collect()
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let device = detect_interface();
    let interface_name = device.name.clone();
    let local_addrs = local_addrs_for(&device);
    println!("capture-agent: using interface {interface_name}");

    let paused = Arc::new(AtomicBool::new(false));
    let flow_table = Arc::new(Mutex::new(FlowTable::new(local_addrs)));
    let process_map = Arc::new(Mutex::new(process_lookup::refresh()));

    let (tx, _rx) = broadcast::channel::<String>(1024);

    // Background: refresh the process-attribution map every 3s.
    {
        let process_map = process_map.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(3));
            let fresh = process_lookup::refresh();
            *process_map.lock().unwrap() = fresh;
        });
    }

    // Blocking capture loop on a dedicated OS thread.
    {
        let flow_table = flow_table.clone();
        let paused = paused.clone();
        let device = device.clone();
        std::thread::spawn(move || {
            let mut cap = match pcap::Capture::from_device(device)
                .and_then(|c| c.promisc(true).snaplen(65535).timeout(1000).open())
            {
                Ok(cap) => cap,
                Err(e) => {
                    eprintln!("capture-agent: failed to open capture device: {e}");
                    return;
                }
            };
            let start = Instant::now();
            loop {
                if paused.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(200));
                    continue;
                }
                match cap.next_packet() {
                    Ok(packet) => {
                        let Some(parsed) = parse::parse_packet(packet.data) else { continue };
                        let l7_info = l7::sniff_l7(&parsed.payload, parsed.dst_port);
                        let now_ms = start.elapsed().as_millis() as u64;
                        flow_table.lock().unwrap().observe(&parsed, &l7_info, now_ms);
                    }
                    Err(pcap::Error::TimeoutExpired) => continue,
                    Err(e) => {
                        eprintln!("capture-agent: capture error (skipping): {e}");
                        continue;
                    }
                }
            }
        });
    }

    // Periodic emitter: every 1s, snapshot the flow table and broadcast connection_update events.
    {
        let flow_table = flow_table.clone();
        let process_map = process_map.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                let now_ms = Instant::now().elapsed().as_millis() as u64;
                let snapshots = flow_table.lock().unwrap().snapshot(now_ms);
                let processes = process_map.lock().unwrap();
                for snap in snapshots {
                    let proc_info = processes.get(&snap.key.local_port);
                    let connection = wire::ConnectionJson {
                        id: format!(
                            "{:?}-{}:{}-{}:{}",
                            snap.key.protocol,
                            snap.key.local_addr,
                            snap.key.local_port,
                            snap.key.remote_addr,
                            snap.key.remote_port
                        ),
                        protocol: snap.app_layer_protocol.clone(),
                        app_layer_protocol: snap.app_layer_protocol,
                        transport_protocol: format!("{:?}", snap.key.protocol).to_uppercase(),
                        osi_stack: format!(
                            "L4:{:?} -> L3:IP",
                            snap.key.protocol
                        ),
                        local_addr: snap.key.local_addr,
                        local_port: snap.key.local_port,
                        remote_addr: snap.key.remote_addr,
                        remote_port: snap.key.remote_port,
                        process_name: proc_info.map(|p| p.name.clone()).unwrap_or_else(|| "unknown".to_string()),
                        pid: proc_info.map(|p| p.pid).unwrap_or(0),
                        rx_speed: snap.rx_speed,
                        tx_speed: snap.tx_speed,
                        rx_bytes_total: snap.rx_bytes_total,
                        tx_bytes_total: snap.tx_bytes_total,
                        latency_ms: snap.latency_ms,
                        packet_loss: snap.packet_loss,
                        status: snap.status,
                        encryption: snap.encryption,
                        sparkline: vec![],
                    };
                    let event = wire::AgentEvent::ConnectionUpdate { connection };
                    let _ = tx.send(wire::encode_event(&event));
                }
            }
        });
    }

    let listener = TcpListener::bind("127.0.0.1:9990").await?;
    println!("capture-agent: listening on 127.0.0.1:9990");

    loop {
        let (socket, _addr) = listener.accept().await?;
        let mut rx = tx.subscribe();
        let paused = paused.clone();
        tokio::spawn(async move {
            let (read_half, mut write_half) = socket.into_split();
            let mut reader = BufReader::new(read_half).lines();

            loop {
                tokio::select! {
                    line = reader.next_line() => {
                        match line {
                            Ok(Some(text)) => {
                                match wire::decode_control(&text) {
                                    Some(wire::ControlMessage::Pause) => paused.store(true, Ordering::Relaxed),
                                    Some(wire::ControlMessage::Resume) => paused.store(false, Ordering::Relaxed),
                                    None => {}
                                }
                            }
                            _ => break,
                        }
                    }
                    event = rx.recv() => {
                        match event {
                            Ok(line) => {
                                if write_half.write_all(line.as_bytes()).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        });
    }
}
```

- [ ] **Step 2: Build and run against real traffic**

Run: `cd capture-agent && cargo build --release`
Expected: builds successfully (adjust any `pcap`/`etherparse` API mismatches per Global Constraints).

Run: `cargo run --release`, then in another terminal: `nc 127.0.0.1 9990 | head -5`
Expected: after a few seconds of real network activity on the Mac, `nc` prints newline-delimited JSON `connection_update` events with real local traffic (visit a website in a browser to generate some).

- [ ] **Step 3: Verify pause/resume**

Run (while the agent is running and `nc 127.0.0.1 9990` is streaming): in a third terminal, `echo '{"type":"pause"}' | nc 127.0.0.1 9990`
Expected: the streaming output stops advancing. Sending `{"type":"resume"}` the same way resumes it.

- [ ] **Step 4: Commit**

```bash
git add capture-agent/src/main.rs
git commit -m "feat(agent): wire capture loop, periodic emitter, and TCP server with pause/resume"
```

---

### Task 9: Trim `lib/types.ts` and `lib/osi-engine.ts`; add `lib/agent-mapping.ts`

**Files:**
- Modify: `lib/types.ts`
- Modify: `lib/osi-engine.ts`
- Create: `lib/agent-mapping.ts`
- Create: `vitest.config.ts`
- Create: `lib/__tests__/agent-mapping.test.ts`
- Modify: `package.json` (add `vitest` devDependency and a `test` script)

**Interfaces:**
- Consumes: the wire JSON shapes defined in `capture-agent/src/wire.rs` (Task 6) — field names must match exactly.
- Produces:
  ```typescript
  export function mapConnectionEvent(json: unknown): NetworkConnection
  export function mapPacketEvent(json: unknown): PacketFrame
  export function mergeLayerStats(
    liveLayers: Record<OSILayerNumber, Partial<OSILayerInfo>>
  ): OSILayerInfo[]
  export const STATIC_LAYER_INFO: Record<OSILayerNumber, Pick<OSILayerInfo,
    'layer' | 'name' | 'shortName' | 'pdu' | 'protocols' | 'color' | 'badgeBg' | 'badgeText'>>
  ```
  Consumed by `lib/agent-client.ts` and `app/page.tsx` (Task 10 and 11).

- [ ] **Step 1: Install Vitest**

```bash
npm install --save-exact --save-dev vitest@3.2.4
```

Add to `package.json` `"scripts"`: `"test": "vitest run"`.

- [ ] **Step 2: Write `vitest.config.ts`**

```typescript
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
  },
});
```

- [ ] **Step 3: Write the failing tests**

```typescript
// lib/__tests__/agent-mapping.test.ts
import { describe, expect, it } from 'vitest';
import { mapConnectionEvent, mapPacketEvent } from '../agent-mapping';

describe('mapConnectionEvent', () => {
  it('maps agent wire JSON to a NetworkConnection', () => {
    const wire = {
      id: 'tcp-192.168.1.10:51000-93.184.216.34:443',
      protocol: 'HTTPS/TLS',
      appLayerProtocol: 'HTTPS/TLS',
      transportProtocol: 'TCP',
      osiStack: 'L4:TCP -> L3:IP',
      localAddr: '192.168.1.10',
      localPort: 51000,
      remoteAddr: '93.184.216.34',
      remotePort: 443,
      processName: 'Safari',
      pid: 1234,
      rxSpeed: 1024,
      txSpeed: 512,
      rxBytesTotal: 4096,
      txBytesTotal: 2048,
      latencyMs: 20,
      packetLoss: 0,
      status: 'ESTABLISHED',
      encryption: 'TLS',
      sparkline: [1, 2, 3],
    };

    const connection = mapConnectionEvent(wire);

    expect(connection.id).toBe(wire.id);
    expect(connection.transportProtocol).toBe('TCP');
    expect(connection.processName).toBe('Safari');
    expect(connection.pid).toBe(1234);
    expect(connection.status).toBe('ESTABLISHED');
  });

  it('throws on a malformed event rather than silently producing garbage', () => {
    expect(() => mapConnectionEvent({ id: 'incomplete' })).toThrow();
  });
});

describe('mapPacketEvent', () => {
  it('maps agent wire JSON to a PacketFrame', () => {
    const wire = {
      id: 'pkt-1',
      timestamp: '2026-08-26T00:00:00.000Z',
      relativeTimeMs: 42,
      layer: 4,
      protocol: 'TCP',
      src: '192.168.1.10:51000',
      dst: '93.184.216.34:443',
      length: 60,
      summary: 'TCP SYN',
      hexDump: '00 01 02',
    };

    const packet = mapPacketEvent(wire);

    expect(packet.id).toBe('pkt-1');
    expect(packet.layer).toBe(4);
    expect(packet.hexDump).toBe('00 01 02');
  });
});
```

- [ ] **Step 4: Run to verify failure**

Run: `npx vitest run lib/__tests__/agent-mapping.test.ts`
Expected: FAIL — `lib/agent-mapping.ts` doesn't exist yet.

- [ ] **Step 5: Trim `lib/types.ts`**

Remove the `export type TrafficScenario = ...` line entirely. `NetworkConnection`, `PacketFrame`, `OSILayerInfo`, `SystemStats`, `ThemeConfig`, `TerminalTheme` are unchanged.

- [ ] **Step 6: Trim `lib/osi-engine.ts`**

Remove `generateRandomPacket` and `INITIAL_CONNECTIONS` entirely. Replace `INITIAL_OSI_LAYERS` with `STATIC_LAYER_INFO`, keeping only the descriptive fields (drop the fake numeric/sparkline/details values that `generateRandomPacket`/the old sim loop used to overwrite anyway):

```typescript
export const STATIC_LAYER_INFO: Record<OSILayerNumber, Pick<OSILayerInfo,
  'layer' | 'name' | 'shortName' | 'pdu' | 'protocols' | 'color' | 'badgeBg' | 'badgeText'>> = {
  7: { layer: 7, name: 'Application', shortName: 'APP', pdu: 'Data', protocols: ['HTTP', 'DNS', 'TLS'], color: 'text-emerald-400', badgeBg: 'bg-emerald-500/10', badgeText: 'text-emerald-400' },
  6: { layer: 6, name: 'Presentation', shortName: 'PRES', pdu: 'Data', protocols: ['TLS', 'SSL'], color: 'text-teal-400', badgeBg: 'bg-teal-500/10', badgeText: 'text-teal-400' },
  5: { layer: 5, name: 'Session', shortName: 'SESS', pdu: 'Data', protocols: ['QUIC', 'NetBIOS'], color: 'text-cyan-400', badgeBg: 'bg-cyan-500/10', badgeText: 'text-cyan-400' },
  4: { layer: 4, name: 'Transport', shortName: 'TRANS', pdu: 'Segment', protocols: ['TCP', 'UDP'], color: 'text-sky-400', badgeBg: 'bg-sky-500/10', badgeText: 'text-sky-400' },
  3: { layer: 3, name: 'Network', shortName: 'NET', pdu: 'Packet', protocols: ['IPv4', 'IPv6', 'ICMP'], color: 'text-blue-400', badgeBg: 'bg-blue-500/10', badgeText: 'text-blue-400' },
  2: { layer: 2, name: 'Data Link', shortName: 'LINK', pdu: 'Frame', protocols: ['Ethernet'], color: 'text-indigo-400', badgeBg: 'bg-indigo-500/10', badgeText: 'text-indigo-400' },
  1: { layer: 1, name: 'Physical', shortName: 'PHYS', pdu: 'Bit', protocols: ['Ethernet PHY'], color: 'text-violet-400', badgeBg: 'bg-violet-500/10', badgeText: 'text-violet-400' },
};
```

Leave `THEMES`, `formatSpeed`, and `formatBytes` untouched.

- [ ] **Step 7: Implement `lib/agent-mapping.ts`**

```typescript
import { NetworkConnection, OSILayerInfo, OSILayerNumber, PacketFrame } from './types';
import { STATIC_LAYER_INFO } from './osi-engine';

function requireField<T>(obj: Record<string, unknown>, key: string): T {
  if (!(key in obj) || obj[key] === undefined) {
    throw new Error(`agent event missing required field "${key}"`);
  }
  return obj[key] as T;
}

export function mapConnectionEvent(json: unknown): NetworkConnection {
  const w = json as Record<string, unknown>;
  return {
    id: requireField(w, 'id'),
    protocol: requireField(w, 'protocol'),
    appLayerProtocol: requireField(w, 'appLayerProtocol'),
    transportProtocol: requireField(w, 'transportProtocol'),
    osiStack: requireField(w, 'osiStack'),
    localAddr: requireField(w, 'localAddr'),
    localPort: requireField(w, 'localPort'),
    remoteAddr: requireField(w, 'remoteAddr'),
    remotePort: requireField(w, 'remotePort'),
    processName: requireField(w, 'processName'),
    pid: requireField(w, 'pid'),
    rxSpeed: requireField(w, 'rxSpeed'),
    txSpeed: requireField(w, 'txSpeed'),
    rxBytesTotal: requireField(w, 'rxBytesTotal'),
    txBytesTotal: requireField(w, 'txBytesTotal'),
    latencyMs: requireField(w, 'latencyMs'),
    packetLoss: requireField(w, 'packetLoss'),
    status: requireField(w, 'status'),
    encryption: requireField(w, 'encryption'),
    sparkline: requireField(w, 'sparkline'),
  };
}

export function mapPacketEvent(json: unknown): PacketFrame {
  const w = json as Record<string, unknown>;
  return {
    id: requireField(w, 'id'),
    timestamp: requireField(w, 'timestamp'),
    relativeTimeMs: requireField(w, 'relativeTimeMs'),
    layer: requireField<OSILayerNumber>(w, 'layer'),
    protocol: requireField(w, 'protocol'),
    src: requireField(w, 'src'),
    dst: requireField(w, 'dst'),
    length: requireField(w, 'length'),
    summary: requireField(w, 'summary'),
    hexDump: requireField(w, 'hexDump'),
    headerBreakdown: (w.headerBreakdown as PacketFrame['headerBreakdown']) ?? {},
  };
}

function healthStatusFor(errorRate: number): 'OPTIMAL' | 'WARNING' | 'CRITICAL' {
  if (errorRate < 1) return 'OPTIMAL';
  if (errorRate < 5) return 'WARNING';
  return 'CRITICAL';
}

export function mergeLayerStats(
  liveLayers: Record<OSILayerNumber, Partial<OSILayerInfo>>
): OSILayerInfo[] {
  return (Object.keys(STATIC_LAYER_INFO) as unknown as OSILayerNumber[]).map((layer) => {
    const staticInfo = STATIC_LAYER_INFO[layer];
    const live = liveLayers[layer] ?? {};
    const rxSpeed = live.rxSpeed ?? 0;
    const txSpeed = live.txSpeed ?? 0;
    const errorRate = live.errorRate ?? 0;
    return {
      ...staticInfo,
      rxSpeed,
      txSpeed,
      rxPacketsPerSec: live.rxPacketsPerSec ?? 0,
      txPacketsPerSec: live.txPacketsPerSec ?? 0,
      totalBytes: live.totalBytes ?? 0,
      errorRate,
      activeSockets: live.activeSockets ?? 0,
      sparkline: live.sparkline ?? [],
      details: {
        primaryMetric: 'Throughput',
        primaryValue: `${Math.round(rxSpeed + txSpeed)} B/s`,
        secondaryMetric: 'Active Sockets',
        secondaryValue: String(live.activeSockets ?? 0),
        tertiaryMetric: 'Error Rate',
        tertiaryValue: `${errorRate.toFixed(2)}%`,
        healthStatus: healthStatusFor(errorRate),
        keyMetrics: {},
      },
    };
  });
}
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `npx vitest run lib/__tests__/agent-mapping.test.ts`
Expected: all tests PASS.

- [ ] **Step 9: Commit**

```bash
git add lib/types.ts lib/osi-engine.ts lib/agent-mapping.ts vitest.config.ts lib/__tests__/agent-mapping.test.ts package.json package-lock.json
git commit -m "feat(web): trim simulated types/generators, add agent event mapping layer"
```

---

### Task 10: Agent TCP client with reconnect/backoff

**Files:**
- Create: `lib/agent-client.ts`
- Create: `lib/__tests__/agent-client.test.ts`

**Interfaces:**
- Consumes: raw newline-delimited JSON lines from the agent's TCP socket (Task 6/8)
- Produces:
  ```typescript
  export class AgentClient extends EventEmitter {
    constructor(host: string, port: number)
    start(): void
    sendControl(message: { type: 'pause' | 'resume' }): void
    stop(): void
    // emits: 'event' with the parsed AgentEvent JSON object, 'status' with { connected: boolean }
  }
  ```
  Consumed by `app/api/stream/route.ts` and `app/api/control/route.ts` (Task 11) — a single shared `AgentClient` instance per Next.js server process.

- [ ] **Step 1: Write the failing test**

```typescript
// lib/__tests__/agent-client.test.ts
import { describe, expect, it, vi, afterEach } from 'vitest';
import net from 'node:net';
import { AgentClient } from '../agent-client';

describe('AgentClient', () => {
  let server: net.Server;
  let port: number;

  afterEach(() => {
    server?.close();
  });

  it('parses newline-delimited JSON lines into "event" emissions', async () => {
    server = net.createServer((socket) => {
      socket.write('{"type":"agent_status","interface":"en0","capturing":true}\n');
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as net.AddressInfo).port;

    const client = new AgentClient('127.0.0.1', port);
    const received = await new Promise((resolve) => {
      client.on('event', resolve);
      client.start();
    });

    expect(received).toEqual({ type: 'agent_status', interface: 'en0', capturing: true });
    client.stop();
  });

  it('emits a disconnected status when the agent is unreachable', async () => {
    const client = new AgentClient('127.0.0.1', 1); // port 1 refuses connections
    const status = await new Promise((resolve) => {
      client.on('status', resolve);
      client.start();
    });
    expect(status).toEqual({ connected: false });
    client.stop();
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run lib/__tests__/agent-client.test.ts`
Expected: FAIL — `lib/agent-client.ts` doesn't exist.

- [ ] **Step 3: Implement `lib/agent-client.ts`**

```typescript
import { EventEmitter } from 'node:events';
import net from 'node:net';

const RECONNECT_DELAY_MS = 2000;

export class AgentClient extends EventEmitter {
  private host: string;
  private port: number;
  private socket: net.Socket | null = null;
  private buffer = '';
  private stopped = false;
  private reconnectTimer: NodeJS.Timeout | null = null;

  constructor(host: string, port: number) {
    super();
    this.host = host;
    this.port = port;
  }

  start(): void {
    this.stopped = false;
    this.connect();
  }

  private connect(): void {
    if (this.stopped) return;
    const socket = net.createConnection({ host: this.host, port: this.port });
    this.socket = socket;

    socket.on('connect', () => {
      this.emit('status', { connected: true });
    });

    socket.on('data', (chunk) => {
      this.buffer += chunk.toString('utf8');
      let newlineIndex: number;
      while ((newlineIndex = this.buffer.indexOf('\n')) !== -1) {
        const line = this.buffer.slice(0, newlineIndex);
        this.buffer = this.buffer.slice(newlineIndex + 1);
        if (line.trim().length === 0) continue;
        try {
          this.emit('event', JSON.parse(line));
        } catch {
          // Malformed line from the agent — skip it, don't crash the relay.
        }
      }
    });

    const handleDisconnect = () => {
      this.emit('status', { connected: false });
      this.socket = null;
      if (!this.stopped) {
        this.reconnectTimer = setTimeout(() => this.connect(), RECONNECT_DELAY_MS);
      }
    };

    socket.on('error', handleDisconnect);
    socket.on('close', handleDisconnect);
  }

  sendControl(message: { type: 'pause' | 'resume' }): void {
    this.socket?.write(JSON.stringify(message) + '\n');
  }

  stop(): void {
    this.stopped = true;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.socket?.destroy();
    this.socket = null;
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run lib/__tests__/agent-client.test.ts`
Expected: both tests PASS. (The second test connects to port `1`, which reliably refuses connections without needing a real unreachable-host timeout.)

- [ ] **Step 5: Commit**

```bash
git add lib/agent-client.ts lib/__tests__/agent-client.test.ts
git commit -m "feat(web): add reconnecting TCP client for the capture agent"
```

---

### Task 11: SSE stream route and control route

**Files:**
- Create: `app/api/stream/route.ts`
- Create: `app/api/control/route.ts`

**Interfaces:**
- Consumes: `AgentClient` (Task 10)
- Produces: `GET /api/stream` (SSE), `POST /api/control` — consumed by `app/page.tsx` (Task 12).

- [ ] **Step 1: Implement a shared agent client singleton**

```typescript
// app/api/stream/route.ts
import { AgentClient } from '@/lib/agent-client';

declare global {
  // eslint-disable-next-line no-var
  var __agentClient: AgentClient | undefined;
}

function getAgentClient(): AgentClient {
  if (!global.__agentClient) {
    global.__agentClient = new AgentClient('127.0.0.1', 9990);
    global.__agentClient.start();
  }
  return global.__agentClient;
}

export async function GET() {
  const client = getAgentClient();
  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    start(controller) {
      const onEvent = (event: unknown) => {
        controller.enqueue(encoder.encode(`data: ${JSON.stringify(event)}\n\n`));
      };
      const onStatus = (status: { connected: boolean }) => {
        controller.enqueue(
          encoder.encode(`data: ${JSON.stringify({ type: 'connection_status', ...status })}\n\n`)
        );
      };
      client.on('event', onEvent);
      client.on('status', onStatus);

      // Replay current connection status immediately so a fresh client
      // doesn't wait for the next status change to know the agent's state.
      onStatus({ connected: client['socket'] !== null });
    },
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    },
  });
}
```

- [ ] **Step 2: Implement the control route**

```typescript
// app/api/control/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { AgentClient } from '@/lib/agent-client';

declare global {
  // eslint-disable-next-line no-var
  var __agentClient: AgentClient | undefined;
}

export async function POST(request: NextRequest) {
  const body = await request.json();
  if (body.type !== 'pause' && body.type !== 'resume') {
    return NextResponse.json({ error: 'invalid control message type' }, { status: 400 });
  }
  if (!global.__agentClient) {
    return NextResponse.json({ error: 'agent not connected' }, { status: 503 });
  }
  global.__agentClient.sendControl({ type: body.type });
  return NextResponse.json({ ok: true });
}
```

- [ ] **Step 3: Manually verify against the running agent**

Run: `cd capture-agent && cargo run --release &` then, from the repo root, `npm run dev`.
Then: `curl -N http://localhost:3000/api/stream | head -5`
Expected: prints `data: {...}` lines mirroring the agent's real connection events, plus an initial `connection_status` event.

Then: `curl -X POST http://localhost:3000/api/control -H 'Content-Type: application/json' -d '{"type":"pause"}'`
Expected: `{"ok":true}`, and the `/api/stream` output stops advancing until `resume` is sent the same way.

- [ ] **Step 4: Commit**

```bash
git add app/api/stream/route.ts app/api/control/route.ts
git commit -m "feat(web): add SSE stream and control API routes relaying the capture agent"
```

---

### Task 12: Rewire `app/page.tsx` to consume live data; remove the simulator UI

**Files:**
- Modify: `app/page.tsx`
- Delete: `components/ScenarioLabView.tsx`

**Interfaces:**
- Consumes: `GET /api/stream` (Task 11), `mapConnectionEvent`/`mapPacketEvent`/`mergeLayerStats` (Task 9)
- Produces: the running application — this is the last task in the plan.

- [ ] **Step 1: Remove the simulation loop and scenario state**

In `app/page.tsx`, delete:
- The `scenario` state (`useState<TrafficScenario>`) and its setter usage
- The entire `setInterval`-based `useEffect` (the "Main High-Frequency Real-time Network Simulation Loop", currently around lines 86–185) — all of it, including the scenario-multiplier logic
- The import of `generateRandomPacket`, `INITIAL_OSI_LAYERS`, `INITIAL_CONNECTIONS` from `@/lib/osi-engine`
- The `ScenarioLabView` import and its case in the tab-rendering switch
- The `'topology'` tab remains (it's `ProtocolMatrixView`, unrelated to the simulator) but the `'scenario'`-tab entry and `lab`/`scenario` command-bar branches in `handleExecuteCommand` are removed

- [ ] **Step 2: Add live-stream state and an agent-connection banner**

Add near the top of the component, replacing the removed simulation state:

```typescript
const [agentConnected, setAgentConnected] = useState(false);
const [liveLayers, setLiveLayers] = useState<Record<OSILayerNumber, Partial<OSILayerInfo>>>({} as never);
```

Add a new `useEffect` replacing the removed simulation loop:

```typescript
useEffect(() => {
  const source = new EventSource('/api/stream');

  source.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (data.type === 'connection_status') {
      setAgentConnected(data.connected);
      return;
    }
    if (data.type === 'connection_update') {
      const connection = mapConnectionEvent(data.connection);
      setConnections((prev) => {
        const idx = prev.findIndex((c) => c.id === connection.id);
        if (idx === -1) return [connection, ...prev].slice(0, 200);
        const next = [...prev];
        next[idx] = connection;
        return next;
      });
    }
    if (data.type === 'packet') {
      const packet = mapPacketEvent(data.packet);
      setPackets((prev) => [packet, ...prev.slice(0, 100)]);
    }
    if (data.type === 'layer_update') {
      setLiveLayers((prev) => {
        const next = { ...prev };
        for (const layer of data.layers) {
          next[layer.layer as OSILayerNumber] = layer;
        }
        return next;
      });
      setLayers(mergeLayerStats({ ...liveLayers }));
    }
  };

  return () => source.close();
  // eslint-disable-next-line react-hooks/exhaustive-deps
}, []);
```

Add the corresponding imports at the top of the file:

```typescript
import { mapConnectionEvent, mapPacketEvent, mergeLayerStats } from '@/lib/agent-mapping';
```

- [ ] **Step 3: Repurpose `pause`/`resume`/`reset`**

Replace the `pause`/`resume` command-bar branches (previously toggling `isPaused`, which drove the removed `setInterval`) to instead call the control API:

```typescript
} else if (mainCmd === 'pause') {
  fetch('/api/control', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'pause' }),
  });
} else if (mainCmd === 'resume') {
  fetch('/api/control', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'resume' }),
  });
} else if (mainCmd === 'reset') {
  setConnections([]);
  setPackets([]);
```

- [ ] **Step 4: Add the "agent not connected" banner to the render output**

Near the top of the returned JSX (immediately inside the outermost container, before the existing header/tab content):

```tsx
{!agentConnected && (
  <div className="w-full bg-red-900/40 border-b border-red-700 text-red-200 text-sm px-4 py-2">
    capture agent not connected — run <code>./capture-agent</code> in <code>capture-agent/</code> (see capture-agent/README.md)
  </div>
)}
```

- [ ] **Step 5: Delete the unused simulator view**

```bash
git rm components/ScenarioLabView.tsx
```

Remove any remaining references to it (the `'scenario'` branch of `activeTab`'s type union and its rendering case) if Step 1 didn't already catch them.

- [ ] **Step 6: Manually verify the full pipeline**

Run: `cd capture-agent && cargo run --release &` then `npm run dev` from the repo root, then open `http://localhost:3000` in a browser.
Expected: the dashboard shows real connections from this Mac's own traffic (generate some by browsing to a few sites in another tab) — no fabricated data, and the layer/connection/packet views update live. Stopping the agent process should surface the "capture agent not connected" banner within a few seconds; restarting it should clear the banner automatically (no page reload needed, since `EventSource` auto-reconnects and the relay's `AgentClient` reconnects to the agent independently).

- [ ] **Step 7: Commit**

```bash
git add app/page.tsx
git commit -m "feat(web): replace simulated traffic loop with live capture stream"
```

---

## Post-plan verification

- [ ] `cd capture-agent && cargo test && cargo build --release` — all Rust tests pass, release binary builds
- [ ] `npx vitest run` — all TypeScript tests pass
- [ ] `npm run lint` — no new lint errors
- [ ] `npm run build` — Next.js production build succeeds
- [ ] End-to-end manual check per Task 12 Step 6, including the pause/resume and agent-disconnect banner behaviors

**Next plan:** `docs/superpowers/plans/2026-08-26-secure-lan-access.md` (mkcert CA, Caddy mTLS reverse proxy, LAN-string sanitization audit, native Swift/WKWebView app) — not yet written; write it once this plan's software is working end-to-end.
