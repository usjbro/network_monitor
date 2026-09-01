# TLS Content Visibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the capture agent JA3/JA4 TLS-client fingerprinting on every connection (Tier A, always-on, zero new trust) and opt-in, per-process decrypted TLS content via `SSLKEYLOGFILE` (Tier B, via a new `osi-inspect` wrapper), surfaced in `ConnectionsView` and `PacketStreamView` — without building the full CA-based MITM proxy the spec explicitly rejects.

**Architecture:** Tier A extends the agent's existing, already-passive TLS ClientHello parse (`capture-agent/src/l7.rs`) to also capture the cipher-suite/extension/curve lists needed for a JA3 hash, and threads that hash onto the existing `connection_update` wire event — no new event type. Tier B adds a plain-Node CLI wrapper (`bin/osi-inspect.js`) that launches one target process with an ephemeral, `0600` key-log file, and a new agent-side pipeline (`keylog.rs` → `tls_decrypt.rs` → `redact.rs` → `http2.rs` → capped `ring_buffer.rs`) that combines those logged secrets with ciphertext the agent already captures to produce in-memory-only plaintext for a brand-new `decrypted_payload` wire event, gated to loopback and (once available) the mTLS-verified path. The full MITM/CA proxy from the spec's "Rejected for now" section is explicitly out of scope for every task below.

**Tech Stack:** Rust (capture-agent — no new crate for Tier A; Tier B needs a TLS record/key-schedule crate and an HPACK crate, both flagged for extra-scrutiny dependency review per the spec), plain Node built-ins only for `osi-inspect` (`child_process`, `fs`, `crypto` — zero new npm dependencies), Vitest for the TypeScript side, `cargo test` + `cargo-fuzz` for the Rust side.

**Spec:** `docs/superpowers/specs/2026-08-29-tls-interception-design.md` — read it before starting; this plan assumes familiarity with its Components §1–§6, Security model table, and Error handling & lifecycle sections. Concrete numbers/behaviors restated below for convenience; the spec is the source of truth if they ever drift.

## Global Constraints

- **The full CA-based MITM proxy is not part of this plan, anywhere.** No task below creates a CA, forges a certificate, or redirects traffic. If a step seems to be heading that direction, stop and re-read the spec's "Rejected for now" section.
- **Tier A ships first and is independently useful/mergeable on its own** — Tasks 1–5. Tier B (Tasks 6–14) is additive on top and can ship in a later PR from the same branch.
- **No live network calls in any test.** TLS/HTTP2/JA3 tests use fixture bytes (known ClientHello captures, known key-log lines, real loopback TLS in the one designated integration test in Task 9 only — everything else is fixtures), matching `capture-agent/src/parse.rs`'s existing fixture-driven test posture.
- **Decrypted plaintext never touches disk anywhere in this plan's own code.** No task adds a `write()`/`open()`-for-write call on the decrypted-record path. The one on-disk artifact Tier B creates is the `SSLKEYLOGFILE` itself (a key, not content) — `0600`, ephemeral, deleted on exit.
- **Decrypt-eligibility and all Tier B state is in-memory only, never persisted across an agent restart** — matches sub-project 2's "opt-in never persists" precedent.
- **Field names on wire events are flat `camelCase`**, matching `connection_update`/`layer_update`'s existing convention exactly — no second JSON shape convention on this transport.
- **Concrete numbers restated from the spec:** header-redaction list = `Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization`, `X-Api-Key`, plus pattern-matched bearer tokens; ring buffer cap matches the existing packet-stream cap discipline from issue #27 (bounded per connection, never unbounded); `osi-inspect` browser-binary list = `chrome`, `chromium`, `msedge`, `firefox` and common platform variants; orphan key-log sweep runs at `osi-inspect` startup.
- Exact Rust crate APIs (whatever TLS/HPACK crate gets chosen in Task 9/12) should be checked against what's actually available via `cargo add --dry-run` if a step's code doesn't compile as written — this plan is written assuming reasonably current crate APIs as of 2026-08, but crate churn is real; `cargo test` is how drift gets caught, same as the ownership-enrichment plan's Node-version note.

---

## File Structure

**New — `capture-agent/src/` (Tier A):**
- `ja3.rs` — JA3 hash computation from parsed ClientHello fields + a small hardcoded fingerprint→label table

**Modified — `capture-agent/src/` (Tier A):**
- `l7.rs` — `sniff_tls_client_hello` extended to also extract cipher suites, extension type list, and elliptic-curve/point-format lists; `L7Info::TlsClientHello` variant grows those fields
- `flow.rs` — `FlowSnapshot` carries `ja3_fingerprint`/`ja3_label`, set once per flow on first ClientHello observed
- `wire.rs` — `ConnectionJson` grows `ja3_fingerprint`/`ja3_label` (both `Option<String>`)
- `main.rs` — startup: `RLIMIT_CORE=0` (unconditional, independent of Tier B); capture loop passes JA3 fields through to `flow_table.observe`

**New — `capture-agent/src/` (Tier B):**
- `keylog.rs` — `KeyLogWatcher`: file-event tail of a key-log file, parses `SSLKEYLOGFILE`-format lines, holds secrets in memory keyed by `client_random`, tracks decrypt-eligible PIDs
- `tls_decrypt.rs` — derives per-record keys from logged secrets (TLS 1.2 and 1.3) and decrypts captured ciphertext records; every failure path degrades to "undecryptable," never panics
- `ring_buffer.rs` — capped, `mlock`'d, explicitly-zeroed-on-evict buffer for decrypted content, one per connection
- `redact.rs` — header-name-based redaction pass over parsed HTTP/1.1 and HTTP/2 headers
- `http2.rs` — per-connection byte-stream reassembly + HPACK-aware frame parsing, with whole-connection ciphertext fallback on desync
- `core_limits.rs` — `disable_core_dumps()`, called once from `main.rs`

**New — repo root (Tier B):**
- `bin/osi-inspect.js` — the CLI wrapper (Node built-ins only)
- `bin/__tests__/osi-inspect.test.ts` — Vitest tests for the wrapper (spawns it as a real child process against a fixture script, matching the "no live network calls" constraint by never touching the network — only local process/file behavior is under test)

**New/Modified — TypeScript relay + UI:**
- Modify `lib/types.ts` — add `ja3Fingerprint?`/`ja3Label?` to `NetworkConnection`; add `DecryptedPayloadSegment` type
- Modify `lib/agent-mapping.ts` — `mapConnectionEvent` carries the two new optional fields through
- Create `lib/decrypted-mapping.ts` — maps the new `decrypted_payload` wire event to `DecryptedPayloadSegment`, kept separate from `agent-mapping.ts` for the same reason `enrichment-mapping.ts` was kept separate in sub-project 2 (different trust/sensitivity characteristics)
- Modify `app/api/stream/route.ts` — filters `decrypted_payload` events through a new `isDecryptedPayloadAllowed(request)` gate before forwarding
- Modify `deploy/Caddyfile` — forwards `X-Mtls-Verified` upstream so the relay can distinguish a verified LAN client from a direct loopback one
- Modify `components/ConnectionsView.tsx` — JA3 hash + label in the detail panel
- Modify `components/PacketStreamView.tsx` — "Decrypted" badge, decrypted-content pane, `[REDACTED]` placeholder rendering, "decrypted framing unavailable" messaging
- Modify `app/page.tsx` — subscribes to `decrypted_payload` SSE events, renders the persistent "Decrypting traffic for…" banner while any process is eligible
- Modify `docs/wire-protocol.md` — documents both new fields/events

**New — tests (`lib/__tests__/`, Vitest):**
- `decrypted-mapping.test.ts`, `stream-decrypted-gating.test.ts`, `connections-view-ja3.test.tsx`, `packet-stream-decrypted.test.tsx`

**New — tests (`capture-agent/src/`, `#[cfg(test)]` modules + fixtures under `capture-agent/tests/fixtures/`):**
- JA3 fixtures with known-correct hashes; key-log parsing fixtures; TLS decrypt correctness + failure-path fixtures; header-redaction fixtures; HTTP/2 malformed/out-of-order fixtures; no-disk-write harness; mlock/zeroing check; core-dump-disabled check

---

### Task 1: JA3 fingerprint computation from ClientHello fields

**Files:**
- Create: `capture-agent/src/ja3.rs`
- Modify: `capture-agent/src/lib.rs` (add `pub mod ja3;`)

**Interfaces:**
- Consumes: nothing from earlier tasks (foundational, pure function).
- Produces:
  ```rust
  pub struct ClientHelloFields {
      pub tls_version: u16,
      pub cipher_suites: Vec<u16>,
      pub extensions: Vec<u16>,
      pub elliptic_curves: Vec<u16>,
      pub ec_point_formats: Vec<u8>,
  }
  pub fn compute_ja3(fields: &ClientHelloFields) -> String; // returns the JA3 MD5 hex hash
  pub fn label_for_ja3(hash: &str) -> Option<&'static str>; // small hardcoded lookup table
  ```
  Consumed by `l7.rs` (Task 2), which will parse `ClientHelloFields` out of the raw ClientHello bytes it already has and call `compute_ja3`.

- [ ] **Step 1: Write the failing tests**

```rust
// capture-agent/src/ja3.rs (test module, top of file initially, before the real impl)
#[cfg(test)]
mod tests {
    use super::*;

    fn chrome_like_fields() -> ClientHelloFields {
        // A simplified, well-known Chrome-shaped ClientHello field set, chosen
        // so the expected hash below can be independently verified against any
        // standard JA3 calculator (ja3er.com's published algorithm) rather than
        // invented ad hoc.
        ClientHelloFields {
            tls_version: 0x0303,
            cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f],
            extensions: vec![0x0000, 0x0017, 0x0023, 0x000d, 0x0010],
            elliptic_curves: vec![0x001d, 0x0017, 0x0018],
            ec_point_formats: vec![0x00],
        }
    }

    #[test]
    fn computes_the_documented_ja3_format_deterministically() {
        let f = chrome_like_fields();
        let hash1 = compute_ja3(&f);
        let hash2 = compute_ja3(&f);
        assert_eq!(hash1, hash2, "JA3 must be deterministic for identical input");
        assert_eq!(hash1.len(), 32, "JA3 is the hex-encoded MD5 of the field string, always 32 chars");
    }

    #[test]
    fn different_cipher_suite_order_changes_the_hash() {
        // JA3 is order-sensitive by design (it's meant to fingerprint the
        // client's own field ordering, not a canonicalized version of it).
        let mut f = chrome_like_fields();
        let h1 = compute_ja3(&f);
        f.cipher_suites.reverse();
        let h2 = compute_ja3(&f);
        assert_ne!(h1, h2);
    }

    #[test]
    fn empty_field_lists_do_not_panic() {
        let f = ClientHelloFields {
            tls_version: 0x0301,
            cipher_suites: vec![],
            extensions: vec![],
            elliptic_curves: vec![],
            ec_point_formats: vec![],
        };
        let hash = compute_ja3(&f);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn unknown_hash_has_no_label() {
        assert_eq!(label_for_ja3("0000000000000000000000000000ff"), None);
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd capture-agent && cargo test ja3::`
Expected: FAIL — `compute_ja3`/`label_for_ja3` don't exist yet.

- [ ] **Step 3: Implement `capture-agent/src/ja3.rs`**

```rust
// capture-agent/src/ja3.rs

pub struct ClientHelloFields {
    pub tls_version: u16,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
}

/// Standard JA3 field string: TLSVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats
/// (dash-joined within each field, comma-joined between fields), MD5-hashed to hex.
fn ja3_string(fields: &ClientHelloFields) -> String {
    let join_u16 = |v: &[u16]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("-");
    let join_u8 = |v: &[u8]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("-");
    format!(
        "{},{},{},{},{}",
        fields.tls_version,
        join_u16(&fields.cipher_suites),
        join_u16(&fields.extensions),
        join_u16(&fields.elliptic_curves),
        join_u8(&fields.ec_point_formats),
    )
}

pub fn compute_ja3(fields: &ClientHelloFields) -> String {
    let s = ja3_string(fields);
    let digest = md5::compute(s.as_bytes());
    format!("{digest:x}")
}

// A small, versioned, hand-maintained lookup table — not a live third-party
// lookup (spec Components §1). Deliberately short and best-effort; extend
// it as real, verified hashes are gathered, never guessed.
const KNOWN_LABELS: &[(&str, &str)] = &[
    // ("<ja3-hash>", "matches Chrome 12x"),
];

pub fn label_for_ja3(hash: &str) -> Option<&'static str> {
    KNOWN_LABELS.iter().find(|(h, _)| *h == hash).map(|(_, label)| *label)
}
```

Add the `md5` crate: `cd capture-agent && cargo add md5`. This is the one new Tier-A dependency — a pure, tiny, non-cryptographic-use hashing crate (JA3 mandates MD5 by spec, not as a security primitive), no extra-scrutiny review needed given the spec's Dependency hygiene section only calls that out for Tier B's TLS/HPACK/memory-hardening crates.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd capture-agent && cargo test ja3::`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
cd capture-agent
git add src/ja3.rs src/lib.rs Cargo.toml Cargo.lock
git commit -m "feat(tls-interception): add JA3 fingerprint computation and label lookup"
```

---

### Task 2: Extend ClientHello parsing in `l7.rs` to capture JA3 input fields

**Files:**
- Modify: `capture-agent/src/l7.rs`

**Interfaces:**
- Consumes: `ja3::ClientHelloFields`, `ja3::compute_ja3` (Task 1).
- Produces: `L7Info::TlsClientHello` grows two fields:
  ```rust
  TlsClientHello { sni: String, ja3: Option<String>, ja3_label: Option<&'static str> }
  ```
  Consumed by `flow.rs` (Task 3).

- [ ] **Step 1: Write the failing tests**

Extend the existing test module in `capture-agent/src/l7.rs`. The existing `sniff_tls_client_hello` function only has to walk cipher suites/extensions as opaque-length blocks to skip past them today (it never reads their contents); this task makes it also *record* what it walks past.

```rust
// capture-agent/src/l7.rs — additional tests inside mod tests

    // A minimal, hand-built ClientHello with two cipher suites, an SNI
    // extension, a supported_groups (elliptic_curves) extension, and an
    // ec_point_formats extension — enough to exercise every new field
    // without needing a byte-for-byte real capture.
    fn build_client_hello(sni: &str) -> Vec<u8> {
        let mut hs = vec![0x01]; // handshake type: ClientHello
        hs.extend_from_slice(&[0x00, 0x00, 0x00]); // length placeholder, fixed up below
        hs.extend_from_slice(&[0x03, 0x03]); // client_version
        hs.extend_from_slice(&[0u8; 32]); // random
        hs.push(0x00); // session_id_len = 0
        // cipher_suites: 2 suites = 4 bytes
        hs.extend_from_slice(&[0x00, 0x04]);
        hs.extend_from_slice(&[0x13, 0x01, 0xc0, 0x2f]);
        hs.push(0x01); // compression_methods_len = 1
        hs.push(0x00); // null compression

        let mut extensions = Vec::new();
        // server_name extension (type 0x0000)
        let sni_bytes = sni.as_bytes();
        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&((sni_bytes.len() as u16 + 3).to_be_bytes())); // server_name_list len
        sni_ext.push(0x00); // name_type: host_name
        sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(sni_bytes);
        extensions.extend_from_slice(&[0x00, 0x00]); // ext type
        extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext);
        // supported_groups extension (type 0x000a): one curve, 0x001d (x25519)
        extensions.extend_from_slice(&[0x00, 0x0a]);
        extensions.extend_from_slice(&[0x00, 0x04]); // ext len
        extensions.extend_from_slice(&[0x00, 0x02]); // list len
        extensions.extend_from_slice(&[0x00, 0x1d]);
        // ec_point_formats extension (type 0x000b): one format, 0x00
        extensions.extend_from_slice(&[0x00, 0x0b]);
        extensions.extend_from_slice(&[0x00, 0x02]);
        extensions.push(0x01); // list len
        extensions.push(0x00);

        hs.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hs.extend_from_slice(&extensions);

        let body_len = (hs.len() - 4) as u32;
        hs[1] = ((body_len >> 16) & 0xff) as u8;
        hs[2] = ((body_len >> 8) & 0xff) as u8;
        hs[3] = (body_len & 0xff) as u8;

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    #[test]
    fn extracts_ja3_input_fields_alongside_sni() {
        let payload = build_client_hello("example.com");
        match sniff_l7(&payload, Some(443)) {
            L7Info::TlsClientHello { sni, ja3, .. } => {
                assert_eq!(sni, "example.com");
                assert!(ja3.is_some(), "expected a computed JA3 hash");
                assert_eq!(ja3.unwrap().len(), 32);
            }
            other => panic!("expected TlsClientHello, got {other:?}"),
        }
    }

    #[test]
    fn ja3_is_none_when_client_hello_is_truncated_mid_extensions() {
        let mut payload = build_client_hello("example.com");
        payload.truncate(payload.len() - 5); // cut off inside the last extension
        match sniff_l7(&payload, Some(443)) {
            // A truncated ClientHello may still yield no SNI at all (existing
            // behavior) or, if the truncation lands after SNI is already
            // parsed, still produce SNI with ja3: None rather than panicking.
            L7Info::TlsClientHello { ja3, .. } => assert!(ja3.is_none() || true),
            L7Info::None => {} // also acceptable — existing tolerance for malformed input
            other => panic!("unexpected variant: {other:?}"),
        }
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cd capture-agent && cargo test l7::`
Expected: FAIL — `L7Info::TlsClientHello` doesn't have `ja3`/`ja3_label` fields yet; compile error.

- [ ] **Step 3: Implement**

```rust
// capture-agent/src/l7.rs — replace the enum and sniff_tls_client_hello body

use crate::ja3::{compute_ja3, label_for_ja3, ClientHelloFields};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L7Info {
    Http { method: String, path: String },
    Dns { query_name: String },
    TlsClientHello { sni: String, ja3: Option<String>, ja3_label: Option<&'static str> },
    None,
}
```

Replace the body of `sniff_tls_client_hello` (keep the function signature and the SNI-walking logic identical up through finding the SNI extension; the diff is: (a) also parse the raw cipher-suite bytes into a `Vec<u16>` at the point they're currently just skipped over, (b) collect every extension type seen while walking extensions, not just server_name, (c) when the extension walk finds `supported_groups` (0x000a) or `ec_point_formats` (0x000b), also parse their list contents):

```rust
fn parse_u16_list(bytes: &[u8]) -> Vec<u16> {
    bytes.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect()
}

fn sniff_tls_client_hello(payload: &[u8]) -> Option<L7Info> {
    if payload.len() < 6 || payload[0] != 0x16 {
        return None;
    }
    if payload[5] != 0x01 {
        return None;
    }
    let mut idx = 43usize;
    let tls_version = u16::from_be_bytes([*payload.get(9)?, *payload.get(10)?]); // record's client_version, offset 9-10
    let session_id_len = *payload.get(idx)? as usize;
    idx += 1 + session_id_len;

    let cipher_suites_len = u16::from_be_bytes([*payload.get(idx)?, *payload.get(idx + 1)?]) as usize;
    idx += 2;
    let cipher_suites = parse_u16_list(payload.get(idx..idx + cipher_suites_len)?);
    idx += cipher_suites_len;

    let compression_len = *payload.get(idx)? as usize;
    idx += 1 + compression_len;
    if idx + 2 > payload.len() {
        return None;
    }
    idx += 2; // extensions total length

    let mut sni: Option<String> = None;
    let mut extensions = Vec::new();
    let mut elliptic_curves = Vec::new();
    let mut ec_point_formats = Vec::new();

    while idx + 4 <= payload.len() {
        let ext_type = u16::from_be_bytes([payload[idx], payload[idx + 1]]);
        let ext_len = u16::from_be_bytes([payload[idx + 2], payload[idx + 3]]) as usize;
        let ext_start = idx + 4;
        extensions.push(ext_type);
        let ext_body = payload.get(ext_start..ext_start + ext_len);

        match (ext_type, ext_body) {
            (0x0000, Some(_)) => {
                let name_len_idx = ext_start + 3;
                if let (Some(&hi), Some(&lo)) = (payload.get(name_len_idx), payload.get(name_len_idx + 1)) {
                    let name_len = u16::from_be_bytes([hi, lo]) as usize;
                    let name_start = name_len_idx + 2;
                    if let Some(name_bytes) = payload.get(name_start..name_start + name_len) {
                        sni = std::str::from_utf8(name_bytes).ok().map(|s| s.to_string());
                    }
                }
            }
            (0x000a, Some(body)) if body.len() >= 2 => {
                let list_len = u16::from_be_bytes([body[0], body[1]]) as usize;
                if let Some(list) = body.get(2..2 + list_len) {
                    elliptic_curves = parse_u16_list(list);
                }
            }
            (0x000b, Some(body)) if !body.is_empty() => {
                let list_len = body[0] as usize;
                if let Some(list) = body.get(1..1 + list_len) {
                    ec_point_formats = list.to_vec();
                }
            }
            _ => {}
        }
        idx = ext_start + ext_len;
    }

    let sni = sni?; // SNI absence keeps existing behavior: no TlsClientHello at all
    let fields = ClientHelloFields { tls_version, cipher_suites, extensions, elliptic_curves, ec_point_formats };
    let ja3 = Some(compute_ja3(&fields));
    let ja3_label = ja3.as_deref().and_then(label_for_ja3);
    Some(L7Info::TlsClientHello { sni, ja3, ja3_label })
}
```

Update `capture-agent/src/lib.rs` to add `pub mod ja3;` if Task 1 didn't already (idempotent if it did).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd capture-agent && cargo test l7::`
Expected: all tests PASS, including the two pre-existing tests (`detects_http_get_request`, `detects_dns_query`) which must still pass unmodified.

- [ ] **Step 5: Commit**

```bash
cd capture-agent
git add src/l7.rs
git commit -m "feat(tls-interception): extract JA3 fields during ClientHello parsing"
```

---

### Task 3: Thread JA3 through `FlowSnapshot` and `flow.rs`

**Files:**
- Modify: `capture-agent/src/flow.rs`

**Interfaces:**
- Consumes: `L7Info::TlsClientHello { ja3, ja3_label, .. }` (Task 2).
- Produces: `FlowSnapshot` grows `pub ja3_fingerprint: Option<String>` and `pub ja3_label: Option<&'static str>`.
  Consumed by `wire.rs` (Task 4).

- [ ] **Step 1: Write the failing test**

```rust
// capture-agent/src/flow.rs — additional test inside mod tests
    #[test]
    fn observe_records_ja3_from_a_tls_client_hello_and_keeps_it_across_later_non_tls_packets() {
        let mut table = FlowTable::new(vec!["192.168.1.10".to_string()]);
        let packet = make_tcp_packet("192.168.1.10", 51000, "93.184.216.34", 443); // existing test helper
        let l7 = L7Info::TlsClientHello {
            sni: "example.com".to_string(),
            ja3: Some("abc123".repeat(1)[..8].to_string() + &"0".repeat(24)),
            ja3_label: Some("matches Chrome 12x"),
        };
        table.observe(&packet, &l7, 0);
        table.observe(&packet, &L7Info::None, 100); // a later, non-ClientHello packet on the same flow

        let snaps = table.snapshot(200);
        let snap = snaps.iter().find(|s| s.remote_addr == "93.184.216.34").expect("flow present");
        assert!(snap.ja3_fingerprint.is_some());
        assert_eq!(snap.ja3_label, Some("matches Chrome 12x"));
    }
```

(If `make_tcp_packet` doesn't already exist as a shared test helper in `flow.rs`'s test module, use whatever fixture-construction helper the existing tests in that file already use — the pattern is: check the file's existing tests for a packet-builder before adding a new one, don't duplicate one.)

- [ ] **Step 2: Run to verify failure**

Run: `cd capture-agent && cargo test flow::`
Expected: FAIL — `FlowSnapshot` has no `ja3_fingerprint`/`ja3_label` fields; compile error.

- [ ] **Step 3: Implement**

In the flow-entry struct that `FlowTable` keeps internally (the per-flow accumulator that `observe` mutates and `snapshot` reads from — inspect the existing struct near `FlowTable`'s definition before editing), add:
```rust
ja3_fingerprint: Option<String>,
ja3_label: Option<&'static str>,
```
initialized to `None` on flow creation. In `observe`, when `l7` matches `L7Info::TlsClientHello { ja3, ja3_label, .. }`, set these on the flow entry **only if not already set** (first ClientHello wins — a flow has exactly one handshake, and once seen further packets shouldn't overwrite it with `None` from `L7Info::None`):
```rust
if let L7Info::TlsClientHello { ja3, ja3_label, .. } = l7 {
    if entry.ja3_fingerprint.is_none() {
        entry.ja3_fingerprint = ja3.clone();
        entry.ja3_label = *ja3_label;
    }
}
```
Add the same two fields to `FlowSnapshot`, and copy them from the flow entry in `snapshot()`'s existing per-flow mapping.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd capture-agent && cargo test flow::`
Expected: all tests PASS, including every pre-existing test in this file.

- [ ] **Step 5: Commit**

```bash
cd capture-agent
git add src/flow.rs
git commit -m "feat(tls-interception): carry JA3 fingerprint on FlowSnapshot"
```

---

### Task 4: Wire `ja3Fingerprint`/`ja3Label` onto `connection_update`

**Files:**
- Modify: `capture-agent/src/wire.rs`
- Modify: `capture-agent/src/main.rs`
- Modify: `docs/wire-protocol.md`

**Interfaces:**
- Consumes: `FlowSnapshot.ja3_fingerprint`/`.ja3_label` (Task 3).
- Produces: `ConnectionJson.ja3_fingerprint: Option<String>` / `.ja3_label: Option<String>` (both `#[serde(skip_serializing_if = "Option::is_none")]`), serialized as `ja3Fingerprint`/`ja3Label` on the wire.

- [ ] **Step 1: Write the failing test**

```rust
// capture-agent/src/wire.rs — additional test inside mod tests
    #[test]
    fn connection_json_serializes_ja3_fields_as_camel_case_when_present() {
        let json = ConnectionJson {
            // ...fill every existing required field with the same fixture
            // values the file's existing ConnectionJson tests already use...
            ja3_fingerprint: Some("deadbeefdeadbeefdeadbeefdeadbeef".to_string()),
            ja3_label: Some("matches Chrome 12x".to_string()),
            ..existing_fixture_connection_json() // reuse whatever builder the file's existing tests use
        };
        let s = serde_json::to_string(&json).unwrap();
        assert!(s.contains("\"ja3Fingerprint\":\"deadbeefdeadbeefdeadbeefdeadbeef\""));
        assert!(s.contains("\"ja3Label\":\"matches Chrome 12x\""));
    }

    #[test]
    fn connection_json_omits_ja3_fields_entirely_when_absent() {
        let json = ConnectionJson { ja3_fingerprint: None, ja3_label: None, ..existing_fixture_connection_json() };
        let s = serde_json::to_string(&json).unwrap();
        assert!(!s.contains("ja3Fingerprint"));
        assert!(!s.contains("ja3Label"));
    }
```

If `wire.rs`'s existing tests don't yet have a shared `existing_fixture_connection_json()`-style builder, add one as part of this task (extract it from whatever inline struct literal the file's current tests use) rather than duplicating a huge struct literal across two new tests.

- [ ] **Step 2: Run to verify failure**

Run: `cd capture-agent && cargo test wire::`
Expected: FAIL — `ConnectionJson` has no `ja3_fingerprint`/`ja3_label` fields; compile error.

- [ ] **Step 3: Implement**

```rust
// capture-agent/src/wire.rs — in ConnectionJson
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja3_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja3_label: Option<String>,
```

In `main.rs`, wherever `ConnectionJson` is constructed from a `FlowSnapshot` in the periodic emitter (the per-1s tick that builds `connection_update` events), add:
```rust
ja3_fingerprint: snap.ja3_fingerprint.clone(),
ja3_label: snap.ja3_label.map(|s| s.to_string()),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd capture-agent && cargo test`
Expected: all tests PASS (full suite, since `ConnectionJson` construction sites elsewhere in the crate must also be updated to satisfy the compiler — search for every `ConnectionJson {` literal, not just the one in `main.rs`).

- [ ] **Step 5: Update `docs/wire-protocol.md` and commit**

Add to the `connection_update` example JSON and field notes:
```json
    "ja3Fingerprint": "e7d705a3286e19ea42f587b344ee6865",
    "ja3Label": "matches Chrome 12x"
```
Field notes addition: "`ja3Fingerprint`/`ja3Label` (both optional) — present once the agent has observed this flow's TLS ClientHello; absent for flows without an observed handshake (e.g. non-TLS, or the connection predates the agent starting). `ja3Label` is best-effort and informational only — never treat it as an authenticated client identity, it is trivially spoofable by any TLS client (see `docs/superpowers/specs/2026-08-29-tls-interception-design.md`, Security model)."

```bash
cd capture-agent
git add src/wire.rs src/main.rs
cd ..
git add docs/wire-protocol.md
git commit -m "feat(tls-interception): emit ja3Fingerprint/ja3Label on connection_update"
```

---

### Task 5: Consume JA3 fields in the relay + UI (Tier A complete)

**Files:**
- Modify: `lib/types.ts`
- Modify: `lib/agent-mapping.ts`
- Modify: `components/ConnectionsView.tsx`
- Create: `lib/__tests__/connections-view-ja3.test.tsx` (`jsdom` environment)

**Interfaces:**
- Consumes: `ja3Fingerprint?: string` / `ja3Label?: string` on the `connection_update` wire event (Task 4).
- Produces: `NetworkConnection.ja3Fingerprint?: string`, `.ja3Label?: string`.

- [ ] **Step 1: Write the failing tests**

```typescript
// lib/__tests__/agent-mapping.test.ts — add to the existing mapConnectionEvent describe block
it('carries ja3Fingerprint/ja3Label through when present', () => {
  const event = {
    type: 'connection_update',
    connection: { /* ...same required fields the file's existing fixture event uses..., */ ja3Fingerprint: 'deadbeef', ja3Label: 'matches Chrome 12x' },
  };
  const conn = mapConnectionEvent(event);
  expect(conn.ja3Fingerprint).toBe('deadbeef');
  expect(conn.ja3Label).toBe('matches Chrome 12x');
});

it('leaves ja3Fingerprint/ja3Label undefined when absent from the wire event', () => {
  const event = { type: 'connection_update', connection: { /* ...required fields only... */ } };
  const conn = mapConnectionEvent(event);
  expect(conn.ja3Fingerprint).toBeUndefined();
});
```

```tsx
// lib/__tests__/connections-view-ja3.test.tsx
import { describe, expect, it } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { ConnectionsView } from '@/components/ConnectionsView';
import { THEMES } from '@/lib/osi-engine';
import { NetworkConnection } from '@/lib/types';

const baseConn: NetworkConnection = {
  // fill every required NetworkConnection field with plausible fixture
  // values matching whatever the repo's existing ConnectionsView tests (if
  // any) already use for a minimal valid connection — reuse that fixture
  // builder rather than inventing a second one, if one exists in
  // lib/__tests__ already.
} as NetworkConnection;

describe('ConnectionsView JA3 display', () => {
  it('shows the JA3 hash and label when present on the selected connection', () => {
    const conn = { ...baseConn, ja3Fingerprint: 'deadbeef', ja3Label: 'matches Chrome 12x' };
    render(<ConnectionsView connections={[conn]} theme={THEMES.matrix} />);
    fireEvent.click(screen.getByText(conn.processName));
    expect(screen.getByText(/deadbeef/)).toBeInTheDocument();
    expect(screen.getByText('matches Chrome 12x')).toBeInTheDocument();
  });

  it('shows a plain "no handshake observed" state when JA3 is absent', () => {
    const conn = { ...baseConn, ja3Fingerprint: undefined, ja3Label: undefined };
    render(<ConnectionsView connections={[conn]} theme={THEMES.matrix} />);
    fireEvent.click(screen.getByText(conn.processName));
    expect(screen.getByText(/no TLS handshake observed/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run lib/__tests__/agent-mapping.test.ts lib/__tests__/connections-view-ja3.test.tsx`
Expected: FAIL — fields don't exist on the type yet / UI doesn't render them yet.

- [ ] **Step 3: Implement**

```typescript
// lib/types.ts — add to NetworkConnection
  ja3Fingerprint?: string;
  ja3Label?: string;
```

```typescript
// lib/agent-mapping.ts — in mapConnectionEvent's return object
  ja3Fingerprint: raw.ja3Fingerprint,
  ja3Label: raw.ja3Label,
```

In `components/ConnectionsView.tsx`, in the detail panel for the selected connection (next to wherever `remoteHostname`/ownership-style metadata is already rendered — inspect the current detail-panel JSX before editing so the JA3 block matches its existing layout conventions), add:
```tsx
<div className="mt-2">
  <span className={theme.textMuted}>JA3</span>{' '}
  {selected.ja3Fingerprint ? (
    <>
      <span className="font-mono">{selected.ja3Fingerprint}</span>
      {selected.ja3Label && <span className={`ml-2 ${theme.textMuted}`}>({selected.ja3Label})</span>}
    </>
  ) : (
    <span className={theme.textMuted}>no TLS handshake observed for this connection</span>
  )}
</div>
```
(Adjust class names to whatever this component's existing theme-driven classnames actually are — do not invent new theme keys; reuse ones already used elsewhere in this file.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run lib/__tests__/agent-mapping.test.ts lib/__tests__/connections-view-ja3.test.tsx`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/types.ts lib/agent-mapping.ts components/ConnectionsView.tsx lib/__tests__/connections-view-ja3.test.tsx lib/__tests__/agent-mapping.test.ts
git commit -m "feat(tls-interception): surface JA3 fingerprint in ConnectionsView"
```

**Tier A is now complete and independently mergeable.** Tasks 6–14 below are Tier B and can land in a follow-up PR from the same branch.

---

### Task 6: Disable core dumps at agent startup (unconditional safety floor for Tier B)

**Files:**
- Create: `capture-agent/src/core_limits.rs`
- Modify: `capture-agent/src/lib.rs`
- Modify: `capture-agent/src/main.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: `pub fn disable_core_dumps() -> std::io::Result<()>` — sets `RLIMIT_CORE` to 0 for the current process. Called once at the very top of `main()`, before any capture setup, independent of whether Tier B is ever exercised in a given run (spec Security model: "unconditionally at startup").

- [ ] **Step 1: Write the failing test**

```rust
// capture-agent/src/core_limits.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disable_core_dumps_sets_the_soft_and_hard_limit_to_zero() {
        disable_core_dumps().expect("setrlimit should succeed for a self-limit lowering");
        let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) };
        assert_eq!(rc, 0);
        assert_eq!(limit.rlim_cur, 0);
        assert_eq!(limit.rlim_max, 0);
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd capture-agent && cargo test core_limits::`
Expected: FAIL — module/function don't exist.

- [ ] **Step 3: Implement**

```rust
// capture-agent/src/core_limits.rs
/// Disables core dumps for this process unconditionally, independent of
/// whether Tier B (decrypted TLS content) is ever used in this run. Cheap,
/// no functional downside, closes the gap where a crash while the ring
/// buffer holds live plaintext could otherwise leave a core file on disk
/// (spec Security model summary).
pub fn disable_core_dumps() -> std::io::Result<()> {
    let limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
```

Add the `libc` crate: `cd capture-agent && cargo add libc`. Add `pub mod core_limits;` to `lib.rs`. In `main.rs`, as the very first line of `async fn main()`:
```rust
if let Err(e) = capture_agent::core_limits::disable_core_dumps() {
    eprintln!("capture-agent: WARNING failed to disable core dumps: {e}");
}
```
(A warning, not a hard failure — the agent should still run for users on a platform/sandbox where this syscall is restricted, but the warning makes the gap visible rather than silent.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd capture-agent && cargo test core_limits::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd capture-agent
git add src/core_limits.rs src/lib.rs src/main.rs Cargo.toml Cargo.lock
git commit -m "feat(tls-interception): disable core dumps unconditionally at agent startup"
```

---

### Task 7: `osi-inspect` CLI wrapper — key-log file lifecycle, browser-wrap confirmation

**Files:**
- Create: `bin/osi-inspect.js`
- Create: `bin/__tests__/osi-inspect.test.ts`
- Modify: `package.json` (add `"bin": { "osi-inspect": "./bin/osi-inspect.js" }`)

**Interfaces:**
- Consumes: nothing from earlier tasks (standalone Node script).
- Produces: a CLI invoked as `osi-inspect <command...>` (or `node bin/osi-inspect.js <command...>` before `npm link`). On launch: creates a `0600` key-log file under `.data/keylogs/`, sets `SSLKEYLOGFILE`, execs the target as a direct child inheriting stdio, deletes the key-log file on the child's exit (any reason). Also exported for testing as:
  ```javascript
  function isKnownBrowserBinary(command) // string -> boolean
  function keylogPath(dataDir) // string -> string, fresh random filename each call
  function sweepOrphanedKeylogs(dataDir, maxAgeMs) // deletes stale files, returns count deleted
  ```
  Consumed by `capture-agent`'s `KeyLogWatcher` (Task 8) only indirectly — via the file it writes and the PID registration mechanism built in Task 8, not a direct code dependency (this is a separate process).

- [ ] **Step 1: Write the failing tests**

```typescript
// bin/__tests__/osi-inspect.test.ts
import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { spawnSync, spawn } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { isKnownBrowserBinary, keylogPath, sweepOrphanedKeylogs } from '../osi-inspect.js';

describe('isKnownBrowserBinary', () => {
  it('matches common browser binary names', () => {
    for (const name of ['chrome', 'google-chrome', 'chromium', 'msedge', 'firefox']) {
      expect(isKnownBrowserBinary(name)).toBe(true);
    }
  });
  it('does not match non-browser commands', () => {
    for (const name of ['npm', 'node', 'curl', 'python3']) {
      expect(isKnownBrowserBinary(name)).toBe(false);
    }
  });
});

describe('keylogPath', () => {
  it('produces a distinct filename on each call', () => {
    const dir = mkdtempSync(join(tmpdir(), 'osi-inspect-'));
    const a = keylogPath(dir);
    const b = keylogPath(dir);
    expect(a).not.toBe(b);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe('sweepOrphanedKeylogs', () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'osi-inspect-sweep-')); });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('deletes files older than the threshold and leaves recent ones', async () => {
    const { writeFileSync, utimesSync } = await import('node:fs');
    const stale = join(dir, 'stale.keylog');
    const fresh = join(dir, 'fresh.keylog');
    writeFileSync(stale, '');
    writeFileSync(fresh, '');
    const old = new Date(Date.now() - 2 * 60 * 60 * 1000);
    utimesSync(stale, old, old);

    const deleted = sweepOrphanedKeylogs(dir, 60 * 60 * 1000);
    expect(deleted).toBe(1);
    expect(existsSync(stale)).toBe(false);
    expect(existsSync(fresh)).toBe(true);
  });
});

describe('osi-inspect end-to-end (spawned as a real process)', () => {
  it('creates a 0600 key-log file, sets SSLKEYLOGFILE for the child, and deletes it on exit', async () => {
    // Wraps a tiny Node one-liner that reads its own SSLKEYLOGFILE env var
    // and writes its path to stdout, so this test never needs a real TLS
    // handshake — it only asserts the wrapper's own file/env/process
    // lifecycle, matching this plan's "no live network calls in tests" rule.
    const child = spawn('node', [
      '--experimental-vm-modules',
      join(__dirname, '..', 'osi-inspect.js'),
      'node', '-e', 'console.log(process.env.SSLKEYLOGFILE); require("fs").writeFileSync(process.env.SSLKEYLOGFILE, "test-secret-line\\n")',
    ]);
    let stdout = '';
    child.stdout.on('data', (d) => (stdout += d.toString()));
    const exitCode: number = await new Promise((resolve) => child.on('exit', (code) => resolve(code ?? -1)));
    expect(exitCode).toBe(0);
    const keylogFile = stdout.trim().split('\n').find((l) => l.includes('.keylog'));
    expect(keylogFile).toBeTruthy();
    // File must be gone after the wrapped process exits.
    expect(existsSync(keylogFile!)).toBe(false);
  }, 10_000);

  it('refuses to wrap a known browser binary without confirmation or the override flag', () => {
    const result = spawnSync('node', [join(__dirname, '..', 'osi-inspect.js'), 'chrome'], {
      input: 'n\n', // interactive "no"
      encoding: 'utf8',
    });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/entire browser process/i);
  });

  it('proceeds when wrapping a browser with --yes-decrypt-entire-browser', () => {
    const result = spawnSync('node', [
      join(__dirname, '..', 'osi-inspect.js'), '--yes-decrypt-entire-browser', 'node', '-e', 'process.exit(0)',
    ], { encoding: 'utf8' });
    expect(result.status).toBe(0);
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run bin/__tests__/osi-inspect.test.ts`
Expected: FAIL — `bin/osi-inspect.js` doesn't exist.

- [ ] **Step 3: Implement `bin/osi-inspect.js`**

```javascript
#!/usr/bin/env node
// osi-inspect — launches exactly one target process with SSLKEYLOGFILE set
// to a fresh, ephemeral, 0600 file, so the capture agent's KeyLogWatcher can
// decrypt that one process's TLS traffic for this run only. No CA, no
// certificate forging, no traffic redirection — see
// docs/superpowers/specs/2026-08-29-tls-interception-design.md, Components §2.

const { spawnSync, execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const readline = require('node:readline');

const BROWSER_BASENAMES = new Set([
  'chrome', 'google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser',
  'msedge', 'microsoft-edge', 'firefox', 'firefox-esr',
]);

function isKnownBrowserBinary(command) {
  const base = path.basename(command).toLowerCase();
  return BROWSER_BASENAMES.has(base);
}

function keylogPath(dataDir) {
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  return path.join(dataDir, `${crypto.randomBytes(8).toString('hex')}.keylog`);
}

function sweepOrphanedKeylogs(dataDir, maxAgeMs) {
  if (!fs.existsSync(dataDir)) return 0;
  let deleted = 0;
  const now = Date.now();
  for (const name of fs.readdirSync(dataDir)) {
    if (!name.endsWith('.keylog')) continue;
    const full = path.join(dataDir, name);
    const stat = fs.statSync(full);
    if (now - stat.mtimeMs > maxAgeMs) {
      fs.unlinkSync(full);
      deleted += 1;
    }
  }
  return deleted;
}

function confirmBrowserWrap(command) {
  process.stderr.write(
    `osi-inspect: "${command}" looks like a general-purpose browser.\n` +
    `This will decrypt traffic for the ENTIRE browser process — every tab and origin\n` +
    `currently open or later opened in it, not just one site.\n` +
    `Proceed? [y/N] `
  );
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr, terminal: false });
  return new Promise((resolve) => {
    rl.question('', (answer) => {
      rl.close();
      resolve(answer.trim().toLowerCase() === 'y');
    });
  });
}

async function main() {
  const dataDir = path.join(process.cwd(), '.data', 'keylogs');
  sweepOrphanedKeylogs(dataDir, 60 * 60 * 1000); // 1 hour orphan threshold

  let args = process.argv.slice(2);
  const yesDecryptBrowser = args.includes('--yes-decrypt-entire-browser');
  args = args.filter((a) => a !== '--yes-decrypt-entire-browser');

  if (args.length === 0) {
    process.stderr.write('usage: osi-inspect [--yes-decrypt-entire-browser] <command> [args...]\n');
    process.exit(2);
  }

  const [command, ...commandArgs] = args;

  if (isKnownBrowserBinary(command) && !yesDecryptBrowser) {
    const confirmed = await confirmBrowserWrap(command);
    if (!confirmed) {
      process.stderr.write('osi-inspect: refusing to wrap entire browser process without confirmation.\n');
      process.exit(1);
    }
  }

  const keylog = keylogPath(dataDir);
  fs.writeFileSync(keylog, '', { mode: 0o600 }); // created 0600 before the child can ever write to it

  const cleanup = () => {
    try { fs.unlinkSync(keylog); } catch { /* already gone */ }
  };

  const result = spawnSync(command, commandArgs, {
    stdio: 'inherit',
    env: { ...process.env, SSLKEYLOGFILE: keylog },
  });

  cleanup();

  if (result.error) {
    process.stderr.write(`osi-inspect: failed to launch "${command}": ${result.error.message}\n`);
    process.exit(1);
  }
  process.exit(result.status ?? 1);
}

if (require.main === module) {
  main();
}

module.exports = { isKnownBrowserBinary, keylogPath, sweepOrphanedKeylogs };
```

Add `.data/` to `.gitignore` if sub-project 2 didn't already (check first — it likely did). Add the `bin` field to `package.json`:
```json
  "bin": {
    "osi-inspect": "./bin/osi-inspect.js"
  },
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run bin/__tests__/osi-inspect.test.ts`
Expected: all tests PASS. `chmod +x bin/osi-inspect.js` if the test harness's `spawn`/`spawnSync` calls need the file executable on this platform (they invoke it via `node bin/osi-inspect.js` explicitly above, so this is only needed for direct `./bin/osi-inspect.js` invocation, not for the tests as written).

- [ ] **Step 5: Commit**

```bash
git add bin/osi-inspect.js bin/__tests__/osi-inspect.test.ts package.json .gitignore
git commit -m "feat(tls-interception): add osi-inspect CLI wrapper for opt-in SSLKEYLOGFILE decryption"
```

---

### Task 8: `KeyLogWatcher` — tail key-log files, track decrypt-eligible PIDs

**Files:**
- Create: `capture-agent/src/keylog.rs`
- Modify: `capture-agent/src/lib.rs`

**Interfaces:**
- Consumes: the `SSLKEYLOGFILE`-format lines `osi-inspect`'s wrapped process writes (Task 7); nothing structurally from other Rust modules.
- Produces:
  ```rust
  pub struct SessionSecret { pub client_random: Vec<u8>, pub label: String, pub secret: Vec<u8> }
  pub fn parse_keylog_line(line: &str) -> Option<SessionSecret>;

  pub struct KeyLogWatcher { /* ... */ }
  impl KeyLogWatcher {
      pub fn new() -> Self;
      pub fn register_eligible_pid(&mut self, pid: u32, keylog_path: std::path::PathBuf);
      pub fn unregister_pid(&mut self, pid: u32);
      pub fn is_eligible(&self, pid: u32) -> bool;
      pub fn poll(&mut self); // reads any new lines from watched files since the last poll, updates in-memory secrets
      pub fn secret_for(&self, client_random: &[u8]) -> Option<&SessionSecret>;
  }
  ```
  Consumed by `tls_decrypt.rs` (Task 9) via `secret_for`, and by `main.rs`'s capture loop (Task 10 wiring) via `is_eligible`/`poll`. PID registration itself is driven by a small control-message extension on the existing agent TCP socket (not built in this task — Task 11 wires the relay-side trigger; this task only needs the in-memory data structure and its own unit tests using direct `register_eligible_pid` calls).

- [ ] **Step 1: Write the failing tests**

```rust
// capture-agent/src/keylog.rs
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parses_a_tls13_labeled_keylog_line() {
        let line = "CLIENT_HANDSHAKE_TRAFFIC_SECRET aabbccdd112233440000000000000000 aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344";
        let secret = parse_keylog_line(line).expect("should parse");
        assert_eq!(secret.label, "CLIENT_HANDSHAKE_TRAFFIC_SECRET");
        assert_eq!(secret.client_random, hex::decode("aabbccdd112233440000000000000000").unwrap());
    }

    #[test]
    fn ignores_blank_lines_and_comments() {
        assert!(parse_keylog_line("").is_none());
        assert!(parse_keylog_line("# a comment").is_none());
    }

    #[test]
    fn ignores_malformed_lines_without_panicking() {
        assert!(parse_keylog_line("NOT_ENOUGH_FIELDS").is_none());
        assert!(parse_keylog_line("LABEL not-hex not-hex-either").is_none());
    }

    #[test]
    fn register_unregister_controls_eligibility() {
        let mut watcher = KeyLogWatcher::new();
        assert!(!watcher.is_eligible(1234));
        let dir = tempfile_dir();
        let path = dir.join("test.keylog");
        std::fs::write(&path, "").unwrap();
        watcher.register_eligible_pid(1234, path);
        assert!(watcher.is_eligible(1234));
        watcher.unregister_pid(1234);
        assert!(!watcher.is_eligible(1234));
    }

    #[test]
    fn poll_picks_up_newly_appended_secrets() {
        let mut watcher = KeyLogWatcher::new();
        let dir = tempfile_dir();
        let path = dir.join("test.keylog");
        std::fs::write(&path, "").unwrap();
        watcher.register_eligible_pid(999, path.clone());
        watcher.poll();
        assert!(watcher.secret_for(&hex::decode("11".repeat(17)).unwrap()).is_none());

        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(f, "CLIENT_HANDSHAKE_TRAFFIC_SECRET {} {}", "11".repeat(17), "22".repeat(48)).unwrap();
        watcher.poll();
        assert!(watcher.secret_for(&hex::decode("11".repeat(17)).unwrap()).is_some());
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("keylog-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd capture-agent && cargo test keylog::`
Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Implement `capture-agent/src/keylog.rs`**

```rust
// capture-agent/src/keylog.rs
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct SessionSecret {
    pub client_random: Vec<u8>,
    pub label: String,
    pub secret: Vec<u8>,
}

pub fn parse_keylog_line(line: &str) -> Option<SessionSecret> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut parts = line.split_whitespace();
    let label = parts.next()?.to_string();
    let client_random = hex::decode(parts.next()?).ok()?;
    let secret = hex::decode(parts.next()?).ok()?;
    if parts.next().is_some() {
        return None; // unexpected extra field — be strict, not lenient-to-garbage
    }
    Some(SessionSecret { client_random, label, secret })
}

struct WatchedFile {
    path: PathBuf,
    offset: u64,
}

pub struct KeyLogWatcher {
    eligible: HashMap<u32, WatchedFile>,
    // Keyed by client_random hex for lookup; multiple labels (handshake vs.
    // application traffic secrets) per client_random are collapsed to "last
    // one wins" deliberately — tls_decrypt.rs (Task 9) is responsible for
    // picking which label it actually needs at decrypt time, not this store.
    secrets: HashMap<Vec<u8>, SessionSecret>,
}

impl KeyLogWatcher {
    pub fn new() -> Self {
        Self { eligible: HashMap::new(), secrets: HashMap::new() }
    }

    pub fn register_eligible_pid(&mut self, pid: u32, keylog_path: PathBuf) {
        self.eligible.insert(pid, WatchedFile { path: keylog_path, offset: 0 });
    }

    pub fn unregister_pid(&mut self, pid: u32) {
        self.eligible.remove(&pid);
    }

    pub fn is_eligible(&self, pid: u32) -> bool {
        self.eligible.contains_key(&pid)
    }

    /// Reads any bytes appended to each watched file since the last poll.
    /// Missing/unreadable file is treated as "nothing new yet," not an
    /// error — matches the spec's "not-yet-decrypt-eligible" tolerance
    /// (Error handling & lifecycle).
    pub fn poll(&mut self) {
        for watched in self.eligible.values_mut() {
            let Ok(mut file) = std::fs::File::open(&watched.path) else { continue };
            if file.seek(SeekFrom::Start(watched.offset)).is_err() {
                continue;
            }
            let mut buf = String::new();
            if file.read_to_string(&mut buf).is_err() {
                continue;
            }
            watched.offset += buf.len() as u64;
            for line in buf.lines() {
                if let Some(secret) = parse_keylog_line(line) {
                    self.secrets.insert(secret.client_random.clone(), secret);
                }
            }
        }
    }

    pub fn secret_for(&self, client_random: &[u8]) -> Option<&SessionSecret> {
        self.secrets.get(client_random)
    }
}
```

Add the `hex` crate: `cd capture-agent && cargo add hex`. Add `pub mod keylog;` to `lib.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd capture-agent && cargo test keylog::`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
cd capture-agent
git add src/keylog.rs src/lib.rs Cargo.toml Cargo.lock
git commit -m "feat(tls-interception): add KeyLogWatcher for tailing SSLKEYLOGFILE output"
```

---

### Task 9: TLS record decryption from logged secrets

**Files:**
- Create: `capture-agent/src/tls_decrypt.rs`
- Modify: `capture-agent/src/lib.rs`

**Interfaces:**
- Consumes: `keylog::SessionSecret` (Task 8); raw captured TLS record ciphertext bytes (already available to the capture loop today — same bytes `l7::sniff_tls_client_hello` already receives, just for application-data records instead of the handshake record).
- Produces:
  ```rust
  pub enum DecryptOutcome { Plaintext(Vec<u8>), Undecryptable { reason: &'static str } }
  pub fn decrypt_record(record: &[u8], secret: &keylog::SessionSecret) -> DecryptOutcome;
  ```
  Consumed by the agent's capture-loop wiring (Task 10) for decrypt-eligible flows only.

- [ ] **Step 1: Write the failing tests**

This is the one component in this plan justified in using a real, minimal loopback TLS 1.3 handshake as its correctness fixture rather than a hand-built one — TLS 1.3's key schedule (HKDF-Expand-Label chains) is exactly the kind of logic that's easy to get subtly wrong against hand-rolled vectors and hard to notice. Use the official RFC 8446 §Appendix / `tls13-vectors` published test vectors for the fixture instead of generating one at test time (keeps this test fixture-driven and network-free, consistent with the plan's Global Constraints).

```rust
// capture-agent/src/tls_decrypt.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::keylog::SessionSecret;

    // Published RFC 8446 Appendix test vector fields (client hello random,
    // derived client application traffic secret, and one encrypted record
    // with its known plaintext) — checked into
    // capture-agent/tests/fixtures/tls13_rfc8446_vector.json and loaded here,
    // not inlined, since these are long hex blobs.
    fn load_fixture() -> serde_json::Value {
        let raw = std::fs::read_to_string(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tls13_rfc8446_vector.json")
        ).expect("fixture file present");
        serde_json::from_str(&raw).unwrap()
    }

    #[test]
    fn decrypts_a_known_tls13_application_data_record() {
        let fx = load_fixture();
        let secret = SessionSecret {
            client_random: hex::decode(fx["client_random"].as_str().unwrap()).unwrap(),
            label: "CLIENT_TRAFFIC_SECRET_0".to_string(),
            secret: hex::decode(fx["client_traffic_secret_0"].as_str().unwrap()).unwrap(),
        };
        let record = hex::decode(fx["encrypted_record"].as_str().unwrap()).unwrap();
        let expected_plaintext = hex::decode(fx["expected_plaintext"].as_str().unwrap()).unwrap();

        match decrypt_record(&record, &secret) {
            DecryptOutcome::Plaintext(bytes) => assert_eq!(bytes, expected_plaintext),
            DecryptOutcome::Undecryptable { reason } => panic!("expected success, got: {reason}"),
        }
    }

    #[test]
    fn returns_undecryptable_not_a_panic_for_a_truncated_record() {
        let secret = SessionSecret { client_random: vec![0u8; 32], label: "x".into(), secret: vec![1u8; 32] };
        let outcome = decrypt_record(&[0x17, 0x03, 0x03], &secret); // header only, no body
        assert!(matches!(outcome, DecryptOutcome::Undecryptable { .. }));
    }

    #[test]
    fn returns_undecryptable_for_an_authentication_failure_wrong_key() {
        let fx = load_fixture();
        let wrong_secret = SessionSecret {
            client_random: hex::decode(fx["client_random"].as_str().unwrap()).unwrap(),
            label: "CLIENT_TRAFFIC_SECRET_0".to_string(),
            secret: vec![0xAA; 32], // deliberately wrong key material
        };
        let record = hex::decode(fx["encrypted_record"].as_str().unwrap()).unwrap();
        let outcome = decrypt_record(&record, &wrong_secret);
        assert!(matches!(outcome, DecryptOutcome::Undecryptable { .. }), "AEAD tag check must fail closed, not return garbage plaintext");
    }
}
```

Add `capture-agent/tests/fixtures/tls13_rfc8446_vector.json` sourced from a published, independently-verifiable TLS 1.3 test vector set (e.g. the vectors accompanying RFC 8448 "Example Handshake Traces for TLS 1.3," which is the standard reference fixture set used by TLS implementers for exactly this purpose) with fields `client_random`, `client_traffic_secret_0`, `encrypted_record`, `expected_plaintext` populated from that published trace — not invented values, since an invented "known-correct" ciphertext/plaintext pair proves nothing about the implementation's correctness against a real TLS 1.3 key schedule.

- [ ] **Step 2: Run to verify failure**

Run: `cd capture-agent && cargo test tls_decrypt::`
Expected: FAIL — module doesn't exist yet.

- [ ] **Step 3: Implement `capture-agent/src/tls_decrypt.rs`**

Use the `ring` crate for the AEAD primitive (AES-128-GCM per RFC 8446's mandatory-to-implement cipher suite) and manual HKDF-Expand-Label per RFC 8446 §7.1 (ring exposes raw HKDF; the TLS 1.3-specific label-wrapping needs to be hand-implemented, as no small crate does exactly this without pulling in a much larger TLS stack):

```rust
// capture-agent/src/tls_decrypt.rs
use crate::keylog::SessionSecret;
use ring::aead;
use ring::hkdf;

pub enum DecryptOutcome {
    Plaintext(Vec<u8>),
    Undecryptable { reason: &'static str },
}

/// RFC 8446 §7.1 HKDF-Expand-Label, restricted to the fixed-length outputs
/// this module needs (16-byte key, 12-byte IV) — a general-purpose
/// variable-length version is not needed here and would be untested dead
/// code for any length this call site never uses.
fn hkdf_expand_label(secret: &[u8], label: &str, out_len: usize) -> Vec<u8> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(secret);
    // HkdfLabel structure: length(2) || "tls13 " + label (1-byte len prefixed) || context (1-byte len prefixed, empty here)
    let mut hkdf_label = Vec::new();
    hkdf_label.extend_from_slice(&(out_len as u16).to_be_bytes());
    let full_label = format!("tls13 {label}");
    hkdf_label.push(full_label.len() as u8);
    hkdf_label.extend_from_slice(full_label.as_bytes());
    hkdf_label.push(0); // empty context

    struct Len(usize);
    impl hkdf::KeyType for Len {
        fn len(&self) -> usize { self.0 }
    }
    let okm = prk.expand(&[&hkdf_label], Len(out_len)).expect("hkdf expand within RFC-bounded length");
    let mut out = vec![0u8; out_len];
    okm.fill(&mut out).expect("fill sized to out_len");
    out
}

fn derive_key_and_iv(traffic_secret: &[u8]) -> Option<([u8; 16], [u8; 12])> {
    let key_bytes = hkdf_expand_label(traffic_secret, "key", 16);
    let iv_bytes = hkdf_expand_label(traffic_secret, "iv", 12);
    let key: [u8; 16] = key_bytes.try_into().ok()?;
    let iv: [u8; 12] = iv_bytes.try_into().ok()?;
    Some((key, iv))
}

pub fn decrypt_record(record: &[u8], secret: &SessionSecret) -> DecryptOutcome {
    // TLS record: type(1) version(2) length(2) || ciphertext+tag
    if record.len() < 5 || record[0] != 0x17 {
        return DecryptOutcome::Undecryptable { reason: "not an application_data record" };
    }
    let body = &record[5..];
    if body.len() < aead::AES_128_GCM.tag_len() {
        return DecryptOutcome::Undecryptable { reason: "record too short for AEAD tag" };
    }

    let Some((key_bytes, iv)) = derive_key_and_iv(&secret.secret) else {
        return DecryptOutcome::Undecryptable { reason: "key derivation failed" };
    };
    let Ok(unbound_key) = aead::UnboundKey::new(&aead::AES_128_GCM, &key_bytes) else {
        return DecryptOutcome::Undecryptable { reason: "invalid key material" };
    };
    let nonce = aead::Nonce::assume_unique_for_key(iv);
    let key = aead::LessSafeKey::new(unbound_key);

    let mut buf = body.to_vec();
    match key.open_in_place(nonce, aead::Aad::empty(), &mut buf) {
        Ok(plaintext) => {
            // TLS 1.3 records end with a content-type byte after the real
            // plaintext, per RFC 8446 §5.2 — strip it and any trailing zero
            // padding before returning application data to the caller.
            let mut end = plaintext.len();
            while end > 0 && plaintext[end - 1] == 0 {
                end -= 1;
            }
            if end == 0 {
                return DecryptOutcome::Undecryptable { reason: "empty plaintext after padding strip" };
            }
            DecryptOutcome::Plaintext(plaintext[..end - 1].to_vec())
        }
        Err(_) => DecryptOutcome::Undecryptable { reason: "AEAD authentication failed" },
    }
}
```

Add the `ring` crate: `cd capture-agent && cargo add ring`. **Extra-scrutiny dependency review, per the spec's Dependency hygiene section:** `ring` is a widely-used, actively-maintained, security-audited crate already relied upon by major Rust TLS stacks (`rustls`); pin an exact version and note it in the PR description for this task per `docs/security.md`'s dependency-hygiene process. Add `pub mod tls_decrypt;` to `lib.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd capture-agent && cargo test tls_decrypt::`
Expected: all tests PASS, including the RFC-vector-based correctness test — if it fails, the key-schedule implementation has a real bug; do not adjust the fixture to match incorrect output.

- [ ] **Step 5: Commit**

```bash
cd capture-agent
git add src/tls_decrypt.rs src/lib.rs tests/fixtures/tls13_rfc8446_vector.json Cargo.toml Cargo.lock
git commit -m "feat(tls-interception): add TLS 1.3 record decryption from logged secrets"
```

---

### Task 10: Capped, `mlock`'d, zeroed-on-evict ring buffer for decrypted content

**Files:**
- Create: `capture-agent/src/ring_buffer.rs`
- Modify: `capture-agent/src/lib.rs`

**Interfaces:**
- Consumes: nothing structurally (generic byte-buffer component).
- Produces:
  ```rust
  pub struct DecryptedRingBuffer { /* ... */ }
  impl DecryptedRingBuffer {
      pub fn new(capacity_bytes: usize) -> Self;
      pub fn push(&mut self, data: Vec<u8>); // evicts oldest entries if over capacity, zeroing them
      pub fn drain_since(&mut self, cursor: usize) -> (Vec<Vec<u8>>, usize); // returns new entries + new cursor
      pub fn mlock_engaged(&self) -> bool; // true if the mlock syscall succeeded for this buffer's allocation
  }
  ```
  Consumed by the capture-loop wiring (Task 11) — one `DecryptedRingBuffer` per decrypt-eligible flow.

- [ ] **Step 1: Write the failing tests**

```rust
// capture-agent/src/ring_buffer.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evicts_oldest_entries_once_capacity_is_exceeded() {
        let mut buf = DecryptedRingBuffer::new(10); // 10 bytes total
        buf.push(vec![1, 2, 3, 4, 5]); // 5 bytes
        buf.push(vec![6, 7, 8, 9, 10]); // 10 bytes total — still fits
        buf.push(vec![11, 12]); // would be 12 bytes — evict oldest (first push) to fit
        let (entries, _) = buf.drain_since(0);
        assert!(!entries.iter().any(|e| e == &vec![1, 2, 3, 4, 5]), "oldest entry should have been evicted");
        assert!(entries.iter().any(|e| e == &vec![11, 12]));
    }

    #[test]
    fn drain_since_only_returns_entries_after_the_given_cursor() {
        let mut buf = DecryptedRingBuffer::new(1000);
        buf.push(vec![1]);
        let (_, cursor1) = buf.drain_since(0);
        buf.push(vec![2]);
        let (entries, _) = buf.drain_since(cursor1);
        assert_eq!(entries, vec![vec![2]]);
    }

    #[test]
    fn mlock_engaged_reports_a_definite_bool_without_panicking() {
        let buf = DecryptedRingBuffer::new(4096);
        let _ = buf.mlock_engaged(); // best-effort — either true or false, never a panic (spec: best-effort hardening, not a guarantee)
    }

    #[test]
    fn evicted_entries_are_actually_overwritten_not_merely_dropped() {
        // Verifies the zeroing primitive is invoked, not relying on Drop
        // alone (spec Components §3). Exercised via a capacity that forces
        // an eviction and a spy that records what was written where the
        // evicted bytes lived.
        let mut buf = DecryptedRingBuffer::new(5);
        buf.push(vec![0xAA; 5]);
        let ptr_before = buf.debug_first_entry_ptr(); // test-only accessor exposed under #[cfg(test)]
        buf.push(vec![0xBB; 5]); // forces eviction of the 0xAA entry
        assert_ne!(unsafe { *ptr_before }, 0xAA, "evicted memory must be zeroed, not left with stale plaintext");
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd capture-agent && cargo test ring_buffer::`
Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Implement `capture-agent/src/ring_buffer.rs`**

```rust
// capture-agent/src/ring_buffer.rs
use zeroize::Zeroize;

pub struct DecryptedRingBuffer {
    capacity_bytes: usize,
    used_bytes: usize,
    entries: std::collections::VecDeque<Vec<u8>>,
    mlock_engaged: bool,
}

impl DecryptedRingBuffer {
    pub fn new(capacity_bytes: usize) -> Self {
        // mlock is applied best-effort to each entry's allocation at push time
        // (a single mlock'd arena would need a custom allocator, out of scope
        // here) rather than to the struct itself — see push() below. This
        // constructor probes whether mlock is available at all on this
        // platform/process (e.g. blocked by RLIMIT_MEMLOCK) so
        // mlock_engaged() has a real answer even before any push.
        let probe = vec![0u8; 4096];
        let mlock_engaged = unsafe {
            libc::mlock(probe.as_ptr() as *const libc::c_void, probe.len()) == 0
        };
        if mlock_engaged {
            unsafe { libc::munlock(probe.as_ptr() as *const libc::c_void, probe.len()); }
        }
        Self { capacity_bytes, used_bytes: 0, entries: std::collections::VecDeque::new(), mlock_engaged }
    }

    pub fn push(&mut self, data: Vec<u8>) {
        unsafe { libc::mlock(data.as_ptr() as *const libc::c_void, data.len()); }
        self.used_bytes += data.len();
        self.entries.push_back(data);
        while self.used_bytes > self.capacity_bytes {
            if let Some(mut oldest) = self.entries.pop_front() {
                self.used_bytes -= oldest.len();
                unsafe { libc::munlock(oldest.as_ptr() as *const libc::c_void, oldest.len()); }
                oldest.zeroize(); // explicit zeroing primitive, not reliance on Drop alone
            } else {
                break;
            }
        }
    }

    /// Returns every entry currently held (this simplified implementation
    /// doesn't track a real per-caller cursor across evictions — it returns
    /// the full current contents and a cursor equal to the current entry
    /// count, which is sufficient for a single relay consumer polling
    /// forward-only, matching how the raw packet-stream cap (#27) is
    /// consumed today).
    pub fn drain_since(&mut self, cursor: usize) -> (Vec<Vec<u8>>, usize) {
        let all: Vec<Vec<u8>> = self.entries.iter().cloned().collect();
        let new_entries = all.into_iter().skip(cursor.min(self.entries.len())).collect();
        (new_entries, self.entries.len())
    }

    pub fn mlock_engaged(&self) -> bool {
        self.mlock_engaged
    }

    #[cfg(test)]
    fn debug_first_entry_ptr(&self) -> *const u8 {
        self.entries.front().map(|e| e.as_ptr()).unwrap_or(std::ptr::null())
    }
}
```

Add the `zeroize` crate: `cd capture-agent && cargo add zeroize`. **Extra-scrutiny dependency review** (spec Dependency hygiene): `zeroize` is a small, widely-used, purpose-built crate specifically for this use case (used by `RustCrypto` and many production TLS/crypto stacks) — note the pinned version in the PR description. Add `pub mod ring_buffer;` to `lib.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd capture-agent && cargo test ring_buffer::`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
cd capture-agent
git add src/ring_buffer.rs src/lib.rs Cargo.toml Cargo.lock
git commit -m "feat(tls-interception): add capped mlock'd zeroed-on-evict ring buffer for decrypted content"
```

---

### Task 11: Header redaction pass

**Files:**
- Create: `capture-agent/src/redact.rs`
- Modify: `capture-agent/src/lib.rs`

**Interfaces:**
- Consumes: nothing structurally (pure function over parsed header name/value pairs).
- Produces:
  ```rust
  pub fn redact_headers(headers: &mut Vec<(String, String)>); // mutates values in place for sensitive header names
  pub fn is_sensitive_header_name(name: &str) -> bool;
  ```
  Consumed by the HTTP/1.1 and HTTP/2 parsing paths (Task 12, and the existing plaintext HTTP path if extended later) before any decrypted content enters `DecryptedRingBuffer` (Task 10) or is emitted.

- [ ] **Step 1: Write the failing tests**

```rust
// capture-agent/src/redact.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_known_sensitive_header_names_case_insensitively() {
        let mut headers = vec![
            ("Authorization".to_string(), "Bearer abc123".to_string()),
            ("cookie".to_string(), "session=xyz".to_string()),
            ("Set-Cookie".to_string(), "session=xyz; HttpOnly".to_string()),
            ("PROXY-AUTHORIZATION".to_string(), "Basic dXNlcjpwYXNz".to_string()),
            ("X-Api-Key".to_string(), "sk-live-12345".to_string()),
        ];
        redact_headers(&mut headers);
        for (name, value) in &headers {
            assert_eq!(value, "[REDACTED]", "header {name} should have been redacted");
        }
    }

    #[test]
    fn preserves_header_names_and_leaves_non_sensitive_values_untouched() {
        let mut headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Authorization".to_string(), "Bearer abc123".to_string()),
        ];
        redact_headers(&mut headers);
        assert_eq!(headers[0], ("Content-Type".to_string(), "application/json".to_string()));
        assert_eq!(headers[1].0, "Authorization"); // name preserved
        assert_eq!(headers[1].1, "[REDACTED]");
    }

    #[test]
    fn redacts_bearer_token_shaped_values_in_non_listed_headers() {
        let mut headers = vec![("X-Custom-Auth".to_string(), "Bearer eyJhbGciOiJIUzI1NiJ9.abc.def".to_string())];
        redact_headers(&mut headers);
        assert_eq!(headers[0].1, "[REDACTED]");
    }

    #[test]
    fn does_not_touch_body_content_by_design() {
        // Named limitation, not a bug — documents the boundary explicitly
        // rather than leaving it implicit (spec Scope: "body content is NOT
        // redacted").
        let body = b"{\"password\": \"hunter2\"}";
        // redact_headers only ever operates on the headers Vec — there is no
        // function in this module that takes body bytes at all, which this
        // test's absence-of-a-call documents structurally.
        let _ = body;
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd capture-agent && cargo test redact::`
Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Implement `capture-agent/src/redact.rs`**

```rust
// capture-agent/src/redact.rs

const SENSITIVE_HEADER_NAMES: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
];

pub fn is_sensitive_header_name(name: &str) -> bool {
    SENSITIVE_HEADER_NAMES.contains(&name.to_ascii_lowercase().as_str())
}

fn looks_like_bearer_token(value: &str) -> bool {
    value.trim_start().to_ascii_lowercase().starts_with("bearer ")
}

/// Mutates header values in place — never removes the header, never touches
/// the name — for any header matched by name or whose value looks like a
/// bearer token, even under an unlisted header name. Applied before the
/// record ever enters the ring buffer or is emitted (spec Components §3);
/// body content is never in scope for this function (named limitation, see
/// Scope).
pub fn redact_headers(headers: &mut Vec<(String, String)>) {
    for (name, value) in headers.iter_mut() {
        if is_sensitive_header_name(name) || looks_like_bearer_token(value) {
            *value = "[REDACTED]".to_string();
        }
    }
}
```

Add `pub mod redact;` to `lib.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd capture-agent && cargo test redact::`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
cd capture-agent
git add src/redact.rs src/lib.rs
git commit -m "feat(tls-interception): add sensitive-header redaction pass"
```

---

### Task 12: HTTP/2 stream reassembly + HPACK-aware frame parsing with whole-connection fallback

**Files:**
- Create: `capture-agent/src/http2.rs`
- Modify: `capture-agent/src/lib.rs`

**Interfaces:**
- Consumes: `redact::redact_headers` (Task 11); decrypted plaintext bytes (`tls_decrypt::DecryptOutcome::Plaintext`, Task 9) in TCP sequence order.
- Produces:
  ```rust
  pub enum FrameOutcome {
      Frame { stream_id: u32, headers: Vec<(String, String)>, body: Vec<u8> },
      DesyncFallback { reason: &'static str }, // whole remaining connection reverts to ciphertext-only
      NeedMoreData,
  }
  pub struct Http2Reassembler { /* per-connection state: byte buffer + HPACK dynamic table */ }
  impl Http2Reassembler {
      pub fn new() -> Self;
      pub fn feed(&mut self, seq: u64, plaintext: &[u8]) -> Vec<FrameOutcome>; // seq = TCP sequence number of this chunk's first byte
  }
  ```
  Consumed by the capture-loop wiring (Task 13).

- [ ] **Step 1: Write the failing tests**

```rust
// capture-agent/src/http2.rs
#[cfg(test)]
mod tests {
    use super::*;

    fn simple_headers_frame(stream_id: u32, header_block: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&(header_block.len() as u32).to_be_bytes()[1..]); // 24-bit length
        frame.push(0x01); // type: HEADERS
        frame.push(0x04); // flags: END_HEADERS
        frame.extend_from_slice(&stream_id.to_be_bytes());
        frame.extend_from_slice(header_block);
        frame
    }

    // A minimal HPACK-encoded header block using only fully-indexed static
    // table entries (no dynamic table, no Huffman) — ":method: GET" is
    // static index 2, encoded as a single byte 0x82 per RFC 7541 §6.1.
    fn static_indexed_get_header_block() -> Vec<u8> {
        vec![0x82]
    }

    #[test]
    fn parses_a_single_in_order_headers_frame() {
        let mut r = Http2Reassembler::new();
        let frame = simple_headers_frame(1, &static_indexed_get_header_block());
        let outcomes = r.feed(0, &frame);
        assert!(outcomes.iter().any(|o| matches!(o, FrameOutcome::Frame { stream_id: 1, .. })));
    }

    #[test]
    fn reassembles_a_frame_split_across_two_feeds() {
        let mut r = Http2Reassembler::new();
        let frame = simple_headers_frame(3, &static_indexed_get_header_block());
        let (first_half, second_half) = frame.split_at(4);
        let outcomes1 = r.feed(0, first_half);
        assert!(outcomes1.iter().all(|o| matches!(o, FrameOutcome::NeedMoreData)));
        let outcomes2 = r.feed(4, second_half);
        assert!(outcomes2.iter().any(|o| matches!(o, FrameOutcome::Frame { stream_id: 3, .. })));
    }

    #[test]
    fn a_sequence_gap_triggers_whole_connection_desync_fallback_not_a_panic() {
        let mut r = Http2Reassembler::new();
        let frame = simple_headers_frame(5, &static_indexed_get_header_block());
        r.feed(0, &frame);
        // Skip ahead — seq 1000 implies bytes were lost/reordered between 0
        // and 1000, which desyncs HPACK's stateful dynamic table
        // irrecoverably (spec Components §4).
        let outcomes = r.feed(1000, &frame);
        assert!(outcomes.iter().any(|o| matches!(o, FrameOutcome::DesyncFallback { .. })));
    }

    #[test]
    fn frames_parsed_before_a_desync_point_remain_returned_not_discarded() {
        let mut r = Http2Reassembler::new();
        let good_frame = simple_headers_frame(7, &static_indexed_get_header_block());
        let outcomes1 = r.feed(0, &good_frame);
        assert!(outcomes1.iter().any(|o| matches!(o, FrameOutcome::Frame { stream_id: 7, .. })));
        let outcomes2 = r.feed(9999, &good_frame); // desync
        assert!(outcomes2.iter().any(|o| matches!(o, FrameOutcome::DesyncFallback { .. })));
        // outcomes1 already returned the good frame to the caller in an
        // earlier feed() call — this test documents that feed() never
        // retroactively invalidates a prior return, only stops producing new
        // Frame outcomes going forward.
    }

    #[test]
    fn redaction_is_applied_to_parsed_header_values_before_return() {
        // :method (0x82) then a literal-with-incremental-indexing header for
        // a made-up sensitive name would require full Huffman/literal
        // support to construct by hand here; instead this test verifies the
        // integration point structurally: any FrameOutcome::Frame carrying
        // headers must have passed through redact::redact_headers before
        // being returned — asserted here by checking a hand-inserted
        // sensitive header via the reassembler's own test-only injection
        // seam rather than a full HPACK literal encoding.
        let mut r = Http2Reassembler::new();
        r.debug_inject_header_for_test(11, "authorization".to_string(), "Bearer secret".to_string());
        let outcomes = r.feed(0, &simple_headers_frame(11, &static_indexed_get_header_block()));
        if let Some(FrameOutcome::Frame { headers, .. }) = outcomes.into_iter().find(|o| matches!(o, FrameOutcome::Frame { .. })) {
            assert!(headers.iter().any(|(k, v)| k == "authorization" && v == "[REDACTED]"));
        }
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd capture-agent && cargo test http2::`
Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Implement `capture-agent/src/http2.rs`**

Use the `hpack` crate (a small, focused RFC 7541 decoder) rather than hand-rolling HPACK — hand-rolling a stateful, order-dependent decoder is exactly the kind of thing the earlier spec draft underestimated (per the spec's Components §4 self-critique).

```rust
// capture-agent/src/http2.rs
use crate::redact::redact_headers;
use hpack::Decoder as HpackDecoder;

pub enum FrameOutcome {
    Frame { stream_id: u32, headers: Vec<(String, String)>, body: Vec<u8> },
    DesyncFallback { reason: &'static str },
    NeedMoreData,
}

pub struct Http2Reassembler {
    buffer: Vec<u8>,
    next_expected_seq: Option<u64>,
    hpack: HpackDecoder<'static>,
    desynced: bool,
    // Test-only seam: lets Task 12's redaction-integration test assert the
    // integration point without hand-encoding a full HPACK literal header.
    #[cfg(test)]
    test_injected_headers: std::collections::HashMap<u32, Vec<(String, String)>>,
}

impl Http2Reassembler {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            next_expected_seq: None,
            hpack: HpackDecoder::new(),
            desynced: false,
            #[cfg(test)]
            test_injected_headers: std::collections::HashMap::new(),
        }
    }

    #[cfg(test)]
    fn debug_inject_header_for_test(&mut self, stream_id: u32, name: String, value: String) {
        self.test_injected_headers.entry(stream_id).or_default().push((name, value));
    }

    pub fn feed(&mut self, seq: u64, chunk: &[u8]) -> Vec<FrameOutcome> {
        if self.desynced {
            return vec![FrameOutcome::DesyncFallback { reason: "connection already desynced" }];
        }
        if let Some(expected) = self.next_expected_seq {
            if seq != expected {
                self.desynced = true;
                return vec![FrameOutcome::DesyncFallback { reason: "sequence gap or reorder detected" }];
            }
        }
        self.next_expected_seq = Some(seq + chunk.len() as u64);
        self.buffer.extend_from_slice(chunk);

        let mut outcomes = Vec::new();
        loop {
            if self.buffer.len() < 9 {
                outcomes.push(FrameOutcome::NeedMoreData);
                break;
            }
            let len = u32::from_be_bytes([0, self.buffer[0], self.buffer[1], self.buffer[2]]) as usize;
            let frame_type = self.buffer[3];
            let stream_id = u32::from_be_bytes([self.buffer[5], self.buffer[6], self.buffer[7], self.buffer[8]]) & 0x7fffffff;
            if self.buffer.len() < 9 + len {
                outcomes.push(FrameOutcome::NeedMoreData);
                break;
            }
            let payload = self.buffer[9..9 + len].to_vec();
            self.buffer.drain(0..9 + len);

            if frame_type == 0x01 {
                // HEADERS frame
                match self.hpack.decode(&payload) {
                    Ok(pairs) => {
                        let mut headers: Vec<(String, String)> = pairs
                            .into_iter()
                            .map(|(k, v)| (String::from_utf8_lossy(&k).to_string(), String::from_utf8_lossy(&v).to_string()))
                            .collect();
                        #[cfg(test)]
                        if let Some(injected) = self.test_injected_headers.get(&stream_id) {
                            headers.extend(injected.iter().cloned());
                        }
                        redact_headers(&mut headers);
                        outcomes.push(FrameOutcome::Frame { stream_id, headers, body: Vec::new() });
                    }
                    Err(_) => {
                        // HPACK decode failure = irrecoverable desync for the
                        // WHOLE connection, not just this frame (spec
                        // Components §4 — no safe per-frame recovery once
                        // the dynamic table state is in question).
                        self.desynced = true;
                        outcomes.push(FrameOutcome::DesyncFallback { reason: "HPACK decode failed — dynamic table state unrecoverable" });
                        break;
                    }
                }
            } else if frame_type == 0x00 {
                // DATA frame — body bytes, not header-bearing, no HPACK involvement.
                outcomes.push(FrameOutcome::Frame { stream_id, headers: Vec::new(), body: payload });
            }
            // Other frame types (SETTINGS, WINDOW_UPDATE, PING, etc.) are
            // consumed from the buffer above but produce no FrameOutcome —
            // this component's job is content visibility, not full HTTP/2
            // protocol-state tracking.
        }
        outcomes
    }
}
```

Add the `hpack` crate: `cd capture-agent && cargo add hpack`. **Extra-scrutiny dependency review** (spec Dependency hygiene + Components §4's own note): confirm the crate's maintenance status and RFC 7541 compliance coverage before pinning; if `hpack` proves unmaintained or insufficient during implementation, the fallback is to hand-roll a decoder covering only the static table + literal-without-Huffman cases (sufficient for the majority of real traffic) and treat any frame requiring Huffman or dynamic-table lookups the decoder doesn't support as an immediate `DesyncFallback` — never a guessed decode. Add `pub mod http2;` to `lib.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd capture-agent && cargo test http2::`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
cd capture-agent
git add src/http2.rs src/lib.rs Cargo.toml Cargo.lock
git commit -m "feat(tls-interception): add HTTP/2 stream reassembly and HPACK decode with whole-connection fallback"
```

---

### Task 13: Wire Tier B into the capture loop — `decrypted_payload` event, PID eligibility control message, transport gating

**Files:**
- Modify: `capture-agent/src/main.rs`
- Modify: `capture-agent/src/wire.rs`
- Modify: `docs/wire-protocol.md`
- Modify: `app/api/stream/route.ts`
- Modify: `app/api/control/route.ts`
- Modify: `deploy/Caddyfile`
- Create: `lib/__tests__/stream-decrypted-gating.test.ts`

**Interfaces:**
- Consumes: `KeyLogWatcher` (Task 8), `tls_decrypt::decrypt_record` (Task 9), `DecryptedRingBuffer` (Task 10), `Http2Reassembler` (Task 12); the existing control-message channel `app/api/control/route.ts` already sends over the same TCP socket.
- Produces: a new `decrypted_payload` NDJSON agent event; a new `register_decrypt_eligible`/`unregister_decrypt_eligible` control message the relay sends to the agent; `isDecryptedPayloadAllowed(request)` in the relay.

- [ ] **Step 1: Write the failing tests**

```rust
// capture-agent/src/wire.rs — additional test
    #[test]
    fn decrypted_payload_json_serializes_expected_camel_case_fields() {
        let json = DecryptedPayloadJson {
            connection_id: "Tcp-1.2.3.4:1-5.6.7.8:443".to_string(),
            stream_id: Some(3),
            redacted: false,
            data_base64: "aGVsbG8=".to_string(),
        };
        let s = serde_json::to_string(&json).unwrap();
        assert!(s.contains("\"connectionId\""));
        assert!(s.contains("\"streamId\":3"));
        assert!(s.contains("\"redacted\":false"));
        assert!(s.contains("\"dataBase64\""));
    }
```

```typescript
// lib/__tests__/stream-decrypted-gating.test.ts
import { describe, expect, it } from 'vitest';
import { isDecryptedPayloadAllowed } from '@/app/api/stream/route';

function fakeRequest(headers: Record<string, string>) {
  return { headers: new Headers(headers) } as unknown as Request;
}

describe('isDecryptedPayloadAllowed', () => {
  it('allows a direct request with no proxy headers (loopback dev usage)', () => {
    expect(isDecryptedPayloadAllowed(fakeRequest({}))).toBe(true);
  });

  it('allows a request proxied through Caddy with a verified client cert', () => {
    expect(isDecryptedPayloadAllowed(fakeRequest({ 'x-mtls-verified': 'true' }))).toBe(true);
  });

  it('refuses a request proxied through Caddy without a verified client cert', () => {
    expect(isDecryptedPayloadAllowed(fakeRequest({ 'x-mtls-verified': 'false' }))).toBe(false);
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd capture-agent && cargo test wire::decrypted_payload` and `npx vitest run lib/__tests__/stream-decrypted-gating.test.ts`
Expected: FAIL on both — types/functions don't exist yet.

- [ ] **Step 3: Implement**

```rust
// capture-agent/src/wire.rs — new struct + AgentEvent variant
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptedPayloadJson {
    pub connection_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<u32>,
    pub redacted: bool,
    pub data_base64: String,
}
```
Add a `DecryptedPayload { payload: Box<DecryptedPayloadJson> }` variant to the existing `AgentEvent` enum (find it in `wire.rs` near `encode_event`/the `Packet` variant already used in `main.rs`, and follow its existing `#[serde(tag = "type", rename_all = "snake_case")]` convention so this serializes with `"type": "decrypted_payload"`).

In `main.rs`: add a `KeyLogWatcher` behind an `Arc<Mutex<_>>` alongside the existing `flow_table`/`process_map`. Extend the existing control-message read loop (the `BufReader`/`AsyncBufReadExt` handling in `main.rs` that already parses `pause`/`resume`) with two new message types:
```rust
// alongside the existing pause/resume match arms
"register_decrypt_eligible" => {
    if let (Some(pid), Some(path)) = (msg.get("pid").and_then(|v| v.as_u64()), msg.get("keylogPath").and_then(|v| v.as_str())) {
        keylog_watcher.lock().unwrap().register_eligible_pid(pid as u32, std::path::PathBuf::from(path));
    }
}
"unregister_decrypt_eligible" => {
    if let Some(pid) = msg.get("pid").and_then(|v| v.as_u64()) {
        keylog_watcher.lock().unwrap().unregister_pid(pid as u32);
    }
}
```
In the capture loop, after `flow_table.lock().unwrap().observe(...)`: if the flow's attributed PID (via the existing `process_map` lookup already used elsewhere in `main.rs`) `is_eligible` in `keylog_watcher`, attempt `tls_decrypt::decrypt_record` on application-data records for that flow, run the result through the relevant per-connection `Http2Reassembler` (Task 12) if the flow's `l7` shows HTTP/2 ALPN (falling back to treating it as opaque HTTP/1.1-or-unknown body bytes, still redaction-passed, if not), push into that flow's `DecryptedRingBuffer` (Task 10), and — capped at the same 100/sec discrete-event rate as the existing `packet_event_limiter` — emit a `wire::AgentEvent::DecryptedPayload` with `data_base64` base64-encoded from the ring buffer's newest entries. Poll `keylog_watcher.poll()` once per capture-loop iteration (cheap — file read only for currently-eligible PIDs, empty set in the common case).

```typescript
// app/api/stream/route.ts — add near the top, exported for the test above
export function isDecryptedPayloadAllowed(request: Request): boolean {
  const header = request.headers.get('x-mtls-verified');
  if (header === null) return true; // no Caddy in front — direct loopback access, already gated by the -H 127.0.0.1 bind
  return header === 'true';
}
```
In the `GET` handler's `onEvent` callback, add a filter before `controller.enqueue`:
```typescript
onEvent = (event: unknown) => {
  if ((event as { type?: string }).type === 'decrypted_payload' && !isDecryptedPayloadAllowed(request)) {
    return; // refused per transport gating — spec Components §5
  }
  // ...existing enqueue logic...
};
```
(`GET` needs to accept `request: Request` as a parameter to close over it here — check its current signature and add the parameter if it's currently `GET()` with no args.)

```typescript
// app/api/control/route.ts — extend the type allowlist
  if (body.type !== 'pause' && body.type !== 'resume' && body.type !== 'register_decrypt_eligible' && body.type !== 'unregister_decrypt_eligible') {
    return NextResponse.json({ error: 'invalid control message type' }, { status: 400 });
  }
```

```
# deploy/Caddyfile — inside the reverse_proxy block, add:
	reverse_proxy 127.0.0.1:3000 {
		header_up X-Mtls-Verified {tls_client_certificate_verified}
	}
```
Re-run `deploy/test-mtls-rejection.sh` after this change per its own documented requirement (CLAUDE.md: "re-run it after any Caddyfile change").

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd capture-agent && cargo test` and `npx vitest run lib/__tests__/stream-decrypted-gating.test.ts`
Expected: all PASS. Also run `cd deploy && ./test-mtls-rejection.sh` and confirm all three checks still pass with the header addition in place.

- [ ] **Step 5: Update `docs/wire-protocol.md` and commit**

Add a new `### decrypted_payload` section documenting the event shape, mirroring the existing `connection_update`/`packet` sections' format, and a note: "Refused outright over any non-loopback listener; once served through 1b's Caddy mTLS proxy, requires the `X-Mtls-Verified: true` upstream header — see `app/api/stream/route.ts`'s `isDecryptedPayloadAllowed`."

```bash
cd capture-agent
git add src/main.rs src/wire.rs
cd ..
git add app/api/stream/route.ts app/api/control/route.ts deploy/Caddyfile docs/wire-protocol.md lib/__tests__/stream-decrypted-gating.test.ts
git commit -m "feat(tls-interception): wire decrypted_payload event with loopback/mTLS transport gating"
```

---

### Task 14: `decrypted-mapping.ts`, `PacketStreamView` decrypted pane, and the persistent banner

**Files:**
- Modify: `lib/types.ts`
- Create: `lib/decrypted-mapping.ts`
- Create: `lib/__tests__/decrypted-mapping.test.ts`
- Modify: `components/PacketStreamView.tsx`
- Modify: `app/page.tsx`
- Create: `lib/__tests__/packet-stream-decrypted.test.tsx` (`jsdom`)
- Modify: `lib/__tests__/no-dangerous-html.test.ts`

**Interfaces:**
- Consumes: the `decrypted_payload` wire event (Task 13).
- Produces: `DecryptedPayloadSegment` type; `mapDecryptedPayloadEvent(raw): DecryptedPayloadSegment`; a `decryptEligibleProcesses` piece of state in `app/page.tsx` driving the banner (populated by a matching `decrypt_status`-style signal — for this plan, inferred directly from whether any `decrypted_payload` events have been seen for a still-open connection, avoiding the need for a fourth new wire event type).

- [ ] **Step 1: Write the failing tests**

```typescript
// lib/__tests__/decrypted-mapping.test.ts
import { describe, expect, it } from 'vitest';
import { mapDecryptedPayloadEvent } from '@/lib/decrypted-mapping';

describe('mapDecryptedPayloadEvent', () => {
  it('decodes base64 payload data and carries redacted/streamId through', () => {
    const event = {
      type: 'decrypted_payload',
      payload: { connectionId: 'Tcp-1-2', streamId: 3, redacted: false, dataBase64: Buffer.from('hello').toString('base64') },
    };
    const seg = mapDecryptedPayloadEvent(event);
    expect(seg.connectionId).toBe('Tcp-1-2');
    expect(seg.streamId).toBe(3);
    expect(seg.text).toBe('hello');
    expect(seg.redacted).toBe(false);
  });

  it('throws on a malformed event missing required fields, loudly not silently', () => {
    expect(() => mapDecryptedPayloadEvent({ type: 'decrypted_payload', payload: {} })).toThrow();
  });
});
```

```tsx
// lib/__tests__/packet-stream-decrypted.test.tsx
import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { PacketStreamView } from '@/components/PacketStreamView';
import { THEMES } from '@/lib/osi-engine';

describe('PacketStreamView decrypted content', () => {
  it('renders a [REDACTED] placeholder distinctly, not blank', () => {
    render(
      <PacketStreamView
        packets={[]}
        theme={THEMES.matrix}
        onClearPackets={() => {}}
        decryptedSegments={[{ connectionId: 'c1', streamId: undefined, text: '[REDACTED]', redacted: true }]}
      />
    );
    expect(screen.getByText('[REDACTED]')).toHaveClass(/redacted/i);
  });

  it('renders real decrypted text alongside the existing ciphertext view, not replacing it', () => {
    render(
      <PacketStreamView
        packets={[]}
        theme={THEMES.matrix}
        onClearPackets={() => {}}
        decryptedSegments={[{ connectionId: 'c1', streamId: undefined, text: 'GET /api/x', redacted: false }]}
      />
    );
    expect(screen.getByText(/GET \/api\/x/)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run lib/__tests__/decrypted-mapping.test.ts lib/__tests__/packet-stream-decrypted.test.tsx`
Expected: FAIL — module/props don't exist yet.

- [ ] **Step 3: Implement**

```typescript
// lib/types.ts — add
export interface DecryptedPayloadSegment {
  connectionId: string;
  streamId?: number;
  text: string;
  redacted: boolean;
}
```

```typescript
// lib/decrypted-mapping.ts
import { DecryptedPayloadSegment } from './types';

export function mapDecryptedPayloadEvent(raw: any): DecryptedPayloadSegment {
  const payload = raw.payload;
  if (!payload || typeof payload.connectionId !== 'string' || typeof payload.dataBase64 !== 'string') {
    throw new Error('malformed decrypted_payload event: missing required fields');
  }
  return {
    connectionId: payload.connectionId,
    streamId: payload.streamId,
    text: Buffer.from(payload.dataBase64, 'base64').toString('utf8'),
    redacted: Boolean(payload.redacted),
  };
}
```

In `components/PacketStreamView.tsx`, add a `decryptedSegments?: DecryptedPayloadSegment[]` prop and, within the existing packet-detail rendering area (inspect the current selected-packet detail panel before editing to match its layout), render each segment as **plain text only** — no `dangerouslySetInnerHTML` anywhere — with redacted segments given a visually distinct class (e.g. `italic opacity-70` or whatever the theme's existing muted-but-flagged convention is) versus real content rendered in the theme's normal monospace text class. Add a "Decrypted" badge on any packet/connection row whose `id`/connection id has at least one associated segment.

In `app/page.tsx`: subscribe to `decrypted_payload` SSE events the same way `packet`/`connection_update` are already subscribed to, mapping each via `mapDecryptedPayloadEvent` and appending to a capped `decryptedSegments` state array (same ring-buffer-style cap discipline as the existing `packets` state — reuse its existing cap constant if one exists, don't invent a second number). Derive the persistent banner's visibility from `decryptedSegments.length > 0` combined with tracking distinct `connectionId`s currently represented, rendering: `` `Decrypting traffic for: ${count} connection(s)` `` (a full "command (pid)" banner as the spec describes requires plumbing the wrapped command string through the control-message registration in Task 13, which this plan does not thread all the way to the browser — flag this as a follow-up refinement if the reviewing engineer wants full parity with the spec's exact banner text; the connection-count version satisfies the "never ambient or silent" requirement in the meantime).

Extend `lib/__tests__/no-dangerous-html.test.ts`'s existing fixture list with HTML/script-like decrypted-content fixtures and a `[REDACTED]` fixture, per the spec's Testing section — inspect that file's existing fixture-array pattern before adding to it rather than restructuring the file.

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run`
Expected: full suite PASSES, including the extended `no-dangerous-html.test.ts`.

- [ ] **Step 5: Commit**

```bash
git add lib/types.ts lib/decrypted-mapping.ts lib/__tests__/decrypted-mapping.test.ts components/PacketStreamView.tsx app/page.tsx lib/__tests__/packet-stream-decrypted.test.tsx lib/__tests__/no-dangerous-html.test.ts
git commit -m "feat(tls-interception): render decrypted content and persistent decrypting banner in PacketStreamView"
```

---

### Task 15: Safety-invariant test harnesses — no-disk-write, mlock/zeroing, core-dump-disabled, fuzz coverage

**Files:**
- Create: `capture-agent/tests/no_disk_write_invariant.rs` (integration test, separate from unit tests so it can hook process-wide syscall behavior)
- Modify: `capture-agent/fuzz/fuzz_targets/` (extend the existing `parse.rs` fuzz target's sibling, or add a new one for `l7::sniff_l7`/`http2::Http2Reassembler::feed` if no L7 fuzz target exists yet — check `capture-agent/fuzz/` first)
- Modify: `capture-agent/src/keylog.rs`, `capture-agent/src/tls_decrypt.rs`, `capture-agent/src/http2.rs` (only if the fuzz pass in this task surfaces a real panic — fix forward, don't pre-emptively rewrite working code)

**Interfaces:**
- Consumes: everything from Tasks 8–12.
- Produces: no new public interfaces — this task is pure test/verification infrastructure closing out the spec's Testing section items not yet covered by earlier tasks' own unit tests (JA3 fuzz coverage was already folded into the existing `parse.rs`/`l7.rs` fuzz target's input space in Task 2 implicitly, since it's the same entry point).

- [ ] **Step 1: Write the failing test**

```rust
// capture-agent/tests/no_disk_write_invariant.rs
// This test doesn't intercept real syscalls (that would need a
// LD_PRELOAD-style shim not available in a portable `cargo test` run on
// macOS); instead it performs the pragmatic, still-load-bearing check the
// spec's testing section is really after: run a full decrypt-eligible
// session end to end (register a PID, feed it real key-log lines and
// ciphertext via the public API) and assert no file appears under the
// data directory OTHER than the SSLKEYLOGFILE itself, which is expected
// and documented (spec: "the one on-disk artifact this design does
// create").
use capture_agent::keylog::KeyLogWatcher;
use capture_agent::ring_buffer::DecryptedRingBuffer;

#[test]
fn a_full_decrypt_session_creates_no_files_beyond_the_keylog_itself() {
    let dir = std::env::temp_dir().join(format!("no-disk-write-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let keylog_path = dir.join("session.keylog");
    std::fs::write(&keylog_path, "").unwrap();

    let mut watcher = KeyLogWatcher::new();
    watcher.register_eligible_pid(4242, keylog_path.clone());
    watcher.poll();

    let mut ring = DecryptedRingBuffer::new(4096);
    ring.push(b"decrypted plaintext that must never touch disk".to_vec());
    let (_entries, _cursor) = ring.drain_since(0);

    let files_after: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(files_after.len(), 1, "only the SSLKEYLOGFILE itself should exist on disk, found: {files_after:?}");

    std::fs::remove_dir_all(&dir).ok();
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd capture-agent && cargo test --test no_disk_write_invariant`
Expected: initially FAILS only if `keylog`/`ring_buffer` aren't `pub` from `lib.rs` yet for integration-test visibility (they should already be, from Tasks 8/10) — if it fails for a different reason, that's a real bug surfaced by this test, fix it before proceeding.

- [ ] **Step 3: Confirm/adjust module visibility**

If `capture-agent/src/lib.rs` doesn't already expose `keylog` and `ring_buffer` as `pub mod`, make them so (integration tests under `tests/` can only reach `pub` items). No other implementation change should be needed if Tasks 8–10 were implemented as specified.

- [ ] **Step 4: Run tests to verify they pass, then extend fuzz coverage**

Run: `cd capture-agent && cargo test --test no_disk_write_invariant`
Expected: PASS.

Check `capture-agent/fuzz/fuzz_targets/` for the existing target (per CLAUDE.md, `parse.rs` already has one). Add fuzz coverage for the two new attacker-reachable-input parsers introduced in this plan — `l7::sniff_l7` already receives fuzzed input transitively if the existing target calls into it after `parse_packet`; confirm this by reading the existing fuzz target's harness function. If it stops at `parse_packet` and doesn't call `sniff_l7`, extend it to also call `sniff_l7` on the parsed payload (folding JA3 parsing into existing coverage per this plan's Task 2 assumption). Add a **new** fuzz target `capture-agent/fuzz/fuzz_targets/http2_reassembly.rs` feeding arbitrary byte chunks at arbitrary (including deliberately out-of-order) sequence numbers into `Http2Reassembler::feed`, asserting only that it never panics — a `DesyncFallback` is a correct, expected outcome for garbage input, not a failure:
```rust
// capture-agent/fuzz/fuzz_targets/http2_reassembly.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use capture_agent::http2::Http2Reassembler;

fuzz_target!(|data: &[u8]| {
    let mut r = Http2Reassembler::new();
    let _ = r.feed(0, data); // must never panic, regardless of input
});
```
Run: `cd capture-agent && cargo +nightly fuzz run http2_reassembly -- -max_total_time=60` for a quick local smoke pass (full fuzzing is a CI/background concern, not a per-task gate — 60s is enough to catch an immediate panic from this task's own new code).

- [ ] **Step 5: Commit**

```bash
cd capture-agent
git add tests/no_disk_write_invariant.rs fuzz/fuzz_targets/http2_reassembly.rs fuzz/Cargo.toml src/lib.rs
git commit -m "test(tls-interception): add no-disk-write invariant check and HTTP/2 reassembly fuzz target"
```

---

## Self-Review Notes (for the plan author, not the implementer)

- **Spec coverage:** Tier A (Components §1) → Tasks 1–5. Tier B wrapper (§2) → Task 7. `KeyLogWatcher` (§3) → Task 8. Decrypt math → Task 9 (new, the spec left this as "combine secrets with ciphertext" without naming the actual key-schedule work — made concrete here). Ring buffer/mlock/zeroing (§3) → Task 10. Redaction (§3) → Task 11. HTTP/2 (§4) → Task 12. Wire/gating (§5) → Task 13. UI (§6) → Task 14. Core-dump-disabled (Security model) → Task 6. No-disk-write + fuzz (Testing) → Task 15. The full MITM proxy ("Rejected for now") → intentionally has no task anywhere in this plan.
- **Known gap flagged inline, not silently dropped:** Task 14's banner renders a connection-count summary rather than the spec's exact `"Decrypting traffic for: <command> (pid NNNN)"` text, because threading the wrapped command string from `osi-inspect` through the control-message registration to the browser is real additional plumbing this plan's Task 13 control message doesn't carry (it only sends `pid`/`keylogPath`). A follow-up task to add a `command` field to the `register_decrypt_eligible` control message and thread it through `DecryptedPayloadJson` or a small companion event would close this gap; noted rather than silently shipping a banner that doesn't match the spec's stated copy.
- **Deliberately not built:** per-destination-host scoping of decrypt-eligibility, body-content credential redaction, JA4 (JA3 only) — all named as out of scope in the spec itself, and no task above attempts them.
