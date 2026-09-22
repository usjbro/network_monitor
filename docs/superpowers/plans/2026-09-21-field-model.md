# Field Model Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the fixed `header_breakdown` packet summary with a registry of typed, named, individually addressable fields, and cut the whole stack (wire protocol, docs, TypeScript types, UI) over to it in one coordinated change — no dual-emit period.

**Architecture:** A new Rust module (`capture-agent/src/fields.rs`) builds a flat `Vec<Field>` per packet from already-parsed data (`ParsedPacket` + `L7Info`), computing each field's byte offset via fixed RFC-defined header-layout arithmetic (no re-parsing). Two independent hex-dump panes replace the assumption that one `hexDump` covers everything: the existing payload dump (unchanged) plus a new header-bytes dump. `PacketStreamView.tsx` renders a collapsible field tree with bidirectional click-to-highlight against whichever pane a field's `region` names.

**Tech Stack:** Rust (capture-agent), TypeScript/React (Next.js relay + UI), serde for wire serialization, Vitest + Testing Library for TS tests, `cargo test` for Rust tests.

**Spec:** `docs/superpowers/specs/2026-09-21-field-model-design.md`

## Global Constraints

- Wire field names are `camelCase` (Rust `#[serde(rename_all = "camelCase")]`), matching TypeScript field names exactly — no translation layer (`CONTRIBUTING.md`).
- Field abbreviations (the `path` value) are dotted, lowercase, Wireshark-style (`tcp.flags.syn`, `ip.ttl`) — this becomes user-visible filter syntax later (JAM-10); use exactly the names in this plan, don't improvise variants mid-implementation.
- No dual-emit: `header_breakdown`/`Layer7Json`/`Layer4Json`/`Layer3Json`/`Layer2Json`/`HeaderBreakdownJson` are deleted in the same change that adds `fields`/`headerHexDump`, not deprecated in place.
- No new protocol/dissector decoding — every field this plan adds comes from data `ParsedPacket`/`L7Info` already compute today.
- Every task must leave `cargo test` (Rust) and `npx vitest run` (TypeScript) fully green — this is a shared-type change with ripple effects across `flow.rs`'s and `l7.rs`'s existing test fixtures; don't skip fixing a fixture because it looks unrelated to your task's main file.

---

### Task 1: `ParsedPacket` gains `header_bytes`

**Files:**
- Modify: `capture-agent/src/parse.rs` (struct + `parse_packet`/`build_parsed_packet`)
- Modify: `capture-agent/src/flow.rs` (7 test-fixture `ParsedPacket` literals — compile-fix ripple, not related to this task's own logic)
- Test: `capture-agent/src/parse.rs` (new `#[cfg(test)]` cases)

**Interfaces:**
- Produces: `ParsedPacket.header_bytes: Vec<u8>` — every byte before `payload` starts, in whichever slice was actually parsed (excludes the 4-byte loopback AF prefix for `NullLoopback` framing, since that's derived from `ip_data`, not the raw wire bytes).

- [ ] **Step 1: Write the failing tests**

Add to the existing `#[cfg(test)] mod tests` in `capture-agent/src/parse.rs`:

```rust
    #[test]
    fn header_bytes_excludes_the_payload() {
        let builder = PacketBuilder::ethernet2([0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11])
            .ipv4([192, 168, 1, 10], [93, 184, 216, 34], 64)
            .tcp(51000, 443, 1000, 65535)
            .syn();
        let payload: &[u8] = b"hello";
        let mut data = Vec::new();
        builder.write(&mut data, payload).unwrap();

        let parsed = parse_packet(&data, LinkType::Ethernet).unwrap();

        assert_eq!(parsed.header_bytes.len(), data.len() - payload.len());
        assert_eq!(parsed.header_bytes, &data[..data.len() - payload.len()]);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn header_bytes_excludes_the_null_loopback_af_prefix() {
        let builder = PacketBuilder::ipv4([127, 0, 0, 1], [127, 0, 0, 1], 64)
            .tcp(51000, 8080, 1000, 65535)
            .syn();
        let payload: &[u8] = b"hi";
        let mut ip_packet = Vec::new();
        builder.write(&mut ip_packet, payload).unwrap();
        let mut data = vec![2, 0, 0, 0]; // 4-byte AF_INET prefix, never a real header
        data.extend_from_slice(&ip_packet);

        let parsed = parse_packet(&data, LinkType::NullLoopback).unwrap();

        // header_bytes must be relative to ip_packet, not the wire bytes
        // that also carried the 4-byte AF prefix — that prefix is not a
        // protocol header and must never show up in a byte-highlighting pane.
        assert_eq!(parsed.header_bytes.len(), ip_packet.len() - payload.len());
        assert_eq!(parsed.header_bytes, &ip_packet[..ip_packet.len() - payload.len()]);
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd capture-agent && cargo test --locked header_bytes -- --nocapture`
Expected: compile error — `ParsedPacket` has no field `header_bytes` yet.

- [ ] **Step 3: Add the field and compute it**

In `capture-agent/src/parse.rs`, add the field to the struct (right after `payload`):

```rust
    pub payload: Vec<u8>,
    /// Every byte before `payload` starts, in whichever slice was actually
    /// parsed — the Ethernet/IP/transport headers, with no artificial cap
    /// (bounded naturally: every currently-decoded field lives in a fixed
    /// header portion, worst case Ethernet+VLAN+IPv4+TCP ≈ 78 bytes). Used
    /// to build the wire's `headerHexDump`, a separate pane from the
    /// existing payload-only `hexDump`.
    pub header_bytes: Vec<u8>,
```

Change `build_parsed_packet`'s signature from `total_len: usize` to `frame_data: &[u8]`, and compute `header_bytes` before constructing the return value:

```rust
fn build_parsed_packet(
    sliced: &SlicedPacket,
    src_mac: String,
    dst_mac: String,
    vlan_tag: Option<String>,
    frame_data: &[u8],
) -> Option<ParsedPacket> {
```

(leave the body unchanged down to the `payload` match arm), then just before `Some(ParsedPacket { ... })`:

```rust
    let header_bytes = frame_data[..frame_data.len() - payload.len()].to_vec();

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
        total_len: frame_data.len() as u16,
        payload,
        header_bytes,
        ip_version,
        ip_checksum,
        vlan_tag,
    })
```

Update the three call sites in `parse_packet` to pass the slice instead of its length:

```rust
        LinkType::Ethernet => {
            // ... unchanged src_mac/dst_mac/vlan_tag derivation ...
            build_parsed_packet(&sliced, src_mac, dst_mac, vlan_tag, data)
        }
        LinkType::NullLoopback => {
            let ip_data = data.get(NULL_LOOPBACK_HEADER_LEN..)?;
            let sliced = SlicedPacket::from_ip(ip_data).ok()?;
            build_parsed_packet(&sliced, NO_MAC.to_string(), NO_MAC.to_string(), None, ip_data)
        }
        LinkType::Raw => {
            let sliced = SlicedPacket::from_ip(data).ok()?;
            build_parsed_packet(&sliced, NO_MAC.to_string(), NO_MAC.to_string(), None, data)
        }
```

- [ ] **Step 4: Fix the compile ripple in `flow.rs`'s test fixtures**

Adding a required field breaks every literal `ParsedPacket { ... }` construction outside `parse.rs` itself. `flow.rs`'s test module has 7 of them. Run:

```bash
cd capture-agent
sed -i '' 's/^\(            payload: vec!\[\],\)$/\1\n            header_bytes: vec![],/' src/flow.rs
sed -i '' 's/^\(            payload,\)$/\1\n            header_bytes: vec![],/' src/flow.rs
```

Verify exactly 7 insertions landed: `grep -c "header_bytes: vec!\[\]," src/flow.rs` should print `7`.

- [ ] **Step 5: Run the full test suite to verify everything passes**

Run: `cd capture-agent && cargo test --locked`
Expected: PASS — all existing tests plus the two new ones, 0 failed.

- [ ] **Step 6: Commit**

```bash
git add capture-agent/src/parse.rs capture-agent/src/flow.rs
git commit -m "Add ParsedPacket.header_bytes for header-region byte highlighting

Needed so a field like tcp.src_port has real bytes to highlight
against -- hex_dump only ever covered the payload, never the headers.
Computed once in parse_packet as everything before payload, correctly
excluding NullLoopback's 4-byte AF prefix since it's never a real
protocol header.

Part of JAM-9 (field model)."
```

---

### Task 2: `fields.rs` — types and serialization

**Files:**
- Create: `capture-agent/src/fields.rs`
- Modify: `capture-agent/src/lib.rs` (register the module)
- Test: inline `#[cfg(test)]` in `fields.rs`

**Interfaces:**
- Produces: `FieldType`, `ByteRegion`, `FieldValue`, `Field` (with `Field::group(...)` and `Field::leaf(...)` constructors), all `pub`, for Tasks 3-6 to build on.
- Consumes: nothing yet (no `build_fields` in this task).

- [ ] **Step 1: Write the failing tests**

Create `capture-agent/src/fields.rs` with just the test module first:

```rust
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    Group,
    Bool,
    Uint,
    Str,
    Addr,
    Bytes,
}

/// Which of the two hex-dump panes a field's `offset`/`len` is relative to.
/// Header fields (eth/ip/tcp/udp/vlan) are offset into `headerHexDump`;
/// app-layer fields (http/dns/tls) are offset into the existing `hexDump`
/// — the two panes are never merged into one shared byte space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ByteRegion {
    Header,
    Payload,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum FieldValue {
    Bool(bool),
    Uint(u64),
    Str(String),
    #[allow(dead_code)] // no currently-decoded field uses this yet; kept for future dissector work per the spec's type enum
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Field {
    pub path: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(rename = "type")]
    pub field_type: FieldType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<FieldValue>,
    pub region: ByteRegion,
    pub offset: u32,
    pub len: u32,
}

impl Field {
    pub fn group(path: &str, label: &str, group: Option<&str>, region: ByteRegion, offset: u32, len: u32) -> Field {
        Field {
            path: path.to_string(),
            label: label.to_string(),
            group: group.map(|g| g.to_string()),
            field_type: FieldType::Group,
            value: None,
            region,
            offset,
            len,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn leaf(
        path: &str,
        label: &str,
        group: &str,
        field_type: FieldType,
        value: FieldValue,
        region: ByteRegion,
        offset: u32,
        len: u32,
    ) -> Field {
        Field {
            path: path.to_string(),
            label: label.to_string(),
            group: Some(group.to_string()),
            field_type,
            value: Some(value),
            region,
            offset,
            len,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_group_omits_the_value_key_entirely() {
        let f = Field::group("tcp", "Transmission Control Protocol", None, ByteRegion::Header, 34, 20);
        let json = serde_json::to_string(&f).unwrap();
        assert!(!json.contains("\"value\""), "group entries must carry no value key at all, not null: {json}");
        assert!(!json.contains("\"group\""), "a top-level group must omit the group key, not send null: {json}");
        assert!(json.contains("\"type\":\"group\""));
        assert!(json.contains("\"region\":\"header\""));
    }

    #[test]
    fn a_leaf_serializes_its_typed_value_untagged() {
        let f = Field::leaf(
            "tcp.flags.syn",
            "SYN",
            "tcp.flags",
            FieldType::Bool,
            FieldValue::Bool(true),
            ByteRegion::Header,
            47,
            1,
        );
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("\"value\":true"), "bool value must serialize as a bare JSON bool, not {{\"Bool\":true}}: {json}");
        assert!(json.contains("\"group\":\"tcp.flags\""));
    }

    #[test]
    fn a_uint_leaf_serializes_as_a_bare_number() {
        let f = Field::leaf("tcp.src_port", "Source Port", "tcp", FieldType::Uint, FieldValue::Uint(51000), ByteRegion::Header, 34, 2);
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("\"value\":51000"), "{json}");
    }

    #[test]
    fn field_uses_camel_case_keys() {
        let f = Field::leaf("ip.ttl", "Time to Live", "ip", FieldType::Uint, FieldValue::Uint(64), ByteRegion::Header, 22, 1);
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("\"path\":\"ip.ttl\""));
        assert!(json.contains("\"offset\":22"));
        assert!(json.contains("\"len\":1"));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd capture-agent && cargo build --locked 2>&1 | head -20`
Expected: compile error — `fields` module doesn't exist / isn't registered yet.

- [ ] **Step 3: Register the module**

In `capture-agent/src/lib.rs`, add alongside the other `pub mod` lines:

```rust
pub mod fields;
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd capture-agent && cargo test --locked fields::`
Expected: PASS, 4 passed, 0 failed.

- [ ] **Step 5: Commit**

```bash
git add capture-agent/src/fields.rs capture-agent/src/lib.rs
git commit -m "Add the field registry's types (capture-agent/src/fields.rs)

FieldType/ByteRegion/FieldValue/Field, with Field::group/Field::leaf
constructors and the serialization contract build_fields (next tasks)
will produce: value omitted entirely for groups, group omitted for
top-level entries, region/offset/len always present on both.

Part of JAM-9 (field model)."
```

---

### Task 3: `fields.rs` — Ethernet and IP fields

**Files:**
- Modify: `capture-agent/src/fields.rs`
- Test: inline `#[cfg(test)]`

**Interfaces:**
- Consumes: `Field::group`/`Field::leaf` (Task 2); `parse::ParsedPacket`, `parse::LinkType` (existing).
- Produces: `eth_fields(parsed: &ParsedPacket) -> (Vec<Field>, u32)` (returns fields plus the byte offset where the IP header starts), `ip_fields(parsed: &ParsedPacket, ip_start: u32) -> (Vec<Field>, u32)` (returns fields plus the byte offset where the transport header starts), `protocol_num(protocol: TransportProtocol) -> u8` — all private to the module (no `pub`; only `build_fields`, added in Task 5, is the module's public entry point).

- [ ] **Step 1: Write the failing tests**

Add to `capture-agent/src/fields.rs`, inside the existing `mod tests` block:

```rust
    use crate::parse::{LinkType, ParsedPacket, TransportProtocol};

    fn base_packet() -> ParsedPacket {
        ParsedPacket {
            src_mac: "00:01:02:03:04:05".to_string(),
            dst_mac: "06:07:08:09:0a:0b".to_string(),
            src_ip: "192.168.1.10".to_string(),
            dst_ip: "93.184.216.34".to_string(),
            protocol: TransportProtocol::Other,
            src_port: None,
            dst_port: None,
            tcp_flags: None,
            seq: None,
            ttl: 64,
            total_len: 100,
            payload: vec![],
            header_bytes: vec![],
            ip_version: 4,
            ip_checksum: Some(0xbeef),
            vlan_tag: None,
        }
    }

    #[test]
    fn eth_fields_places_the_ip_header_right_after_a_14_byte_untagged_ethernet_header() {
        let (fields, ip_start) = eth_fields(&base_packet());
        assert_eq!(ip_start, 14);
        let eth = fields.iter().find(|f| f.path == "eth").unwrap();
        assert_eq!(eth.offset, 0);
        assert_eq!(eth.len, 14);
        let src = fields.iter().find(|f| f.path == "eth.src").unwrap();
        assert_eq!(src.offset, 6);
        assert_eq!(src.len, 6);
        assert!(matches!(&src.value, Some(FieldValue::Str(v)) if v == "00:01:02:03:04:05"));
    }

    #[test]
    fn eth_fields_accounts_for_the_4_byte_vlan_tag_when_present() {
        let mut p = base_packet();
        p.vlan_tag = Some("100".to_string());
        let (fields, ip_start) = eth_fields(&p);
        assert_eq!(ip_start, 18, "a VLAN-tagged frame's IP header starts 4 bytes later");
        let vlan_id = fields.iter().find(|f| f.path == "eth.vlan.id").unwrap();
        assert!(matches!(&vlan_id.value, Some(FieldValue::Uint(100))));
        assert_eq!(vlan_id.offset, 14);
        assert_eq!(vlan_id.len, 2);
    }

    #[test]
    fn ip_fields_places_ipv4_addresses_at_their_rfc_791_offsets() {
        let (fields, transport_start) = ip_fields(&base_packet(), 14);
        assert_eq!(transport_start, 34, "14 (eth) + 20 (ipv4) = 34");
        let src = fields.iter().find(|f| f.path == "ip.src").unwrap();
        assert_eq!(src.offset, 14 + 12);
        assert_eq!(src.len, 4);
        assert!(matches!(&src.value, Some(FieldValue::Str(v)) if v == "192.168.1.10"));
        let ttl = fields.iter().find(|f| f.path == "ip.ttl").unwrap();
        assert_eq!(ttl.offset, 14 + 8);
        assert!(matches!(&ttl.value, Some(FieldValue::Uint(64))));
        let checksum = fields.iter().find(|f| f.path == "ip.checksum").unwrap();
        assert!(matches!(&checksum.value, Some(FieldValue::Str(v)) if v == "0xbeef"));
    }

    #[test]
    fn ip_fields_uses_the_ip6_group_and_16_byte_addresses_for_ipv6() {
        let mut p = base_packet();
        p.ip_version = 6;
        p.ip_checksum = None; // IPv6 has no header checksum — see ParsedPacket's own doc comment
        let (fields, transport_start) = ip_fields(&p, 14);
        assert_eq!(transport_start, 14 + 40);
        assert!(fields.iter().any(|f| f.path == "ip6"));
        assert!(fields.iter().all(|f| f.path != "ip.checksum"), "IPv6 must never fabricate a checksum field");
        let src = fields.iter().find(|f| f.path == "ip6.src").unwrap();
        assert_eq!(src.len, 16);
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd capture-agent && cargo test --locked fields:: 2>&1 | head -20`
Expected: compile error — `eth_fields`/`ip_fields` not found.

- [ ] **Step 3: Implement**

Add to `capture-agent/src/fields.rs`, above the `#[cfg(test)]` block:

```rust
use crate::parse::{ParsedPacket, TransportProtocol};

const ETH_HEADER_LEN: u32 = 14;
const VLAN_TAG_LEN: u32 = 4;
const IPV4_HEADER_LEN: u32 = 20;
const IPV6_HEADER_LEN: u32 = 40;

/// Maps a `TransportProtocol` to its IANA protocol number. `Other`/`Icmp`
/// cover cases etherparse classifies without exposing a raw number at the
/// current call site — `Icmp` uses the well-known IANA value, `Other`
/// reports 0 rather than a fabricated number. Moved here from wire.rs's
/// deleted `build_header_breakdown` (Task 6), same logic.
fn protocol_num(protocol: TransportProtocol) -> u8 {
    match protocol {
        TransportProtocol::Tcp => 6,
        TransportProtocol::Udp => 17,
        TransportProtocol::Icmp => 1,
        TransportProtocol::Other => 0,
    }
}

/// Returns (fields, byte offset where the IP header starts). Ethernet is
/// always 14 bytes (+4 if VLAN-tagged) — every currently-decoded field
/// lives in that fixed portion, so this is exact constant arithmetic, no
/// re-parsing.
fn eth_fields(parsed: &ParsedPacket) -> (Vec<Field>, u32) {
    let vlan_tagged = parsed.vlan_tag.is_some();
    let eth_len = ETH_HEADER_LEN + if vlan_tagged { VLAN_TAG_LEN } else { 0 };
    let mut fields = vec![Field::group("eth", "Ethernet II", None, ByteRegion::Header, 0, eth_len)];
    fields.push(Field::leaf(
        "eth.dst", "Destination MAC", "eth", FieldType::Addr,
        FieldValue::Str(parsed.dst_mac.clone()), ByteRegion::Header, 0, 6,
    ));
    fields.push(Field::leaf(
        "eth.src", "Source MAC", "eth", FieldType::Addr,
        FieldValue::Str(parsed.src_mac.clone()), ByteRegion::Header, 6, 6,
    ));
    if let Some(vlan_tag) = &parsed.vlan_tag {
        fields.push(Field::group("eth.vlan", "802.1Q VLAN Tag", Some("eth"), ByteRegion::Header, 12, VLAN_TAG_LEN));
        let id: u64 = vlan_tag.parse().unwrap_or(0);
        fields.push(Field::leaf(
            "eth.vlan.id", "VLAN ID", "eth.vlan", FieldType::Uint,
            FieldValue::Uint(id), ByteRegion::Header, 14, 2,
        ));
    }
    let ethertype_offset = if vlan_tagged { 16 } else { 12 };
    let ethertype_label = match parsed.ip_version {
        4 => "IPv4",
        6 => "IPv6",
        _ => "Unknown",
    };
    fields.push(Field::leaf(
        "eth.type", "EtherType", "eth", FieldType::Str,
        FieldValue::Str(ethertype_label.to_string()), ByteRegion::Header, ethertype_offset, 2,
    ));
    (fields, eth_len)
}

/// Returns (fields, byte offset where the transport header starts). Every
/// currently-decoded field sits in the fixed (non-options/non-extension)
/// portion of the IPv4/IPv6 header, at its RFC 791 / RFC 8200 offset.
fn ip_fields(parsed: &ParsedPacket, ip_start: u32) -> (Vec<Field>, u32) {
    if parsed.ip_version == 6 {
        let mut fields = vec![Field::group("ip6", "Internet Protocol Version 6", None, ByteRegion::Header, ip_start, IPV6_HEADER_LEN)];
        fields.push(Field::leaf(
            "ip6.src", "Source Address", "ip6", FieldType::Addr,
            FieldValue::Str(parsed.src_ip.clone()), ByteRegion::Header, ip_start + 8, 16,
        ));
        fields.push(Field::leaf(
            "ip6.dst", "Destination Address", "ip6", FieldType::Addr,
            FieldValue::Str(parsed.dst_ip.clone()), ByteRegion::Header, ip_start + 24, 16,
        ));
        fields.push(Field::leaf(
            "ip6.hop_limit", "Hop Limit", "ip6", FieldType::Uint,
            FieldValue::Uint(parsed.ttl as u64), ByteRegion::Header, ip_start + 7, 1,
        ));
        fields.push(Field::leaf(
            "ip6.next_header", "Next Header", "ip6", FieldType::Uint,
            FieldValue::Uint(protocol_num(parsed.protocol) as u64), ByteRegion::Header, ip_start + 6, 1,
        ));
        (fields, ip_start + IPV6_HEADER_LEN)
    } else {
        let mut fields = vec![Field::group("ip", "Internet Protocol Version 4", None, ByteRegion::Header, ip_start, IPV4_HEADER_LEN)];
        fields.push(Field::leaf(
            "ip.src", "Source Address", "ip", FieldType::Addr,
            FieldValue::Str(parsed.src_ip.clone()), ByteRegion::Header, ip_start + 12, 4,
        ));
        fields.push(Field::leaf(
            "ip.dst", "Destination Address", "ip", FieldType::Addr,
            FieldValue::Str(parsed.dst_ip.clone()), ByteRegion::Header, ip_start + 16, 4,
        ));
        fields.push(Field::leaf(
            "ip.ttl", "Time to Live", "ip", FieldType::Uint,
            FieldValue::Uint(parsed.ttl as u64), ByteRegion::Header, ip_start + 8, 1,
        ));
        fields.push(Field::leaf(
            "ip.protocol_num", "Protocol", "ip", FieldType::Uint,
            FieldValue::Uint(protocol_num(parsed.protocol) as u64), ByteRegion::Header, ip_start + 9, 1,
        ));
        if let Some(checksum) = parsed.ip_checksum {
            fields.push(Field::leaf(
                "ip.checksum", "Header Checksum", "ip", FieldType::Str,
                FieldValue::Str(format!("0x{checksum:04x}")), ByteRegion::Header, ip_start + 10, 2,
            ));
        }
        (fields, ip_start + IPV4_HEADER_LEN)
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd capture-agent && cargo test --locked fields::`
Expected: PASS, all tests including Task 2's 4 plus these 4 new ones.

- [ ] **Step 5: Commit**

```bash
git add capture-agent/src/fields.rs
git commit -m "fields.rs: build eth.*/ip.*/ip6.* fields with real byte offsets

Constant arithmetic off ParsedPacket's own ip_version/vlan_tag —
every currently-decoded field lives in a header's fixed portion, so
no re-parsing is needed to locate it.

Part of JAM-9 (field model)."
```

---

### Task 4: `fields.rs` — transport-layer fields

**Files:**
- Modify: `capture-agent/src/fields.rs`
- Test: inline `#[cfg(test)]`

**Interfaces:**
- Consumes: `eth_fields`/`ip_fields` (Task 3, for the offsets tests build on).
- Produces: `transport_fields(parsed: &ParsedPacket, start: u32) -> Vec<Field>`, private.

- [ ] **Step 1: Write the failing tests**

Add to `fields.rs`'s `mod tests`:

```rust
    #[test]
    fn transport_fields_places_tcp_ports_and_flags_at_their_fixed_offsets() {
        let mut p = base_packet();
        p.protocol = TransportProtocol::Tcp;
        p.src_port = Some(51000);
        p.dst_port = Some(443);
        p.seq = Some(1000);
        p.tcp_flags = Some(crate::parse::TcpFlags { syn: true, ack: false, fin: false, rst: false, window_size: 65535, ack_number: 0 });

        let fields = transport_fields(&p, 34);

        let tcp = fields.iter().find(|f| f.path == "tcp").unwrap();
        assert_eq!(tcp.offset, 34);
        assert_eq!(tcp.len, 20);
        let src_port = fields.iter().find(|f| f.path == "tcp.src_port").unwrap();
        assert_eq!(src_port.offset, 34);
        assert!(matches!(&src_port.value, Some(FieldValue::Uint(51000))));
        let syn = fields.iter().find(|f| f.path == "tcp.flags.syn").unwrap();
        assert_eq!(syn.offset, 34 + 13);
        assert_eq!(syn.group.as_deref(), Some("tcp.flags"));
        assert!(matches!(&syn.value, Some(FieldValue::Bool(true))));
        let ack = fields.iter().find(|f| f.path == "tcp.flags.ack").unwrap();
        assert_eq!(ack.offset, 34 + 13, "flag siblings share the one flags byte");
        assert!(matches!(&ack.value, Some(FieldValue::Bool(false))));
        let window = fields.iter().find(|f| f.path == "tcp.window_size").unwrap();
        assert_eq!(window.offset, 34 + 14);
        assert!(matches!(&window.value, Some(FieldValue::Uint(65535))));
    }

    #[test]
    fn transport_fields_covers_udp_with_just_ports_no_fabricated_flags_or_seq() {
        let mut p = base_packet();
        p.protocol = TransportProtocol::Udp;
        p.src_port = Some(60123);
        p.dst_port = Some(53);

        let fields = transport_fields(&p, 34);

        assert!(fields.iter().any(|f| f.path == "udp.src_port"));
        assert!(fields.iter().any(|f| f.path == "udp.dst_port"));
        assert!(fields.iter().all(|f| !f.path.starts_with("tcp")));
        assert!(
            fields.iter().all(|f| !f.path.contains("flags") && !f.path.contains("seq")),
            "UDP has neither — the old model fabricated seq=0 ack=0 for it, this must not"
        );
    }

    #[test]
    fn transport_fields_is_empty_for_icmp_and_other_nothing_decoded_to_show() {
        let mut p = base_packet();
        p.protocol = TransportProtocol::Icmp;
        assert!(transport_fields(&p, 34).is_empty());

        p.protocol = TransportProtocol::Other;
        assert!(transport_fields(&p, 34).is_empty());
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd capture-agent && cargo test --locked fields:: 2>&1 | head -20`
Expected: compile error — `transport_fields` not found.

- [ ] **Step 3: Implement**

Add to `fields.rs`:

```rust
const TCP_HEADER_LEN: u32 = 20;
const UDP_HEADER_LEN: u32 = 8;

/// Every currently-decoded transport field sits in TCP/UDP's fixed
/// (non-options) portion, at its RFC 793 / RFC 768 offset. ICMP and
/// unrecognized protocols produce no fields — nothing about them is
/// decoded into ParsedPacket today (payload is even empty for ICMP), so
/// there is nothing honest to hang a group on; the old header_breakdown
/// model fabricated a "Transport: ICMP, Ports: 0->0" block here, which
/// this deliberately does not reproduce.
fn transport_fields(parsed: &ParsedPacket, start: u32) -> Vec<Field> {
    match parsed.protocol {
        TransportProtocol::Tcp => {
            let flags = parsed.tcp_flags.unwrap_or_default();
            vec![
                Field::group("tcp", "Transmission Control Protocol", None, ByteRegion::Header, start, TCP_HEADER_LEN),
                Field::leaf("tcp.src_port", "Source Port", "tcp", FieldType::Uint, FieldValue::Uint(parsed.src_port.unwrap_or(0) as u64), ByteRegion::Header, start, 2),
                Field::leaf("tcp.dst_port", "Destination Port", "tcp", FieldType::Uint, FieldValue::Uint(parsed.dst_port.unwrap_or(0) as u64), ByteRegion::Header, start + 2, 2),
                Field::leaf("tcp.seq", "Sequence Number", "tcp", FieldType::Uint, FieldValue::Uint(parsed.seq.unwrap_or(0) as u64), ByteRegion::Header, start + 4, 4),
                Field::leaf("tcp.ack_number", "Acknowledgment Number", "tcp", FieldType::Uint, FieldValue::Uint(flags.ack_number as u64), ByteRegion::Header, start + 8, 4),
                Field::group("tcp.flags", "Flags", Some("tcp"), ByteRegion::Header, start + 13, 1),
                Field::leaf("tcp.flags.syn", "SYN", "tcp.flags", FieldType::Bool, FieldValue::Bool(flags.syn), ByteRegion::Header, start + 13, 1),
                Field::leaf("tcp.flags.ack", "ACK", "tcp.flags", FieldType::Bool, FieldValue::Bool(flags.ack), ByteRegion::Header, start + 13, 1),
                Field::leaf("tcp.flags.fin", "FIN", "tcp.flags", FieldType::Bool, FieldValue::Bool(flags.fin), ByteRegion::Header, start + 13, 1),
                Field::leaf("tcp.flags.rst", "RST", "tcp.flags", FieldType::Bool, FieldValue::Bool(flags.rst), ByteRegion::Header, start + 13, 1),
                Field::leaf("tcp.window_size", "Window Size", "tcp", FieldType::Uint, FieldValue::Uint(flags.window_size as u64), ByteRegion::Header, start + 14, 2),
            ]
        }
        TransportProtocol::Udp => vec![
            Field::group("udp", "User Datagram Protocol", None, ByteRegion::Header, start, UDP_HEADER_LEN),
            Field::leaf("udp.src_port", "Source Port", "udp", FieldType::Uint, FieldValue::Uint(parsed.src_port.unwrap_or(0) as u64), ByteRegion::Header, start, 2),
            Field::leaf("udp.dst_port", "Destination Port", "udp", FieldType::Uint, FieldValue::Uint(parsed.dst_port.unwrap_or(0) as u64), ByteRegion::Header, start + 2, 2),
        ],
        TransportProtocol::Icmp | TransportProtocol::Other => Vec::new(),
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd capture-agent && cargo test --locked fields::`
Expected: PASS, all tests so far plus these 3.

- [ ] **Step 5: Commit**

```bash
git add capture-agent/src/fields.rs
git commit -m "fields.rs: build tcp.*/udp.* fields; icmp/other yield none

UDP correctly omits flags/seq (the old model fabricated seq=0 ack=0
for it); ICMP/Other yield no group at all since nothing about them is
decoded into ParsedPacket today, rather than fabricating an empty
'Transport: ICMP' block the way header_breakdown did.

Part of JAM-9 (field model)."
```

---

### Task 5: `fields.rs` + `l7.rs` — application-layer fields and `build_fields`

**Files:**
- Modify: `capture-agent/src/fields.rs`
- Modify: `capture-agent/src/l7.rs` (`TlsClientHello` gains `sni_offset`/`sni_len`; doc-comment touch-up)
- Modify: `capture-agent/src/flow.rs` (2 test-fixture `L7Info::TlsClientHello` literals — compile-fix ripple)
- Test: inline `#[cfg(test)]` in `fields.rs`

**Interfaces:**
- Consumes: `eth_fields`/`ip_fields`/`transport_fields` (Tasks 3-4); `l7::L7Info` (existing, modified here).
- Produces: `app_fields(l7: &L7Info, payload_len: u32) -> Vec<Field>` (private), and the module's public entry point: `pub fn build_fields(parsed: &ParsedPacket, l7: &L7Info, link_type: LinkType) -> Vec<Field>`.

- [ ] **Step 1: Add `sni_offset`/`sni_len` to `L7Info::TlsClientHello`**

In `capture-agent/src/l7.rs`, change the variant:

```rust
    TlsClientHello {
        sni: String,
        ja3: Option<String>,
        ja3_label: Option<&'static str>,
        // The ClientHello's 32-byte `random` field, kept so the capture loop
        // can look up this flow's logged session secret by client_random
        // (Tier B / Task 13) — never sent over the wire, purely an
        // in-process decrypt-eligibility lookup key.
        client_random: Option<Vec<u8>>,
        /// Byte offset/length of the SNI value within `payload` — carried
        /// forward from the extension walk below instead of discarded, so
        /// fields.rs can highlight exactly the SNI bytes rather than the
        /// whole ClientHello. Both 0 only in the (impossible in practice,
        /// since `sni` is only ever `Some` after this is set) case sni
        /// itself is absent.
        sni_offset: usize,
        sni_len: usize,
    },
```

In `sniff_tls_client_hello`, hoist tracking variables above the extension loop (right after `let mut ec_point_formats = Vec::new();`):

```rust
    let mut sni_offset = 0usize;
    let mut sni_len = 0usize;
```

In the `(0x0000, Some(_))` match arm, set them alongside `sni`:

```rust
            (0x0000, Some(_)) => {
                // server_name extension: skip list length(2) + type(1) to reach name length(2)
                let name_len_idx = ext_start + 3;
                if let (Some(&hi), Some(&lo)) = (payload.get(name_len_idx), payload.get(name_len_idx + 1)) {
                    let name_len = u16::from_be_bytes([hi, lo]) as usize;
                    let name_start = name_len_idx + 2;
                    if let Some(name_bytes) = payload.get(name_start..name_start + name_len) {
                        sni = std::str::from_utf8(name_bytes).ok().map(|s| s.to_string());
                        sni_offset = name_start;
                        sni_len = name_len;
                    }
                }
            }
```

And update the final construction:

```rust
    Some(L7Info::TlsClientHello { sni, ja3, ja3_label, client_random, sni_offset, sni_len })
```

Update the doc comment on `HttpResponse` that references the old wire shape:

```rust
    /// Populates `http.response.code` on the wire (fields.rs), which was
```

(replacing the existing `Populates \`Layer7Json.status_or_code\`, which was previously` line — same sentence, new field name.)

- [ ] **Step 2: Fix the compile ripple in `flow.rs`'s two `TlsClientHello` fixtures**

In `capture-agent/src/flow.rs`, both `L7Info::TlsClientHello { ... }` test literals (in `observe_records_ja3_from_a_tls_client_hello_and_keeps_it_across_later_non_tls_packets` and `client_random_for_returns_none_until_a_client_hello_is_observed`) need `sni_offset: 0, sni_len: 0` added — these tests only assert on `ja3`/`ja3_label`/`client_random`, not offsets, so a valid-but-unused 0/0 is honest here (it's simply not what those tests are about). Add the two fields to each literal, e.g.:

```rust
        let l7 = L7Info::TlsClientHello {
            sni: "example.com".to_string(),
            ja3: Some("abc123".to_string() + &"0".repeat(26)),
            ja3_label: Some("matches Chrome 12x"),
            client_random: Some(vec![0xab; 32]),
            sni_offset: 0,
            sni_len: 0,
        };
```

(and the same two lines added to the second literal, in `client_random_for_returns_none_until_a_client_hello_is_observed`).

- [ ] **Step 3: Run to verify the crate still compiles and existing tests pass**

Run: `cd capture-agent && cargo test --locked l7:: flow::`
Expected: PASS — this step only changed data shape, not behavior; every existing assertion should still hold.

- [ ] **Step 4: Write the failing `fields.rs` tests**

Add to `fields.rs`'s `mod tests`:

```rust
    use crate::l7::L7Info;

    #[test]
    fn app_fields_covers_an_http_request() {
        let l7 = L7Info::Http { method: "GET".to_string(), path: "/index.html".to_string() };
        let fields = app_fields(&l7, 50);
        assert!(fields.iter().any(|f| f.path == "http"));
        let method = fields.iter().find(|f| f.path == "http.request.method").unwrap();
        assert!(matches!(&method.value, Some(FieldValue::Str(v)) if v == "GET"));
        assert_eq!(method.region, ByteRegion::Payload);
        let uri = fields.iter().find(|f| f.path == "http.request.uri").unwrap();
        assert!(matches!(&uri.value, Some(FieldValue::Str(v)) if v == "/index.html"));
    }

    #[test]
    fn app_fields_covers_an_http_response_status_as_a_real_uint() {
        let l7 = L7Info::HttpResponse { status: "404".to_string() };
        let fields = app_fields(&l7, 30);
        let code = fields.iter().find(|f| f.path == "http.response.code").unwrap();
        assert!(matches!(&code.value, Some(FieldValue::Uint(404))));
    }

    #[test]
    fn app_fields_covers_dns() {
        let l7 = L7Info::Dns { query_name: "example.com".to_string() };
        let fields = app_fields(&l7, 20);
        let name = fields.iter().find(|f| f.path == "dns.qry.name").unwrap();
        assert!(matches!(&name.value, Some(FieldValue::Str(v)) if v == "example.com"));
    }

    #[test]
    fn app_fields_covers_tls_with_a_precisely_offset_sni_and_optional_ja3() {
        let l7 = L7Info::TlsClientHello {
            sni: "example.com".to_string(),
            ja3: Some("deadbeef".to_string()),
            ja3_label: Some("matches Chrome 12x"),
            client_random: None,
            sni_offset: 49,
            sni_len: 11,
        };
        let fields = app_fields(&l7, 165);
        let sni = fields.iter().find(|f| f.path == "tls.handshake.sni").unwrap();
        assert_eq!(sni.offset, 49);
        assert_eq!(sni.len, 11);
        assert!(matches!(&sni.value, Some(FieldValue::Str(v)) if v == "example.com"));
        let ja3 = fields.iter().find(|f| f.path == "tls.ja3").unwrap();
        assert!(matches!(&ja3.value, Some(FieldValue::Str(v)) if v == "deadbeef"));
        let label = fields.iter().find(|f| f.path == "tls.ja3_label").unwrap();
        assert!(matches!(&label.value, Some(FieldValue::Str(v)) if v == "matches Chrome 12x"));
    }

    #[test]
    fn app_fields_omits_ja3_and_ja3_label_when_absent() {
        let l7 = L7Info::TlsClientHello {
            sni: "example.com".to_string(), ja3: None, ja3_label: None, client_random: None,
            sni_offset: 0, sni_len: 11,
        };
        let fields = app_fields(&l7, 100);
        assert!(fields.iter().all(|f| f.path != "tls.ja3"));
        assert!(fields.iter().all(|f| f.path != "tls.ja3_label"));
    }

    #[test]
    fn app_fields_is_empty_when_no_l7_info() {
        assert!(app_fields(&L7Info::None, 10).is_empty());
    }

    #[test]
    fn build_fields_assembles_a_complete_tcp_http_packet() {
        let mut p = base_packet();
        p.protocol = TransportProtocol::Tcp;
        p.src_port = Some(51000);
        p.dst_port = Some(80);
        p.tcp_flags = Some(crate::parse::TcpFlags::default());
        let l7 = L7Info::Http { method: "GET".to_string(), path: "/".to_string() };

        let fields = build_fields(&p, &l7, LinkType::Ethernet);

        assert!(fields.iter().any(|f| f.path == "eth"));
        assert!(fields.iter().any(|f| f.path == "ip"));
        assert!(fields.iter().any(|f| f.path == "tcp"));
        assert!(fields.iter().any(|f| f.path == "http"));
    }

    #[test]
    fn build_fields_omits_eth_for_non_ethernet_framing() {
        let p = base_packet();
        let fields = build_fields(&p, &L7Info::None, LinkType::NullLoopback);
        assert!(
            fields.iter().all(|f| !f.path.starts_with("eth")),
            "no real Ethernet header exists on loopback/raw framing — an eth group here would point at bytes that were never sent"
        );
        assert!(fields.iter().any(|f| f.path == "ip"), "the IP header starts at offset 0 when there's no L2 header");
        let ip = fields.iter().find(|f| f.path == "ip").unwrap();
        assert_eq!(ip.offset, 0);
    }
```

- [ ] **Step 5: Run to verify it fails**

Run: `cd capture-agent && cargo test --locked fields:: 2>&1 | head -20`
Expected: compile error — `app_fields`/`build_fields` not found.

- [ ] **Step 6: Implement**

Add to `fields.rs`:

```rust
/// Application-layer fields, offset relative to `payload` (region=Payload,
/// the existing hexDump pane — unchanged base, unchanged cap). Text-based
/// leaves (method/uri/status/query name) span the whole payload rather than
/// pinpointing their exact substring — a deliberate, honest simplification;
/// only tls.handshake.sni gets a precise sub-range, since l7.rs's existing
/// extension walk already computes it for free. JA3/ja3_label are derived
/// from several non-contiguous ClientHello sub-fields, so they too span the
/// whole message — the same "derived field points at what it was derived
/// from" convention.
fn app_fields(l7: &L7Info, payload_len: u32) -> Vec<Field> {
    match l7 {
        L7Info::Http { method, path } => vec![
            Field::group("http", "Hypertext Transfer Protocol", None, ByteRegion::Payload, 0, payload_len),
            Field::leaf("http.request.method", "Request Method", "http", FieldType::Str, FieldValue::Str(method.clone()), ByteRegion::Payload, 0, payload_len),
            Field::leaf("http.request.uri", "Request URI", "http", FieldType::Str, FieldValue::Str(path.clone()), ByteRegion::Payload, 0, payload_len),
        ],
        L7Info::HttpResponse { status } => {
            let code: u64 = status.parse().unwrap_or(0);
            vec![
                Field::group("http", "Hypertext Transfer Protocol", None, ByteRegion::Payload, 0, payload_len),
                Field::leaf("http.response.code", "Status Code", "http", FieldType::Uint, FieldValue::Uint(code), ByteRegion::Payload, 0, payload_len),
            ]
        }
        L7Info::Dns { query_name } => vec![
            Field::group("dns", "Domain Name System", None, ByteRegion::Payload, 0, payload_len),
            Field::leaf("dns.qry.name", "Query Name", "dns", FieldType::Str, FieldValue::Str(query_name.clone()), ByteRegion::Payload, 0, payload_len),
        ],
        L7Info::TlsClientHello { sni, ja3, ja3_label, sni_offset, sni_len, .. } => {
            let mut fields = vec![Field::group("tls", "Transport Layer Security", None, ByteRegion::Payload, 0, payload_len)];
            fields.push(Field::leaf(
                "tls.handshake.sni", "Server Name", "tls", FieldType::Str,
                FieldValue::Str(sni.clone()), ByteRegion::Payload, *sni_offset as u32, *sni_len as u32,
            ));
            if let Some(ja3_hash) = ja3 {
                fields.push(Field::leaf("tls.ja3", "JA3 Fingerprint", "tls", FieldType::Str, FieldValue::Str(ja3_hash.clone()), ByteRegion::Payload, 0, payload_len));
            }
            if let Some(label) = ja3_label {
                fields.push(Field::leaf("tls.ja3_label", "JA3 Label", "tls", FieldType::Str, FieldValue::Str(label.to_string()), ByteRegion::Payload, 0, payload_len));
            }
            fields
        }
        L7Info::None => Vec::new(),
    }
}

/// The module's public entry point — one call per `Packet` wire event,
/// replacing `wire::build_header_breakdown` (deleted in the next task).
/// `link_type` decides whether an `eth` group exists at all: NullLoopback
/// and Raw framing carry no real Ethernet header, so fabricating one would
/// point at bytes that were never on the wire.
pub fn build_fields(parsed: &ParsedPacket, l7: &L7Info, link_type: crate::parse::LinkType) -> Vec<Field> {
    let mut fields = Vec::new();
    let ip_start = if link_type == crate::parse::LinkType::Ethernet {
        let (eth, next) = eth_fields(parsed);
        fields.extend(eth);
        next
    } else {
        0
    };
    let (ip, transport_start) = ip_fields(parsed, ip_start);
    fields.extend(ip);
    fields.extend(transport_fields(parsed, transport_start));
    fields.extend(app_fields(l7, parsed.payload.len() as u32));
    fields
}
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cd capture-agent && cargo test --locked fields::`
Expected: PASS — all tests from Tasks 2-5.

- [ ] **Step 8: Run the full crate test suite**

Run: `cd capture-agent && cargo test --locked`
Expected: PASS, 0 failed — confirms the `l7.rs`/`flow.rs` ripple edits didn't break anything.

- [ ] **Step 9: Commit**

```bash
git add capture-agent/src/fields.rs capture-agent/src/l7.rs capture-agent/src/flow.rs
git commit -m "fields.rs: app-layer fields; build_fields is now the module's entry point

L7Info::TlsClientHello carries sni_offset/sni_len forward instead of
discarding them, so tls.handshake.sni highlights precisely rather
than spanning the whole payload like every other text-based L7 leaf
does. build_fields(parsed, l7, link_type) assembles the complete
per-packet field list and is now ready to replace
wire::build_header_breakdown at its one call site (next task).

Part of JAM-9 (field model)."
```

---

### Task 6: Wire `fields`/`headerHexDump` into `PacketJson`; delete the old shape

**Files:**
- Modify: `capture-agent/src/wire.rs` (add `PacketJson.fields`/`header_hex_dump`; delete `HeaderBreakdownJson`, `Layer7Json`, `Layer4Json`, `Layer3Json`, `Layer2Json`, `build_header_breakdown`, `protocol_num`, and their tests)
- Modify: `capture-agent/src/main.rs` (call site)
- Test: `capture-agent/src/wire.rs` inline (new), plus verifying old tests are gone, not just disabled

**Interfaces:**
- Consumes: `fields::{Field, build_fields}` (Task 5); `parse::ParsedPacket.header_bytes` (Task 1).
- Produces: `PacketJson.fields: Vec<Field>`, `PacketJson.header_hex_dump: String` — what `lib/agent-mapping.ts` (Task 9) will read.

- [ ] **Step 1: Update `PacketJson` and delete the old structs**

In `capture-agent/src/wire.rs`, delete these top-to-bottom: `Layer7Json`, `Layer4Json`, `Layer3Json`, `Layer2Json`, `HeaderBreakdownJson`, the `protocol_num` function, and the `build_header_breakdown` function (everything from the doc comment above `protocol_num` through the closing brace of `build_header_breakdown`).

Change `PacketJson`:

```rust
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
    pub header_hex_dump: String,
    pub fields: Vec<crate::fields::Field>,
}
```

- [ ] **Step 2: Delete the old tests that exercised the deleted code**

Remove these test functions from `wire.rs`'s `mod tests` (they test `build_header_breakdown`/`HeaderBreakdownJson`, which no longer exist): `sample_tcp_packet`, `sample_udp_packet` (the two fixture-builder helpers), `build_header_breakdown_fills_layer7_for_tcp_http`, `build_header_breakdown_fills_layer7_status_or_code_for_http_response`, `build_header_breakdown_fills_layer7_for_udp_dns`, `build_header_breakdown_omits_layer7_when_no_l7_info`.

Update `encode_event_uses_camel_case_and_omits_unmeasurable_layers` — it built a `PacketJson` using `header_breakdown`, which no longer compiles. Replace it:

```rust
    #[test]
    fn encode_event_uses_camel_case_for_packet_fields() {
        let event = AgentEvent::Packet {
            packet: Box::new(PacketJson {
                id: "pkt-1".to_string(),
                timestamp: "1000".to_string(),
                relative_time_ms: 1,
                layer: 4,
                protocol: "TCP".to_string(),
                src: "192.168.1.10:51000".to_string(),
                dst: "93.184.216.34:80".to_string(),
                length: 60,
                summary: "TCP 192.168.1.10 -> 93.184.216.34".to_string(),
                hex_dump: "00 01".to_string(),
                header_hex_dump: "aa bb cc".to_string(),
                fields: vec![crate::fields::Field::leaf(
                    "tcp.src_port", "Source Port", "tcp",
                    crate::fields::FieldType::Uint, crate::fields::FieldValue::Uint(51000),
                    crate::fields::ByteRegion::Header, 34, 2,
                )],
            }),
        };

        let line = encode_event(&event);

        assert!(line.contains("\"headerHexDump\":\"aa bb cc\""));
        assert!(line.contains("\"path\":\"tcp.src_port\""));
        assert!(line.contains("\"relativeTimeMs\":1"));
    }
```

- [ ] **Step 3: Run to verify wire.rs compiles and its remaining tests pass**

Run: `cd capture-agent && cargo test --locked wire:: 2>&1 | tail -40`
Expected: FAIL to compile — `main.rs` still calls `wire::build_header_breakdown` and constructs `PacketJson { header_breakdown: ..., .. }`, both now gone. This is expected; fixed in the next step.

- [ ] **Step 4: Update the `main.rs` call site**

In `capture-agent/src/main.rs`, replace:

```rust
                        let header_breakdown = wire::build_header_breakdown(&parsed, &l7_info);
                        let packet_json = wire::PacketJson {
                            id: format!("pkt-{epoch_ms}-{seq}"),
                            timestamp: epoch_ms.to_string(),
                            relative_time_ms: now_ms,
                            layer: 4,
                            protocol: format!("{:?}", parsed.protocol).to_uppercase(),
                            src: format!("{}:{}", parsed.src_ip, parsed.src_port.unwrap_or(0)),
                            dst: format!("{}:{}", parsed.dst_ip, parsed.dst_port.unwrap_or(0)),
                            length: parsed.total_len as u32,
                            summary: format!(
                                "{:?} {} -> {}",
                                parsed.protocol, parsed.src_ip, parsed.dst_ip
                            ),
                            hex_dump: parsed
                                .payload
                                .iter()
                                .take(64)
                                .map(|b| format!("{b:02x}"))
                                .collect::<Vec<_>>()
                                .join(" "),
                            header_breakdown,
                        };
```

with:

```rust
                        let packet_fields = fields::build_fields(&parsed, &l7_info, link_type);
                        let packet_json = wire::PacketJson {
                            id: format!("pkt-{epoch_ms}-{seq}"),
                            timestamp: epoch_ms.to_string(),
                            relative_time_ms: now_ms,
                            layer: 4,
                            protocol: format!("{:?}", parsed.protocol).to_uppercase(),
                            src: format!("{}:{}", parsed.src_ip, parsed.src_port.unwrap_or(0)),
                            dst: format!("{}:{}", parsed.dst_ip, parsed.dst_port.unwrap_or(0)),
                            length: parsed.total_len as u32,
                            summary: format!(
                                "{:?} {} -> {}",
                                parsed.protocol, parsed.src_ip, parsed.dst_ip
                            ),
                            // Capped to the first 64 bytes of payload — plenty
                            // for display, avoids sending huge lines for large
                            // payloads.
                            hex_dump: parsed
                                .payload
                                .iter()
                                .take(64)
                                .map(|b| format!("{b:02x}"))
                                .collect::<Vec<_>>()
                                .join(" "),
                            // No cap: every currently-decoded field lives in a
                            // header's fixed portion, so header_bytes is
                            // inherently small (worst case today ~78 bytes).
                            header_hex_dump: parsed
                                .header_bytes
                                .iter()
                                .map(|b| format!("{b:02x}"))
                                .collect::<Vec<_>>()
                                .join(" "),
                            fields: packet_fields,
                        };
```

Add `use crate::fields;` near the top of `main.rs` alongside the other `use crate::...` lines if not already present (check first — `main.rs` likely already has a block of `use crate::{...}` imports; add `fields` to it rather than a new standalone `use` line).

- [ ] **Step 5: Run the full crate build and test suite**

Run: `cd capture-agent && cargo build --locked && cargo test --locked`
Expected: builds clean, all tests pass, 0 failed.

- [ ] **Step 6: Run clippy**

Run: `cd capture-agent && cargo clippy --all-targets --locked -- -D warnings`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add capture-agent/src/wire.rs capture-agent/src/main.rs
git commit -m "Cut PacketJson over to fields/headerHexDump; delete header_breakdown

No dual-emit: header_breakdown and its four Layer*Json structs are
gone in this same change, not deprecated in place. Deleted their
tests along with them and added new coverage for the replacement
shape. This is the wire-protocol cutover commit -- lib/types.ts and
lib/agent-mapping.ts (next tasks) must land before the relay can
parse this agent's output again.

Part of JAM-9 (field model)."
```

---

### Task 7: `docs/wire-protocol.md`

**Files:**
- Modify: `docs/wire-protocol.md`

**Interfaces:** none (documentation only).

- [ ] **Step 1: Replace the `packet` event section**

Replace the existing `### \`packet\`` section (from its heading through the paragraph ending "`timestamp` is epoch milliseconds as a string, not ISO-8601.") with:

```markdown
### `packet`

Sent once per captured packet, immediately (not batched).

```json
{
  "type": "packet",
  "packet": {
    "id": "pkt-1787799628962-37",
    "timestamp": "1787799628962",
    "relativeTimeMs": 2243,
    "layer": 4,
    "protocol": "TCP",
    "src": "192.168.1.10:51000",
    "dst": "93.184.216.34:443",
    "length": 60,
    "summary": "Tcp 192.168.1.10 -> 93.184.216.34",
    "hexDump": "00 01 02 ...",
    "headerHexDump": "06 07 08 09 0a 0b 00 01 02 03 04 05 08 00 45 00 ...",
    "fields": [
      {"path":"eth","label":"Ethernet II","type":"group","region":"header","offset":0,"len":14},
      {"path":"eth.dst","label":"Destination MAC","type":"addr","group":"eth","region":"header","value":"06:07:08:09:0a:0b","offset":0,"len":6},
      {"path":"eth.src","label":"Source MAC","type":"addr","group":"eth","region":"header","value":"00:01:02:03:04:05","offset":6,"len":6},
      {"path":"eth.type","label":"EtherType","type":"str","group":"eth","region":"header","value":"IPv4","offset":12,"len":2},
      {"path":"ip","label":"Internet Protocol Version 4","type":"group","region":"header","offset":14,"len":20},
      {"path":"ip.src","label":"Source Address","type":"addr","group":"ip","region":"header","value":"192.168.1.10","offset":26,"len":4},
      {"path":"ip.dst","label":"Destination Address","type":"addr","group":"ip","region":"header","value":"93.184.216.34","offset":30,"len":4},
      {"path":"ip.ttl","label":"Time to Live","type":"uint","group":"ip","region":"header","value":64,"offset":22,"len":1},
      {"path":"ip.protocol_num","label":"Protocol","type":"uint","group":"ip","region":"header","value":6,"offset":23,"len":1},
      {"path":"ip.checksum","label":"Header Checksum","type":"str","group":"ip","region":"header","value":"0xbeef","offset":24,"len":2},
      {"path":"tcp","label":"Transmission Control Protocol","type":"group","region":"header","offset":34,"len":20},
      {"path":"tcp.src_port","label":"Source Port","type":"uint","group":"tcp","region":"header","value":51000,"offset":34,"len":2},
      {"path":"tcp.dst_port","label":"Destination Port","type":"uint","group":"tcp","region":"header","value":443,"offset":36,"len":2},
      {"path":"tcp.seq","label":"Sequence Number","type":"uint","group":"tcp","region":"header","value":1000,"offset":38,"len":4},
      {"path":"tcp.ack_number","label":"Acknowledgment Number","type":"uint","group":"tcp","region":"header","value":0,"offset":42,"len":4},
      {"path":"tcp.flags","label":"Flags","type":"group","group":"tcp","region":"header","offset":47,"len":1},
      {"path":"tcp.flags.syn","label":"SYN","type":"bool","group":"tcp.flags","region":"header","value":true,"offset":47,"len":1},
      {"path":"tcp.flags.ack","label":"ACK","type":"bool","group":"tcp.flags","region":"header","value":false,"offset":47,"len":1},
      {"path":"tcp.flags.fin","label":"FIN","type":"bool","group":"tcp.flags","region":"header","value":false,"offset":47,"len":1},
      {"path":"tcp.flags.rst","label":"RST","type":"bool","group":"tcp.flags","region":"header","value":false,"offset":47,"len":1},
      {"path":"tcp.window_size","label":"Window Size","type":"uint","group":"tcp","region":"header","value":65535,"offset":48,"len":2}
    ]
  }
}
```

Maps to `PacketFrame` via `mapPacketEvent`, which throws if `fields` is missing entirely rather than defaulting it to `[]` — same discipline `headerBreakdown` used to have (see [issue #29](https://github.com/usjbro/network_monitor/issues/29), closed). `PacketJson` (`capture-agent/src/wire.rs`) carries `fields: Vec<Field>` and `headerHexDump: String`, built by `fields::build_fields` (`capture-agent/src/fields.rs`) and `parsed.header_bytes` respectively, at the point each `Packet` event is constructed in `main.rs`'s capture loop.

**Two independent hex-dump panes, not one.** `hexDump` (unchanged from before this field model existed) covers only `parsed.payload` — bytes after the transport header — capped at 64. `headerHexDump` is new: the Ethernet/IP/transport header bytes, uncapped (bounded naturally, since every currently-decoded field lives in a fixed header portion). Every `Field` carries a `region` (`"header"` or `"payload"`) saying which pane its `offset`/`len` is relative to — the two byte spaces are never merged.

**Field shape.** `path` is the stable, dotted, Wireshark-style abbreviation (`tcp.flags.syn`) — this is user-visible filter syntax once JAM-10 lands, so treat it as part of the wire contract, not internal naming. `label` is for display. `group` is the immediate parent's `path`, omitted (not `null`) for a top-level entry. `type` is one of `group`/`bool`/`uint`/`string`/`addr`/`bytes`. `value` is omitted entirely (not `null`) for a `group` entry — groups carry no value, only a byte range spanning their children (so hovering `tcp` highlights the whole 20-byte TCP header, hovering `tcp.flags` highlights just its one byte). Sibling bit-fields sharing one byte (all four of `tcp.flags.*`) legitimately share the same `offset`/`len`.

**Top-level groups are named by the protocol actually present**, not by OSI layer number: `eth` only for real Ethernet framing (never fabricated for `NullLoopback`/`Raw`, which carry no real L2 header at all — see `capture-agent/src/fields.rs`'s `build_fields`), `ip` or `ip6`, `tcp`/`udp` (never both; ICMP and unrecognized protocols produce no transport group at all — nothing about them is decoded today, so there's nothing honest to show, unlike the old model's fabricated `"Transport: ICMP, Ports: 0->0"`), and an app-layer group named for whatever was detected (`http`, `dns`, `tls`) — absent entirely when nothing matched. A VLAN tag, when present, is `eth.vlan` (group) → `eth.vlan.id` (child).

**Byte offsets are exact**, computed from fixed RFC-defined header-layout constants (`capture-agent/src/fields.rs`) — no field today lives in a variable-length region (TCP options, IPv6 extension headers) so none needs dynamic offset resolution beyond that arithmetic. The one exception is `tls.handshake.sni`, whose offset comes from the extension walk that already locates it (`l7::sniff_tls_client_hello`). Every other application-layer leaf (`http.request.method`, `http.request.uri`, `http.response.code`, `dns.qry.name`, `tls.ja3`, `tls.ja3_label`) spans its whole app-layer group's payload range rather than pinpointing an exact substring — a deliberate simplification, not an omission.

`timestamp` is epoch milliseconds as a string, not ISO-8601.
```

- [ ] **Step 2: Update the field-addition checklist**

Replace the `## Adding a new field or event type` section's step 1-2 (which reference `*Json` structs generically — still broadly correct, but the packet-field case now has a more specific path worth naming) by adding a note directly beneath the existing numbered list:

```markdown
For a new *packet* field specifically: register it in `capture-agent/src/fields.rs` (`eth_fields`/`ip_fields`/`transport_fields`/`app_fields`, whichever protocol it belongs to) rather than adding a new struct — the whole point of the field model (see the `packet` event section above) is that one registration there is the decode, the wire shape, and the tree label at once. `lib/types.ts`'s `WireField` and `lib/agent-mapping.ts`'s mapping need no change for a new field of an existing type — they're already generic over the flat field list.
```

- [ ] **Step 3: Commit**

```bash
git add docs/wire-protocol.md
git commit -m "docs/wire-protocol.md: document the field model, retire headerBreakdown

Part of JAM-9 (field model)."
```

---

### Task 8: `lib/types.ts` — `WireField` and `PacketFrame`

**Files:**
- Modify: `lib/types.ts`

**Interfaces:**
- Produces: `WireField` (exported type), `PacketFrame.fields: WireField[]`, `PacketFrame.headerHexDump: string` — what Task 9's mapping and Task 10/11's UI consume.

- [ ] **Step 1: Replace the `headerBreakdown` block**

In `lib/types.ts`, find the `PacketFrame` interface (currently has `headerBreakdown: { layer7?: ...; layer6?: ...; ... }`) and replace:

```typescript
  headerBreakdown: {
    layer7?: { app: string; methodOrType: string; pathOrQuery: string; statusOrCode?: string; payloadBytes: number };
    layer6?: { tlsVersion: string; cipherSuite: string; compression: string; payloadEncrypted: boolean };
    layer5?: { sessionType: string; sessionId: string; token: string };
    layer4?: { transport: string; srcPort: number; dstPort: number; flags: string; windowSize: number; seqAck: string };
    layer3?: { ipVersion: string; srcIp: string; dstIp: string; ttl: number; protocolNum: number; checksum: string };
    layer2?: { srcMac: string; dstMac: string; ethType: string; vlanTag?: string };
    layer1?: { phyType: string; bitrateMbps: number; snrDb: number; linkStatus: string };
  };
```

with:

```typescript
  // Header-region bytes (Ethernet/IP/transport) — a separate pane from
  // hexDump below, which covers only the L4 payload. No cap: every
  // currently-decoded field lives in a fixed header portion, so this is
  // inherently small.
  headerHexDump: string;
  // The field registry's per-packet output (docs/wire-protocol.md's
  // `packet` event section) — a flat list; components/FieldTree.ts (Task
  // 10) groups it into a tree by each entry's `group`.
  fields: WireField[];
```

Add the `WireField` type above the `PacketFrame` interface it's now used by:

```typescript
// One entry from the agent's per-packet field registry
// (capture-agent/src/fields.rs, docs/wire-protocol.md's `packet` event
// section). A `group` entry (type: 'group') carries no `value` — only a
// byte range spanning its children. `region` says which of the two
// hex-dump panes `offset`/`len` is relative to.
export interface WireField {
  path: string;
  label: string;
  group?: string;
  // Note: 'str' below, not 'string' — matches Rust's FieldType enum
  // serializing via #[serde(rename_all = "lowercase")], which lowercases
  // the variant name "Str" as-is rather than spelling it out.
  type: 'group' | 'bool' | 'uint' | 'str' | 'addr' | 'bytes';
  value?: boolean | number | string;
  region: 'header' | 'payload';
  offset: number;
  len: number;
}
```

- [ ] **Step 2: Confirm the type-only change compiles**

Run: `cd /Users/jamesbrown/Documents/GitHub/network_monitor && npx tsc --noEmit 2>&1 | head -60`
Expected: many errors — every consumer of `PacketFrame.headerBreakdown` (agent-mapping.ts, PacketStreamView.tsx, export.ts's comment, and several test files) now fails to typecheck. This is expected; each is fixed in its own task below. Confirm the errors are all in the files this plan already knows about (`lib/agent-mapping.ts`, `components/PacketStreamView.tsx`, `lib/__tests__/*`) and nowhere unexpected — if `tsc` names a file not already in this plan's scope, stop and investigate before continuing.

- [ ] **Step 3: Commit**

```bash
git add lib/types.ts
git commit -m "lib/types.ts: WireField type; PacketFrame.headerBreakdown -> fields/headerHexDump

Part of JAM-9 (field model). Downstream consumers fixed in following commits."
```

---

### Task 9: `lib/agent-mapping.ts` — `mapPacketEvent`

**Files:**
- Modify: `lib/agent-mapping.ts`
- Modify: `lib/__tests__/agent-mapping.test.ts` (rewrite the `mapPacketEvent` describe block)
- Modify: `lib/__tests__/page-command-bar-capture.test.tsx` (one-line fixture fix)

**Interfaces:**
- Consumes: `WireField`, `PacketFrame` (Task 8).
- Produces: `mapPacketEvent(json: unknown): PacketFrame` — same signature, new body.

- [ ] **Step 1: Write the failing tests**

In `lib/__tests__/agent-mapping.test.ts`, replace the entire `describe('mapPacketEvent', ...)` block (all three existing `it` cases — they test the deleted `headerBreakdown` shape) with:

```typescript
describe('mapPacketEvent', () => {
  const wireField = {
    path: 'tcp.flags.syn',
    label: 'SYN',
    group: 'tcp.flags',
    type: 'bool',
    value: true,
    region: 'header',
    offset: 47,
    len: 1,
  };

  it('maps agent wire JSON to a PacketFrame, passing fields/headerHexDump through unchanged', () => {
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
      headerHexDump: 'aa bb cc',
      fields: [wireField],
    };

    const packet = mapPacketEvent(wire);

    expect(packet.id).toBe('pkt-1');
    expect(packet.hexDump).toBe('00 01 02');
    expect(packet.headerHexDump).toBe('aa bb cc');
    expect(packet.fields).toEqual([wireField]);
  });

  it('throws when fields is missing entirely, rather than defaulting to []', () => {
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
      headerHexDump: 'aa bb cc',
      // fields intentionally omitted
    };

    expect(() => mapPacketEvent(wire)).toThrow();
  });
});
```

In `lib/__tests__/page-command-bar-capture.test.tsx`, change the `packetEvent` fixture helper's `headerBreakdown: {}` line to:

```typescript
        headerHexDump: '',
        fields: [],
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /Users/jamesbrown/Documents/GitHub/network_monitor && npx vitest run lib/__tests__/agent-mapping.test.ts 2>&1 | tail -30`
Expected: FAIL — `mapPacketEvent` still reads `headerBreakdown`, which is `undefined` on these fixtures (or `packet.fields` is `undefined` since the implementation hasn't changed yet).

- [ ] **Step 3: Implement**

In `lib/agent-mapping.ts`, change `mapPacketEvent`:

```typescript
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
    headerHexDump: requireField(w, 'headerHexDump'),
    fields: requireField<PacketFrame['fields']>(w, 'fields'),
  };
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /Users/jamesbrown/Documents/GitHub/network_monitor && npx vitest run lib/__tests__/agent-mapping.test.ts lib/__tests__/page-command-bar-capture.test.tsx`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/agent-mapping.ts lib/__tests__/agent-mapping.test.ts lib/__tests__/page-command-bar-capture.test.tsx
git commit -m "lib/agent-mapping.ts: mapPacketEvent reads fields/headerHexDump

Straight passthrough now -- the field list is already flat on the
wire, no reshaping needed (unlike the old per-layer object).

Part of JAM-9 (field model)."
```

---

### Task 10: `lib/field-tree.ts` — the tree-builder

**Files:**
- Create: `lib/field-tree.ts`
- Test: `lib/__tests__/field-tree.test.ts`

**Interfaces:**
- Consumes: `WireField` (Task 8).
- Produces: `FieldTreeNode` (exported type), `buildFieldTree(fields: WireField[]): FieldTreeNode[]` — what Task 11's `PacketStreamView` renders from.

- [ ] **Step 1: Write the failing tests**

Create `lib/__tests__/field-tree.test.ts`:

```typescript
import { describe, expect, it } from 'vitest';
import { buildFieldTree } from '@/lib/field-tree';
import { WireField } from '@/lib/types';

function f(overrides: Partial<WireField> & Pick<WireField, 'path' | 'label' | 'type'>): WireField {
  return { region: 'header', offset: 0, len: 0, ...overrides };
}

describe('buildFieldTree', () => {
  it('nests a leaf under its group', () => {
    const fields: WireField[] = [
      f({ path: 'tcp', label: 'TCP', type: 'group' }),
      f({ path: 'tcp.src_port', label: 'Source Port', type: 'uint', group: 'tcp', value: 51000 }),
    ];

    const tree = buildFieldTree(fields);

    expect(tree).toHaveLength(1);
    expect(tree[0].field.path).toBe('tcp');
    expect(tree[0].children).toHaveLength(1);
    expect(tree[0].children[0].field.path).toBe('tcp.src_port');
  });

  it('nests multiple levels deep (group under group under group)', () => {
    const fields: WireField[] = [
      f({ path: 'tcp', label: 'TCP', type: 'group' }),
      f({ path: 'tcp.flags', label: 'Flags', type: 'group', group: 'tcp' }),
      f({ path: 'tcp.flags.syn', label: 'SYN', type: 'bool', group: 'tcp.flags', value: true }),
    ];

    const tree = buildFieldTree(fields);

    expect(tree[0].children[0].field.path).toBe('tcp.flags');
    expect(tree[0].children[0].children[0].field.path).toBe('tcp.flags.syn');
  });

  it('treats a field with no group as a root, even alongside other roots', () => {
    const fields: WireField[] = [
      f({ path: 'eth', label: 'Ethernet', type: 'group' }),
      f({ path: 'ip', label: 'IP', type: 'group' }),
    ];

    const tree = buildFieldTree(fields);

    expect(tree.map((n) => n.field.path)).toEqual(['eth', 'ip']);
  });

  it('preserves input order among siblings', () => {
    const fields: WireField[] = [
      f({ path: 'tcp', label: 'TCP', type: 'group' }),
      f({ path: 'tcp.flags.rst', label: 'RST', type: 'bool', group: 'tcp.flags', value: false }),
      f({ path: 'tcp.flags', label: 'Flags', type: 'group', group: 'tcp' }),
      f({ path: 'tcp.flags.syn', label: 'SYN', type: 'bool', group: 'tcp.flags', value: true }),
    ];

    const tree = buildFieldTree(fields);

    // tcp.flags.rst appears in the input before its own parent tcp.flags —
    // the tree-builder must still place it correctly once tcp.flags is
    // known, not require parent-before-child ordering in the wire data.
    const flagsNode = tree[0].children.find((n) => n.field.path === 'tcp.flags')!;
    expect(flagsNode.children.map((n) => n.field.path)).toEqual(['tcp.flags.rst', 'tcp.flags.syn']);
  });

  it('returns an empty tree for an empty field list', () => {
    expect(buildFieldTree([])).toEqual([]);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /Users/jamesbrown/Documents/GitHub/network_monitor && npx vitest run lib/__tests__/field-tree.test.ts 2>&1 | tail -20`
Expected: FAIL — `lib/field-tree.ts` doesn't exist yet.

- [ ] **Step 3: Implement**

Create `lib/field-tree.ts`:

```typescript
import { WireField } from './types';

export interface FieldTreeNode {
  field: WireField;
  children: FieldTreeNode[];
}

/**
 * Groups a flat WireField list into a tree by each entry's `group` (its
 * immediate parent's `path`). A field whose `group` doesn't match any
 * known path (or has none) becomes a root. Two passes: first build every
 * node, then attach each to its parent — this is what lets a child appear
 * before its own group in the input array (the wire has no ordering
 * guarantee) without needing a second lookup pass per field.
 */
export function buildFieldTree(fields: WireField[]): FieldTreeNode[] {
  const nodeByPath = new Map<string, FieldTreeNode>();
  for (const field of fields) {
    nodeByPath.set(field.path, { field, children: [] });
  }

  const roots: FieldTreeNode[] = [];
  for (const field of fields) {
    const node = nodeByPath.get(field.path)!;
    const parent = field.group ? nodeByPath.get(field.group) : undefined;
    if (parent) {
      parent.children.push(node);
    } else {
      roots.push(node);
    }
  }
  return roots;
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /Users/jamesbrown/Documents/GitHub/network_monitor && npx vitest run lib/__tests__/field-tree.test.ts`
Expected: PASS, 5 passed.

- [ ] **Step 5: Commit**

```bash
git add lib/field-tree.ts lib/__tests__/field-tree.test.ts
git commit -m "Add buildFieldTree: flat WireField list -> renderable tree

Part of JAM-9 (field model)."
```

---

### Task 11: `PacketStreamView.tsx` — render the tree, two-pane highlighting

**Files:**
- Create: `components/FieldTree.tsx`
- Modify: `components/PacketStreamView.tsx`
- Modify: `lib/__tests__/packet-stream-status-code.test.tsx` (rewrite fixtures/assertions)
- Modify: `lib/__tests__/packet-stream-vlan.test.tsx` (rewrite fixtures/assertions)
- Test: `lib/__tests__/packet-stream-field-highlight.test.tsx` (new — click-to-highlight interaction)
- Modify: `lib/export.ts` (one comment, `headerBreakdown` → `fields`)
- Modify: `lib/__tests__/export.test.ts` (fixture + assertion using the new shape)

**Interfaces:**
- Consumes: `WireField`, `buildFieldTree`/`FieldTreeNode` (Task 10).
- Produces: `FieldTree` component (`{ fields: WireField[]; theme: ThemeConfig; selectedPath: string | null; onSelectField: (path: string | null) => void }` — the caller filters `fields` by `region` before passing them in, so the pane distinction lives in `PacketStreamView`, not in `FieldTree` itself) — a focused, independently-testable piece `PacketStreamView` composes twice (once per pane).

- [ ] **Step 1: Create the `FieldTree` component**

`components/PacketStreamView.tsx` is already 370 lines before this task; per this repo's "smaller, focused files" convention, the recursive tree-row rendering and its collapse/selection state live in their own component rather than growing that file further.

Create `components/FieldTree.tsx`:

```tsx
'use client';

import React, { useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { WireField, ThemeConfig } from '@/lib/types';
import { buildFieldTree, FieldTreeNode } from '@/lib/field-tree';

interface FieldTreeProps {
  fields: WireField[];
  theme: ThemeConfig;
  selectedPath: string | null;
  onSelectField: (path: string | null) => void;
}

function formatValue(field: WireField): string | null {
  if (field.value === undefined) return null;
  if (typeof field.value === 'boolean') return field.value ? 'true' : 'false';
  return String(field.value);
}

function Row({
  node,
  depth,
  theme,
  selectedPath,
  onSelectField,
}: {
  node: FieldTreeNode;
  depth: number;
  theme: ThemeConfig;
  selectedPath: string | null;
  onSelectField: (path: string | null) => void;
}) {
  const [collapsed, setCollapsed] = useState(false);
  const hasChildren = node.children.length > 0;
  const isSelected = selectedPath === node.field.path;
  const value = formatValue(node.field);

  return (
    <div>
      <div
        onClick={() => onSelectField(isSelected ? null : node.field.path)}
        onMouseEnter={() => onSelectField(node.field.path)}
        onMouseLeave={() => onSelectField(null)}
        style={{ paddingLeft: `${depth * 14}px` }}
        className={`flex items-center space-x-1.5 py-0.5 px-1 rounded cursor-pointer text-[11px] ${
          isSelected ? theme.highlight : 'hover:bg-slate-800/60'
        }`}
      >
        {hasChildren ? (
          <button
            onClick={(e) => {
              e.stopPropagation();
              setCollapsed(!collapsed);
            }}
            className="text-slate-500"
          >
            {collapsed ? <ChevronRight className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
          </button>
        ) : (
          <span className="w-3" />
        )}
        <span className="text-slate-300">{node.field.label}</span>
        {value !== null && <span className="text-emerald-400 font-mono">{value}</span>}
      </div>
      {hasChildren && !collapsed && (
        <div>
          {node.children.map((child) => (
            <Row key={child.field.path} node={child} depth={depth + 1} theme={theme} selectedPath={selectedPath} onSelectField={onSelectField} />
          ))}
        </div>
      )}
    </div>
  );
}

export const FieldTree: React.FC<FieldTreeProps> = ({ fields, theme, selectedPath, onSelectField }) => {
  const tree = buildFieldTree(fields);
  if (tree.length === 0) return null;
  return (
    <div className="space-y-0.5">
      {tree.map((node) => (
        <Row key={node.field.path} node={node} depth={0} theme={theme} selectedPath={selectedPath} onSelectField={onSelectField} />
      ))}
    </div>
  );
};
```

- [ ] **Step 2: Write the failing `PacketStreamView` tests**

Replace `lib/__tests__/packet-stream-status-code.test.tsx` entirely:

```tsx
// @vitest-environment jsdom
//
// Regression coverage for issue #65 (status_or_code), now expressed
// against the field model: an HTTP response's status renders as a real
// http.response.code field, not the old fabricated string composite.
import { afterEach, describe, expect, it } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { PacketStreamView } from '@/components/PacketStreamView';
import { THEMES } from '@/lib/osi-engine';
import { PacketFrame } from '@/lib/types';

afterEach(() => {
  cleanup();
});

const basePacket: PacketFrame = {
  id: 'pkt-1',
  timestamp: '1000',
  relativeTimeMs: 1,
  layer: 4,
  protocol: 'TCP',
  src: '93.184.216.34:443',
  dst: '192.168.1.10:51000',
  length: 60,
  summary: 'TCP 93.184.216.34 -> 192.168.1.10',
  hexDump: '00 01',
  headerHexDump: 'aa bb',
  fields: [
    { path: 'http', label: 'HTTP', type: 'group', region: 'payload', offset: 0, len: 20 },
    { path: 'http.request.method', label: 'Request Method', type: 'str', group: 'http', value: 'GET', region: 'payload', offset: 0, len: 20 },
  ],
};

describe('PacketStreamView status_or_code rendering', () => {
  it('shows the HTTP status code when the selected packet is a response', () => {
    const response: PacketFrame = {
      ...basePacket,
      fields: [
        { path: 'http', label: 'HTTP', type: 'group', region: 'payload', offset: 0, len: 20 },
        { path: 'http.response.code', label: 'Status Code', type: 'uint', group: 'http', value: 404, region: 'payload', offset: 0, len: 20 },
      ],
    };
    render(<PacketStreamView packets={[response]} theme={THEMES.matrix} onClearPackets={() => {}} />);
    expect(screen.getByText('Status Code')).toBeInTheDocument();
    expect(screen.getByText('404')).toBeInTheDocument();
  });

  it('shows Request Method, not Status Code, for an HTTP request', () => {
    render(<PacketStreamView packets={[basePacket]} theme={THEMES.matrix} onClearPackets={() => {}} />);
    expect(screen.getByText('Request Method')).toBeInTheDocument();
    expect(screen.queryByText('Status Code')).not.toBeInTheDocument();
  });
});
```

Replace `lib/__tests__/packet-stream-vlan.test.tsx` entirely:

```tsx
// @vitest-environment jsdom
//
// Regression coverage for issue #62 (VLAN tag), now expressed against the
// field model: a tagged frame gets an eth.vlan.id field, an untagged frame
// gets none.
import { afterEach, describe, expect, it } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { PacketStreamView } from '@/components/PacketStreamView';
import { THEMES } from '@/lib/osi-engine';
import { PacketFrame, WireField } from '@/lib/types';

afterEach(() => {
  cleanup();
});

const ethFields: WireField[] = [
  { path: 'eth', label: 'Ethernet II', type: 'group', region: 'header', offset: 0, len: 14 },
  { path: 'eth.src', label: 'Source MAC', type: 'addr', group: 'eth', value: '00:01:02:03:04:05', region: 'header', offset: 6, len: 6 },
];

const basePacket: PacketFrame = {
  id: 'pkt-1',
  timestamp: '1000',
  relativeTimeMs: 1,
  layer: 4,
  protocol: 'TCP',
  src: '192.168.1.10:51000',
  dst: '93.184.216.34:443',
  length: 60,
  summary: 'TCP 192.168.1.10 -> 93.184.216.34',
  hexDump: '00 01',
  headerHexDump: '00 01 02 03 04 05',
  fields: ethFields,
};

describe('PacketStreamView VLAN tag rendering', () => {
  it('shows the 802.1Q VLAN ID when the selected packet carries one', () => {
    const tagged: PacketFrame = {
      ...basePacket,
      fields: [
        ...ethFields,
        { path: 'eth.vlan', label: '802.1Q VLAN Tag', type: 'group', group: 'eth', region: 'header', offset: 12, len: 4 },
        { path: 'eth.vlan.id', label: 'VLAN ID', type: 'uint', group: 'eth.vlan', value: 100, region: 'header', offset: 14, len: 2 },
      ],
    };
    render(<PacketStreamView packets={[tagged]} theme={THEMES.matrix} onClearPackets={() => {}} />);
    expect(screen.getByText('VLAN ID')).toBeInTheDocument();
    expect(screen.getByText('100')).toBeInTheDocument();
  });

  it('shows no VLAN entry for an untagged frame', () => {
    render(<PacketStreamView packets={[basePacket]} theme={THEMES.matrix} onClearPackets={() => {}} />);
    expect(screen.queryByText('VLAN ID')).not.toBeInTheDocument();
  });
});
```

Create `lib/__tests__/packet-stream-field-highlight.test.tsx` — this exercises the actual click-to-highlight interaction the spec promises, which the two rewritten files above don't cover (they only check that the tree renders labels/values):

```tsx
// @vitest-environment jsdom
//
// Coverage for bidirectional byte<->field highlighting: clicking a field
// in the tree must highlight exactly its own byte range in the correct
// pane (header fields against headerHexDump, payload fields against
// hexDump) and nothing outside that range.
import { afterEach, describe, expect, it } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { PacketStreamView } from '@/components/PacketStreamView';
import { THEMES } from '@/lib/osi-engine';
import { PacketFrame } from '@/lib/types';

afterEach(() => {
  cleanup();
});

// 14 header bytes: dst MAC(6) + src MAC(6) + EtherType(2), matching a real
// eth frame's layout so the offsets below are meaningful, not arbitrary.
const packet: PacketFrame = {
  id: 'pkt-1',
  timestamp: '1000',
  relativeTimeMs: 1,
  layer: 4,
  protocol: 'TCP',
  src: '192.168.1.10:51000',
  dst: '93.184.216.34:443',
  length: 60,
  summary: 'TCP 192.168.1.10 -> 93.184.216.34',
  hexDump: '16 03 01 00 a5',
  headerHexDump: '06 07 08 09 0a 0b 00 01 02 03 04 05 08 00',
  fields: [
    { path: 'eth', label: 'Ethernet II', type: 'group', region: 'header', offset: 0, len: 14 },
    { path: 'eth.dst', label: 'Destination MAC', type: 'addr', group: 'eth', value: '06:07:08:09:0a:0b', region: 'header', offset: 0, len: 6 },
    { path: 'eth.src', label: 'Source MAC', type: 'addr', group: 'eth', value: '00:01:02:03:04:05', region: 'header', offset: 6, len: 6 },
    { path: 'tls', label: 'TLS', type: 'group', region: 'payload', offset: 0, len: 5 },
    { path: 'tls.handshake.sni', label: 'Server Name', type: 'str', group: 'tls', value: 'example.com', region: 'payload', offset: 0, len: 5 },
  ],
};

describe('PacketStreamView field<->byte highlighting', () => {
  it('highlighting a header field lights up only its own bytes in the header pane', () => {
    render(<PacketStreamView packets={[packet]} theme={THEMES.matrix} onClearPackets={() => {}} />);

    fireEvent.click(screen.getByText('Source MAC'));

    const headerPane = screen.getByTestId('header-hex-dump');
    const highlighted = headerPane.querySelectorAll('span.bg-emerald-500\\/40');
    // eth.src is offset 6, len 6 -> bytes "00 01 02 03 04 05", 6 highlighted spans.
    expect(highlighted).toHaveLength(6);
    expect(Array.from(highlighted).map((el) => el.textContent?.trim())).toEqual(['00', '01', '02', '03', '04', '05']);
  });

  it('does not highlight anything in the payload pane when a header field is selected', () => {
    render(<PacketStreamView packets={[packet]} theme={THEMES.matrix} onClearPackets={() => {}} />);

    fireEvent.click(screen.getByText('Source MAC'));

    const payloadPane = screen.getByTestId('payload-hex-dump');
    expect(payloadPane.querySelectorAll('span.bg-emerald-500\\/40')).toHaveLength(0);
  });

  it('highlighting a payload field lights up bytes in the payload pane, independent of the header pane', () => {
    render(<PacketStreamView packets={[packet]} theme={THEMES.matrix} onClearPackets={() => {}} />);

    fireEvent.click(screen.getByText('Server Name'));

    const payloadPane = screen.getByTestId('payload-hex-dump');
    expect(payloadPane.querySelectorAll('span.bg-emerald-500\\/40')).toHaveLength(5);
    const headerPane = screen.getByTestId('header-hex-dump');
    expect(headerPane.querySelectorAll('span.bg-emerald-500\\/40')).toHaveLength(0);
  });
});
```

- [ ] **Step 3: Run to verify they fail**

Run: `cd /Users/jamesbrown/Documents/GitHub/network_monitor && npx vitest run lib/__tests__/packet-stream-status-code.test.tsx lib/__tests__/packet-stream-vlan.test.tsx lib/__tests__/packet-stream-field-highlight.test.tsx 2>&1 | tail -40`
Expected: FAIL — `PacketStreamView` still reads `selectedPacket.headerBreakdown`, which no longer exists on `PacketFrame`, and neither `FieldTree` nor the highlight renderer exist yet.

- [ ] **Step 4: Rewrite `PacketStreamView.tsx`'s detail pane**

In `components/PacketStreamView.tsx`, add the import:

```typescript
import { FieldTree } from '@/components/FieldTree';
```

Add state, alongside the existing `hexCopyState` declaration:

```typescript
  const [selectedHeaderFieldPath, setSelectedHeaderFieldPath] = useState<string | null>(null);
  const [selectedPayloadFieldPath, setSelectedPayloadFieldPath] = useState<string | null>(null);
```

Reset both whenever the selected packet changes — add this alongside the existing `setSelectedPacket` call sites, or simpler: derive them fresh each render isn't needed since `null` is already the safe default and switching packets naturally makes any stale selected path just not match anything in the new tree (the highlight rendering below only lights up ranges for paths that exist in the current packet's fields, so a stale selection from a previous packet harmlessly matches nothing). No extra reset code needed.

Add a small byte-highlight renderer above the `PacketStreamView` component (module-level, so it doesn't need to be recreated every render):

```tsx
function renderHexWithHighlight(hexDump: string, fields: WireField[], selectedPath: string | null): React.ReactNode {
  if (!selectedPath) return hexDump;
  const selected = fields.find((f) => f.path === selectedPath);
  if (!selected) return hexDump;

  const bytes = hexDump.split(' ');
  return bytes.map((byte, i) => {
    const inRange = i >= selected.offset && i < selected.offset + selected.len;
    return (
      <span key={i} className={inRange ? 'bg-emerald-500/40 text-emerald-200 rounded-sm' : undefined}>
        {byte}
        {i < bytes.length - 1 ? ' ' : ''}
      </span>
    );
  });
}
```

Add the `WireField` import needed by the function above:

```typescript
import { DecryptedPayloadSegment, PacketFrame, ThemeConfig, OSILayerNumber, WireField } from '@/lib/types';
```

Replace the entire "Layer Header Decomposition" block (the `{/* Layer 7 */}` through `{/* Layer 2 */}` sections, i.e. everything between the `{/* Layer Header Decomposition */}` comment's opening `<div>` and its closing `</div>`) with:

```tsx
              {/* Field Tree: header region */}
              <div className="space-y-1 text-[11px]">
                <div className="text-[10px] font-bold text-slate-400">HEADER FIELDS</div>
                <FieldTree
                  fields={selectedPacket.fields.filter((f) => f.region === 'header')}
                  theme={theme}
                  selectedPath={selectedHeaderFieldPath}
                  onSelectField={setSelectedHeaderFieldPath}
                />
              </div>

              {/* Header bytes hex pane */}
              <div className="space-y-1">
                <div className="text-[10px] font-bold text-slate-400">HEADER BYTES</div>
                <pre data-testid="header-hex-dump" className="p-2 bg-black text-slate-300 text-[10px] rounded border border-slate-800 leading-tight overflow-x-auto select-all">
                  {renderHexWithHighlight(selectedPacket.headerHexDump, selectedPacket.fields.filter((f) => f.region === 'header'), selectedHeaderFieldPath)}
                </pre>
              </div>

              {/* Field Tree: application-layer (payload) region */}
              {selectedPacket.fields.some((f) => f.region === 'payload') && (
                <div className="space-y-1 text-[11px]">
                  <div className="text-[10px] font-bold text-slate-400">APPLICATION FIELDS</div>
                  <FieldTree
                    fields={selectedPacket.fields.filter((f) => f.region === 'payload')}
                    theme={theme}
                    selectedPath={selectedPayloadFieldPath}
                    onSelectField={setSelectedPayloadFieldPath}
                  />
                </div>
              )}
```

Update the existing "Raw Hex Dump Box" section (the payload `hexDump` pane) to also highlight, by replacing its `<pre>` body:

```tsx
                <pre data-testid="payload-hex-dump" className="p-2 bg-black text-emerald-400 text-[10px] rounded border border-slate-800 leading-tight overflow-x-auto select-all">
                  {renderHexWithHighlight(selectedPacket.hexDump, selectedPacket.fields.filter((f) => f.region === 'payload'), selectedPayloadFieldPath)}
                </pre>
```

- [ ] **Step 5: Run the `PacketStreamView` tests to verify they pass**

Run: `cd /Users/jamesbrown/Documents/GitHub/network_monitor && npx vitest run lib/__tests__/packet-stream-status-code.test.tsx lib/__tests__/packet-stream-vlan.test.tsx lib/__tests__/packet-stream-decrypted.test.tsx lib/__tests__/packet-stream-field-highlight.test.tsx`
Expected: PASS, all four files (decrypted was already unaffected — confirms it still is).

- [ ] **Step 6: Fix `lib/export.ts` and its test**

In `lib/export.ts`, update the `packetsToJson` doc comment:

```typescript
/**
 * The packet list as JSON, indented for reading. Round-trips through
 * JSON.parse with `fields` intact — the full field registry is the
 * point of exporting packets rather than a flat summary table.
 */
```

In `lib/__tests__/export.test.ts`, find the packet fixture (around line 47, `headerBreakdown: { ... }`) and the assertion at line ~104 (`expect(parsed[0].headerBreakdown.layer4.srcPort).toBe(51234);`). Replace the fixture's `headerBreakdown` field with:

```typescript
    headerHexDump: '00 01',
    fields: [
      { path: 'tcp', label: 'TCP', type: 'group', region: 'header', offset: 0, len: 20 },
      { path: 'tcp.src_port', label: 'Source Port', type: 'uint', group: 'tcp', value: 51234, region: 'header', offset: 0, len: 2 },
    ],
```

and the assertion:

```typescript
    expect(parsed[0].fields.find((f: { path: string }) => f.path === 'tcp.src_port').value).toBe(51234);
```

- [ ] **Step 7: Run the full website test suite**

Run: `cd /Users/jamesbrown/Documents/GitHub/network_monitor && npx vitest run`
Expected: PASS, 0 failed. (This is the first point every TS-side consumer has been fixed — confirms nothing was missed.)

- [ ] **Step 8: Run typecheck, lint, and build**

Run: `cd /Users/jamesbrown/Documents/GitHub/network_monitor && npx tsc --noEmit && npm run lint && npm run build`
Expected: all three clean.

- [ ] **Step 9: Commit**

```bash
git add components/FieldTree.tsx components/PacketStreamView.tsx lib/__tests__/packet-stream-status-code.test.tsx lib/__tests__/packet-stream-vlan.test.tsx lib/__tests__/packet-stream-field-highlight.test.tsx lib/export.ts lib/__tests__/export.test.ts
git commit -m "PacketStreamView: render the field tree, two-pane byte highlighting

New components/FieldTree.tsx (collapsible, click-to-select) composed
twice -- header fields against headerHexDump, application fields
against the existing hexDump -- each pane highlighting independently
via each field's region. This is JAM-9's full-cutover scope
(interactive highlighting), which also discharges JAM-11's core
deliverable ('packet detail: collapsible field tree with bidirectional
byte highlighting') -- flagging that explicitly rather than letting it
surface as a surprise when JAM-11 is picked up later.

Part of JAM-9 (field model)."
```

---

### Task 12: Wire-size measurement and full verification sweep

**Files:** none modified — this task runs and records, doesn't change code.

**Interfaces:** none.

- [ ] **Step 1: Measure wire-size overhead**

Add a throwaway measurement (not committed) to confirm the acceptance criterion, e.g. in a scratch Rust test run manually:

```bash
cd capture-agent
cat > /tmp/wire_size_check.rs << 'EOF'
// Scratch — not part of the crate, deleted after use.
EOF
```

Simpler: temporarily add one `#[test]` to `wire.rs` that builds the same representative packet (TCP + TLS ClientHello with JA3, matching the spec's "deepest currently-decoded case") both the old way (impossible now — the old structs are deleted) and new way isn't a real A/B in code anymore since the old shape no longer exists to compare against live. Instead, measure directly: construct a realistic `PacketJson` fixture via `fields::build_fields` for a TCP+TLS packet, `serde_json::to_string` it, and print/assert its byte length — then compute the old shape's size by hand from its known fixed structure (every `Layer*Json` field, worst case with `ja3Fingerprint`/`ja3Label` present, is a fixed, countable set of JSON keys) and state the delta directly in the PR description. Run:

```bash
cd capture-agent && cargo test --locked -- --nocapture 2>&1 | grep -A2 "wire_size"
```

(No committed test needed for this — it's a one-time measurement for the PR description, per the spec's "Stated in the PR description... the point is visibility, not a gate.")

- [ ] **Step 2: Full Rust verification**

```bash
cd capture-agent
cargo build --release --locked
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
```

Expected: all clean, all tests passing.

- [ ] **Step 3: Fuzz targets touched by this change**

`fields.rs` doesn't parse raw bytes (it consumes already-parsed `ParsedPacket`/`L7Info`), so no fuzz target needs updating. `parse.rs` changed (`header_bytes`), which `fuzz/fuzz_targets/parse_packet.rs` already exercises indirectly through `parse_packet`. Run it briefly to confirm nothing regressed:

```bash
cargo +nightly fuzz run parse_packet -- -max_total_time=30
```

Expected: no crashes.

- [ ] **Step 4: Full website verification**

```bash
cd /Users/jamesbrown/Documents/GitHub/network_monitor
npm audit --audit-level=high
npx tsc --noEmit
npm run lint
npx vitest run
npm run build
npx playwright test
```

Expected: all clean. Playwright's `e2e/smoke.spec.ts` drives a real browser against `e2e/fake-agent.ts` — if the fake agent's fixture data doesn't already include valid `fields`/`headerHexDump`, this step will surface it; fix the fixture in `e2e/fake-agent.ts` the same way Task 11's other fixtures were fixed, matching this plan's established `fields`/`headerHexDump` shape.

- [ ] **Step 5: Report the wire-size delta**

State the number from Step 1 in the PR description (per the spec's Wire-size overhead section) — no code change, just the number and a one-sentence characterization (e.g. "adds ~X bytes per packet event, informational only, no threshold gate").
