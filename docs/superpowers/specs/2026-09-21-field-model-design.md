# Field Model — Design Spec

> JAM-9 (GitHub #76), keystone task of JAM-126 (Epic: Field model and display filters, phase 2 epic C).

## Purpose

Replace the hand-maintained, fixed five-layer packet summary (`HeaderBreakdownJson` in `capture-agent/src/wire.rs`, mirrored by hand in `lib/types.ts`, rendered by hand in `components/PacketStreamView.tsx`) with a registry of typed, named, individually addressable fields. Each field carries a stable abbreviation, a type, and its byte offset/length in the frame — one registration that simultaneously defines the decode, the tree label, and (later, JAM-10) the filter grammar and exportable column.

Today those responsibilities are maintained separately in four places with no compiler check across the Rust/TypeScript boundary (`CONTRIBUTING.md`, "Wire protocol changes"). Every new field costs four coordinated edits and buys zero query power — the direct cause of two prior drift bugs (issue #62, VLAN tag; issue #65, `statusOrCode`).

## Scope

**In scope:**
- A field registry in the agent (`capture-agent/src/fields.rs`), producing a flat, typed field list per packet from already-parsed data (`ParsedPacket` + `L7Info`) — no new protocol decoding.
- A new wire representation (`PacketJson.fields`) replacing `header_breakdown` entirely.
- Full cutover: `PacketStreamView.tsx` renders from the new field list, including interactive bidirectional byte↔field highlighting. `headerBreakdown`/`Layer7Json`/`Layer4Json`/`Layer3Json`/`Layer2Json`/`HeaderBreakdownJson` are deleted, not deprecated-in-place — there is no dual-emit transition period.
- `docs/wire-protocol.md` updated: a field-abbreviation table replaces the `headerBreakdown` section; "adding a new field" becomes "register a field."
- Per-packet wire-size overhead measured (old shape vs. new) and stated.

**Explicitly out of scope** (belongs to later JAM-126/JAM-127 tasks, listed so this task isn't silently asked to grow into them):
- The display-filter language itself (JAM-10) — this task only makes fields addressable; nothing here parses or evaluates filter expressions.
- New protocol/dissector coverage beyond what's already decoded today (HTTP request/response, DNS query, TLS ClientHello + JA3, plus the existing L2/L3/L4 headers). No QUIC, no new home-network protocols — that's epic JAM-128.
- Expert-info / anomaly surfacing (a separate JAM-127 task).
- Any change to the `decrypted_payload` event or Tier B decrypted-content pipeline — untouched by this work; it never went through `build_header_breakdown` and doesn't go through `build_fields` either.

## Field model

```rust
// capture-agent/src/fields.rs

pub enum FieldType { Group, Bool, Uint, Str, Addr, Bytes }

pub enum FieldValue {
    None,             // Group entries carry no value
    Bool(bool),
    Uint(u64),
    Str(String),
    Addr(String),     // MAC or IP — formatted, not raw bytes
    Bytes(Vec<u8>),
}

pub struct Field {
    pub path: String,           // stable, dotted, user-facing abbreviation: "tcp.flags.syn"
    pub label: String,          // human-readable tree label: "SYN"
    pub group: Option<String>,  // immediate parent's `path`; None for a top-level group
    pub field_type: FieldType,
    pub value: FieldValue,
    pub offset: u32,            // byte offset into the raw frame
    pub len: u32,               // byte length
}

pub fn build_fields(parsed: &ParsedPacket, l7: &L7Info, raw_frame: &[u8]) -> Vec<Field>
```

`build_fields` replaces `build_header_breakdown` as the function called once per `Packet` wire event in `main.rs`'s capture loop. It takes the same inputs `build_header_breakdown` already takes (nothing new is parsed), plus the raw frame bytes (already available at the call site as the source `hex_dump` is built from) so offsets can be resolved.

### Naming convention

Dotted, lowercase, Wireshark-style abbreviations (`tcp.flags.syn`, `ip.ttl`, `tls.handshake.sni`, `eth.src`) — the convention already used throughout the JAM-9/JAM-10 issue text, and the natural fit for a product explicitly modeled on Wireshark's display-filter mental model (`docs/superpowers/specs/` baseline design document). This becomes user-visible filter syntax once JAM-10 lands; get it right here because renaming later breaks every saved filter.

### Grouping

Top-level groups are named by the *protocol actually present*, not by OSI layer number: `eth`, `ip` or `ip6`, `tcp`/`udp`/`icmp`, and an app-layer group named for whatever `L7Info` detected (`http`, `dns`, `tls`). This is strictly more honest than today's `layer4`/`layer7` wrapping a `"transport": "TCP"` string — a UDP packet gets a `udp` group, never a `tcp` group with a `transport` field lying about which protocol it is. A VLAN tag, when present, nests under Ethernet: `eth.vlan` (group) → `eth.vlan.id` (child), matching where it physically sits in the frame.

### Byte offsets

Two sources, both exact, neither requiring new parsing:
1. **Header-level ranges** come from pointer arithmetic against etherparse's existing zero-copy `SlicedPacket` slices (`parse_packet` already holds these) — e.g. the IPv4 header's slice start/end relative to `raw_frame`'s start.
2. **Individual field ranges within a header's fixed portion** are constants: every currently-rendered field (TTL, flags, ports, sequence numbers, MAC addresses, SNI is the one exception — see below) sits at a fixed RFC-defined offset within a header's non-variable portion. None sit inside TCP options or other variable-length regions, so no field currently needs dynamic offset computation beyond the header-level slice math.

`tls.handshake.sni` is the one field whose offset is itself computed during parsing today (`l7::sniff_tls_client_hello` already walks TLS extensions to find it) — its offset/len come directly from that existing walk, just carried forward into the `Field` instead of discarded.

Sibling bit-fields sharing one byte (`tcp.flags.syn`/`.ack`/`.fin`/`.rst`, all bits of the single TCP flags byte) legitimately share the same offset/len. Clicking any one highlights that byte — the finest granularity a hex dump can show, and how Wireshark itself handles bitfields.

## Wire representation

`PacketJson` gains `fields: Vec<Field>` (camelCase on the wire per this repo's convention: `path`, `label`, `group`, `type`, `value`, `offset`, `len`); `header_breakdown` and its four `Layer*Json` structs are deleted from `wire.rs`.

```json
{
  "type": "packet",
  "packet": {
    "id": "pkt-1",
    "...": "...",
    "fields": [
      {"path":"eth","label":"Ethernet II","type":"group","offset":0,"len":14},
      {"path":"eth.src","label":"Source MAC","type":"addr","group":"eth","value":"00:01:02:03:04:05","offset":6,"len":6},
      {"path":"ip","label":"Internet Protocol Version 4","type":"group","offset":14,"len":20},
      {"path":"ip.ttl","label":"Time to Live","type":"uint","group":"ip","value":64,"offset":22,"len":1},
      {"path":"tcp","label":"Transmission Control Protocol","type":"group","offset":34,"len":20},
      {"path":"tcp.flags","label":"Flags","type":"group","group":"tcp","offset":47,"len":1},
      {"path":"tcp.flags.syn","label":"SYN","type":"bool","group":"tcp.flags","value":true,"offset":47,"len":1},
      {"path":"tcp.src_port","label":"Source Port","type":"uint","group":"tcp","value":51000,"offset":34,"len":2}
    ]
  }
}
```

A `Field` serializes its `value` key only when `field_type != Group` (a group has no value, same "omit rather than null" discipline this wire protocol already uses elsewhere — e.g. `capture_file_status`'s optional fields); `group` is omitted for top-level entries rather than sent as `null`.

## TypeScript side

`lib/types.ts`: `PacketFrame.headerBreakdown` (the nested `layer1`..`layer7` block) is deleted and replaced by `fields: WireField[]`:

```typescript
export interface WireField {
  path: string;
  label: string;
  group?: string;
  type: 'group' | 'bool' | 'uint' | 'string' | 'addr' | 'bytes';
  value?: boolean | number | string;
  offset: number;
  len: number;
}
```

`lib/agent-mapping.ts`'s `mapPacketEvent` maps `data.fields` straight through — it's already flat, no reshaping needed (unlike the old per-layer object it replaces).

`components/PacketStreamView.tsx`'s hard-coded layer7/6/5/4/3/2/1 JSX blocks (current lines ~180-224 and following) are replaced by:
- A small tree-builder: one pass over the flat `fields` array, grouping children under their `group` path, producing a renderable tree. (Lives in `lib/` as a pure function so it's unit-testable without rendering.)
- A collapsible tree view for the selected packet's fields.
- Bidirectional highlighting: clicking a field highlights its `[offset, offset+len)` byte range in the existing `hexDump` view; hovering a byte range in the hex dump highlights the field(s) whose range contains it (a shared byte can highlight multiple fields, e.g. hovering the TCP flags byte highlights `tcp.flags` and all four boolean children).

## Migration

No dual-emit period. This is one coordinated change across `wire.rs`, `lib/types.ts`, `lib/agent-mapping.ts`, and `components/PacketStreamView.tsx`, landing together. `docs/wire-protocol.md` is updated in the same change (per `CONTRIBUTING.md`'s "Wire protocol changes" rule — Rust and TypeScript changes together, no compiler check across the boundary so this has to be verified by hand and by the updated tests).

## Wire-size overhead

Measured by serializing one representative real packet — a TCP segment carrying a TLS ClientHello, the deepest currently-decoded case (eth → ip → tcp → tls, with JA3 fields) — under the old `header_breakdown` shape and the new `fields` shape, and diffing serialized byte counts. Stated in the PR description. No target threshold is set here; the point is visibility, not a gate, since this event already rides a broadcast channel sized for today's `ConnectionJson`/`PacketJson` payloads (see `wire.rs`'s boxing comments) and a moderate overhead is an acceptable, informed trade for addressability.

## Testing

- **Rust**: unit tests on `build_fields`, one per currently-decoded protocol combination (Ethernet/VLAN/loopback/raw framing × TCP/UDP/ICMP × each `L7Info` variant), mirroring today's `build_header_breakdown` test coverage in `wire.rs`. Assert exact `path`/`type`/`value`/`offset`/`len` for a representative field per header, plus the "omit value for group entries" and "omit group key for top-level entries" serialization rules. No new fuzz target: `build_fields` consumes already-parsed, already-fuzzed `ParsedPacket`/`L7Info` — it does not re-parse raw untrusted bytes itself.
- **TypeScript**: unit tests on `mapPacketEvent`'s new field mapping, the tree-builder function (flat list → tree, including the shared-byte multi-parent highlight case), and `PacketStreamView`'s render/click-to-highlight behavior (component test, mirroring this repo's existing `packet-stream-*.test.tsx` pattern).

## Deferred to later tasks

- Display-filter language and evaluator (JAM-10) — depends on this task's field list existing, not built here.
- Custom columns / colouring rules, headless CLI `--fields`, richer export using field paths — all downstream, per JAM-126's epic description.
- Any new dissector coverage (JAM-128).

## Spec self-review

- No placeholders (no TBD/TODO left in this document).
- Internal consistency: the wire example, the Rust struct, and the TypeScript interface all agree on field names and casing (snake_case in Rust struct fields, camelCase on the wire per this repo's existing convention, matching `WireField`).
- Scope check: this is one task's worth of work (registry + wire + full UI cutover), explicitly excluding the filter language and any new dissector coverage — both called out above so they aren't silently pulled in during implementation.
- Ambiguity check: the group/leaf distinction (Approach C: every group is its own explicit entry with `type: "group"` and no `value`) removes the "is this path a group or a leaf" ambiguity a pure path-splitting scheme would have.
