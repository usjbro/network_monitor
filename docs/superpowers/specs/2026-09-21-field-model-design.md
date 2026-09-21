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

/// Which of the two hex-dump panes (below) a field's offset/len is relative
/// to. Header fields (eth/ip/tcp/udp/vlan) are offset into `header_bytes`;
/// app-layer fields (http/dns/tls) are offset into `payload` — the two
/// panes are never merged into one shared byte space.
pub enum ByteRegion { Header, Payload }

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
    pub region: ByteRegion,
    pub offset: u32,            // byte offset into whichever pane `region` names
    pub len: u32,               // byte length
}

pub fn build_fields(parsed: &ParsedPacket, l7: &L7Info) -> Vec<Field>
```

`build_fields` replaces `build_header_breakdown` as the function called once per `Packet` wire event in `main.rs`'s capture loop, taking the same inputs `build_header_breakdown` already takes — nothing new is parsed, and it needs no raw-frame parameter: `ParsedPacket` (below) now carries its own header bytes.

### Two hex-dump panes, not one

`hex_dump` (`parsed.payload`, capped at 64 bytes) already exists and is unchanged. `ParsedPacket` gains a new field, `header_bytes: Vec<u8>`, computed once in `parse_packet` as "everything before `payload`" in whichever slice was actually used to build the packet (for `NullLoopback` framing this is relative to `ip_data`, so the 4-byte AF prefix — never a real protocol header — is naturally excluded, matching `parse.rs`'s existing comment that it's "never inspected"). `PacketJson` gains `header_hex_dump: String`, hex-formatted from `parsed.header_bytes` the same way `hex_dump` already formats `parsed.payload`; unlike the payload dump it carries no artificial cap, since every currently-rendered field lives in a header's fixed, bounded portion (worst case today: Ethernet+VLAN+IPv4+TCP ≈ 78 bytes).

Header-group fields (`eth`, `ip`/`ip6`, `tcp`/`udp`/`icmp`, `vlan`) get `region: Header`, offsets relative to `header_hex_dump`. App-layer fields (`http`, `dns`, `tls`) get `region: Payload`, offsets relative to the existing `hex_dump` — unchanged base, unchanged cap. The UI (below) renders and highlights these as two independent panes; a field's `region` says which one it belongs to.

### Naming convention

Dotted, lowercase, Wireshark-style abbreviations (`tcp.flags.syn`, `ip.ttl`, `tls.handshake.sni`, `eth.src`) — the convention already used throughout the JAM-9/JAM-10 issue text, and the natural fit for a product explicitly modeled on Wireshark's display-filter mental model (`docs/superpowers/specs/` baseline design document). This becomes user-visible filter syntax once JAM-10 lands; get it right here because renaming later breaks every saved filter.

### Grouping

Top-level groups are named by the *protocol actually present*, not by OSI layer number: `eth`, `ip` or `ip6`, `tcp`/`udp`/`icmp`, and an app-layer group named for whatever `L7Info` detected (`http`, `dns`, `tls`). This is strictly more honest than today's `layer4`/`layer7` wrapping a `"transport": "TCP"` string — a UDP packet gets a `udp` group, never a `tcp` group with a `transport` field lying about which protocol it is. A VLAN tag, when present, nests under Ethernet: `eth.vlan` (group) → `eth.vlan.id` (child), matching where it physically sits in the frame.

### Byte offsets

Two sources, both exact, neither requiring new parsing:
1. **Header-level ranges** are constants relative to `header_bytes`'s own start (offset 0): Ethernet is always 14 bytes (+4 if VLAN-tagged), IPv4/IPv6 and TCP/UDP/ICMP follow immediately after at their own fixed lengths — all computable from fields `ParsedPacket` already exposes (`ip_version`, `vlan_tag.is_some()`, `protocol`, and the `LinkType` the caller parsed with), no re-parsing or pointer arithmetic against etherparse's slices needed.
2. **Individual field ranges within a header's fixed portion** are likewise constants: every currently-rendered field (TTL, flags, ports, sequence numbers, MAC addresses, SNI is the one exception — see below) sits at a fixed RFC-defined offset within a header's non-variable portion. None sit inside TCP options or other variable-length regions, so no field currently needs dynamic offset computation.

`tls.handshake.sni` is the one field whose offset is itself computed during parsing today (`l7::sniff_tls_client_hello` already walks TLS extensions to find it) — its offset/len (relative to `payload`) come directly from that existing walk, just carried forward into the `Field` instead of discarded. JA3/`ja3_label` are derived from several non-contiguous ClientHello sub-fields (cipher suites, extensions, elliptic curves, ec_point_formats — not one byte run); both get `region: Payload` with offset/len spanning the whole ClientHello message, the same "derived field points at what it was derived from" convention Wireshark itself uses for computed fields.

Sibling bit-fields sharing one byte (`tcp.flags.syn`/`.ack`/`.fin`/`.rst`, all bits of the single TCP flags byte) legitimately share the same offset/len. Clicking any one highlights that byte — the finest granularity a hex dump can show, and how Wireshark itself handles bitfields.

## Wire representation

`PacketJson` gains `fields: Vec<Field>` and `header_hex_dump: String` (camelCase on the wire per this repo's convention: `path`, `label`, `group`, `type`, `value`, `region`, `offset`, `len`, `headerHexDump`); `header_breakdown` and its four `Layer*Json` structs are deleted from `wire.rs`. The existing `hex_dump` field is unchanged.

```json
{
  "type": "packet",
  "packet": {
    "id": "pkt-1",
    "...": "...",
    "headerHexDump": "00 01 02 03 04 05 06 07 08 09 0a 0b 08 00 45 00 ...",
    "hexDump": "16 03 01 00 a5 01 00 00 a1 03 03 ...",
    "fields": [
      {"path":"eth","label":"Ethernet II","type":"group","region":"header","offset":0,"len":14},
      {"path":"eth.src","label":"Source MAC","type":"addr","group":"eth","region":"header","value":"00:01:02:03:04:05","offset":6,"len":6},
      {"path":"ip","label":"Internet Protocol Version 4","type":"group","region":"header","offset":14,"len":20},
      {"path":"ip.ttl","label":"Time to Live","type":"uint","group":"ip","region":"header","value":64,"offset":22,"len":1},
      {"path":"tcp","label":"Transmission Control Protocol","type":"group","region":"header","offset":34,"len":20},
      {"path":"tcp.flags","label":"Flags","type":"group","group":"tcp","region":"header","offset":47,"len":1},
      {"path":"tcp.flags.syn","label":"SYN","type":"bool","group":"tcp.flags","region":"header","value":true,"offset":47,"len":1},
      {"path":"tcp.src_port","label":"Source Port","type":"uint","group":"tcp","region":"header","value":51000,"offset":34,"len":2},
      {"path":"tls","label":"Transport Layer Security","type":"group","region":"payload","offset":0,"len":165},
      {"path":"tls.handshake.sni","label":"Server Name","type":"str","group":"tls","region":"payload","value":"example.com","offset":49,"len":11}
    ]
  }
}
```

A `Field` serializes its `value` key only when `field_type != Group` (a group has no value, same "omit rather than null" discipline this wire protocol already uses elsewhere — e.g. `capture_file_status`'s optional fields); `group` is omitted for top-level entries rather than sent as `null`. `region`/`offset`/`len` are always present, on groups and leaves alike, so a group itself can be highlighted (e.g. hovering the `tcp` group highlights the whole 20-byte TCP header).

## TypeScript side

`lib/types.ts`: `PacketFrame.headerBreakdown` (the nested `layer1`..`layer7` block) is deleted and replaced by `fields: WireField[]`; `PacketFrame` also gains `headerHexDump: string` alongside its existing `hexDump`:

```typescript
export interface WireField {
  path: string;
  label: string;
  group?: string;
  type: 'group' | 'bool' | 'uint' | 'string' | 'addr' | 'bytes';
  value?: boolean | number | string;
  region: 'header' | 'payload';
  offset: number;
  len: number;
}
```

`lib/agent-mapping.ts`'s `mapPacketEvent` maps `data.fields`/`data.headerHexDump` straight through — the field list is already flat, no reshaping needed (unlike the old per-layer object it replaces).

`components/PacketStreamView.tsx`'s hard-coded layer7/6/5/4/3/2/1 JSX blocks (current lines ~180-224 and following) are replaced by:
- A small tree-builder: one pass over the flat `fields` array, grouping children under their `group` path, producing a renderable tree. (Lives in `lib/` as a pure function so it's unit-testable without rendering.)
- A collapsible tree view for the selected packet's fields, split into two sections — header fields and app-layer fields — matching the two panes below.
- **Two independent hex panes**: the existing payload hex dump (`hexDump`) and a new header-bytes pane (`headerHexDump`), rendered side by side or stacked. Bidirectional highlighting is scoped per pane by each field's `region`: clicking a header-region field highlights bytes in the header pane only; clicking a payload-region field highlights the payload pane only. Hovering a byte range in either pane highlights the field(s) in that same pane whose range contains it (a shared byte can highlight multiple fields, e.g. hovering the TCP flags byte highlights `tcp.flags` and all four boolean children).

## Migration

No dual-emit period. This is one coordinated change across `wire.rs`, `lib/types.ts`, `lib/agent-mapping.ts`, and `components/PacketStreamView.tsx`, landing together. `docs/wire-protocol.md` is updated in the same change (per `CONTRIBUTING.md`'s "Wire protocol changes" rule — Rust and TypeScript changes together, no compiler check across the boundary so this has to be verified by hand and by the updated tests).

## Wire-size overhead

Measured by serializing one representative real packet — a TCP segment carrying a TLS ClientHello, the deepest currently-decoded case (eth → ip → tcp → tls, with JA3 fields) — under the old `header_breakdown` shape and the new `fields` shape, and diffing serialized byte counts. Stated in the PR description. No target threshold is set here; the point is visibility, not a gate, since this event already rides a broadcast channel sized for today's `ConnectionJson`/`PacketJson` payloads (see `wire.rs`'s boxing comments) and a moderate overhead is an acceptable, informed trade for addressability.

## Testing

- **Rust**: unit tests on `parse_packet`/`build_parsed_packet` asserting `header_bytes` excludes the payload and, for `NullLoopback`, excludes the 4-byte AF prefix. Unit tests on `build_fields`, one per currently-decoded protocol combination (Ethernet/VLAN/loopback/raw framing × TCP/UDP/ICMP × each `L7Info` variant), mirroring today's `build_header_breakdown` test coverage in `wire.rs`. Assert exact `path`/`type`/`value`/`region`/`offset`/`len` for a representative field per header, plus the "omit value for group entries," "omit group key for top-level entries," and "region present on both groups and leaves" serialization rules. No new fuzz target: `build_fields` consumes already-parsed, already-fuzzed `ParsedPacket`/`L7Info` — it does not re-parse raw untrusted bytes itself.
- **TypeScript**: unit tests on `mapPacketEvent`'s new field/`headerHexDump` mapping, the tree-builder function (flat list → tree, including the shared-byte multi-parent highlight case), and `PacketStreamView`'s render/click-to-highlight behavior for both panes independently (component test, mirroring this repo's existing `packet-stream-*.test.tsx` pattern).

## Deferred to later tasks

- Display-filter language and evaluator (JAM-10) — depends on this task's field list existing, not built here.
- Custom columns / colouring rules, headless CLI `--fields`, richer export using field paths — all downstream, per JAM-126's epic description.
- Any new dissector coverage (JAM-128).

## Spec self-review

- No placeholders (no TBD/TODO left in this document).
- Internal consistency: the wire example, the Rust struct, and the TypeScript interface all agree on field names and casing (snake_case in Rust struct fields, camelCase on the wire per this repo's existing convention, matching `WireField`).
- Scope check: this is one task's worth of work (registry + wire + full UI cutover), explicitly excluding the filter language and any new dissector coverage — both called out above so they aren't silently pulled in during implementation.
- Ambiguity check: the group/leaf distinction (Approach C: every group is its own explicit entry with `type: "group"` and no `value`) removes the "is this path a group or a leaf" ambiguity a pure path-splitting scheme would have. The header/payload pane split (added after the first approval pass, once it became clear `hex_dump` never included header bytes at all) removes the "which byte space does this offset mean" ambiguity the same way — every field's `region` says explicitly which of the two panes it's relative to.
