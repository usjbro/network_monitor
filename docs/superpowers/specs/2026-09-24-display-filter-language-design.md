# Display Filter Language Design

Date: 2026-09-24

Status: Approved for implementation by the user

Linear: JAM-10 (part of JAM-126)

## Problem

The packet view and connection view currently use separate local substring,
protocol, and layer controls. There is no expression language over JAM-9's
typed packet fields, and there is no shared display filter. The existing
`filter <bpf expression>` command is a capture filter: it changes what the
agent captures. A display filter must only hide items in the browser's
existing buffers.

## Goals

- Provide the Phase 1 expression grammar from JAM-10 over decoded packet
  fields and explicit connection properties.
- Apply one active expression to both packet and connection views.
- Compile an expression once when it is submitted, then evaluate the
  compiled predicate against buffered records.
- Distinguish display filtering from BPF capture filtering in commands,
  labels, and parse errors.
- Show display-filter match counts and make clear that non-matching buffered
  records remain available after clearing the filter.
- Include `frame.len` in Phase 1. The user explicitly chose this despite the
  original issue placing engine meta-fields in Phase 2.

## Non-goals

- Do not send display filters to the capture agent or change capture behavior.
- Do not add regular expressions, slices, arithmetic, functions, field-to-
  field comparisons, or other Phase 2 syntax.
- Do not add a new wire event or dependency.
- Do not delete, reorder, or mutate buffered packets or connections when a
  filter changes.
- Do not claim that fields absent from a record match that record.

## Expression language

### Grammar

Phase 1 supports:

- Field existence: `tls.handshake.sni`
- Comparisons: `==`, `!=`, `>`, `<`, `>=`, `<=`
- Membership: `tcp.dst_port in {80, 443, 8080}`
- Substring: `tls.handshake.sni contains "example.com"`
- Boolean operators: `not`, `and`, `or`
- Parentheses
- Base-10 integer, boolean (`true` / `false`), and quoted string literals

Operator precedence is parentheses, `not`, comparisons/existence, `and`, then
`or`. Keywords and field paths are case-insensitive; quoted string values
retain their spelling. String and address equality and `contains` are
case-insensitive. Numeric and boolean comparisons use their native types.
`contains` is valid only for string and address values. Ordered comparisons
are valid only for numeric values. `in` requires exact typed equality, uses
the same case rules as `==`, and performs no coercion. String literals use
double quotes, with `\\` and `\"` escapes. Type or operator mismatches
evaluate false, including `!=`; there is no implicit coercion.

An absent field never satisfies a comparison, including `!=`; `not` negates
the result of its child expression. A bare field path tests whether that
field is present in the record. Syntax errors identify the unexpected token
and its character position. An unknown but syntactically valid path simply
has no value on the record and does not match; paths are not validated against
the currently buffered packets, so filters can be entered before a matching
packet arrives.

### Packet values

Packet predicates read the packet's `WireField[]` from `PacketFrame.fields`.
Only fields with scalar values can be compared; group entries can be tested
for existence. The field abbreviations remain defined by the capture agent
and documented in `docs/wire-protocol.md`.

`frame.len` is a Phase 1 numeric metadata field backed by the already-present
`PacketFrame.length`. It does not change the wire protocol. This is the one
approved Phase 1 extension beyond JAM-10's original list.

### Connection values

Connection predicates use only explicit `connection.*` fields backed by
`NetworkConnection` properties:

| Filter field | Source property | Type |
|---|---|---|
| `connection.protocol` | `protocol` | string |
| `connection.transport` | `transportProtocol` | string |
| `connection.local_addr` | `localAddr` | address |
| `connection.local_port` | `localPort` | number |
| `connection.remote_addr` | `remoteAddr` | address |
| `connection.remote_port` | `remotePort` | number |
| `connection.process` | `processName` | string |

Connection-only paths have no value on packets; packet-field paths have no
value on connection rows. A single compiled expression is passed to both
views, and each view evaluates it against its own applicable fields.

## Command and view behavior

- `display <expression>` compiles and activates a shared display filter.
- `display clear` removes it and restores all buffered records.
- The existing `filter <bpf expression>` and `filter clear` commands remain
  capture-filter controls and are not aliases for display filtering.
- A syntax error names the display-filter language and offending token; it
  leaves the last valid display filter active.
- Each view reports how many of its buffered records match the display
  filter and states that other records remain buffered. Existing per-view
  quick search and layer/protocol controls remain local refinements and do
  not change the shared expression.
- Selection and detail rendering stay consistent with the visible filtered
  records; filtering does not mutate the source buffers.

## Architecture

Add a pure TypeScript parser/compiler under `lib/`. It returns either a
compiled predicate or a structured syntax error with the offending token and
position. `app/page.tsx` owns the active source expression, compiled
predicate, and parse-error state, handling the `display` command locally.
`ConnectionsView` and `PacketStreamView` receive the same compiled predicate
and their display-filter match counts. Filtering is applied to each view's
existing in-memory data before rendering/exporting its current rows.

No API, capture-agent, wire-protocol, or server-side state changes are
required.

## Performance

Compilation occurs once per `display` command, not once per record. Each
evaluation walks the current record's fields and the expression tree. The
acceptance target is imperceptible filtering for 100 buffered packets; no
benchmark framework or dependency is introduced for this bounded client-side
operation.

## Testing and documentation

- Unit tests cover grammar precedence, all Phase 1 operators, typed values,
  malformed expressions and token positions, absent fields, `frame.len`,
  and packet/connection evaluation.
- Component and command-bar tests prove the shared expression scopes both
  views, does not invoke capture control, retains buffers on filtering, and
  distinguishes display-filter errors from BPF errors.
- `docs/usage.md` documents the grammar and worked examples, explicitly
  distinguishing `display` from BPF `filter`.

## Acceptance criteria

- Phase 1 grammar evaluates correctly against real buffered traffic,
  including `frame.len`, and malformed expressions report the offending
  token.
- The same expression scopes packets and applicable connection properties.
- Compilation is once per edit/command; 100 buffered packets filter
  imperceptibly.
- Display and capture filters have distinct commands, labels, and errors.
- Filtering reports match counts and never deletes buffered records.
- Unit tests cover parser and evaluator; usage documentation includes
  worked examples.

## References

- `JAM-10` — Linear task and approved acceptance criteria
- `docs/wire-protocol.md` — packet field names and types
- `docs/usage.md` — existing BPF capture-filter command and user command
  reference
- `lib/types.ts` — `WireField`, `PacketFrame`, and `NetworkConnection`
- `CONTRIBUTING.md` — spec/plan workflow
