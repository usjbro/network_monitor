# Display Filter Language Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a compiled client-side display-filter language shared by the buffered packet and connection views.

**Architecture:** Implement a pure TypeScript tokenizer, parser, and predicate compiler in `lib/display-filter.ts`. Keep the original buffers in `app/page.tsx`, compile only when the `display` command is submitted, and pass the compiled predicate to both views; preserve the existing `filter` command as BPF capture control.

**Tech Stack:** TypeScript, React 19, Vitest, Testing Library; no new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-24-display-filter-language-design.md`

## Global Constraints

- Display filters are client-side only and never alter capture-agent state.
- `frame.len` reads the existing `PacketFrame.length` value and requires no wire change.
- Packet field paths and types remain defined by `WireField` and `docs/wire-protocol.md`.
- Connection expressions use only the explicit `connection.*` mappings in the spec.
- A field absent on a record never matches a comparison, including `!=`.
- Invalid expressions leave the last valid display filter active.
- Filtering never mutates or deletes buffered records.
- Do not add dependencies, simulated values, or Phase 2 syntax.

## Review Focus

- Absent fields with `!=` must remain false; test missing packet and connection properties.
- Malformed quoted strings and trailing tokens must report the offending token and its character position.
- String/address comparison and `in` matching must be case-insensitive without coercing numbers or booleans.
- Switching filters must not leave a selected row/detail pointing at a hidden record.
- Submitting/clearing display filters must never call `/api/control`; test alongside existing BPF filter behavior.

---

### Task 1: Build and test the display-filter compiler

**Files:**
- Create: `lib/display-filter.ts`
- Test: `lib/__tests__/display-filter.test.ts`
- Read: `lib/types.ts`, `docs/wire-protocol.md`

**Interfaces:**
- Export `type DisplayFilterRecord = { kind: 'packet'; packet: PacketFrame } | { kind: 'connection'; connection: NetworkConnection }`.
- Export `type DisplayFilterError = { message: string; token: string; position: number }`.
- Export `type CompiledDisplayFilter = (record: DisplayFilterRecord) => boolean`.
- Export `compileDisplayFilter(source: string): { ok: true; predicate: CompiledDisplayFilter } | { ok: false; error: DisplayFilterError }`.
- `frame.len` maps to `PacketFrame.length`. Packet paths map to matching `WireField.path` entries; group paths are present when a matching group entry exists, while scalar paths read `WireField.value` according to `WireField.type`.
- Connection paths map to the spec's seven explicitly listed properties. Paths from the other record kind are absent.

- [ ] **Step 1: Write failing tests for typed comparisons and absent values.** Start with tests like these, using a packet fixture whose `fields` contains `tcp.dst_port` as `{ type: 'uint', value: 443 }` and `tls.handshake.sni` as `{ type: 'str', value: 'Example.COM' }`, plus a connection fixture with `remotePort: 443`:

```ts
it('matches typed packet fields and frame.len', () => {
  expect(run('tcp.dst_port == 443', packetRecord)).toBe(true);
  expect(run('frame.len >= 100', packetRecord)).toBe(true);
  expect(run('tls.handshake.sni == "example.com"', packetRecord)).toBe(true);
});

it('does not make an absent field match !=', () => {
  expect(run('tcp.src_port != 443', packetRecord)).toBe(false);
  expect(run('connection.remote_port != 443', packetRecord)).toBe(false);
});
```

  Also assert boolean values compare only to boolean literals and `connection.remote_port == 443` matches the connection fixture.
- [ ] **Step 2: Run the focused test and confirm the compiler export is missing.** Run `npx vitest run lib/__tests__/display-filter.test.ts`; expect the new test to fail because `lib/display-filter.ts` does not yet exist.
- [ ] **Step 3: Implement the smallest tokenizer/parser/evaluator for field existence and typed comparisons.** Use a lexer that retains source offsets; do not use `eval` or generate executable source. The evaluator must check field presence before applying any comparison.
- [ ] **Step 4: Add failing tests for all remaining grammar.** Include assertions equivalent to `tcp.dst_port in {80, 443}`, `tls.handshake.sni contains "example"`, `tcp.dst_port >= 400 and not tcp.dst_port == 80`, and `(tcp.dst_port == 80 or tcp.dst_port == 443) and frame.len < 1500`. Add escaped quote/backslash string values, ordered numeric comparisons, unknown paths, type/operator mismatch returning false (including `!=`), case-insensitive string/address membership, and no-coercion assertions such as numeric `443` not matching string `"443"`.
- [ ] **Step 5: Run the focused tests and confirm the new grammar cases fail.** Run `npx vitest run lib/__tests__/display-filter.test.ts`; verify failures exercise the missing syntax/semantics.
- [ ] **Step 6: Complete the parser and evaluator.** Enforce parentheses, `not`, comparison/existence, `and`, `or` precedence; restrict `contains` to string/address, ordered comparisons to numeric, and membership to exact typed values; do not coerce.
- [ ] **Step 7: Add malformed-expression tests and verify source locations.** Include empty source, unterminated string, missing RHS, unclosed set/parenthesis, and an otherwise valid expression followed by an unexpected token. Assert `error.token` and zero-based `error.position` identify the first offending token; use a stable end-of-input token spelling such as `<end>` for missing-token errors.
- [ ] **Step 8: Run parser tests and type-check through the repository's test tooling.** Run `npx vitest run lib/__tests__/display-filter.test.ts`; expect all parser/evaluator cases to pass.

### Task 2: Apply the compiled predicate consistently in both views

**Files:**
- Modify: `components/PacketStreamView.tsx`
- Modify: `components/ConnectionsView.tsx`
- Test: `lib/__tests__/packet-stream-display-filter.test.tsx`
- Test: `lib/__tests__/connections-view-display-filter.test.tsx`

**Interfaces:**
- Each view accepts optional `displayFilter?: CompiledDisplayFilter` and `displayFilterExpression?: string`; omitted predicate preserves current behavior for existing callers/tests.
- Each view evaluates its own record kind and computes a shared-filter match count from its full buffer before applying its existing local search/layer/protocol refinements.

- [ ] **Step 1: Write failing packet-view tests.** Render two fixture packets with `displayFilter={(record) => record.kind === 'packet' && record.packet.id === 'pkt-match'}`; assert only `pkt-match` appears in the feed/export rows, the count says one match out of two buffered, and the copy explicitly says hidden packets remain buffered. Assert selecting a visible packet keeps its detail pane aligned.
- [ ] **Step 2: Run the focused packet-view tests and confirm the filter props are not yet applied.** Run `npx vitest run lib/__tests__/packet-stream-display-filter.test.tsx`; expect the nonmatching packet to remain visible or the match indicator to be absent.
- [ ] **Step 3: Add optional predicate/expression props and apply them before local packet refinements.** Keep `packets` untouched. Derive selected packet details from a visible selection, falling back to the first visible packet when the current selected packet is hidden; show no selected detail when there are no visible packets.
- [ ] **Step 4: Run the focused packet-view tests.** Run `npx vitest run lib/__tests__/packet-stream-display-filter.test.tsx`; expect matching rows, count, retention text, and detail selection assertions to pass.
- [ ] **Step 5: Write failing connection-view tests.** Render two fixture connections with `displayFilter={(record) => record.kind === 'connection' && record.connection.id === 'conn-match'}`; assert only that row and its export data are filtered, the count is based on both buffered connections, hidden rows remain buffered, and selection/details fall back to a visible row.
- [ ] **Step 6: Run the focused connection-view tests and confirm they fail before implementation.** Run `npx vitest run lib/__tests__/connections-view-display-filter.test.tsx`; expect the second connection to remain visible or the match indicator to be absent.
- [ ] **Step 7: Add optional predicate/expression props and apply them before local connection refinements.** Preserve the connection array, include the shared filter in table/export rows, and ensure selection/detail content refers only to visible rows.
- [ ] **Step 8: Run both view suites plus existing view regressions.** Run `npx vitest run lib/__tests__/packet-stream-display-filter.test.tsx lib/__tests__/connections-view-display-filter.test.tsx lib/__tests__/packet-stream-decrypted.test.tsx lib/__tests__/connections-view-traceroute.test.tsx`; expect all to pass.

### Task 3: Add `display` command state without changing BPF capture controls

**Files:**
- Modify: `app/page.tsx`
- Modify: `components/CommandLineBar.tsx`
- Test: `lib/__tests__/page-command-bar-display-filter.test.tsx`
- Read: `components/CommandLineBar.tsx`, `lib/__tests__/page-command-bar-capture.test.tsx`

**Interfaces:**
- Page state stores the active expression and its `CompiledDisplayFilter`; both view components receive the same predicate instance and expression.
- `display <expression>` compiles locally; `display clear` resets predicate, expression, and error.
- A failed compile reports a display-filter-specific message including token and character position, and preserves the last valid filter.

- [ ] **Step 1: Write command-bar tests for activation and clearing.** Submit `display tcp.dst_port == 443`; assert the packet/connection views show the active expression and no `/api/control` request occurs. Submit `display clear`; assert all buffered rows return and no `/api/control` request occurs.
- [ ] **Step 2: Run the focused command test and confirm `display` is ignored.** Run `npx vitest run lib/__tests__/page-command-bar-display-filter.test.tsx`; expect the active expression/filter behavior to fail.
- [ ] **Step 3: Add state and command routing.** Preserve expression case by slicing it from original `cmdStr`, as existing BPF command handling does. Add `display` to `CommandLineBar` help text and display parse errors there using a small optional prop. Pass one compiled predicate to both views.
- [ ] **Step 4: Run activation/clear tests and verify no control request.** Run `npx vitest run lib/__tests__/page-command-bar-display-filter.test.tsx`; expect the display command cases to pass with no fetch to `/api/control`.
- [ ] **Step 5: Add failing-error retention and capture-filter distinction tests.** Activate a valid display filter, submit malformed `display` syntax, and assert the error identifies display filtering, offending token, and position while the valid filter remains active. Submit `filter host Example.com` and assert it still sends the original case-preserved BPF request; `filter clear` still sends an empty capture filter.
- [ ] **Step 6: Implement local error feedback and preserve last valid predicate on parse failure.** Do not route display syntax to `sendCaptureFilter`; make `display clear` remove any display parse error.
- [ ] **Step 7: Run command tests and existing capture-command regressions.** Run `npx vitest run lib/__tests__/page-command-bar-display-filter.test.tsx lib/__tests__/page-command-bar-capture.test.tsx lib/__tests__/page-capture-config-handling.test.tsx`; expect both command families to remain distinct.

### Task 4: Document usage and perform scoped regression verification

**Files:**
- Modify: `docs/usage.md`
- Read: `docs/wire-protocol.md`, `docs/superpowers/specs/2026-09-24-display-filter-language-design.md`

- [ ] **Step 1: Add usage examples.** Document `display <expression>`, `display clear`, field existence, comparisons, `in`, `contains`, boolean precedence/parentheses, `frame.len`, connection-prefixed fields, absent-field behavior, match counts/buffer retention, and the fact that existing `filter` remains a capture-side BPF command.
- [ ] **Step 2: Review documentation against the implemented grammar.** Check each documented operator and example against parser tests; remove any syntax not in Phase 1.
- [ ] **Step 3: Run all relevant display-filter and view/command regression tests.** Run `npx vitest run lib/__tests__/display-filter.test.ts lib/__tests__/packet-stream-display-filter.test.tsx lib/__tests__/connections-view-display-filter.test.tsx lib/__tests__/page-command-bar-display-filter.test.tsx lib/__tests__/page-command-bar-capture.test.tsx lib/__tests__/packet-stream-decrypted.test.tsx lib/__tests__/connections-view-traceroute.test.tsx`.
- [ ] **Step 4: Run the full TypeScript/React test suite and lint.** Run `npm test` and `npm run lint`; report any unrelated pre-existing failures without expanding scope.
- [ ] **Step 5: Review the final diff.** Run `git diff --check` and `git diff --stat`; confirm no capture-agent, wire, API, TLS, enrichment, traceroute, deployment, or macOS implementation changed, and confirm buffers are not mutated by filtering.
