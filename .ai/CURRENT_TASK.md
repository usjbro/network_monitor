# Current Task

## Objective

Complete JAM-27: add offline MAC vendor lookup from an IEEE OUI snapshot and expand common port-to-service names.

## Acceptance Criteria

- Known globally assigned MAC prefixes resolve offline; unknown and locally administered addresses remain unknown.
- Packet details show vendor labels beside Ethernet source/destination fields.
- Common service names are available for ports, without overriding parsed application protocols.
- No outbound lookup is made; existing opt-in enrichment behavior is unchanged.
- Document dataset provenance, snapshot date, and refresh process.

## Status

Implementation and local validation are complete. The PR, independent review, CI, merge, and Linear close-out remain. See `HANDOFF.md` and `TEST_STATUS.md` for evidence.
