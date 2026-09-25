---
task: lateral-movement-rule
owner: claude-code
status: open
branch: agent/lateral-movement-rule
depends_on: []
created: 2026-09-24
---

## Goal

Add a correlation rule to the Network Monitor that flags lateral-movement
behavior: a source that performs service discovery against host A, then
within N minutes authenticates to host B using credentials/service patterns
first seen on host A.

## Owned files

- `network-monitor/rules/lateral_movement.py`
- `network-monitor/tests/test_lateral_movement.py`

## Do not edit

- `network-monitor/rules/reconnaissance.py` (owned by another in-flight task)
- Anything in `agents/` (location-agent code)

## Validation

- `pytest network-monitor/tests/test_lateral_movement.py -v`
- Rule must not fire on the existing benign-traffic fixture set.

## Handoff

- **Files changed:**
- **Test results:**
- **Risks / follow-ups:**
- **Branch:** `agent/lateral-movement-rule`
