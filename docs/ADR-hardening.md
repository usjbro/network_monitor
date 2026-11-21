# ADR: Hardening Rules

Stub. Status: **proposed**. The rules themselves are the Standing Rules in `CLAUDE.md` / `AGENTS.md`. This ADR records the decisions behind them and what is still planned.

## Context

## Decision

## Consequences

## Status of Each Rule

Inventory taken 2026-11-21. Rules are numbered as in the Standing Rules.

| # | Rule | Status | Evidence |
|---|---|---|---|
| 1 | State-changing actions need a plan + approval | partial | Jira gate: `coordination/scripts/create-gate.sh`; no operational-action plan format |
| 2 | Post as an agent, never as James | implemented (convention) | `coordination/scripts/slack-notify.sh` per-agent identity |
| 3 | No listeners beyond loopback; fleet connects outward | partial | loopback binds in `capture-agent/src/main.rs`, `package.json`; fleet not built |
| 4 | Nothing between agent↔uplink↔ingest | planned | components don't exist |
| 5 | No secrets in repo | partial | `.gitignore`, 0600 token file (`capture-agent/src/control_auth.rs`); no scanner |
| 6 | Flags off by default | partial | `docs/feature-flags.md`; no code registry |
| 7 | Tier budgets, 3-day retention | planned | caps exist (`MAX_FLOWS` etc.); enrichment cache is 14 days |
| 8 | Permissions from policy files | planned | auth checks are hard-coded |

## TODO

- [ ] **Secret scan in pre-commit and CI.** No scanner (gitleaks, trufflehog, detect-secrets) and no pre-commit framework is installed, so none was added. Pick one, pin it, add a pre-commit hook and a CI job.
- [ ] **Budget gate.** Define tiers. Add a budgets file (proposed: `config/budgets.toml`) and a check that fails when a cap exceeds its tier.
- [ ] **Retention.** Make 3 days the default. Decide the fate of the 14-day enrichment cache (`lib/enrichment.ts` `CACHE_TTL_MS`): conform it or record an explicit exception. Behavior is unchanged until decided.
- [ ] **Policy files.** Proposed location: `policy/`. Move the hard-coded authorization checks there and add policy tests.
- [ ] **Exposure check.** Automate the manual bind grep in `CLAUDE.md` §4 as a CI job (fail on non-loopback binds outside `deploy/`).
- [ ] **Settings manifest and staleness check.** Proposed: `config/settings-manifest.toml`, listing every env var and setting. CI fails when code reads a name the manifest (and `.env.example`) lacks.
- [ ] **Operational-action plan format** (who/what/target/reason/rollback) as a `slack-notify.sh` status or template, plus a dedicated `alert` status.
- [ ] **Fleet mode design** (uplink, Rust ingest, central backend): spec → plan per `CONTRIBUTING.md`, honoring rules 3 and 4.
- [ ] Fill in `THREAT_MODEL.md`.
