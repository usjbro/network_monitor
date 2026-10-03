#!/usr/bin/env node
// Fails CI on any high/critical npm advisory except an explicit, documented
// allowlist of advisories with no patched version upstream. Plain
// `npm audit --audit-level=high` can't express that distinction, and
// `--omit=dev` is too broad: it would also hide future *fixable*
// dev-dependency advisories (see JAM-171 -- undici, the vulnerability this
// allowlist replaced blindly excluding, is itself a devDependency pulled in
// via jsdom).
//
// Usage: node check-npm-audit.mjs <npm-audit-json-file>

import { readFileSync } from "node:fs";

const ALLOWLIST = new Set([
  // braces: stack-exhaustion DoS (GHSA-vfj7-8cjw-p6xm). Affected range is
  // "*" -- no patched version has ever been published. Reached only via
  // eslint-config-next's lint-only dependency chain (micromatch ->
  // fast-glob -> @next/eslint-plugin-next -> eslint-config-next); never
  // shipped, never run against untrusted input. npm's own suggested fix is
  // downgrading eslint-config-next two majors (16.0.8 -> 14.2.35), a real
  // regression for an advisory with no exploitation path here. Revisit if
  // a patched `braces` is ever published.
  "GHSA-vfj7-8cjw-p6xm",
]);

const SEVERITY_ORDER = { info: 0, low: 1, moderate: 2, high: 3, critical: 4 };
const THRESHOLD = SEVERITY_ORDER.high;

const path = process.argv[2];
if (!path) {
  console.error("usage: check-npm-audit.mjs <npm-audit-json-file>");
  process.exit(2);
}

const data = JSON.parse(readFileSync(path, "utf8"));

// `npm audit --json` doesn't always produce a report: on a registry/network
// failure it exits non-zero and prints `{"message": ..., "error": {...}}`
// instead, with no `vulnerabilities` key at all. Defaulting that to `{}`
// would make this script report "OK -- no advisories" on a run that never
// actually audited anything -- fail-open on exactly the failure mode this
// gate exists to catch. Treat a missing `vulnerabilities` key as a hard
// failure, not as a clean result.
if (data.error || !data.vulnerabilities) {
  console.error("npm audit did not produce a usable report:");
  console.error(JSON.stringify(data, null, 2));
  process.exit(1);
}

const found = new Set();

for (const vuln of Object.values(data.vulnerabilities)) {
  if ((SEVERITY_ORDER[vuln.severity] ?? 0) < THRESHOLD) continue;
  for (const via of vuln.via ?? []) {
    if (typeof via === "object" && via.url) {
      found.add(via.url.split("/").pop());
    }
  }
}

const unexpected = [...found].filter((id) => !ALLOWLIST.has(id));

if (unexpected.length > 0) {
  console.error(
    `Unexpected high/critical severity npm advisories found: ${unexpected.join(", ")}`,
  );
  console.error("If genuinely unfixable upstream, add to ALLOWLIST in this script with a dated comment explaining why. Otherwise, fix it.");
  process.exit(1);
}

console.log(
  found.size > 0
    ? `OK -- only allowlisted advisories present: ${[...found].join(", ")}`
    : "OK -- no high/critical severity advisories.",
);
