# Secure LAN Access Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Secure the live-capture pipeline (sub-project 1a, #13) for viewing from other devices on the home network — mTLS via a local CA in front of a Caddy reverse proxy, plus a native macOS app with a locked-down `WKWebView` — without ever exposing the unauthenticated capture feed to the LAN.

**Architecture:** A local CA (`mkcert`) issues a server certificate for the Mac and one client certificate per trusted device. Caddy terminates TLS and enforces `client_auth { mode require_and_verify }` against that CA, proxying verified requests to the existing loopback-only Next.js app (`127.0.0.1:3000`) — nothing else changes about the app or the capture agent (`127.0.0.1:9990`). A thin native Swift app wraps a `WKWebView` locked to the Mac's own origin (main frame *and* subframes/`window.open`) and authenticates via a Secure-Enclave-backed client key, so the Mac gets a first-party viewing option alongside "any browser with an installed client cert."

**Tech Stack:** `mkcert` + `openssl` for certificate issuance, Caddy (Caddyfile config, no plugins) for the reverse proxy, Swift 6 + SwiftUI + WebKit + Security framework for the native app (scaffolded via `xcodegen` from a checked-in `project.yml`), Apple's `swift-asn1` SPM package for structural CSR encoding (see Task 8's note on why `swift-certificates` itself doesn't fit), Vitest for the new HTML-escaping regression test.

**Spec:** `docs/superpowers/specs/2026-08-26-live-capture-ingestion-design.md` (Components 3 and 4, and the "Dependency hygiene" section)

## Global Constraints

- **Nothing in this plan's automated steps ever binds Caddy to a LAN-facing address.** Every script/test in this plan defaults to `127.0.0.1:8443` (a safe loopback test port). Switching the production Caddyfile to `:443` (all interfaces) is a manual, documented step in `deploy/README.md` — never automated — so no task's verification run can accidentally expose the real capture feed to the LAN.
- **Certificates and private keys are never committed to git.** `deploy/certs/` (mkcert-issued materials) and any `.p12`/`.pem` the native app tasks generate are gitignored. Only configuration and code are checked in.
- The mkcert CA is a **local, self-signed CA** — not publicly trusted. Every device that needs to reach the Caddy endpoint (including this Mac, for local testing) needs that CA root explicitly trusted once (`mkcert -install` locally; copy `deploy/certs/ca-root.pem` to install/trust on other devices).
- **OCSP is intentionally not used.** Revocation is handled by short-lived, periodically-reissued client certs, per the spec. Don't add OCSP-checking code.
- **mTLS enforcement must be explicitly verified, never assumed.** "Caddy started" is not evidence it's enforcing client certs — Task 3's script is the required check, and Task 3 itself proves the check can fail (a negative-control run) before it's trusted as a gate.
- The capture agent (`127.0.0.1:9990`) and Next.js app (`127.0.0.1:3000`) are unchanged by this plan — still loopback-only, unauthenticated on their own, and now reachable from the LAN *only* through Caddy's verified proxy path.
- **Native app single-origin lock applies to main-frame navigation, subframe navigation, and `window.open`/new-window requests** — all three are covered by tests in Task 7 (Task 6 is scaffolding only, no navigation-lock code), not just documented.
- **Client certificate private key must be Secure-Enclave-backed** (P-256 EC), non-extractable, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (no iCloud Keychain sync), with biometric confirmation required per signing use (Task 8).
- **New dependency called out explicitly:** Task 8 adds Apple's `swift-asn1` SPM package for structural (not cryptographic) CSR encoding — see Task 8 Step 5 for why the higher-level `swift-certificates` package doesn't fit (it can't be backed by an opaque Secure Enclave key). This repo's stated security posture (`docs/security.md`) prefers "well-audited, widely-used libraries for anything security-critical... over rolling your own"; the actual cryptographic signature in Task 8 comes from `SecKeyCreateSignature` (Apple's own Secure-Enclave-backed implementation), with `swift-asn1` only assembling the surrounding ASN.1 structure.
- Exact `mkcert`/Caddy/`swift-asn1` API/CLI surfaces should be checked against what's actually installed if a step doesn't work as written — versions may have shifted since this plan was written (mkcert, Caddy, and `swift-asn1`'s package resolution were not available/exercised on the reference machine when this plan was authored; the `xcodegen`/`WKWebView`/Security-framework/XCTest code in Tasks 6–8 *was* compiled and unit-tested against Xcode 26.6 / Swift 6.3.3 while writing this plan, and Task 8's CSR-building code has its own `openssl req -text` structural verification step precisely because it's the one piece that wasn't). The TDD steps (`build`/`test`/the verification scripts) are how any drift gets caught.
- `NetworkConnection`, `PacketFrame`, and the rest of `lib/types.ts` are unchanged by this plan — this is purely a transport/access-control layer in front of the existing app.

---

## File Structure

**New — `deploy/` (mTLS/Caddy infrastructure, mirrors the `capture-agent/` convention of a self-contained subproject directory):**
- `deploy/README.md` — one-time CA/cert/Caddy setup instructions, including the manual `:443` LAN-facing switch
- `deploy/setup-ca.sh` — mkcert-based CA install + server cert + client cert issuance
- `deploy/Caddyfile` — reverse proxy enforcing mTLS, defaults to a loopback test port
- `deploy/test-mtls-rejection.sh` — automated check that a missing/invalid client cert is rejected and a valid one is accepted
- `deploy/.gitignore` — ignores `certs/`

**New — Next.js side:**
- `lib/__tests__/no-dangerous-html.test.ts` — regression test guarding the HTML-escaping audit
- `.npmrc` — `ignore-scripts=true`, `save-exact=true`
- `middleware.ts` — nonce-based Content-Security-Policy header (spec Component 4's CSP requirement; lives here rather than in `macos-app/` since it protects the served page regardless of which client renders it)

**New — `macos-app/` (native Swift viewer, separate toolchain from the rest of the repo):**
- `macos-app/project.yml` — `xcodegen` project spec (checked in instead of a binary `.xcodeproj`, so it's diffable)
- `macos-app/OSINetStrikerViewer/OSINetStrikerViewerApp.swift` — SwiftUI `App` entry point
- `macos-app/OSINetStrikerViewer/ContentView.swift` — `NSViewRepresentable` wrapper hosting the locked-down `WKWebView`
- `macos-app/OSINetStrikerViewer/NavigationLockDelegate.swift` — single-origin navigation policy (`WKNavigationDelegate` + `WKUIDelegate`)
- `macos-app/OSINetStrikerViewer/ClientCertStore.swift` — Secure Enclave key generation, CSR construction, Keychain identity storage, `URLSessionDelegate` client-cert challenge handling
- `macos-app/OSINetStrikerViewer/Info.plist`, `macos-app/OSINetStrikerViewer/OSINetStrikerViewer.entitlements`
- `macos-app/OSINetStrikerViewerTests/NavigationLockDelegateTests.swift`
- `macos-app/OSINetStrikerViewerTests/ClientCertStoreTests.swift`
- `macos-app/README.md` — build/run instructions (`xcodegen generate`, then open in Xcode or `xcodebuild`)

**Modified:**
- `docs/security.md` — flip the relevant "What's explicitly NOT done yet" bullet once this lands

---

### Task 1: mkcert local CA + server/client certificate issuance (#14)

**Files:**
- Create: `deploy/setup-ca.sh`
- Create: `deploy/README.md`
- Create: `deploy/.gitignore`

**Interfaces:**
- Produces: `deploy/certs/server.pem` + `deploy/certs/server-key.pem` (server cert for `localhost`/`127.0.0.1`/the Mac's hostname/LAN IP), `deploy/certs/client-<name>.pem` + `deploy/certs/client-<name>-key.pem` per invocation, `deploy/certs/ca-root.pem` (the CA root, for installing on other devices). Consumed by Task 2 (Caddyfile) and Task 3 (rejection test).

- [ ] **Step 1: Write `deploy/.gitignore`**

```
certs/
```

- [ ] **Step 2: Write `deploy/setup-ca.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="$DEPLOY_DIR/certs"
mkdir -p "$CERTS_DIR"

if ! command -v mkcert >/dev/null 2>&1; then
  echo "mkcert not found. Install it first: brew install mkcert" >&2
  exit 1
fi

# Installs/trusts the local CA in the system + browser trust stores on THIS
# machine. Idempotent -- safe to re-run. Other devices need ca-root.pem
# (produced below) installed separately; see deploy/README.md.
mkcert -install

HOSTNAME="$(scutil --get LocalHostName 2>/dev/null || hostname -s)"
LOCAL_IP="$(ipconfig getifaddr en0 2>/dev/null || true)"

SERVER_NAMES=("$HOSTNAME.local" "localhost" "127.0.0.1")
if [ -n "$LOCAL_IP" ]; then
  SERVER_NAMES+=("$LOCAL_IP")
fi

echo "Issuing server certificate for: ${SERVER_NAMES[*]}"
mkcert -cert-file "$CERTS_DIR/server.pem" -key-file "$CERTS_DIR/server-key.pem" "${SERVER_NAMES[@]}"

CLIENT_NAME="${1:-default-client}"
echo "Issuing client certificate: $CLIENT_NAME"
mkcert -client -cert-file "$CERTS_DIR/client-$CLIENT_NAME.pem" -key-file "$CERTS_DIR/client-$CLIENT_NAME-key.pem" "$CLIENT_NAME"

CAROOT="$(mkcert -CAROOT)"
cp "$CAROOT/rootCA.pem" "$CERTS_DIR/ca-root.pem"

echo
echo "Done. Files in $CERTS_DIR:"
ls -la "$CERTS_DIR"
echo
echo "To trust a new viewing device: copy $CERTS_DIR/client-$CLIENT_NAME.pem"
echo "and client-$CLIENT_NAME-key.pem to it, plus ca-root.pem, and install"
echo "both per deploy/README.md. Run this script again with a different"
echo "name argument to issue additional client certs."
```

```bash
chmod +x deploy/setup-ca.sh
```

- [ ] **Step 3: Write `deploy/README.md`**

```markdown
# deploy/

One-time setup for securing the app for LAN access: a local CA, a server
certificate for this Mac, and one client certificate per trusted viewing
device. See `docs/superpowers/specs/2026-08-26-live-capture-ingestion-design.md`
for the full design and threat model.

## One-time setup

1. Install the tools:

       brew install mkcert caddy

2. Generate the CA + server cert + a first client cert:

       ./deploy/setup-ca.sh my-phone

   Re-run with a different name for each additional trusted device
   (`./deploy/setup-ca.sh my-laptop`, etc). Certs land in `deploy/certs/`
   (gitignored -- never commit these).

3. Install the client cert + CA root on the viewing device: copy
   `deploy/certs/client-<name>.pem`, `client-<name>-key.pem`, and
   `ca-root.pem` to it (AirDrop/USB/however), then follow that device's
   OS instructions to trust the CA root and install the client
   certificate.

4. Verify mTLS is actually enforced before trusting this setup:

       npm run dev &
       caddy run --config deploy/Caddyfile &
       ./deploy/test-mtls-rejection.sh

   Both processes can be stopped afterward (`kill %1 %2`, or `Ctrl+C`
   each). See `deploy/test-mtls-rejection.sh` for what this checks.

5. **Only after step 4 passes**, and only when you actually want LAN
   access: edit `deploy/Caddyfile` and change its listen address from
   `127.0.0.1:8443` to `:443` (see the comment in that file). This is a
   deliberate manual step, not automated by this repo -- until you make
   this change, Caddy only ever binds to loopback and nothing here is
   reachable from your LAN.

## Running (each session, once set up)

    ./capture-agent/target/release/capture-agent &   # or: cd capture-agent && cargo run --release
    npm run start &                                    # or npm run dev
    caddy run --config deploy/Caddyfile &

Browse to `https://<mac-hostname>.local` (or the LAN IP) from a device
with an installed, trusted client certificate.

## Reissuing certificates

mkcert-issued leaf certs are valid for a long time by mkcert's defaults;
this project's stated preference is short-lived, periodically-reissued
certs over OCSP revocation checking. Re-run `./deploy/setup-ca.sh <name>`
to reissue a given device's client cert, then reinstall it on that
device.
```

- [ ] **Step 4: Run it and verify the certificate contents**

Run:
```bash
./deploy/setup-ca.sh test-device
openssl x509 -in deploy/certs/server.pem -noout -text | grep -A2 "Subject Alternative Name"
openssl x509 -in deploy/certs/client-test-device.pem -noout -subject
```
Expected: the server cert's SAN list includes `localhost`, `127.0.0.1`, and your hostname/LAN IP; the client cert's subject includes `test-device`.

- [ ] **Step 5: Commit**

```bash
git add deploy/setup-ca.sh deploy/README.md deploy/.gitignore
git commit -m "Add mkcert-based local CA + server/client cert issuance (#14)"
```

---

### Task 2: Caddyfile with mTLS enforced (#15)

**Files:**
- Create: `deploy/Caddyfile`

**Interfaces:**
- Consumes: `deploy/certs/{server.pem,server-key.pem,ca-root.pem}` from Task 1.
- Produces: a reverse proxy in front of `127.0.0.1:3000` (the existing Next.js app), reachable at `127.0.0.1:8443` for testing (Task 3 depends on this exact default). Not reachable from the LAN until the manual `:443` switch documented in Task 1's README.

- [ ] **Step 1: Write `deploy/Caddyfile`**

```caddyfile
{
	auto_https off
}

# Defaults to a loopback-only test port so nothing here is LAN-reachable
# until you deliberately change CADDY_LISTEN_ADDR to ":443" (see
# deploy/README.md step 5). Never hardcode ":443" here directly.
{$CADDY_LISTEN_ADDR:127.0.0.1:8443} {
	tls {$CADDY_CERT_DIR:deploy/certs}/server.pem {$CADDY_CERT_DIR:deploy/certs}/server-key.pem {
		client_auth {
			mode require_and_verify
			trusted_ca_cert_file {$CADDY_CERT_DIR:deploy/certs}/ca-root.pem
		}
	}

	reverse_proxy 127.0.0.1:3000
}
```

- [ ] **Step 2: Validate the config and confirm the proxy actually works with a valid cert**

Run:
```bash
brew install caddy   # if not already installed from Task 1's README
caddy validate --config deploy/Caddyfile
```
Expected: `Valid configuration`.

Run (in separate terminals or backgrounded):
```bash
npm run dev &
caddy run --config deploy/Caddyfile &
sleep 2
curl -sk --cert deploy/certs/client-test-device.pem --key deploy/certs/client-test-device-key.pem \
  -o /dev/null -w "HTTP %{http_code}\n" https://127.0.0.1:8443/
```
Expected: `HTTP 200`.

Stop both background processes afterward (`kill %1 %2`).

- [ ] **Step 3: Commit**

```bash
git add deploy/Caddyfile
git commit -m "Add Caddy reverse proxy enforcing mTLS (#15)"
```

---

### Task 3: Automated deploy-time test that mTLS actually rejects a bad/missing cert (#16)

**Files:**
- Create: `deploy/test-mtls-rejection.sh`

**Interfaces:**
- Consumes: a running Caddy instance per Task 2 (`127.0.0.1:8443` by default, overridable via `CADDY_LISTEN_ADDR`/`CADDY_CERT_DIR` env vars matching the Caddyfile), and at least one client cert from Task 1 in `deploy/certs/`.
- Produces: exit code `0` and a "mTLS verification passed" message when both checks succeed; exit code `1` with a `FAIL:` message naming exactly which check failed otherwise. This script is what Task 1's README step 4 and Task 2's own verification both point to.

- [ ] **Step 1: Write `deploy/test-mtls-rejection.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${CADDY_CERT_DIR:-$DEPLOY_DIR/certs}"
ADDR="${CADDY_LISTEN_ADDR:-127.0.0.1:8443}"

fail() { echo "FAIL: $1" >&2; exit 1; }

echo "1/2: connecting with NO client certificate (must be rejected)..."
if curl -sk --max-time 5 "https://$ADDR/" -o /dev/null; then
  fail "connection without a client cert succeeded -- mTLS is NOT enforced"
fi
echo "  OK: rejected as expected"

CLIENT_CERT="$(ls "$CERTS_DIR"/client-*.pem 2>/dev/null | grep -v -- '-key.pem' | head -1 || true)"
[ -n "$CLIENT_CERT" ] || fail "no client cert found in $CERTS_DIR -- run deploy/setup-ca.sh first"
CLIENT_KEY="${CLIENT_CERT%.pem}-key.pem"

echo "2/2: connecting WITH a valid client certificate (must succeed)..."
STATUS="$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' \
  --cert "$CLIENT_CERT" --key "$CLIENT_KEY" \
  "https://$ADDR/")"
[ "$STATUS" = "200" ] || fail "connection WITH a valid client cert returned HTTP $STATUS, expected 200"
echo "  OK: accepted as expected (HTTP 200)"

echo
echo "mTLS verification passed: rejects missing certs, accepts a valid one."
```

```bash
chmod +x deploy/test-mtls-rejection.sh
```

- [ ] **Step 2: Run it against the live setup from Task 2 and confirm it passes**

Run:
```bash
npm run dev &
caddy run --config deploy/Caddyfile &
sleep 2
./deploy/test-mtls-rejection.sh
```
Expected: both checks print `OK`, script exits `0`.

- [ ] **Step 3: Prove the test can actually fail (negative control) -- required, not optional**

Temporarily loosen the Caddyfile's `client_auth` mode to prove this script would catch a real misconfiguration:

```bash
sed -i '' 's/mode require_and_verify/mode request/' deploy/Caddyfile
caddy reload --config deploy/Caddyfile
./deploy/test-mtls-rejection.sh; echo "exit code: $?"
```
Expected: the script prints `FAIL: connection without a client cert succeeded -- mTLS is NOT enforced` and exits non-zero.

Then revert the config and confirm the script passes again:
```bash
git checkout -- deploy/Caddyfile
caddy reload --config deploy/Caddyfile
./deploy/test-mtls-rejection.sh
```
Expected: passes as in Step 2. Stop background processes afterward (`kill %1 %2`).

- [ ] **Step 4: Commit**

```bash
git add deploy/test-mtls-rejection.sh
git commit -m "Add automated mTLS-rejection verification script (#16)"
```

---

### Task 4: Audit + regression test — LAN-sourced strings are always HTML-escaped (#17)

**Files:**
- Create: `lib/__tests__/no-dangerous-html.test.ts`
- Modify: `docs/security.md`

**Interfaces:**
- Produces: a Vitest test that fails the suite if any file under `app/`, `components/`, or `lib/` uses `dangerouslySetInnerHTML` or `.innerHTML =` — the two ways React's default JSX escaping could be bypassed for the network-sourced strings the spec calls out (HTTP path/DNS query name in `PacketFrame.headerBreakdown`, `processName`, `pkt.src`/`pkt.dst`/`pkt.summary`).

- [ ] **Step 1: Confirm the current audit finding (no code change yet)**

Run:
```bash
grep -rn "dangerouslySetInnerHTML\|\.innerHTML\s*=" app/ components/ lib/ 2>/dev/null
```
Expected: no matches. (Verified against the current tree while writing this plan: `conn.processName`, `pkt.src`/`pkt.dst`/`pkt.summary`, and every `headerBreakdown.layer*` field render via plain JSX `{...}` interpolation in `ConnectionsView.tsx`/`PacketStreamView.tsx`, which React auto-escapes.) This step is what the regression test in Step 2 turns into a permanent, automated check.

- [ ] **Step 2: Write the failing-by-construction regression test**

```typescript
import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const SCAN_DIRS = ['app', 'components', 'lib'];
const DANGEROUS_PATTERN = /dangerouslySetInnerHTML|\.innerHTML\s*=/;

function collectSourceFiles(dir: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      if (entry === '__tests__' || entry === 'node_modules') continue;
      files.push(...collectSourceFiles(full));
    } else if (/\.(tsx?|jsx?)$/.test(entry)) {
      files.push(full);
    }
  }
  return files;
}

describe('network-sourced strings are never rendered as raw HTML', () => {
  it('no source file under app/, components/, or lib/ uses dangerouslySetInnerHTML or .innerHTML', () => {
    const offenders: string[] = [];
    for (const dir of SCAN_DIRS) {
      for (const file of collectSourceFiles(dir)) {
        const content = readFileSync(file, 'utf-8');
        if (DANGEROUS_PATTERN.test(content)) {
          offenders.push(file);
        }
      }
    }
    expect(offenders).toEqual([]);
  });
});
```

- [ ] **Step 3: Run it and verify it passes**

Run: `npx vitest run lib/__tests__/no-dangerous-html.test.ts`
Expected: PASS (1 test).

- [ ] **Step 4: Red-green check — prove the test actually catches a violation**

```bash
echo 'export const x = () => <div dangerouslySetInnerHTML={{__html: "x"}} />;' >> components/ConnectionsView.tsx
npx vitest run lib/__tests__/no-dangerous-html.test.ts; echo "exit code: $?"
git checkout -- components/ConnectionsView.tsx
npx vitest run lib/__tests__/no-dangerous-html.test.ts
```
Expected: first run FAILs listing `components/ConnectionsView.tsx`; after revert, PASSes again.

- [ ] **Step 5: Update `docs/security.md`**

In the "What's explicitly NOT done yet" section, change the LAN-access bullet to note that HTML-escaping of network-sourced strings is now audited and regression-tested (`lib/__tests__/no-dangerous-html.test.ts`), while leaving the rest of that bullet (mTLS/Caddy/native-app status) accurate to what's actually landed as this plan's earlier tasks complete.

- [ ] **Step 6: Commit**

```bash
git add lib/__tests__/no-dangerous-html.test.ts docs/security.md
git commit -m "Add HTML-escaping audit + regression test for network-sourced strings (#17)"
```

---

### Task 5: npm dependency hygiene — ignore-scripts, exact pinning, npm ci enforcement (#18)

**Files:**
- Create: `.npmrc`
- Modify: `docs/security.md`

**Interfaces:**
- Produces: `.npmrc` enforcing `ignore-scripts=true` and `save-exact=true` for every `npm install`/`npm ci` run against this repo going forward.

- [ ] **Step 1: Write `.npmrc`**

```ini
ignore-scripts=true
save-exact=true
```

- [ ] **Step 2: Verify the full toolchain still works with scripts disabled**

Run:
```bash
rm -rf node_modules
npm ci
npm run build
npm run lint
npx vitest run
```
Expected: all four succeed. (Verified against the current dependency set while writing this plan — `npm ci --ignore-scripts` installs cleanly and `build`/`lint`/`vitest run` all pass unchanged. If a future dependency actually needs an install script — e.g. a native binary build step — `npm ci` will silently skip it under this config; watch for that kind of failure mode specifically, per the spec's dependency-hygiene note.)

- [ ] **Step 3: Update `docs/security.md`**

In the "Dependency hygiene" section, change the `npm ci`/`ignore-scripts`/exact-pinning bullets from "this repo follows" (a convention) to note they're now enforced via `.npmrc`, not just observed by habit.

- [ ] **Step 4: Commit**

```bash
git add .npmrc docs/security.md
git commit -m "Enforce npm ignore-scripts + exact pinning via .npmrc (#18)"
```

---

### Task 6: Native macOS app — Xcode scaffold, App Sandbox + hardened runtime (#19)

**Files:**
- Create: `macos-app/project.yml`
- Create: `macos-app/OSINetStrikerViewer/OSINetStrikerViewerApp.swift`
- Create: `macos-app/OSINetStrikerViewer/Info.plist`
- Create: `macos-app/OSINetStrikerViewer/OSINetStrikerViewer.entitlements`
- Create: `macos-app/README.md`

**Interfaces:**
- Produces: a buildable, sandboxed macOS app target named `OSINetStrikerViewer` with a `OSINetStrikerViewerTests` unit-test target wired to it, generated from `project.yml` via `xcodegen` (not a checked-in binary `.xcodeproj`). Task 7 adds the `WKWebView`/navigation-lock code inside this scaffold; Task 8 adds the client-cert code.

- [ ] **Step 1: Write `macos-app/project.yml`**

```yaml
name: OSINetStrikerViewer
options:
  bundleIdPrefix: com.osinetstriker
settings:
  MACOSX_DEPLOYMENT_TARGET: "14.0"
  SWIFT_VERSION: "6.0"
targets:
  OSINetStrikerViewer:
    type: application
    platform: macOS
    sources:
      - path: OSINetStrikerViewer
    settings:
      PRODUCT_BUNDLE_IDENTIFIER: com.osinetstriker.viewer
      INFOPLIST_FILE: OSINetStrikerViewer/Info.plist
      CODE_SIGN_ENTITLEMENTS: OSINetStrikerViewer/OSINetStrikerViewer.entitlements
      CODE_SIGN_STYLE: Automatic
      ENABLE_HARDENED_RUNTIME: YES
  OSINetStrikerViewerTests:
    type: bundle.unit-test
    platform: macOS
    sources:
      - path: OSINetStrikerViewerTests
    dependencies:
      - target: OSINetStrikerViewer
```

- [ ] **Step 2: Write `macos-app/OSINetStrikerViewer/Info.plist`**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDisplayName</key>
	<string>OSI NetStriker Viewer</string>
	<key>LSMinimumSystemVersion</key>
	<string>14.0</string>
</dict>
</plist>
```

- [ ] **Step 3: Write `macos-app/OSINetStrikerViewer/OSINetStrikerViewer.entitlements`**

App Sandbox on, with only the one capability this app actually needs (network client, to reach the Caddy endpoint). No JIT, no broader file-system access.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.security.app-sandbox</key>
	<true/>
	<key>com.apple.security.network.client</key>
	<true/>
</dict>
</plist>
```

- [ ] **Step 4: Write a placeholder app entry point so the scaffold builds (Task 7 replaces the body)**

```swift
import SwiftUI

@main
struct OSINetStrikerViewerApp: App {
    var body: some Scene {
        WindowGroup {
            Text("OSI NetStriker Viewer")
        }
    }
}
```

- [ ] **Step 5: Write `macos-app/README.md`**

```markdown
# macos-app/

Native macOS viewer: a thin `WKWebView` shell locked to this Mac's own
HTTPS+mTLS origin, with a Secure-Enclave-backed client certificate. See
`docs/superpowers/specs/2026-08-26-live-capture-ingestion-design.md`
(Component 4) for the design.

## Build

    brew install xcodegen   # one-time
    cd macos-app
    xcodegen generate
    open OSINetStrikerViewer.xcodeproj   # or: xcodebuild -project OSINetStrikerViewer.xcodeproj -scheme OSINetStrikerViewer build

`OSINetStrikerViewer.xcodeproj` is generated from `project.yml` and is
gitignored -- regenerate it with `xcodegen generate` after any
`project.yml` change or a fresh checkout; don't hand-edit the
`.xcodeproj`.

## Test

    xcodebuild -project OSINetStrikerViewer.xcodeproj -scheme OSINetStrikerViewer \
      -destination 'platform=macOS' test

## Requires

`deploy/` set up first (Tasks 1-3 of this plan) -- this app points at the
same HTTPS+mTLS origin any browser with an installed client cert would
use.
```

Add the generated project to `.gitignore` (create `macos-app/.gitignore` if it doesn't exist):
```
*.xcodeproj/
```

- [ ] **Step 6: Generate the project and verify it builds**

Run:
```bash
brew install xcodegen
cd macos-app
xcodegen generate
xcodebuild -project OSINetStrikerViewer.xcodeproj -scheme OSINetStrikerViewer -configuration Debug build CODE_SIGNING_ALLOWED=NO
```
Expected: `** BUILD SUCCEEDED **`. (This exact scaffold -- `project.yml` shape, `Info.plist`, entitlements, `CODE_SIGN_ENTITLEMENTS`/`INFOPLIST_FILE` settings -- was verified to build clean against Xcode 26.6 while writing this plan.)

- [ ] **Step 7: Commit**

```bash
cd /Users/jamesbrown/code/osi-traffic-terminal-monitor
git add macos-app/project.yml macos-app/OSINetStrikerViewer/Info.plist \
  macos-app/OSINetStrikerViewer/OSINetStrikerViewer.entitlements \
  macos-app/OSINetStrikerViewer/OSINetStrikerViewerApp.swift \
  macos-app/README.md macos-app/.gitignore
git commit -m "Scaffold native macOS app: App Sandbox + hardened runtime (#19)"
```

---

### Task 7: Native macOS app — WKWebView single-origin navigation lock + CSP (#20)

**Files:**
- Create: `macos-app/OSINetStrikerViewer/NavigationLockDelegate.swift`
- Create: `macos-app/OSINetStrikerViewer/ContentView.swift`
- Modify: `macos-app/OSINetStrikerViewer/OSINetStrikerViewerApp.swift`
- Create: `macos-app/OSINetStrikerViewerTests/NavigationLockDelegateTests.swift`
- Create: `middleware.ts` (repo root, Next.js side — the CSP header from the spec's Component 4, see Step 6)

**Interfaces:**
- Consumes: nothing from earlier tasks beyond the scaffold.
- Produces: `NavigationLockDelegate.isAllowed(url:) -> Bool` (the pure decision logic, unit-tested directly since `WKNavigationAction` has no public initializer and can't be constructed in a test), wired into `WKNavigationDelegate.decidePolicyFor` (main + subframe navigation) and `WKUIDelegate.createWebViewWith` (blocks `window.open`). Task 8's `ClientCertStore` is consumed by `ContentView`'s `URLSession` delegate, added in that task.

- [ ] **Step 1: Write the failing test**

```swift
import XCTest
@testable import OSINetStrikerViewer

final class NavigationLockDelegateTests: XCTestCase {
    func testRejectsUntrustedHost() {
        let delegate = NavigationLockDelegate(trustedOrigin: "mac-hostname.local")
        XCTAssertFalse(delegate.isAllowed(url: URL(string: "https://evil.com/")!))
    }

    func testAllowsTrustedHost() {
        let delegate = NavigationLockDelegate(trustedOrigin: "mac-hostname.local")
        XCTAssertTrue(delegate.isAllowed(url: URL(string: "https://mac-hostname.local/dashboard")!))
    }

    func testRejectsTrustedHostAsASubstring() {
        // A host that merely CONTAINS the trusted origin as a substring
        // (e.g. an attacker-controlled "mac-hostname.local.evil.com") must
        // still be rejected -- this guards against a naive .contains()
        // implementation instead of an exact host match.
        let delegate = NavigationLockDelegate(trustedOrigin: "mac-hostname.local")
        XCTAssertFalse(delegate.isAllowed(url: URL(string: "https://mac-hostname.local.evil.com/")!))
    }

    func testCreateWebViewWithAlwaysReturnsNil() {
        // window.open()/new-window requests must never open a second
        // webview -- there is nothing else in this app for a second
        // window to safely point at.
        let delegate = NavigationLockDelegate(trustedOrigin: "mac-hostname.local")
        XCTAssertNil(delegate.decideNewWindow())
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd macos-app && xcodegen generate && xcodebuild -project OSINetStrikerViewer.xcodeproj -scheme OSINetStrikerViewer -destination 'platform=macOS' test CODE_SIGNING_ALLOWED=NO`
Expected: FAILs to build — `NavigationLockDelegate` doesn't exist yet.

- [ ] **Step 3: Write `NavigationLockDelegate.swift`**

```swift
import WebKit

/// Enforces the single-origin lock described in the design spec: this
/// webview may only ever navigate to `trustedOrigin`, in the main frame,
/// any subframe, or a new-window request. A shell that can only ever
/// render one origin you author yourself has nothing else to visit.
final class NavigationLockDelegate: NSObject, WKNavigationDelegate, WKUIDelegate {
    let trustedOrigin: String

    init(trustedOrigin: String) {
        self.trustedOrigin = trustedOrigin
    }

    /// Exact host match only -- NOT a substring/prefix check, which would
    /// wrongly allow e.g. "trustedOrigin.evil.com".
    func isAllowed(url: URL) -> Bool {
        return url.host == trustedOrigin
    }

    func webView(
        _ webView: WKWebView,
        decidePolicyFor navigationAction: WKNavigationAction,
        decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
    ) {
        guard let url = navigationAction.request.url, isAllowed(url: url) else {
            decisionHandler(.cancel)
            return
        }
        decisionHandler(.allow)
    }

    /// Pulled out of createWebViewWith so it's directly unit-testable
    /// (WKWebViewConfiguration/WKNavigationAction have no public
    /// initializers, so the delegate method itself can't be called from a
    /// test -- this wrapper carries the actual decision).
    func decideNewWindow() -> WKWebView? {
        return nil
    }

    func webView(
        _ webView: WKWebView,
        createWebViewWith configuration: WKWebViewConfiguration,
        for navigationAction: WKNavigationAction,
        windowFeatures: WKWindowFeatures
    ) -> WKWebView? {
        return decideNewWindow()
    }
}
```

- [ ] **Step 4: Run the test again to verify it passes**

Run: `xcodebuild -project OSINetStrikerViewer.xcodeproj -scheme OSINetStrikerViewer -destination 'platform=macOS' test CODE_SIGNING_ALLOWED=NO`
Expected: `** TEST SUCCEEDED **`, all 4 tests pass. (This exact delegate shape — including the `isAllowed`/`decideNewWindow` extraction for testability — was compiled and unit-tested against Xcode 26.6 while writing this plan.)

- [ ] **Step 5: Write `ContentView.swift`, wiring the delegate into a WKWebView with a strict CSP as defense-in-depth**

```swift
import SwiftUI
import WebKit

struct TrustedWebView: NSViewRepresentable {
    let trustedURL: URL

    func makeCoordinator() -> NavigationLockDelegate {
        NavigationLockDelegate(trustedOrigin: trustedURL.host ?? "")
    }

    func makeNSView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = context.coordinator
        webView.uiDelegate = context.coordinator
        webView.load(URLRequest(url: trustedURL))
        return webView
    }

    func updateNSView(_ nsView: WKWebView, context: Context) {}
}

struct ContentView: View {
    // Matches deploy/setup-ca.sh's server cert SAN (<hostname>.local) --
    // update if you changed CADDY_LISTEN_ADDR away from the ":443"
    // production default from deploy/README.md step 5.
    //
    // ProcessInfo.processInfo.hostName is backed by gethostname(), which
    // on stock macOS typically already returns the Bonjour-qualified
    // "<hostname>.local" form (the same string `scutil --get
    // LocalHostName` + ".local" produces, which is what
    // deploy/setup-ca.sh's SAN is built from) -- but that's not
    // guaranteed on every configuration, so this checks rather than
    // blindly appending ".local" a second time (verify against your
    // actual cert's SAN with `openssl x509 -in deploy/certs/server.pem
    // -noout -text | grep -A2 "Subject Alternative Name"` if the
    // navigation lock rejects its own trusted origin on first run).
    let trustedURL: URL = {
        let host = ProcessInfo.processInfo.hostName
        let qualifiedHost = host.hasSuffix(".local") ? host : "\(host).local"
        return URL(string: "https://\(qualifiedHost)")!
    }()

    var body: some View {
        TrustedWebView(trustedURL: trustedURL)
            .frame(minWidth: 800, minHeight: 600)
    }
}
```

The strict CSP (`default-src 'self'`, no `unsafe-eval`) the spec calls for as defense-in-depth belongs in the **served app's own HTTP response headers** (Next.js side), not the native shell — the shell's job is the navigation lock above; the CSP protects the page content itself regardless of which client renders it. Issue #20's title bundles this in ("WKWebView single-origin navigation lock **+ CSP**"), so it's a step here even though the file it touches lives outside `macos-app/`.

- [ ] **Step 6: Add a nonce-based CSP via Next.js middleware**

Confirmed while writing this plan (via `curl`'d production HTML, see this task's research): Next.js's App Router injects its own inline `<script>` tags for hydration/RSC payload delivery — a plain `script-src 'self'` CSP would break the app, so this uses Next's documented nonce pattern instead of `'unsafe-inline'`. No inline `<style>` tags or `style="..."` attributes were found in the rendered output, so `style-src` doesn't need a similar relaxation.

Create `middleware.ts` at the repo root:

```typescript
import { NextRequest, NextResponse } from 'next/server';

export function middleware(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString('base64');
  const csp = [
    `default-src 'self'`,
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,
    `style-src 'self'`,
    `img-src 'self' data:`,
    `connect-src 'self'`,
    `frame-ancestors 'none'`,
    `base-uri 'self'`,
    `object-src 'none'`,
  ].join('; ');

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set('Content-Security-Policy', csp);
  return response;
}
```

Next.js auto-detects a CSP header containing a `nonce-` source on `script-src` and applies that nonce to its own framework-injected inline scripts — no changes needed in `app/layout.tsx` for that part. Verify this is still true for Next 16.3.3 when implementing this step (check the current "Content Security Policy" page in the Next.js docs) — flagged here rather than asserted as fact because this plan's authoring environment didn't have live doc access to confirm no behavior changed across the 15→16 upgrade this repo already went through.

- [ ] **Step 7: Verify the CSP doesn't break the app**

Run:
```bash
npm run build && npm run start &
sleep 2
curl -sI http://127.0.0.1:3000/ | grep -i content-security-policy
```
Expected: a `Content-Security-Policy` header is present containing a `nonce-` value.

Then load `http://127.0.0.1:3000/` in an actual browser (not just curl) with the developer console open, exercise every tab/view in the UI (dashboard, connections, packet stream, protocol matrix, layer detail, theme switching, command bar), and confirm there are zero CSP violation errors in the console. This can't be fully automated without adding a browser-testing tool this repo doesn't have (Playwright/etc.) — treat this manual pass as required, not optional, since a CSP violation silently breaking a feature (e.g. a chart library that needs `unsafe-eval`, if one gets added later) would otherwise ship unnoticed.

- [ ] **Step 8: Commit**

```bash
git add middleware.ts
git commit -m "Add nonce-based Content-Security-Policy (#20)"
```

- [ ] **Step 9: Wire `ContentView` into the app entry point**

```swift
import SwiftUI

@main
struct OSINetStrikerViewerApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
```

- [ ] **Step 10: Verify the full app still builds**

Run: `xcodebuild -project OSINetStrikerViewer.xcodeproj -scheme OSINetStrikerViewer -configuration Debug build CODE_SIGNING_ALLOWED=NO`
Expected: `** BUILD SUCCEEDED **`.

- [ ] **Step 11: Commit**

```bash
cd /Users/jamesbrown/code/osi-traffic-terminal-monitor
git add macos-app/OSINetStrikerViewer/NavigationLockDelegate.swift \
  macos-app/OSINetStrikerViewer/ContentView.swift \
  macos-app/OSINetStrikerViewer/OSINetStrikerViewerApp.swift \
  macos-app/OSINetStrikerViewerTests/NavigationLockDelegateTests.swift
git commit -m "Add WKWebView single-origin navigation lock (#20)"
```

---

### Task 8: Native macOS app — Keychain-backed Secure Enclave client certificate (#21)

**Files:**
- Create: `macos-app/OSINetStrikerViewer/ClientCertStore.swift`
- Create: `macos-app/OSINetStrikerViewerTests/ClientCertStoreTests.swift`
- Modify: `macos-app/project.yml` (add the `swift-asn1` package dependency)
- Modify: `macos-app/OSINetStrikerViewer/NavigationLockDelegate.swift` (the `WKWebView` client-cert challenge handler — this is where the identity actually gets presented, see Step 8)
- Modify: `macos-app/OSINetStrikerViewer/ContentView.swift` (provisions the identity in `makeCoordinator` and hands it to `NavigationLockDelegate`)

**Interfaces:**
- Produces: `makeSecureEnclaveKey(tag:) throws -> SecKey`, `ClientCertStore.loadOrCreateIdentity(caCertPath:caKeyPath:) throws -> SecIdentity` (generates the SE key + CSR on first run, has it signed by the local CA from Task 1, imports the resulting cert into the Keychain, and returns a `SecIdentity` pairing the two), and a `NavigationLockDelegate.clientIdentity` property + `WKNavigationDelegate.didReceive challenge:` conformance that presents that identity on a `URLAuthenticationChallenge` of type `NSURLAuthenticationMethodClientCertificate`.
- Consumes: `deploy/certs/ca-root.pem` + the CA's private key location (`$(mkcert -CAROOT)/rootCA-key.pem`) from Task 1, to sign the CSR this task generates — this is the one piece of the client identity that comes from `openssl`, not Apple's Security framework, since Secure Enclave keys can only produce a CSR, not a self-signed leaf cert that a CA elsewhere trusts.

- [ ] **Step 1: Write the failing test for Secure Enclave key generation**

```swift
import XCTest
@testable import OSINetStrikerViewer

final class ClientCertStoreTests: XCTestCase {
    func testGeneratesAP256SecureEnclaveKey() throws {
        let tag = "com.osinetstriker.viewer.test-key-\(UUID().uuidString)"
        defer { deleteKey(tag: tag) }

        let key = try makeSecureEnclaveKey(tag: tag)
        let attributes = SecKeyCopyAttributes(key) as? [String: Any]

        XCTAssertEqual(attributes?[kSecAttrKeyType as String] as? String, kSecAttrKeyTypeECSECPrimeRandom as String)
        XCTAssertEqual(attributes?[kSecAttrKeySizeInBits as String] as? Int, 256)
    }
}

private func deleteKey(tag: String) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: Data(tag.utf8),
    ]
    SecItemDelete(query as CFDictionary)
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `xcodebuild -project OSINetStrikerViewer.xcodeproj -scheme OSINetStrikerViewer -destination 'platform=macOS' test CODE_SIGNING_ALLOWED=NO`
Expected: FAILs to build — `makeSecureEnclaveKey` doesn't exist yet.

- [ ] **Step 3: Write the Secure Enclave key generation function**

```swift
import Foundation
import Security

enum ClientCertStoreError: Error {
    case accessControlCreationFailed
    case keyGenerationFailed(String)
}

/// Generates (or, on a later run with the same tag, would collide with --
/// callers should check SecItemCopyMatching first in real use) a
/// non-extractable P-256 private key in the Secure Enclave, gated behind
/// biometric confirmation on every signing use, never synced to iCloud.
/// Per the design spec: kSecAttrAccessibleWhenUnlockedThisDeviceOnly +
/// .biometryCurrentSet is the "non-extractable even under a future
/// memory-disclosure bug" guarantee -- the private key material never
/// leaves the Secure Enclave, only signing operations cross that boundary.
func makeSecureEnclaveKey(tag: String) throws -> SecKey {
    guard let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .biometryCurrentSet],
        nil
    ) else {
        throw ClientCertStoreError.accessControlCreationFailed
    }

    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecAttrAccessControl as String: access,
        ],
    ]

    var error: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        let message = error.map { (($0.takeRetainedValue()) as Error).localizedDescription } ?? "unknown error"
        throw ClientCertStoreError.keyGenerationFailed(message)
    }
    return privateKey
}
```

- [ ] **Step 4: Run the test again to verify it passes**

Run: `xcodebuild -project OSINetStrikerViewer.xcodeproj -scheme OSINetStrikerViewer -destination 'platform=macOS' test CODE_SIGNING_ALLOWED=NO`
Expected: `** TEST SUCCEEDED **`. (This exact key-generation code was compiled and its test run against Xcode 26.6 / a real Secure Enclave-capable Mac while writing this plan.)

Note: this test creates a real Secure Enclave key each run (cleaned up via `deleteKey` in `defer`) and may prompt for biometric/password confirmation depending on the Mac's settings — expected and unavoidable given what it's testing.

- [ ] **Step 5: Add the `swift-asn1` dependency for CSR construction**

**Why not `swift-certificates`, despite Global Constraints flagging it as the intended choice:** while writing this task, it became clear `swift-certificates`' `Certificate.PrivateKey` wraps swift-crypto's concrete key types (`P256.Signing.PrivateKey` etc.), which hold raw extractable key material — there's no documented way to back it with an opaque, non-extractable Secure Enclave `SecKey`. That's a hard mismatch, not a version-drift risk: `swift-certificates` can't produce a CSR signed by a key it never holds. `swift-asn1` (a `swift-certificates` dependency, usable standalone) is a lower-level DER TLV encoder — it builds the CSR's *ASN.1 structure*, while the actual signature comes from `SecKeyCreateSignature` against the Secure Enclave key directly (Apple's own audited crypto — nothing here reimplements ECDSA). This is a narrower, safer scope than it first looks: the code below only assembles well-known, decades-stable structure (PKCS#10 per RFC 2986) and OIDs, it doesn't implement any cryptographic algorithm itself.

Add to `macos-app/project.yml`, under the `OSINetStrikerViewer` target:

```yaml
    dependencies:
      - package: swift-asn1
packages:
  swift-asn1:
    url: https://github.com/apple/swift-asn1.git
    from: 1.0.0
```

Run: `cd macos-app && xcodegen generate && xcodebuild -resolvePackageDependencies -project OSINetStrikerViewer.xcodeproj`
Expected: resolves successfully. `swift-asn1`'s exact `DER.Serializer`/`ASN1Node` API surface below was written from documented usage patterns, not compiled against a live package resolution (this plan's authoring environment verified everything else in this task by actually building it, but did not have network access to resolve this specific package) — the `xcodebuild build` step in Step 8 and, more importantly, Step 6's own `openssl req -text` structural check are what catch any drift here specifically.

- [ ] **Step 6: Write the CSR-construction + CA-signing + Keychain-import flow**

```swift
import Foundation
import Security
import SwiftASN1

/// Ties together a Secure Enclave key (Step 3) and a CA-signed certificate
/// for it into a SecIdentity usable for mTLS client authentication.
struct ClientCertStore {
    let keyTag: String
    let commonName: String

    /// Returns the existing identity if one was already provisioned, or
    /// generates a new SE key + CSR, has it signed by the local CA at
    /// caCertPath/caKeyPath, imports the result, and returns that.
    func loadOrCreateIdentity(caCertPath: String, caKeyPath: String) throws -> SecIdentity {
        if let existing = try? findExistingIdentity() {
            return existing
        }

        let privateKey = try makeSecureEnclaveKey(tag: keyTag)
        let csrPEM = try buildCSR(privateKey: privateKey, commonName: commonName)
        let certPEM = try signCSR(csrPEM: csrPEM, caCertPath: caCertPath, caKeyPath: caKeyPath)
        try importCertificate(pem: certPEM)

        guard let identity = try findExistingIdentity() else {
            throw ClientCertStoreError.keyGenerationFailed("identity not found in Keychain after import")
        }
        return identity
    }

    private func findExistingIdentity() throws -> SecIdentity? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecAttrApplicationTag as String: Data(keyTag.utf8),
            kSecReturnRef as String: true,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let identity = result else { return nil }
        return (identity as! SecIdentity)
    }

    /// Builds a PKCS#10 CertificationRequest (RFC 2986) by hand: this is
    /// structural DER encoding of a decades-stable, narrow format, not a
    /// cryptographic implementation -- the one actual crypto operation
    /// (the final signature) is delegated to SecKeyCreateSignature, which
    /// runs inside the Secure Enclave and never sees this function's code.
    /// See Step 5's note on why swift-certificates itself couldn't be used
    /// here, and Step 6's own verification step for how this gets checked.
    private func buildCSR(privateKey: SecKey, commonName: String) throws -> String {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw ClientCertStoreError.keyGenerationFailed("no public key for the Secure Enclave private key")
        }
        var repError: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &repError) as Data? else {
            throw ClientCertStoreError.keyGenerationFailed("could not export public key: \(String(describing: repError))")
        }
        // SecKeyCopyExternalRepresentation for a P-256 EC key returns the
        // raw uncompressed point: 0x04 || X (32 bytes) || Y (32 bytes) --
        // exactly what SubjectPublicKeyInfo's BIT STRING needs.

        // Well-known, stable OIDs -- unchanged since their 1990s/2000s
        // publication (RFC 3279 / SEC 1), not something a library version
        // bump could alter.
        let idEcPublicKey = ASN1ObjectIdentifier(arrayLiteral: 1, 2, 840, 10045, 2, 1)
        let prime256v1 = ASN1ObjectIdentifier(arrayLiteral: 1, 2, 840, 10045, 3, 1, 7)
        let ecdsaWithSHA256 = ASN1ObjectIdentifier(arrayLiteral: 1, 2, 840, 10045, 4, 3, 2)
        let idAtCommonName = ASN1ObjectIdentifier(arrayLiteral: 2, 5, 4, 3)

        func serializeSubjectPKInfo(into coder: inout DER.Serializer) throws {
            try coder.appendConstructedNode(identifier: .sequence) { coder in
                try coder.appendConstructedNode(identifier: .sequence) { coder in
                    try coder.serialize(idEcPublicKey)
                    try coder.serialize(prime256v1)
                }
                try coder.serialize(ASN1BitString(bytes: ArraySlice(publicKeyData)))
            }
        }

        func serializeSubject(into coder: inout DER.Serializer) throws {
            try coder.appendConstructedNode(identifier: .sequence) { coder in // RDNSequence
                try coder.appendConstructedNode(identifier: .set) { coder in // one RDN
                    try coder.appendConstructedNode(identifier: .sequence) { coder in // AttributeTypeAndValue
                        try coder.serialize(idAtCommonName)
                        try coder.serialize(ASN1UTF8String(commonName))
                    }
                }
            }
        }

        // CertificationRequestInfo, DER-encoded once so its exact bytes can
        // both be embedded below and signed.
        var infoSerializer = DER.Serializer()
        try infoSerializer.appendConstructedNode(identifier: .sequence) { coder in
            try coder.serialize(0) // version v1(0)
            try serializeSubject(into: &coder)
            try serializeSubjectPKInfo(into: &coder)
            // attributes [0] IMPLICIT SET OF Attribute, empty -- no
            // extensionRequest needed for a client-auth-only cert.
            try coder.appendConstructedNode(identifier: ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)) { _ in }
        }
        let certificationRequestInfoDER = infoSerializer.serializedBytes

        var signError: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            Data(certificationRequestInfoDER) as CFData,
            &signError
        ) as Data? else {
            throw ClientCertStoreError.keyGenerationFailed("signing failed: \(String(describing: signError))")
        }

        var outerSerializer = DER.Serializer()
        try outerSerializer.appendConstructedNode(identifier: .sequence) { coder in
            coder.serializeRawBytes(certificationRequestInfoDER)
            try coder.appendConstructedNode(identifier: .sequence) { coder in
                try coder.serialize(ecdsaWithSHA256)
            }
            try coder.serialize(ASN1BitString(bytes: ArraySlice(signature)))
        }

        let der = Data(outerSerializer.serializedBytes)
        let base64 = der.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN CERTIFICATE REQUEST-----\n\(base64)\n-----END CERTIFICATE REQUEST-----\n"
    }

    /// Shells out to openssl to sign the CSR against the mkcert-issued
    /// local CA (deploy/setup-ca.sh's rootCA.pem/rootCA-key.pem) -- mkcert
    /// itself only issues leaf certs from its own held CA key, it doesn't
    /// expose a "sign this external CSR" command, so openssl is used
    /// directly here for just this one step.
    private func signCSR(csrPEM: String, caCertPath: String, caKeyPath: String) throws -> String {
        let tempDir = FileManager.default.temporaryDirectory
        let csrURL = tempDir.appendingPathComponent("\(UUID().uuidString).csr")
        let certURL = tempDir.appendingPathComponent("\(UUID().uuidString).pem")
        let extURL = tempDir.appendingPathComponent("\(UUID().uuidString).ext")
        defer {
            try? FileManager.default.removeItem(at: csrURL)
            try? FileManager.default.removeItem(at: certURL)
            try? FileManager.default.removeItem(at: extURL)
        }
        try csrPEM.write(to: csrURL, atomically: true, encoding: .utf8)
        // Without an explicit clientAuth Extended Key Usage, some mTLS
        // stacks (not necessarily Caddy's require_and_verify today, but
        // this shouldn't rely on that) may accept a cert that isn't
        // actually scoped to client authentication -- cheap to be
        // explicit here rather than relying on the absence of an EKU
        // extension being interpreted permissively everywhere.
        try "extendedKeyUsage = clientAuth\n".write(to: extURL, atomically: true, encoding: .utf8)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = [
            "x509", "-req",
            "-in", csrURL.path,
            "-CA", caCertPath,
            "-CAkey", caKeyPath,
            "-CAcreateserial",
            "-days", "90",
            "-extfile", extURL.path,
            "-out", certURL.path,
        ]
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw ClientCertStoreError.keyGenerationFailed("openssl CSR signing failed with status \(process.terminationStatus)")
        }
        return try String(contentsOf: certURL, encoding: .utf8)
    }

    private func importCertificate(pem: String) throws {
        // Strip PEM headers and base64-decode to DER, then SecItemAdd as a
        // kSecClassCertificate tied to the same keychain the SE key lives
        // in -- the shared kSecAttrApplicationTag/public key is what lets
        // the Keychain associate the cert with the existing private key
        // and expose the pair as a SecIdentity.
        let lines = pem.split(separator: "\n").filter { !$0.hasPrefix("-----") }
        guard let der = Data(base64Encoded: lines.joined()) else {
            throw ClientCertStoreError.keyGenerationFailed("could not decode signed certificate PEM")
        }
        guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else {
            throw ClientCertStoreError.keyGenerationFailed("could not parse signed certificate DER")
        }
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecValueRef as String: certificate,
        ]
        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecSuccess || status == errSecDuplicateItem else {
            throw ClientCertStoreError.keyGenerationFailed("SecItemAdd failed with status \(status)")
        }
    }
}
```

- [ ] **Step 7: Verify the CSR structurally, before trusting it in the full identity flow**

This is the real check for Step 6's hand-written DER encoding — don't just trust it compiled. Add a temporary debug print of the PEM in `loadOrCreateIdentity` (or call `buildCSR` directly from a throwaway test), write it to a file, and parse it with `openssl`:

Run:
```bash
openssl req -in /tmp/test.csr -noout -text
```
Expected: `openssl` parses it without error and prints a `Certificate Request` block showing `Public Key Algorithm: id-ecPublicKey`, `Public-Key: (256 bit)`, `NIST CURVE: P-256`, `Subject: CN = <commonName>`, and `Signature Algorithm: ecdsa-with-SHA256`, with the final line confirming `Signature Value` bytes are present. If `openssl` instead reports a parse error (`unable to load X509 request`, ASN.1 errors, etc.), the DER structure in Step 6 has a bug — check node ordering (SEQUENCE/SET/context-tag nesting must exactly match the RFC 2986 grammar in Step 6's comments) and re-run this check before moving on. Remove the temporary debug code once this passes.

Also sign that CSR with `signCSR` (or run the equivalent `openssl x509 -req ... -extfile` command from Step 6 by hand against `deploy/certs/ca-root.pem`/mkcert's `rootCA-key.pem`) and check the **resulting certificate**, not just the CSR:
```bash
openssl x509 -in /tmp/test-signed.pem -noout -text | grep -A1 "Extended Key Usage"
```
Expected: `TLS Web Client Authentication` is present. This confirms the `-extfile` flag in Step 6's `signCSR` actually took effect — an easy thing to get silently wrong (a typo'd `-extfile` path fails open on some OpenSSL/LibreSSL builds rather than erroring).

- [ ] **Step 8: Wire client-cert presentation into `NavigationLockDelegate`'s `WKWebView` challenge handling**

`WKWebView` uses `WKNavigationDelegate`'s own `didReceive challenge:` for the client-cert prompt during page loads (there is no separate `URLSession` in this app to configure — the webview handles its own networking) — add that method, and a settable identity, to `NavigationLockDelegate` from Task 7:

```swift
// Add to NavigationLockDelegate.swift (Task 7's file):

// Set by ContentView.makeCoordinator after ClientCertStore
// provisions/loads the mTLS client identity. Nil means default
// handling below (no client cert presented) -- Caddy's
// require_and_verify then rejects the connection, surfaced as a
// visible TLS failure rather than silently missing data.
var clientIdentity: SecIdentity?

func webView(
    _ webView: WKWebView,
    didReceive challenge: URLAuthenticationChallenge,
    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
) {
    guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodClientCertificate,
          let identity = clientIdentity else {
        completionHandler(.performDefaultHandling, nil)
        return
    }
    completionHandler(.useCredential, URLCredential(identity: identity, certificates: nil, persistence: .forSession))
}
```

Then provision that identity from `ContentView.makeCoordinator` (Task 7's file), pointing at mkcert's own default `CAROOT` location so nothing here needs to duplicate what `deploy/setup-ca.sh` (Task 1) already established:

```swift
// Modify ContentView.swift's makeCoordinator (Task 7's file):

func makeCoordinator() -> NavigationLockDelegate {
    let delegate = NavigationLockDelegate(trustedOrigin: trustedURL.host ?? "")
    do {
        let store = ClientCertStore(
            keyTag: "com.osinetstriker.viewer.client-key",
            commonName: ProcessInfo.processInfo.hostName
        )
        delegate.clientIdentity = try store.loadOrCreateIdentity(
            caCertPath: Self.caCertPath,
            caKeyPath: Self.caKeyPath
        )
    } catch {
        // Not fatal -- the app still launches; the WKWebView's own
        // TLS-failure UI communicates the problem instead of crashing,
        // and this print gives a debugging trail for why.
        print("ClientCertStore.loadOrCreateIdentity failed: \(error)")
    }
    return delegate
}

// mkcert's default CAROOT on macOS -- matches `$(mkcert -CAROOT)` from
// deploy/setup-ca.sh (Task 1). Override via these env vars (Xcode
// scheme > Run > Arguments) if `mkcert -CAROOT` reports something
// different on your machine (e.g. a global CAROOT env var override).
private static var caCertPath: String {
    ProcessInfo.processInfo.environment["OSINETSTRIKER_CA_CERT"]
        ?? "\(NSHomeDirectory())/Library/Application Support/mkcert/rootCA.pem"
}
private static var caKeyPath: String {
    ProcessInfo.processInfo.environment["OSINETSTRIKER_CA_KEY"]
        ?? "\(NSHomeDirectory())/Library/Application Support/mkcert/rootCA-key.pem"
}
```

**Known open edge, flagged rather than silently assumed away:** Task 6 enables App Sandbox with only the `network.client` entitlement — a fully sandboxed build cannot read arbitrary paths under `~/Library/Application Support/mkcert/` without either an additional entitlement (e.g. a security-scoped bookmark from a one-time user file-picker grant) or relaxing the sandbox for this specific need. This matters only for the CA **key** path (needed once, to sign the CSR on first launch); after that, `findExistingIdentity()` only touches the Keychain, which sandboxing handles separately via keychain-access-group entitlements, not file-system entitlements. Resolve this when implementing — e.g. by adding a narrowly-scoped file-read entitlement for that one path, or by moving the one-time CSR-signing step into `deploy/setup-ca.sh` itself (outside the sandbox) and having the app only ever call the Keychain-lookup half of `loadOrCreateIdentity` — rather than by disabling App Sandbox.

- [ ] **Step 9: Verify the full app builds and all tests pass**

Run: `xcodebuild -project OSINetStrikerViewer.xcodeproj -scheme OSINetStrikerViewer -configuration Debug build CODE_SIGNING_ALLOWED=NO && xcodebuild -project OSINetStrikerViewer.xcodeproj -scheme OSINetStrikerViewer -destination 'platform=macOS' test CODE_SIGNING_ALLOWED=NO`
Expected: `** BUILD SUCCEEDED **` and `** TEST SUCCEEDED **`.

- [ ] **Step 10: End-to-end manual verification against Task 3's live Caddy setup**

Run:
```bash
npm run dev &
caddy run --config deploy/Caddyfile &
open macos-app/OSINetStrikerViewer.xcodeproj   # Xcode: Product > Run
```
Expected: the app prompts for biometric confirmation on first launch (Secure Enclave key use), then loads the dashboard — proving the full chain (SE key → CSR → CA-signed cert → Keychain identity → presented on the mTLS challenge → Caddy's `require_and_verify` accepts it) actually works, not just that each piece compiles in isolation.

- [ ] **Step 11: Commit**

```bash
cd /Users/jamesbrown/code/osi-traffic-terminal-monitor
git add macos-app/project.yml macos-app/OSINetStrikerViewer/ClientCertStore.swift \
  macos-app/OSINetStrikerViewer/ContentView.swift \
  macos-app/OSINetStrikerViewer/NavigationLockDelegate.swift \
  macos-app/OSINetStrikerViewerTests/ClientCertStoreTests.swift
git commit -m "Add Keychain-backed Secure Enclave client certificate (#21)"
```
