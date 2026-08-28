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
      -destination 'platform=macOS' test CODE_SIGNING_ALLOWED=NO

`CODE_SIGNING_ALLOWED=NO` is required: the test bundle target has no
`Info.plist`, so a signing-enabled build of it fails outright with
"Cannot code sign because the target does not have an Info.plist file".

Known failure: `ClientCertStoreTests.testGeneratesAP256SecureEnclaveKey`
fails with an `OSStatus` error (observed: `-25308`, `-34018` -- same root
cause, different manifestation) in an unsigned and/or headless build --
Secure Enclave key generation gated on `.biometryCurrentSet` needs a real
signed app, a real Team ID, and an interactive session (see "Provisioning
the client certificate" below for what a real run needs). The
`NavigationLockDelegateTests` suite passes in full and has no such
requirement.

When changing `NavigationLockDelegate`, always run a **`clean build`**,
not an incremental one, and check for `nearly matches optional
requirement` in the output. `WKNavigationDelegate`'s methods are all
optional, so a signature that doesn't exactly match the protocol's
(including the `@MainActor` isolation the SDK declares on its
completion-handler parameters) is only a warning -- the method silently
isn't bound and WebKit never calls it. Xcode's incremental cache hides
that warning on rebuilds.
`NavigationLockDelegateTests.testConformsToRequiredWKNavigationDelegateSelectors`
guards it via `responds(to:)`.

## Requires

`deploy/` set up first (Tasks 1-3 of this plan) -- this app points at the
same HTTPS+mTLS origin any browser with an installed client cert would
use.

By default the app connects to `https://<this-mac-hostname>.local`, i.e.
port 443 -- which only exists after the **manual** step 5 in
`deploy/README.md`. `deploy/Caddyfile`'s shipped default is
`localhost:8443` on loopback, so following the documented setup and then
launching this app without an override gives you a connection failure.
Point it at whatever Caddy is really serving with:

    OSINETSTRIKER_URL=https://localhost:8443

(Xcode scheme > Run > Arguments > Environment Variables, or export it
before launching the built `.app` from a shell.) The host you choose must
appear in the server certificate's SAN list; `deploy/setup-ca.sh` puts
both `<hostname>.local` and `localhost` there.

## Provisioning the client certificate

**Confirmed working end-to-end on real Secure Enclave hardware.** The app
generates its own P-256 Secure Enclave key and builds its own PKCS#10
CSR, but it never touches the CA private key -- App Sandbox blocks that
outright (confirmed: `SecKeyCreateRandomKey`/keychain operations that
need it fail with `errSecMissingEntitlement`, `OSStatus -34018`, unless
the app is given a security-relevant entitlement this design deliberately
avoids). Instead, the CA-signing step happens entirely outside the
sandbox:

1. Launch the app. On first run it generates the Secure Enclave key
   (a Touch ID/password prompt appears) and writes its CSR to its own
   sandbox container -- always writable, no extra entitlement needed.
   Console.app will show it waiting, e.g.:
   ```
   OSINetStrikerViewer: waiting for a signed client certificate.
   Run this once from Terminal, then this app will pick it up automatically:
       ./deploy/sign-native-app-csr.sh
   ```
2. From Terminal (**not** from inside the sandboxed app -- this script
   runs unsandboxed and is the only thing that ever reads the CA private
   key), run:
   ```
   ./deploy/sign-native-app-csr.sh
   ```
   This signs the CSR sitting in the app's container against the same
   local CA `deploy/setup-ca.sh` established, and writes the result back
   to that same container directory.
3. The app polls for the signed certificate every 3 seconds while it's
   running and imports it automatically once it appears -- no relaunch
   needed. The dashboard loads within a few seconds of running the
   script.

This requires two things beyond a default Xcode setup, both one-time:
a real Apple ID **Team** selected under Signing & Capabilities (not
"Automatic" with no team -- Secure-Enclave-backed *permanent* Keychain
items need a properly provisioned signing identity), and the
`keychain-access-groups` entitlement (already in
`OSINetStrikerViewer.entitlements`) actually taking effect, which may
prompt Xcode to offer to update your provisioning -- accept it.

See `docs/security.md` ("Residual risks in the LAN-access design") for
what this design does and doesn't protect against.
