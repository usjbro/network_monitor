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
fails with `OSStatus -25308` in an unsigned and/or headless build --
Secure Enclave key generation gated on `.biometryCurrentSet` needs a real
signed app and an interactive session. The `NavigationLockDelegateTests`
suite passes in full and has no such requirement.

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

## Known limitation: App Sandbox vs. the CA private key

`ClientCertStore.signCSR` reads the mkcert CA private key from
`~/Library/Application Support/mkcert/rootCA-key.pem` at runtime and
shells out to `/usr/bin/openssl` to sign its CSR.
`OSINetStrikerViewer.entitlements` enables the App Sandbox with only
`com.apple.security.network.client` -- which grants neither read access
to that path nor unconstrained execution of external binaries. First-run
certificate provisioning is therefore expected to fail on a sandboxed
build.

This is known and **not yet resolved**. It has not been confirmed on real
hardware (Secure Enclave key generation doesn't succeed in this build
environment either -- see the known test failure above), so treat it as a
reasoned expectation rather than a measured result. Resolving it means
picking one of: sign the CSR out-of-band and import the finished
certificate, add an entitlement plus user-selected file access for the CA
key, or drop the sandbox. Until then, don't assume this app completes
end-to-end mTLS provisioning on its own. See `docs/security.md`
("Residual risks in the LAN-access design").
