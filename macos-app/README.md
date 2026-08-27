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
