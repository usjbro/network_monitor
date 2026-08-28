#!/usr/bin/env bash
set -euo pipefail

# Signs the native macOS app's client certificate request against the
# local CA, without the app ever touching the CA private key itself.
#
# The app runs under App Sandbox and can never read the CA private key
# directly (confirmed on real Secure Enclave hardware: it fails with
# errSecMissingEntitlement / OSStatus -34018 unless the app is given a
# broad, security-relevant file-read entitlement this design deliberately
# avoids). Instead, the app writes its CSR to its own sandbox container --
# always writable, no extra entitlement needed -- and this script, run
# unsandboxed from Terminal, reads that same path directly (an unsandboxed
# process sees a sandboxed app's container as ordinary files on disk, no
# special access required) and writes the signed certificate back to the
# same directory. The app polls for it and picks it up automatically
# within a few seconds, no relaunch needed.

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="$DEPLOY_DIR/certs"

# Must match ClientCertStore.containerSupportDirectory in the app and
# macos-app/project.yml's PRODUCT_BUNDLE_IDENTIFIER.
APP_SUPPORT_DIR="$HOME/Library/Containers/com.osinetstriker.viewer/Data/Library/Application Support/OSINetStrikerViewer"
CSR_PATH="$APP_SUPPORT_DIR/client.csr"
OUT_PATH="$APP_SUPPORT_DIR/client-signed.pem"

if [ ! -f "$CSR_PATH" ]; then
  echo "No CSR found at:" >&2
  echo "  $CSR_PATH" >&2
  echo "Launch the native app first (macos-app/) so it can generate one, then re-run this script." >&2
  exit 1
fi

if [ ! -f "$CERTS_DIR/ca-root.pem" ]; then
  echo "No local CA found at $CERTS_DIR/ca-root.pem -- run ./deploy/setup-ca.sh first." >&2
  exit 1
fi

if ! command -v mkcert >/dev/null 2>&1; then
  echo "mkcert not found. Install it first: brew install mkcert" >&2
  exit 1
fi

CAROOT="$(mkcert -CAROOT)"
CA_KEY_PATH="$CAROOT/rootCA-key.pem"
if [ ! -f "$CA_KEY_PATH" ]; then
  echo "mkcert CA key not found at $CA_KEY_PATH -- run ./deploy/setup-ca.sh first." >&2
  exit 1
fi

EXT_FILE="$(mktemp -t signclientext).cnf"
trap 'rm -f "$EXT_FILE"' EXIT
# Same clientAuth-only Extended Key Usage as deploy/setup-ca.sh's
# mkcert-issued client certs -- keeps this cert scoped to client
# authentication, matching what deploy/test-mtls-rejection.sh's checks
# assume of every client cert in this setup.
echo "extendedKeyUsage = clientAuth" > "$EXT_FILE"

echo "Signing $CSR_PATH against the local CA..."
openssl x509 -req \
  -in "$CSR_PATH" \
  -CA "$CERTS_DIR/ca-root.pem" \
  -CAkey "$CA_KEY_PATH" \
  -CAcreateserial \
  -days 90 \
  -extfile "$EXT_FILE" \
  -out "$OUT_PATH"

echo
echo "Signed certificate written to:"
echo "  $OUT_PATH"
echo
echo "The app polls for this every 3s while it's running and will import it"
echo "automatically -- no relaunch needed. If it's not currently running,"
echo "just launch it."
