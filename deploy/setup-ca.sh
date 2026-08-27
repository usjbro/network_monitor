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
