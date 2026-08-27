#!/usr/bin/env bash
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${CADDY_CERT_DIR:-$DEPLOY_DIR/certs}"
ADDR="${CADDY_LISTEN_ADDR:-localhost:8443}"

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
if ! STATUS="$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' \
  --cert "$CLIENT_CERT" --key "$CLIENT_KEY" \
  "https://$ADDR/")"; then
  fail "connection WITH a valid client cert failed at the transport/TLS layer"
fi
[ "$STATUS" = "200" ] || fail "connection WITH a valid client cert returned HTTP $STATUS, expected 200"
echo "  OK: accepted as expected (HTTP 200)"

echo
echo "mTLS verification passed: rejects missing certs, accepts a valid one."
