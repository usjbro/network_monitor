#!/usr/bin/env bash
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${CADDY_CERT_DIR:-$DEPLOY_DIR/certs}"
ADDR="${CADDY_LISTEN_ADDR:-localhost:8443}"

# Check 3 mints a throwaway cert + key. A private directory (rather than
# two `mktemp` files) keeps them off a world-readable path and makes
# cleanup a single unconditional rm -rf, so nothing outlives this run --
# including on an early `set -e` exit or a Ctrl+C.
TMPDIR_IMPOSTOR="$(mktemp -d -t osinetstriker-mtls)"
trap 'rm -rf "$TMPDIR_IMPOSTOR"' EXIT INT TERM
IMPOSTOR_CERT="$TMPDIR_IMPOSTOR/untrusted-client.pem"
IMPOSTOR_KEY="$TMPDIR_IMPOSTOR/untrusted-client-key.pem"

fail() { echo "FAIL: $1" >&2; exit 1; }

echo "1/3: connecting with NO client certificate (must be rejected)..."
if curl -sk --max-time 5 "https://$ADDR/" -o /dev/null; then
  fail "connection without a client cert succeeded -- mTLS is NOT enforced"
fi
echo "  OK: rejected as expected"

CLIENT_CERT="$(ls "$CERTS_DIR"/client-*.pem 2>/dev/null | grep -v -- '-key.pem' | head -1 || true)"
[ -n "$CLIENT_CERT" ] || fail "no client cert found in $CERTS_DIR -- run deploy/setup-ca.sh first"
CLIENT_KEY="${CLIENT_CERT%.pem}-key.pem"

echo "2/3: connecting WITH a valid client certificate (must succeed)..."
if ! STATUS="$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' \
  --cert "$CLIENT_CERT" --key "$CLIENT_KEY" \
  "https://$ADDR/")"; then
  fail "connection WITH a valid client cert failed at the transport/TLS layer"
fi
[ "$STATUS" = "200" ] || fail "connection WITH a valid client cert returned HTTP $STATUS, expected 200"
echo "  OK: accepted as expected (HTTP 200)"

# Checks 1 and 2 together only prove "a cert is required" -- they pass
# just as happily against `client_auth { mode require }`, which demands a
# certificate but never verifies who signed it, and would therefore accept
# ANY self-signed cert an attacker on the LAN generated for themselves.
# This check is what distinguishes require from require_and_verify.
echo "3/3: connecting with an UNTRUSTED self-signed client certificate (must be rejected)..."
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$IMPOSTOR_KEY" -out "$IMPOSTOR_CERT" \
  -days 1 -subj "/CN=untrusted-imposter" 2>/dev/null \
  || fail "could not mint the throwaway untrusted client cert (openssl failed)"
if curl -sk --max-time 5 --cert "$IMPOSTOR_CERT" --key "$IMPOSTOR_KEY" \
  "https://$ADDR/" -o /dev/null; then
  fail "connection with a client cert NOT signed by the trusted CA succeeded -- Caddy is requiring a cert but not verifying its issuer (check that client_auth uses mode require_and_verify, with trusted_ca_cert_file set)"
fi
echo "  OK: rejected as expected"

echo
echo "mTLS verification passed: rejects missing and untrusted certs, accepts a valid one."
