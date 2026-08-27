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
