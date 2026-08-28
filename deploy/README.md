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

   Three checks must all pass: a connection with **no** client cert is
   rejected, a connection with a **valid** one is accepted (HTTP 200),
   and a connection with an **untrusted** self-signed one is rejected.
   That third check is the one that distinguishes `mode
   require_and_verify` from a `mode require` misconfiguration, which
   would demand a certificate but accept any self-signed cert an
   attacker minted for themselves.

   Both processes can be stopped afterward (`kill %1 %2`, or `Ctrl+C`
   each).

5. **Only after step 4 passes**, and only when you actually want LAN
   access: edit `deploy/Caddyfile` and make **both** of these changes
   (see the comments in that file):

   - change the site address from `localhost:8443` to `:443`
   - change `bind {$CADDY_BIND_ADDR:127.0.0.1}` to bind all interfaces
     (`bind 0.0.0.0`), or just delete the `bind` line

   Both are needed and they do different jobs: the site address is the
   name Caddy *matches* requests against, while `bind` is what chooses
   the network *interface*. Until you change `bind`, Caddy listens on
   loopback only (verify with `lsof -nP -iTCP:8443 -sTCP:LISTEN` --
   `127.0.0.1:8443` means loopback-only, `*:8443` means every
   interface). This is a deliberate manual step, not automated by this
   repo. Binding `:443` also needs elevated privileges, since it's a
   privileged port.

## Running (each session, once set up)

    ./capture-agent/target/release/capture-agent &   # or: cd capture-agent && cargo run --release
    npm run start &                                    # or npm run dev
    caddy run --config deploy/Caddyfile &

From a device with an installed, trusted client certificate, browse to:

- **after step 5** (`:443`): `https://<mac-hostname>.local`
- **before step 5** (the loopback-only default): `https://localhost:8443`,
  from this Mac only

Connect **by hostname, never by bare IP address**. Caddy turns on strict
SNI-Host enforcement automatically whenever `client_auth` is configured,
and most TLS clients (confirmed: curl on macOS) send no SNI at all when
you point them at a literal IP -- so the handshake is rejected outright
(observed: `tlsv1 alert internal error`) before your client certificate
is ever looked at. `deploy/setup-ca.sh` does put this Mac's LAN IP in the
server certificate's SAN list, but that only makes the *certificate*
valid for the IP; it does not make an IP-literal connection work.

## Reissuing certificates

mkcert-issued leaf certs are valid for a long time by mkcert's defaults;
this project's stated preference is short-lived, periodically-reissued
certs over OCSP revocation checking. Re-run `./deploy/setup-ca.sh <name>`
to reissue a given device's client cert, then reinstall it on that
device.
