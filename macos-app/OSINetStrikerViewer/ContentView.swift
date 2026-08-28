import SwiftUI
import WebKit
import os

private let logger = Logger(subsystem: "com.osinetstriker.viewer", category: "ContentView")

struct TrustedWebView: NSViewRepresentable {
    let trustedURL: URL

    func makeCoordinator() -> NavigationLockDelegate {
        let delegate = NavigationLockDelegate(trustedURL: trustedURL)
        let keyTag = "com.osinetstriker.viewer.client-key"
        let hostName = ProcessInfo.processInfo.hostName
        let store = ClientCertStore(keyTag: keyTag, commonName: hostName)
        Self.provisionIdentity(using: store, into: delegate)
        return delegate
    }

    /// ClientCertStore.loadOrCreateIdentity can block on a
    /// .biometryCurrentSet-gated SecKeyCreateSignature (a Touch ID/password
    /// prompt), so this always runs on a background queue -- unsafe on the
    /// main thread makeCoordinator executes on during SwiftUI view
    /// construction (risks a UI deadlock). The challenge handler tolerates
    /// a nil clientIdentity by falling through to .performDefaultHandling,
    /// so nothing needs to block waiting for this to finish.
    ///
    /// On first launch this normally throws .awaitingExternalSigning: the
    /// SE key + CSR are ready, but the CA-signing step happens outside App
    /// Sandbox entirely (see ClientCertStore's doc comment) via
    /// `deploy/sign-native-app-csr.sh`, run manually from Terminal. Rather
    /// than surface that as a dead end, this polls every 3s for the signed
    /// certificate to appear -- once you run that script, the app picks it
    /// up on its own within a few seconds, no relaunch needed.
    ///
    /// Explicitly `nonisolated`: `TrustedWebView: NSViewRepresentable`
    /// otherwise infers this whole type's members as @MainActor (the
    /// protocol's own requirements are MainActor-isolated), but this
    /// function is deliberately designed to run entirely off the main
    /// thread via plain GCD dispatch queues -- it only ever touches
    /// `delegate` back on the main queue explicitly, inside the
    /// `DispatchQueue.main.async` block below, never via Swift
    /// concurrency's actor hopping. Without `nonisolated` here, calling
    /// this recursively from the `DispatchQueue.global().asyncAfter`
    /// retry below is flagged: "call to main actor-isolated static method
    /// ... in a synchronous nonisolated context" -- exactly the same
    /// *class* of actor-isolation mismatch that made NavigationLockDelegate's
    /// WKNavigationDelegate methods silently never get called elsewhere in
    /// this app (see that file's own @MainActor closure-parameter fix) --
    /// so this was verified with a clean build showing the warning is
    /// actually gone, not just silenced.
    private nonisolated static func provisionIdentity(using store: ClientCertStore, into delegate: NavigationLockDelegate) {
        DispatchQueue.global(qos: .userInitiated).async {
            logger.notice("provisionIdentity: calling loadOrCreateIdentity")
            do {
                let identity = try store.loadOrCreateIdentity()
                logger.notice("provisionIdentity: loadOrCreateIdentity succeeded")
                DispatchQueue.main.async {
                    delegate.clientIdentity = identity
                    // The very first page load (triggered synchronously in
                    // makeNSView, below) can race ahead of provisioning and
                    // fail its TLS handshake with no client cert to present
                    // -- nothing else would ever retry it, since trustedURL
                    // is a constant (no state change to re-trigger
                    // updateNSView) and the delegate previously held no
                    // reference back to the webview. Re-issuing the load
                    // here, now that a real identity exists, picks up
                    // exactly that case.
                    //
                    // load(), NOT reload(): in precisely the case this is
                    // meant to fix, the first handshake failed, so no
                    // navigation was ever committed and there is nothing
                    // for reload() to re-fetch -- it would be a no-op.
                    // load() has no such precondition and is equivalent
                    // otherwise. The target comes off the delegate (already
                    // captured here) rather than a second captured copy,
                    // and is by construction the same URL the navigation
                    // lock permits.
                    delegate.webView?.load(URLRequest(url: delegate.trustedURL))
                }
            } catch ClientCertStoreError.awaitingExternalSigning(let csrPath) {
                logger.notice("provisionIdentity: awaiting external signing, CSR at \(csrPath, privacy: .public); retrying in 3s")
                DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 3) {
                    provisionIdentity(using: store, into: delegate)
                }
            } catch {
                // Not fatal -- the app still launches; the WKWebView's own
                // TLS-failure UI communicates the problem instead of
                // crashing, and this log gives a debugging trail for why.
                let message = String(describing: error)
                logger.error("provisionIdentity: loadOrCreateIdentity failed: \(message, privacy: .public)")
            }
        }
    }

    func makeNSView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = context.coordinator
        webView.uiDelegate = context.coordinator
        // Gives the delegate a way to reload this webview once identity
        // provisioning (still running in the background at this point --
        // see makeCoordinator) finishes, in case this first load races
        // ahead of it.
        context.coordinator.webView = webView
        webView.load(URLRequest(url: trustedURL))
        return webView
    }

    func updateNSView(_ nsView: WKWebView, context: Context) {}
}

struct ContentView: View {
    // The one origin this app is allowed to render. Defaults to
    // "https://<hostname>.local" (implicit port 443), which matches
    // deploy/setup-ca.sh's server cert SAN AND the LAN-facing ":443"
    // listen address from deploy/README.md step 5.
    //
    // IMPORTANT: ":443" is a deliberate MANUAL opt-in, not the default --
    // deploy/Caddyfile ships listening on "localhost:8443" (loopback only)
    // precisely so nothing is LAN-reachable until you choose it. If you're
    // following the documented setup and haven't made that switch yet, set
    // OSINETSTRIKER_URL to match whatever Caddy is actually listening on,
    // e.g.:
    //
    //     OSINETSTRIKER_URL=https://localhost:8443
    //
    // (Xcode scheme > Run > Arguments > Environment Variables, or just
    // export it before `open`ing the built .app from a shell.) Whatever
    // host you point at must be in the server cert's SAN list --
    // deploy/setup-ca.sh includes both "<hostname>.local" and "localhost",
    // so both of the above work out of the box.
    //
    // On the default: ProcessInfo.processInfo.hostName is backed by
    // gethostname(), which on stock macOS typically already returns the
    // Bonjour-qualified "<hostname>.local" form (the same string `scutil
    // --get LocalHostName` + ".local" produces, which is what
    // deploy/setup-ca.sh's SAN is built from) -- but that's not
    // guaranteed on every configuration, so this checks rather than
    // blindly appending ".local" a second time (verify against your
    // actual cert's SAN with `openssl x509 -in deploy/certs/server.pem
    // -noout -text | grep -A2 "Subject Alternative Name"` if the
    // navigation lock rejects its own trusted origin on first run).
    let trustedURL: URL = ContentView.resolveTrustedURL()

    static func resolveTrustedURL(
        override: String? = ProcessInfo.processInfo.environment["OSINETSTRIKER_URL"],
        hostName: String = ProcessInfo.processInfo.hostName
    ) -> URL {
        // An override that isn't a usable absolute URL falls through to the
        // default rather than trapping on a force-unwrap at launch. The
        // navigation lock re-validates the scheme regardless, so a
        // plaintext override can't downgrade anything.
        if let override, let url = URL(string: override), url.host != nil {
            return url
        }
        let qualifiedHost = hostName.hasSuffix(".local") ? hostName : "\(hostName).local"
        return URL(string: "https://\(qualifiedHost)")!
    }

    var body: some View {
        TrustedWebView(trustedURL: trustedURL)
            .frame(minWidth: 800, minHeight: 600)
    }
}
