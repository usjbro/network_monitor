import SwiftUI
import WebKit

struct TrustedWebView: NSViewRepresentable {
    let trustedURL: URL

    func makeCoordinator() -> NavigationLockDelegate {
        let delegate = NavigationLockDelegate(trustedOrigin: trustedURL.host ?? "")
        let keyTag = "com.osinetstriker.viewer.client-key"
        let hostName = ProcessInfo.processInfo.hostName
        let caCertPath = Self.caCertPath
        let caKeyPath = Self.caKeyPath
        // ClientCertStore.loadOrCreateIdentity can block on a
        // .biometryCurrentSet-gated SecKeyCreateSignature (a Touch
        // ID/password prompt) plus a synchronous Process.waitUntilExit() --
        // both unsafe to run on the main thread makeCoordinator executes on
        // during SwiftUI view construction (risks a UI deadlock). Run it on
        // a background queue and assign clientIdentity back on the main
        // queue once it completes; the challenge handler above already
        // tolerates a nil clientIdentity by falling through to
        // .performDefaultHandling, so nothing needs to block waiting for
        // this to finish.
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let store = ClientCertStore(keyTag: keyTag, commonName: hostName)
                let identity = try store.loadOrCreateIdentity(
                    caCertPath: caCertPath,
                    caKeyPath: caKeyPath
                )
                DispatchQueue.main.async {
                    delegate.clientIdentity = identity
                }
            } catch {
                // Not fatal -- the app still launches; the WKWebView's own
                // TLS-failure UI communicates the problem instead of
                // crashing, and this print gives a debugging trail for why.
                print("ClientCertStore.loadOrCreateIdentity failed: \(error)")
            }
        }
        return delegate
    }

    // mkcert's default CAROOT on macOS -- matches `$(mkcert -CAROOT)` from
    // deploy/setup-ca.sh (Task 1). Override via these env vars (Xcode
    // scheme > Run > Arguments) if `mkcert -CAROOT` reports something
    // different on your machine (e.g. a global CAROOT env var override).
    private static var caCertPath: String {
        ProcessInfo.processInfo.environment["OSINETSTRIKER_CA_CERT"]
            ?? "\(NSHomeDirectory())/Library/Application Support/mkcert/rootCA.pem"
    }
    private static var caKeyPath: String {
        ProcessInfo.processInfo.environment["OSINETSTRIKER_CA_KEY"]
            ?? "\(NSHomeDirectory())/Library/Application Support/mkcert/rootCA-key.pem"
    }

    func makeNSView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = context.coordinator
        webView.uiDelegate = context.coordinator
        webView.load(URLRequest(url: trustedURL))
        return webView
    }

    func updateNSView(_ nsView: WKWebView, context: Context) {}
}

struct ContentView: View {
    // Matches deploy/setup-ca.sh's server cert SAN (<hostname>.local) --
    // update if you changed CADDY_LISTEN_ADDR away from the ":443"
    // production default from deploy/README.md step 5.
    //
    // ProcessInfo.processInfo.hostName is backed by gethostname(), which
    // on stock macOS typically already returns the Bonjour-qualified
    // "<hostname>.local" form (the same string `scutil --get
    // LocalHostName` + ".local" produces, which is what
    // deploy/setup-ca.sh's SAN is built from) -- but that's not
    // guaranteed on every configuration, so this checks rather than
    // blindly appending ".local" a second time (verify against your
    // actual cert's SAN with `openssl x509 -in deploy/certs/server.pem
    // -noout -text | grep -A2 "Subject Alternative Name"` if the
    // navigation lock rejects its own trusted origin on first run).
    let trustedURL: URL = {
        let host = ProcessInfo.processInfo.hostName
        let qualifiedHost = host.hasSuffix(".local") ? host : "\(host).local"
        return URL(string: "https://\(qualifiedHost)")!
    }()

    var body: some View {
        TrustedWebView(trustedURL: trustedURL)
            .frame(minWidth: 800, minHeight: 600)
    }
}
