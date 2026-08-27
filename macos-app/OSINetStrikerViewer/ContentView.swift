import SwiftUI
import WebKit

struct TrustedWebView: NSViewRepresentable {
    let trustedURL: URL

    func makeCoordinator() -> NavigationLockDelegate {
        NavigationLockDelegate(trustedOrigin: trustedURL.host ?? "")
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
