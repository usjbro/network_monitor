import Security
import WebKit

/// Enforces the single-origin lock described in the design spec: this
/// webview may only ever navigate to `trustedURL`'s origin -- scheme,
/// host AND port -- in the main frame, any subframe, or a new-window
/// request. A shell that can only ever render one origin you author
/// yourself has nothing else to visit.
final class NavigationLockDelegate: NSObject, WKNavigationDelegate, WKUIDelegate {
    /// The one URL this webview is allowed to be at. Also what
    /// ContentView re-loads through once mTLS identity provisioning
    /// finishes (see `webView`, below).
    let trustedURL: URL

    private let trustedHost: String
    private let trustedPort: Int

    // Set by ContentView.makeCoordinator after ClientCertStore
    // provisions/loads the mTLS client identity. Nil means default
    // handling below (no client cert presented) -- Caddy's
    // require_and_verify then rejects the connection, surfaced as a
    // visible TLS failure rather than silently missing data.
    var clientIdentity: SecIdentity?

    // Set by TrustedWebView.makeNSView right after creating the webview.
    // Identity provisioning runs on a background queue and can take
    // seconds (Secure Enclave key gen + biometric prompt + an openssl
    // subprocess), so the very first page load can race ahead of it with
    // no client cert to present. Weak because the webview owns/outlives
    // this delegate via the NSViewRepresentable Coordinator machinery, not
    // the other way around -- holding it weakly avoids a retain cycle.
    // ContentView's provisioning completion handler re-issues the load of
    // trustedURL through this reference once a real identity becomes
    // available.
    weak var webView: WKWebView?

    /// The implicit port for the only scheme this lock ever allows.
    private static let httpsDefaultPort = 443

    init(trustedURL: URL) {
        self.trustedURL = trustedURL
        // A trusted URL that isn't itself https would mean the app was
        // configured away from mTLS entirely. Rather than silently
        // permitting that, store an unmatchable empty host so isAllowed
        // rejects everything and the failure is visible immediately.
        self.trustedHost = trustedURL.scheme == "https" ? (trustedURL.host ?? "") : ""
        self.trustedPort = trustedURL.port ?? Self.httpsDefaultPort
    }

    /// Full-origin match: scheme AND host AND port must all agree.
    ///
    /// - Host is compared for exact equality -- NOT a substring/prefix
    ///   check, which would wrongly allow e.g. "trustedhost.evil.com".
    /// - Scheme must be https: a host-only check would happily follow
    ///   `http://<trusted-host>/`, silently downgrading off TLS and
    ///   therefore off mTLS, since a plaintext connection presents no
    ///   client certificate at all.
    /// - Port must match: a host-only check would also allow
    ///   `https://<trusted-host>:3000/`, i.e. anything else this machine
    ///   happens to be serving, bypassing the Caddy mTLS front door.
    ///   Absent ports are normalized to 443 on both sides so
    ///   `https://host` and `https://host:443` compare equal.
    func isAllowed(url: URL) -> Bool {
        guard !trustedHost.isEmpty,
              url.scheme == "https",
              url.host == trustedHost,
              (url.port ?? Self.httpsDefaultPort) == trustedPort
        else {
            return false
        }
        return true
    }

    // The `@MainActor` on decisionHandler is load-bearing, not decoration:
    // WKNavigationDelegate declares these completion handlers
    // WK_SWIFT_UI_ACTOR (main-actor-isolated). Without it Swift treats this
    // as a merely "nearly matching" method, does NOT bind it as the
    // protocol conformance, and WebKit never calls it -- making the entire
    // navigation lock dead code, with only a compiler warning to say so.
    // NavigationLockDelegateTests guards this with a responds(to:) check.
    func webView(
        _ webView: WKWebView,
        decidePolicyFor navigationAction: WKNavigationAction,
        decisionHandler: @escaping @MainActor (WKNavigationActionPolicy) -> Void
    ) {
        guard let url = navigationAction.request.url, isAllowed(url: url) else {
            decisionHandler(.cancel)
            return
        }
        decisionHandler(.allow)
    }

    /// Pulled out of createWebViewWith so it's directly unit-testable
    /// (WKWebViewConfiguration/WKNavigationAction have no public
    /// initializers, so the delegate method itself can't be called from a
    /// test -- this wrapper carries the actual decision).
    func decideNewWindow() -> WKWebView? {
        return nil
    }

    func webView(
        _ webView: WKWebView,
        createWebViewWith configuration: WKWebViewConfiguration,
        for navigationAction: WKNavigationAction,
        windowFeatures: WKWindowFeatures
    ) -> WKWebView? {
        return decideNewWindow()
    }

    // Same @MainActor requirement as decidePolicyFor above -- and the same
    // consequence if it's omitted, except here the dead code is the mTLS
    // client-certificate presentation, so every connection would silently
    // fall back to .performDefaultHandling and be rejected by Caddy.
    func webView(
        _ webView: WKWebView,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping @MainActor (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodClientCertificate,
              let identity = clientIdentity else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(identity: identity, certificates: nil, persistence: .forSession))
    }
}
