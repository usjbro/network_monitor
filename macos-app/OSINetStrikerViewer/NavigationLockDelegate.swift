import Security
import WebKit

/// Enforces the single-origin lock described in the design spec: this
/// webview may only ever navigate to `trustedOrigin`, in the main frame,
/// any subframe, or a new-window request. A shell that can only ever
/// render one origin you author yourself has nothing else to visit.
final class NavigationLockDelegate: NSObject, WKNavigationDelegate, WKUIDelegate {
    let trustedOrigin: String

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
    // ContentView's provisioning completion handler calls webView.reload()
    // through this reference once a real identity becomes available.
    weak var webView: WKWebView?

    init(trustedOrigin: String) {
        self.trustedOrigin = trustedOrigin
    }

    /// Exact host match only -- NOT a substring/prefix check, which would
    /// wrongly allow e.g. "trustedOrigin.evil.com".
    func isAllowed(url: URL) -> Bool {
        return url.host == trustedOrigin
    }

    func webView(
        _ webView: WKWebView,
        decidePolicyFor navigationAction: WKNavigationAction,
        decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
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

    func webView(
        _ webView: WKWebView,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodClientCertificate,
              let identity = clientIdentity else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(identity: identity, certificates: nil, persistence: .forSession))
    }
}
