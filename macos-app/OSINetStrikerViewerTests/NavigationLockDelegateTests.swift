import WebKit
import XCTest
@testable import OSINetStrikerViewer

final class NavigationLockDelegateTests: XCTestCase {
    /// The delegate under test, locked to the default-shaped trusted URL
    /// (https, implicit port 443).
    private func makeDelegate(
        _ trusted: String = "https://mac-hostname.local"
    ) -> NavigationLockDelegate {
        return NavigationLockDelegate(trustedURL: URL(string: trusted)!)
    }

    func testConformsToRequiredWKNavigationDelegateSelectors() {
        // Both of these are OPTIONAL WKNavigationDelegate requirements, so a
        // signature that doesn't exactly match the protocol's (e.g. missing
        // the @MainActor isolation the SDK declares on the completion-handler
        // parameters) compiles fine, emits only a "nearly matches optional
        // requirement" WARNING, and is silently never called by WebKit --
        // turning both the navigation lock and the mTLS client-cert
        // presentation into dead code. A non-conforming method also isn't
        // exported to the Objective-C runtime, so responds(to:) is a real
        // check that the binding actually happened.
        //
        // Selectors are spelled as runtime strings rather than #selector on
        // purpose: an Objective-C selector name is the stable identity being
        // asserted here, and #selector(WKNavigationDelegate.webView(...)) is
        // both ambiguous (two decidePolicyFor overloads) and would have to
        // restate the very isolation this test exists to verify. A typo in
        // either string fails the test rather than passing it vacuously.
        let delegate = makeDelegate()
        XCTAssertTrue(
            delegate.responds(to: NSSelectorFromString("webView:decidePolicyForNavigationAction:decisionHandler:")),
            "navigation policy method is not bound as a WKNavigationDelegate conformance -- the single-origin lock is dead code"
        )
        XCTAssertTrue(
            delegate.responds(to: NSSelectorFromString("webView:didReceiveAuthenticationChallenge:completionHandler:")),
            "auth-challenge method is not bound as a WKNavigationDelegate conformance -- the mTLS client cert is never presented"
        )
    }

    func testRejectsUntrustedHost() {
        XCTAssertFalse(makeDelegate().isAllowed(url: URL(string: "https://evil.com/")!))
    }

    func testAllowsTrustedHost() {
        XCTAssertTrue(makeDelegate().isAllowed(url: URL(string: "https://mac-hostname.local/dashboard")!))
    }

    func testRejectsTrustedHostAsASubstring() {
        // A host that merely CONTAINS the trusted origin as a substring
        // (e.g. an attacker-controlled "mac-hostname.local.evil.com") must
        // still be rejected -- this guards against a naive .contains()
        // implementation instead of an exact host match.
        XCTAssertFalse(makeDelegate().isAllowed(url: URL(string: "https://mac-hostname.local.evil.com/")!))
    }

    func testRejectsPlaintextHTTPOnTheTrustedHost() {
        // Right host, wrong scheme. A plaintext connection presents no
        // client certificate at all, so allowing this would silently
        // bypass mTLS on the very origin the lock exists to protect.
        XCTAssertFalse(makeDelegate().isAllowed(url: URL(string: "http://mac-hostname.local/")!))
    }

    func testRejectsANonHTTPSchemeOnTheTrustedHost() {
        XCTAssertFalse(makeDelegate().isAllowed(url: URL(string: "ftp://mac-hostname.local/")!))
    }

    func testRejectsADifferentPortOnTheTrustedHost() {
        // Right host and scheme, wrong port -- e.g. the unauthenticated
        // Next.js server this Mac is also running, reachable around Caddy.
        XCTAssertFalse(makeDelegate().isAllowed(url: URL(string: "https://mac-hostname.local:9999/")!))
    }

    func testAllowsTheExplicitDefaultPortForAnImplicitPortTrustedURL() {
        // "https://host" and "https://host:443" are the same origin; the
        // port comparison must normalize rather than compare nil to 443.
        XCTAssertTrue(makeDelegate().isAllowed(url: URL(string: "https://mac-hostname.local:443/")!))
    }

    func testAllowsTheMatchingNonDefaultPortWhenTheTrustedURLHasOne() {
        // The loopback test setup (deploy/Caddyfile's localhost:8443
        // default, reachable via OSINETSTRIKER_URL) must work too.
        let delegate = makeDelegate("https://localhost:8443")
        XCTAssertTrue(delegate.isAllowed(url: URL(string: "https://localhost:8443/dashboard")!))
        XCTAssertFalse(delegate.isAllowed(url: URL(string: "https://localhost/")!))
    }

    func testRejectsEverythingWhenTheTrustedURLIsItselfNotHTTPS() {
        // A misconfigured non-https trusted URL must fail closed, not
        // become a plaintext-allowing lock.
        let delegate = makeDelegate("http://mac-hostname.local")
        XCTAssertFalse(delegate.isAllowed(url: URL(string: "http://mac-hostname.local/")!))
        XCTAssertFalse(delegate.isAllowed(url: URL(string: "https://mac-hostname.local/")!))
    }

    func testCreateWebViewWithAlwaysReturnsNil() {
        // window.open()/new-window requests must never open a second
        // webview -- there is nothing else in this app for a second
        // window to safely point at.
        XCTAssertNil(makeDelegate().decideNewWindow())
    }

    func testResolveTrustedURLDefaultsToTheQualifiedLocalHostname() {
        XCTAssertEqual(
            ContentView.resolveTrustedURL(override: nil, hostName: "mac-hostname"),
            URL(string: "https://mac-hostname.local")!
        )
        // Already-qualified hostnames must not get a second ".local".
        XCTAssertEqual(
            ContentView.resolveTrustedURL(override: nil, hostName: "mac-hostname.local"),
            URL(string: "https://mac-hostname.local")!
        )
    }

    func testResolveTrustedURLHonorsTheEnvironmentOverride() {
        // deploy/Caddyfile's actual default is localhost:8443, not :443 --
        // this override is how the app reaches the documented default
        // setup before the manual :443 switch.
        XCTAssertEqual(
            ContentView.resolveTrustedURL(override: "https://localhost:8443", hostName: "mac-hostname"),
            URL(string: "https://localhost:8443")!
        )
    }

    func testResolveTrustedURLFallsBackWhenTheOverrideIsUnusable() {
        // Must not trap at launch on a malformed override.
        XCTAssertEqual(
            ContentView.resolveTrustedURL(override: "not a url", hostName: "mac-hostname"),
            URL(string: "https://mac-hostname.local")!
        )
        XCTAssertEqual(
            ContentView.resolveTrustedURL(override: "", hostName: "mac-hostname"),
            URL(string: "https://mac-hostname.local")!
        )
    }
}
