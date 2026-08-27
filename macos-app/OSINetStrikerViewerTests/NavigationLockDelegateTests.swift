import XCTest
@testable import OSINetStrikerViewer

final class NavigationLockDelegateTests: XCTestCase {
    func testRejectsUntrustedHost() {
        let delegate = NavigationLockDelegate(trustedOrigin: "mac-hostname.local")
        XCTAssertFalse(delegate.isAllowed(url: URL(string: "https://evil.com/")!))
    }

    func testAllowsTrustedHost() {
        let delegate = NavigationLockDelegate(trustedOrigin: "mac-hostname.local")
        XCTAssertTrue(delegate.isAllowed(url: URL(string: "https://mac-hostname.local/dashboard")!))
    }

    func testRejectsTrustedHostAsASubstring() {
        // A host that merely CONTAINS the trusted origin as a substring
        // (e.g. an attacker-controlled "mac-hostname.local.evil.com") must
        // still be rejected -- this guards against a naive .contains()
        // implementation instead of an exact host match.
        let delegate = NavigationLockDelegate(trustedOrigin: "mac-hostname.local")
        XCTAssertFalse(delegate.isAllowed(url: URL(string: "https://mac-hostname.local.evil.com/")!))
    }

    func testCreateWebViewWithAlwaysReturnsNil() {
        // window.open()/new-window requests must never open a second
        // webview -- there is nothing else in this app for a second
        // window to safely point at.
        let delegate = NavigationLockDelegate(trustedOrigin: "mac-hostname.local")
        XCTAssertNil(delegate.decideNewWindow())
    }
}
