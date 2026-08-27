import XCTest
@testable import OSINetStrikerViewer

final class ClientCertStoreTests: XCTestCase {
    func testGeneratesAP256SecureEnclaveKey() throws {
        let tag = "com.osinetstriker.viewer.test-key-\(UUID().uuidString)"
        defer { deleteKey(tag: tag) }

        let key = try makeSecureEnclaveKey(tag: tag)
        let attributes = SecKeyCopyAttributes(key) as? [String: Any]

        XCTAssertEqual(attributes?[kSecAttrKeyType as String] as? String, kSecAttrKeyTypeECSECPrimeRandom as String)
        XCTAssertEqual(attributes?[kSecAttrKeySizeInBits as String] as? Int, 256)

        // Type and size alone would also be satisfied by a plain software
        // key -- these two are the properties that actually distinguish a
        // real Secure Enclave key (non-extractable, gated behind an access
        // control) from a software one, so they're the real regression
        // guard for this function's whole purpose.
        XCTAssertEqual(attributes?[kSecAttrTokenID as String] as? String, kSecAttrTokenIDSecureEnclave as String)

        // SecAccessControlGetConstraints isn't a real public API on this SDK
        // (checked directly against Security.framework's SecAccessControl.h
        // -- only SecAccessControlGetTypeID/SecAccessControlCreateWithFlags
        // are declared), so the strongest publicly-available check is that
        // kSecAttrAccessControl actually holds a genuine SecAccessControl
        // instance -- i.e. an access control was really attached to this
        // key, not merely present-but-empty or silently dropped.
        guard let accessControlValue = attributes?[kSecAttrAccessControl as String] else {
            XCTFail("expected an access control to be set on the key")
            return
        }
        XCTAssertEqual(
            CFGetTypeID(accessControlValue as CFTypeRef),
            SecAccessControlGetTypeID(),
            "expected kSecAttrAccessControl to hold a real SecAccessControl instance"
        )
    }
}

private func deleteKey(tag: String) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: Data(tag.utf8),
    ]
    SecItemDelete(query as CFDictionary)
}
