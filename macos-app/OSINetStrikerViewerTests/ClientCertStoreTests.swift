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
    }
}

private func deleteKey(tag: String) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: Data(tag.utf8),
    ]
    SecItemDelete(query as CFDictionary)
}
