import Foundation
import Security
import SwiftASN1

enum ClientCertStoreError: Error {
    case accessControlCreationFailed
    case keyGenerationFailed(String)
}

/// Generates (or, on a later run with the same tag, would collide with --
/// callers should check SecItemCopyMatching first in real use) a
/// non-extractable P-256 private key in the Secure Enclave, gated behind
/// biometric confirmation on every signing use, never synced to iCloud.
/// Per the design spec: kSecAttrAccessibleWhenUnlockedThisDeviceOnly +
/// .biometryCurrentSet is the "non-extractable even under a future
/// memory-disclosure bug" guarantee -- the private key material never
/// leaves the Secure Enclave, only signing operations cross that boundary.
func makeSecureEnclaveKey(tag: String) throws -> SecKey {
    guard let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .biometryCurrentSet],
        nil
    ) else {
        throw ClientCertStoreError.accessControlCreationFailed
    }

    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        // SE/token-backed keys with an access control live in the
        // data-protection keychain, not the legacy file-based one -- without
        // this flag, this key and the cert imported alongside it in
        // ClientCertStore.importCertificate would target different stores,
        // and SecIdentity formation in findExistingIdentity would silently
        // never succeed.
        kSecUseDataProtectionKeychain as String: true,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecAttrAccessControl as String: access,
        ],
    ]

    var error: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        let message = error.map { (($0.takeRetainedValue()) as Error).localizedDescription } ?? "unknown error"
        throw ClientCertStoreError.keyGenerationFailed(message)
    }
    return privateKey
}

/// Ties together a Secure Enclave key (above) and a CA-signed certificate
/// for it into a SecIdentity usable for mTLS client authentication.
struct ClientCertStore {
    let keyTag: String
    let commonName: String

    /// Returns the existing identity if one was already provisioned, or
    /// generates a new SE key + CSR, has it signed by the local CA at
    /// caCertPath/caKeyPath, imports the result, and returns that.
    func loadOrCreateIdentity(caCertPath: String, caKeyPath: String) throws -> SecIdentity {
        if let existing = try? findExistingIdentity() {
            return existing
        }

        // Reuse an already-generated SE key under this tag if one exists --
        // "key created, identity absent" (e.g. a prior run that generated
        // the key but failed before/during CSR signing or cert import) is a
        // realistic first-run outcome, and unconditionally calling
        // makeSecureEnclaveKey again would either hit errSecDuplicateItem
        // or, if a colliding tag isn't already firmly rejected, silently
        // accumulate orphaned SE keys. makeSecureEnclaveKey's own doc
        // comment flags exactly this: "callers should check
        // SecItemCopyMatching first in real use."
        let privateKey = try findExistingKey() ?? (try makeSecureEnclaveKey(tag: keyTag))
        let csrPEM = try buildCSR(privateKey: privateKey, commonName: commonName)
        let certPEM = try signCSR(csrPEM: csrPEM, caCertPath: caCertPath, caKeyPath: caKeyPath)
        try importCertificate(pem: certPEM)

        guard let identity = try findExistingIdentity() else {
            throw ClientCertStoreError.keyGenerationFailed("identity not found in Keychain after import")
        }
        return identity
    }

    private func findExistingIdentity() throws -> SecIdentity? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecAttrApplicationTag as String: Data(keyTag.utf8),
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnRef as String: true,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let identity = result else { return nil }
        return (identity as! SecIdentity)
    }

    private func findExistingKey() throws -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(keyTag.utf8),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnRef as String: true,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let key = result else { return nil }
        return (key as! SecKey)
    }

    /// Builds a PKCS#10 CertificationRequest (RFC 2986) by hand: this is
    /// structural DER encoding of a decades-stable, narrow format, not a
    /// cryptographic implementation -- the one actual crypto operation
    /// (the final signature) is delegated to SecKeyCreateSignature, which
    /// runs inside the Secure Enclave and never sees this function's code.
    /// See Step 5's note on why swift-certificates itself couldn't be used
    /// here, and Step 6's own verification step for how this gets checked.
    private func buildCSR(privateKey: SecKey, commonName: String) throws -> String {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw ClientCertStoreError.keyGenerationFailed("no public key for the Secure Enclave private key")
        }
        var repError: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &repError) as Data? else {
            throw ClientCertStoreError.keyGenerationFailed("could not export public key: \(String(describing: repError))")
        }
        // SecKeyCopyExternalRepresentation for a P-256 EC key returns the
        // raw uncompressed point: 0x04 || X (32 bytes) || Y (32 bytes) --
        // exactly what SubjectPublicKeyInfo's BIT STRING needs.

        // Well-known, stable OIDs -- unchanged since their 1990s/2000s
        // publication (RFC 3279 / SEC 1), not something a library version
        // bump could alter.
        let idEcPublicKey = ASN1ObjectIdentifier(arrayLiteral: 1, 2, 840, 10045, 2, 1)
        let prime256v1 = ASN1ObjectIdentifier(arrayLiteral: 1, 2, 840, 10045, 3, 1, 7)
        let ecdsaWithSHA256 = ASN1ObjectIdentifier(arrayLiteral: 1, 2, 840, 10045, 4, 3, 2)
        let idAtCommonName = ASN1ObjectIdentifier(arrayLiteral: 2, 5, 4, 3)

        func serializeSubjectPKInfo(into coder: inout DER.Serializer) throws {
            try coder.appendConstructedNode(identifier: .sequence) { coder in
                try coder.appendConstructedNode(identifier: .sequence) { coder in
                    try coder.serialize(idEcPublicKey)
                    try coder.serialize(prime256v1)
                }
                try coder.serialize(ASN1BitString(bytes: ArraySlice(publicKeyData)))
            }
        }

        func serializeSubject(into coder: inout DER.Serializer) throws {
            try coder.appendConstructedNode(identifier: .sequence) { coder in // RDNSequence
                try coder.appendConstructedNode(identifier: .set) { coder in // one RDN
                    try coder.appendConstructedNode(identifier: .sequence) { coder in // AttributeTypeAndValue
                        try coder.serialize(idAtCommonName)
                        try coder.serialize(ASN1UTF8String(commonName))
                    }
                }
            }
        }

        // CertificationRequestInfo, DER-encoded once so its exact bytes can
        // both be embedded below and signed.
        var infoSerializer = DER.Serializer()
        try infoSerializer.appendConstructedNode(identifier: .sequence) { coder in
            try coder.serialize(0) // version v1(0)
            try serializeSubject(into: &coder)
            try serializeSubjectPKInfo(into: &coder)
            // attributes [0] IMPLICIT SET OF Attribute, empty -- no
            // extensionRequest needed for a client-auth-only cert.
            try coder.appendConstructedNode(identifier: ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)) { _ in }
        }
        let certificationRequestInfoDER = infoSerializer.serializedBytes

        var signError: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            Data(certificationRequestInfoDER) as CFData,
            &signError
        ) as Data? else {
            throw ClientCertStoreError.keyGenerationFailed("signing failed: \(String(describing: signError))")
        }

        var outerSerializer = DER.Serializer()
        try outerSerializer.appendConstructedNode(identifier: .sequence) { coder in
            coder.serializeRawBytes(certificationRequestInfoDER)
            try coder.appendConstructedNode(identifier: .sequence) { coder in
                try coder.serialize(ecdsaWithSHA256)
            }
            try coder.serialize(ASN1BitString(bytes: ArraySlice(signature)))
        }

        let der = Data(outerSerializer.serializedBytes)
        let base64 = der.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN CERTIFICATE REQUEST-----\n\(base64)\n-----END CERTIFICATE REQUEST-----\n"
    }

    /// Shells out to openssl to sign the CSR against the mkcert-issued
    /// local CA (deploy/setup-ca.sh's rootCA.pem/rootCA-key.pem) -- mkcert
    /// itself only issues leaf certs from its own held CA key, it doesn't
    /// expose a "sign this external CSR" command, so openssl is used
    /// directly here for just this one step.
    private func signCSR(csrPEM: String, caCertPath: String, caKeyPath: String) throws -> String {
        let tempDir = FileManager.default.temporaryDirectory
        let csrURL = tempDir.appendingPathComponent("\(UUID().uuidString).csr")
        let certURL = tempDir.appendingPathComponent("\(UUID().uuidString).pem")
        let extURL = tempDir.appendingPathComponent("\(UUID().uuidString).ext")
        defer {
            try? FileManager.default.removeItem(at: csrURL)
            try? FileManager.default.removeItem(at: certURL)
            try? FileManager.default.removeItem(at: extURL)
        }
        try csrPEM.write(to: csrURL, atomically: true, encoding: .utf8)
        // Without an explicit clientAuth Extended Key Usage, some mTLS
        // stacks (not necessarily Caddy's require_and_verify today, but
        // this shouldn't rely on that) may accept a cert that isn't
        // actually scoped to client authentication -- cheap to be
        // explicit here rather than relying on the absence of an EKU
        // extension being interpreted permissively everywhere.
        try "extendedKeyUsage = clientAuth\n".write(to: extURL, atomically: true, encoding: .utf8)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = [
            "x509", "-req",
            "-in", csrURL.path,
            "-CA", caCertPath,
            "-CAkey", caKeyPath,
            "-CAcreateserial",
            "-days", "90",
            "-extfile", extURL.path,
            "-out", certURL.path,
        ]
        // Capture stderr so a failure (including e.g. a sandboxed build
        // being unable to read caKeyPath -- see the App Sandbox note on
        // ClientCertStore.loadOrCreateIdentity's callers) surfaces openssl's
        // actual message instead of collapsing to an opaque exit status.
        let stderrPipe = Pipe()
        process.standardError = stderrPipe
        try process.run()
        let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            let stderrOutput = String(data: stderrData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            throw ClientCertStoreError.keyGenerationFailed(
                "openssl CSR signing failed with status \(process.terminationStatus): \(stderrOutput)"
            )
        }
        return try String(contentsOf: certURL, encoding: .utf8)
    }

    private func importCertificate(pem: String) throws {
        // Strip PEM headers and base64-decode to DER, then SecItemAdd as a
        // kSecClassCertificate tied to the same keychain the SE key lives
        // in -- the shared kSecAttrApplicationTag/public key is what lets
        // the Keychain associate the cert with the existing private key
        // and expose the pair as a SecIdentity.
        let lines = pem.split(separator: "\n").filter { !$0.hasPrefix("-----") }
        guard let der = Data(base64Encoded: lines.joined()) else {
            throw ClientCertStoreError.keyGenerationFailed("could not decode signed certificate PEM")
        }
        guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else {
            throw ClientCertStoreError.keyGenerationFailed("could not parse signed certificate DER")
        }
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecValueRef as String: certificate,
            kSecUseDataProtectionKeychain as String: true,
        ]
        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecSuccess || status == errSecDuplicateItem else {
            throw ClientCertStoreError.keyGenerationFailed("SecItemAdd failed with status \(status)")
        }
    }
}
