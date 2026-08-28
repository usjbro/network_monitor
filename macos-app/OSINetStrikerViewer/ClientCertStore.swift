import Foundation
import Security
import SwiftASN1
import os

/// print() to a GUI app's stdout is fully buffered (not line-buffered, the
/// way it is in a terminal), so output from a long-running app session can
/// sit invisible until the process exits -- misleading during exactly the
/// kind of "which step is this stuck on" debugging this store needs.
/// os.Logger writes straight to the unified logging system instead
/// (queryable live with `log stream`/`log show` or Console.app), regardless
/// of how the app was launched.
private let logger = Logger(subsystem: "com.osinetstriker.viewer", category: "ClientCertStore")

enum ClientCertStoreError: Error {
    case accessControlCreationFailed
    case keyGenerationFailed(String)
    /// Not a failure -- the SE key + CSR are ready and waiting at csrPath
    /// for `deploy/sign-native-app-csr.sh` (run unsandboxed, from
    /// Terminal) to sign. The app can never read the CA private key
    /// itself under App Sandbox; this is the intended, expected state on
    /// first launch (and any relaunch before that script has been run).
    case awaitingExternalSigning(csrPath: String)
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

    logger.notice("makeSecureEnclaveKey: calling SecKeyCreateRandomKey (may prompt Touch ID/password to set the biometryCurrentSet gate)")
    var error: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        let message = error.map { (($0.takeRetainedValue()) as Error).localizedDescription } ?? "unknown error"
        logger.error("makeSecureEnclaveKey: SecKeyCreateRandomKey failed: \(message, privacy: .public)")
        throw ClientCertStoreError.keyGenerationFailed(message)
    }
    logger.notice("makeSecureEnclaveKey: SecKeyCreateRandomKey returned successfully")
    return privateKey
}

/// Ties together a Secure Enclave key (above) and a CA-signed certificate
/// for it into a SecIdentity usable for mTLS client authentication.
struct ClientCertStore {
    let keyTag: String
    let commonName: String

    /// Confirmed on real Secure Enclave hardware: App Sandbox blocks this
    /// app from ever reading the CA private key directly (verified --
    /// `com.apple.security.temporary-exception.*`-style workarounds were
    /// deliberately not used; a sandboxed app reading an arbitrary CA
    /// private key path is exactly the kind of access this design's own
    /// threat model argues against). Instead, the CA-signing step happens
    /// entirely outside the sandbox: this app writes its CSR to a path
    /// inside its own container (always writable, no extra entitlement),
    /// and `deploy/sign-native-app-csr.sh` -- a plain, unsandboxed script
    /// you run from Terminal -- reads that same path directly (an
    /// unsandboxed process sees a sandboxed app's container as ordinary
    /// files on disk, no special access needed) and writes the signed
    /// certificate back to the same directory. This app never touches the
    /// CA private key at any point.
    static let containerSupportDirectory: URL = {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        return base.appendingPathComponent("OSINetStrikerViewer", isDirectory: true)
    }()
    static let csrURL = containerSupportDirectory.appendingPathComponent("client.csr")
    static let signedCertURL = containerSupportDirectory.appendingPathComponent("client-signed.pem")

    /// Returns the existing identity if one was already provisioned.
    /// Otherwise generates (or reuses) an SE key, builds its CSR, and
    /// either imports an already-signed certificate waiting at
    /// `Self.signedCertURL` (left there by `deploy/sign-native-app-csr.sh`
    /// on a prior run) or writes the CSR to `Self.csrURL` and throws
    /// `.awaitingExternalSigning` -- the caller is expected to tell the
    /// user to run that script, then retry.
    func loadOrCreateIdentity() throws -> SecIdentity {
        logger.notice("loadOrCreateIdentity: checking for an existing identity")
        if let existing = try? findExistingIdentity() {
            logger.notice("loadOrCreateIdentity: found an existing identity, returning it")
            return existing
        }

        try FileManager.default.createDirectory(at: Self.containerSupportDirectory, withIntermediateDirectories: true)

        if let signedPEM = try? String(contentsOf: Self.signedCertURL, encoding: .utf8) {
            logger.notice("loadOrCreateIdentity: found a signed cert on disk, importing it")
            try importCertificate(pem: signedPEM)
            // Clean up now that the cert is safely in the Keychain -- no
            // reason to leave the CSR/signed-cert pair sitting on disk.
            try? FileManager.default.removeItem(at: Self.csrURL)
            try? FileManager.default.removeItem(at: Self.signedCertURL)

            guard let identity = try findExistingIdentity() else {
                throw ClientCertStoreError.keyGenerationFailed("identity not found in Keychain after import")
            }
            return identity
        }

        // A CSR from an earlier call is still sitting on disk, waiting on
        // deploy/sign-native-app-csr.sh -- reuse it as-is rather than
        // rebuilding. buildCSR signs with the SE key below, which is gated
        // behind .biometryCurrentSet; the caller (ContentView) retries this
        // function every 3s while waiting, and re-signing on every retry
        // would re-prompt Touch ID/password every 3s right along with it.
        if FileManager.default.fileExists(atPath: Self.csrURL.path) {
            logger.notice("loadOrCreateIdentity: a CSR is already on disk, awaiting external signing")
            throw ClientCertStoreError.awaitingExternalSigning(csrPath: Self.csrURL.path)
        }

        // Reuse an already-generated SE key under this tag if one exists --
        // unconditionally calling makeSecureEnclaveKey again would either
        // hit errSecDuplicateItem or, if a colliding tag isn't already
        // firmly rejected, silently accumulate orphaned SE keys.
        // makeSecureEnclaveKey's own doc comment flags exactly this:
        // "callers should check SecItemCopyMatching first in real use."
        logger.notice("loadOrCreateIdentity: no existing key or CSR found, looking one up")
        let existingKey = try findExistingKey()
        logger.notice("loadOrCreateIdentity: existing key lookup done, found=\(existingKey != nil)")
        let privateKey = try existingKey ?? (try makeSecureEnclaveKey(tag: keyTag))
        logger.notice("loadOrCreateIdentity: have a private key, building CSR (this signs -- may prompt Touch ID/password)")
        let csrPEM = try buildCSR(privateKey: privateKey, commonName: commonName)
        logger.notice("loadOrCreateIdentity: CSR built, writing to disk")
        try csrPEM.write(to: Self.csrURL, atomically: true, encoding: .utf8)
        throw ClientCertStoreError.awaitingExternalSigning(csrPath: Self.csrURL.path)
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

        logger.notice("buildCSR: calling SecKeyCreateSignature (biometryCurrentSet-gated -- expect a Touch ID/password prompt here)")
        var signError: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            Data(certificationRequestInfoDER) as CFData,
            &signError
        ) as Data? else {
            let message = String(describing: signError)
            logger.error("buildCSR: SecKeyCreateSignature failed: \(message, privacy: .public)")
            throw ClientCertStoreError.keyGenerationFailed("signing failed: \(message)")
        }
        logger.notice("buildCSR: SecKeyCreateSignature returned successfully")

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
