//===----------------------------------------------------------------------===//
//
// This source file is part of the WebAuthn Swift open source project
//
// Copyright (c) 2023 the WebAuthn Swift project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of WebAuthn Swift project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import Crypto
import WebAuthn
import X509
import SwiftASN1

struct TestECCKeyPair {
    static let privateKeyPEM = """
    -----BEGIN PRIVATE KEY-----
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUC6oOLmd9F3Ak32L
    WJCzQB1eF00UX5MCzYi47hNS+zqhRANCAASWIbQJIqS1L1E8G2Z5uNSPgQGZcsfz
    xk1shW3jTkWmRWY3MSr+CumivsCLz0YR4OkIHm8SAxGomGYF1dO0skj4
    -----END PRIVATE KEY-----
    """

    static let publicKeyPEM = """
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEliG0CSKktS9RPBtmebjUj4EBmXLH
    88ZNbIVt405FpkVmNzEq/grpor7Ai89GEeDpCB5vEgMRqJhmBdXTtLJI+A==
    -----END PUBLIC KEY-----
    """
    static let publicKeyXCoordinate = "9621b40922a4b52f513c1b6679b8d48f81019972c7f3c64d6c856de34e45a645".hexadecimal!
    static let publicKeyYCoordinate = "6637312afe0ae9a2bec08bcf4611e0e9081e6f120311a8986605d5d3b4b248f8".hexadecimal!

    static func signature(data: Data) throws -> P256.Signing.ECDSASignature {
        let privateKey = try P256.Signing.PrivateKey(pemRepresentation: privateKeyPEM)
        return try privateKey.signature(for: data)
    }

    static var signature: [UInt8] {
        let authenticatorData = TestAuthDataBuilder()
            .validAuthenticationMock()
            // .counter([0, 0, 0, 1])
            .buildAsBase64URLEncoded()

        // Create a signature. This part is usually performed by the authenticator
        let clientData: Data = TestClientDataJSON(type: "webauthn.get").jsonData
        let clientDataHash = SHA256.hash(data: clientData)
        let rawAuthenticatorData = authenticatorData.urlDecoded.decoded!
        let signatureBase = rawAuthenticatorData + clientDataHash
        // swiftlint:disable:next force_try
        let signature = try! TestECCKeyPair.signature(data: signatureBase).derRepresentation

        return [UInt8](signature)
    }
    
    static func certificates() throws -> (leaf: Data, ca: Certificate) {
        let caPrivateKey = P256.KeyAgreement.PrivateKey()
        let ca = try Certificate.init(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(pemEncoded: caPrivateKey.publicKey.pemRepresentation),
            notValidBefore: Date(),
            notValidAfter: Date().advanced(by: 3600),
            issuer: DistinguishedName { CommonName("Example CA") },
            subject: DistinguishedName { CommonName("Example CA") },
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try .init{
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 1))
            },
            issuerPrivateKey: .init(pemEncoded: caPrivateKey.pemRepresentation)
        )
        
        let privateKey = try P256.KeyAgreement.PrivateKey(pemRepresentation: privateKeyPEM)
        let leaf = try Certificate.init(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(pemEncoded: privateKey.publicKey.pemRepresentation),
            notValidBefore: Date(),
            notValidAfter: Date().advanced(by: 3600),
            issuer: ca.subject,
            subject: DistinguishedName {
                CommonName("Example leaf certificate")
                OrganizationalUnitName("Authenticator Attestation")
                OrganizationName("Example vendor")
                CountryName("US")
            },
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.notCertificateAuthority)
                try ExtendedKeyUsage([
                    .init(oid: .init(arrayLiteral: 2, 23, 133, 8, 3))
                ])
            },
            issuerPrivateKey: .init(pemEncoded: caPrivateKey.pemRepresentation)
        )
        var leafSerializer = DER.Serializer()
        try leafSerializer.serialize(leaf)
        let leafDER = leafSerializer.serializedBytes
        
        return (leaf: Data(leafDER), ca: ca)
    }
}
