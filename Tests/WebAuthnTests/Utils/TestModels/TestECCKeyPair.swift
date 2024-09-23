//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift WebAuthn open source project
//
// Copyright (c) 2023 the Swift WebAuthn project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import Crypto
import WebAuthn

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
}
