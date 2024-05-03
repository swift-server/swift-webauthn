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
import X509
import SwiftASN1
import Crypto
import _CryptoExtras

extension Certificate.PublicKey {
    func verifySignature(_ signature: Data, algorithm: Certificate.SignatureAlgorithm, data: Data) throws -> Bool {
        switch algorithm {

        case .ecdsaWithSHA256:
            guard let key = P256.Signing.PublicKey(self) else {
                return false
            }
            let signature = try P256.Signing.ECDSASignature(derRepresentation: signature)
            return key.isValidSignature(signature, for: data)
        case .ecdsaWithSHA384:
            guard let key = P384.Signing.PublicKey(self) else {
                return false
            }
            let signature = try P384.Signing.ECDSASignature(derRepresentation: signature)
            return key.isValidSignature(signature, for: data)
        case .ecdsaWithSHA512:
            guard let key = P521.Signing.PublicKey(self) else {
                return false
            }
            let signature = try P521.Signing.ECDSASignature(derRepresentation: signature)
            return key.isValidSignature(signature, for: data)
        // This hasn't been tested
        case .sha1WithRSAEncryption, .sha256WithRSAEncryption, .sha384WithRSAEncryption, .sha512WithRSAEncryption:
            guard let key = _RSA.Signing.PublicKey(self) else {
                return false
            }
            let signature = _RSA.Signing.RSASignature(rawRepresentation: signature)
            return key.isValidSignature(signature, for: data)
        default: // Should we return more explicit info (signature alg not supported) in that case?
            return false
        }
    }
}

extension SwiftASN1.ASN1ObjectIdentifier {
    static var idFidoGenCeAaguid: Self {
        .init(arrayLiteral: 1, 3, 6, 1, 4, 1, 45724, 1, 1, 4)
    }
    static var tcgKpAIKCertificate: Self {
        .init(arrayLiteral: 2, 23, 133, 8, 3)
    }
    static var certificatePolicies: Self {
        .init(arrayLiteral: 2, 5, 29, 32)
    }
    static var androidAttestation: Self {
        .init(arrayLiteral: 1, 3, 6, 1, 4, 1, 11129, 2, 1, 17)
    }
}
