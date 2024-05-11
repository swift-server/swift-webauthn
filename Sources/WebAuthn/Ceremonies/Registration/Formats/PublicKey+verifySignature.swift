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
    func verifySignature(_ signature: Data, algorithm: COSEAlgorithmIdentifier, data: Data) throws -> Bool {
        switch algorithm {
        case .algES256:
            guard let key = P256.Signing.PublicKey(self) else {
                return false
            }
            let signature = try P256.Signing.ECDSASignature(derRepresentation: signature)
            return key.isValidSignature(signature, for: data)
            
        case .algES384:
            guard let key = P384.Signing.PublicKey(self) else {
                return false
            }
            let signature = try P384.Signing.ECDSASignature(derRepresentation: signature)
            return key.isValidSignature(signature, for: data)
            
        case .algES512:
            guard let key = P521.Signing.PublicKey(self) else {
                return false
            }
            let signature = try P521.Signing.ECDSASignature(derRepresentation: signature)
            return key.isValidSignature(signature, for: data)
            
        case .algRS1, .algRS256, .algRS384, .algRS512:
            guard let key = _RSA.Signing.PublicKey(self) else {
                return false
            }
            let signature = _RSA.Signing.RSASignature(rawRepresentation: signature)
            return key.isValidSignature(signature, for: data, padding: .insecurePKCS1v1_5)
            
        case .algPS256, .algPS384, .algPS512:
            guard let key = _RSA.Signing.PublicKey(self) else {
                return false
            }
            let signature = _RSA.Signing.RSASignature(rawRepresentation: signature)
            return key.isValidSignature(signature, for: data, padding: .PSS)
            
        default:
            throw WebAuthnError.unsupported
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
