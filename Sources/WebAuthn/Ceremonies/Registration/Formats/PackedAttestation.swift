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
import SwiftCBOR
import SwiftASN1
import X509
import Crypto
import _CryptoExtras

struct PackedAttestation {
    enum PackedAttestationError: Error {
        case invalidAlg
        case invalidSig
        case invalidX5C
        case invalidLeafCertificate
        case invalidLeafCertificatePublicKey
        case missingAttestationCertificate
        case algDoesNotMatch
        case missingAttestedCredential
        // Authenticator data cannot be verified
        case invalidVerificationData
        case notImplemented
    }

    static func verify(
        attStmt: CBOR,
        authenticatorData: Data,
        clientDataHash: Data,
        credentialPublicKey: CredentialPublicKey,
        pemRootCertificates: [Data]
    ) async throws {
        guard let algCBOR = attStmt["alg"],
            case let .negativeInt(algorithmNegative) = algCBOR,
            let alg = COSEAlgorithmIdentifier(rawValue: -1 - Int(algorithmNegative)) else {
            throw PackedAttestationError.invalidAlg
        }
        guard let sigCBOR = attStmt["sig"], case let .byteString(sig) = sigCBOR else {
            throw PackedAttestationError.invalidSig
        }
        
        let verificationData = authenticatorData + clientDataHash

        if let x5cCBOR = attStmt["x5c"] {
            guard case let .array(x5cCBOR) = x5cCBOR else {
                throw PackedAttestationError.invalidX5C
            }

            let x5c: [Certificate] = try x5cCBOR.map {
                guard case let .byteString(certificate) = $0 else {
                    throw PackedAttestationError.invalidX5C
                }
                return try Certificate(derEncoded: certificate)
            }
            guard let leafCertificate = x5c.first else { throw PackedAttestationError.invalidX5C }
            let intermediates = CertificateStore(x5c[1...])
            let rootCertificates = CertificateStore(
                try pemRootCertificates.map { try Certificate(derEncoded: [UInt8]($0)) }
            )

            var verifier = Verifier(rootCertificates: rootCertificates) {
                // TODO: do we really want to validate a cert expiry for devices that cannot be updated?
                // An expired device cert just means that the device is "old". 
                RFC5280Policy(validationTime: Date())
            }
            let verifierResult: VerificationResult = await verifier.validate(
                leafCertificate: leafCertificate,
                intermediates: intermediates
            )
            guard case .validCertificate = verifierResult else {
                throw PackedAttestationError.invalidLeafCertificate
            }

            // 2. Verify signature
            // 2.1 Determine key type (with new Swift ASN.1/ Certificates library)
            // 2.2 Create corresponding public key object (EC2PublicKey/RSAPublicKey/OKPPublicKey)
            // 2.3 Call verify method on public key with signature + data
            let leafCertificatePublicKey: Certificate.PublicKey = leafCertificate.publicKey
            guard try leafCertificatePublicKey.verifySignature(Data(sig), algorithm: leafCertificate.signatureAlgorithm, data: verificationData) else {
                throw PackedAttestationError.invalidVerificationData
            }

        } else { // self attestation is in use
            guard credentialPublicKey.key.algorithm == alg else {
                throw PackedAttestationError.algDoesNotMatch
            }

            try credentialPublicKey.verify(signature: Data(sig), data: verificationData)
        }
    }
}


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
