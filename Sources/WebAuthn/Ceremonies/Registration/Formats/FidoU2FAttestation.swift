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
import X509

struct FidoU2FAttestation {
    enum FidoU2FAttestationError: Error {
        case invalidSig
        case invalidX5C
        case invalidTrustPath
        // attestation cert can only have a ecdsaWithSHA256 signature
        case invalidLeafCertificateSigType
        case invalidAttestationKeyType
        case missingAttestedCredential
        // Authenticator data cannot be verified
        case invalidVerificationData
    }

    static func verify(
        attStmt: CBOR,
        authenticatorData: AuthenticatorData,
        clientDataHash: Data,
        credentialPublicKey: CredentialPublicKey,
        pemRootCertificates: [Data]
    ) async throws -> [Certificate] {
        guard let sigCBOR = attStmt["sig"], case let .byteString(sig) = sigCBOR else {
            throw FidoU2FAttestationError.invalidSig
        }

        guard let attestedData = authenticatorData.attestedData else {
            throw FidoU2FAttestationError.missingAttestedCredential
        }
        
        guard case let .ec2(key) = credentialPublicKey, key.algorithm == .algES256 else {
            throw FidoU2FAttestationError.invalidAttestationKeyType
        }

        guard let x5cCBOR = attStmt["x5c"], case let .array(x5cCBOR) = x5cCBOR else {
                throw FidoU2FAttestationError.invalidX5C
        }

        let x5c: [Certificate] = try x5cCBOR.map {
            guard case let .byteString(certificate) = $0 else {
                throw FidoU2FAttestationError.invalidX5C
            }
            return try Certificate(derEncoded: certificate)
        }

        // U2F attestation can only have 1 certificate
        guard x5c.count == 1 else {
            throw FidoU2FAttestationError.invalidX5C
        }

        guard let leafCertificate = x5c.first else { throw FidoU2FAttestationError.invalidX5C }
        let rootCertificates = CertificateStore(
            try pemRootCertificates.map { try Certificate(derEncoded: [UInt8]($0)) }
        )

        guard leafCertificate.signatureAlgorithm == .ecdsaWithSHA256 else {
            throw FidoU2FAttestationError.invalidLeafCertificateSigType
        }

        var verifier = Verifier(rootCertificates: rootCertificates) {
            PackedVerificationPolicy()
        }
        let verifierResult: VerificationResult = await verifier.validate(
            leafCertificate: leafCertificate,
            intermediates: .init()
        )
        guard case .validCertificate(let chain) = verifierResult else {
            throw FidoU2FAttestationError.invalidTrustPath
        }

        // With U2F, the public key used when calculating the signature (`sig`) was encoded in ANSI X9.62 format
        let ansiPublicKey = [0x04] + key.xCoordinate + key.yCoordinate

        // https://fidoalliance.org/specs/fido-u2f-v1.1-id-20160915/fido-u2f-raw-message-formats-v1.1-id-20160915.html#registration-response-message-success
        let verificationData = Data(
            [0x00] // A byte "reserved for future use" with the value 0x00.
            + authenticatorData.relyingPartyIDHash
            + Array(clientDataHash)
            + attestedData.credentialID
            + ansiPublicKey
        )

        // Verify signature
        let leafCertificatePublicKey: Certificate.PublicKey = leafCertificate.publicKey
        guard try leafCertificatePublicKey.verifySignature(
            Data(sig),
            algorithm: leafCertificate.signatureAlgorithm,
            data: verificationData) else {
            throw FidoU2FAttestationError.invalidVerificationData
        }
        
        return chain
    }
}

