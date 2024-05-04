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

// https://www.w3.org/TR/webauthn-2/#sctn-fido-u2f-attestation
struct FidoU2FAttestation: AttestationProtocol {
    static func verify(
        attStmt: CBOR,
        authenticatorData: AuthenticatorData,
        clientDataHash: Data,
        credentialPublicKey: CredentialPublicKey,
        rootCertificates: [Certificate]
    ) async throws -> (AttestationResult.AttestationType, [Certificate]) {
        guard let sigCBOR = attStmt["sig"], case let .byteString(sig) = sigCBOR else {
            throw WebAuthnError.invalidSignature
        }
        
        guard case let .ec2(key) = credentialPublicKey, key.algorithm == .algES256 else {
            throw WebAuthnError.invalidAttestationPublicKeyType
        }

        guard let x5cCBOR = attStmt["x5c"], case let .array(x5cCBOR) = x5cCBOR else {
                throw WebAuthnError.invalidAttestationCertificate
        }

        let x5c: [Certificate] = try x5cCBOR.map {
            guard case let .byteString(certificate) = $0 else {
                throw WebAuthnError.invalidAttestationCertificate
            }
            return try Certificate(derEncoded: certificate)
        }

        guard let leafCertificate = x5c.first else { throw WebAuthnError.invalidAttestationCertificate }
        let intermediates = CertificateStore(x5c[1...])
        let rootCertificatesStore = CertificateStore(rootCertificates)

        var verifier = Verifier(rootCertificates: rootCertificatesStore) {
            FidoU2FVerificationPolicy()
        }
        let verifierResult: VerificationResult = await verifier.validate(
            leafCertificate: leafCertificate,
            intermediates: intermediates
        )
        guard case .validCertificate(let chain) = verifierResult else {
            throw WebAuthnError.invalidTrustPath
        }

        // With U2F, the public key used when calculating the signature (`sig`) was encoded in ANSI X9.62 format
        let ansiPublicKey = [0x04] + key.xCoordinate + key.yCoordinate

        // https://www.w3.org/TR/webauthn-2/#sctn-fido-u2f-attestation Verification Procedure step 5.
        let verificationData = Data(
            [0x00] // A byte "reserved for future use" with the value 0x00.
            + authenticatorData.relyingPartyIDHash
            + Array(clientDataHash)
            // This has been verified as not nil in AttestationObject
            + authenticatorData.attestedData!.credentialID
            + ansiPublicKey
        )

        // Verify signature
        let leafCertificatePublicKey: Certificate.PublicKey = leafCertificate.publicKey
        guard try leafCertificatePublicKey.verifySignature(
            Data(sig),
            algorithm: leafCertificate.signatureAlgorithm,
            data: verificationData) else {
            throw WebAuthnError.invalidVerificationData
        }
        
        return (.basicFull, chain)
    }
}

