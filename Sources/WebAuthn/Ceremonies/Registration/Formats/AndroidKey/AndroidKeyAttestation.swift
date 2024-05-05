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

// https://www.w3.org/TR/webauthn-2/#sctn-android-key-attestation
struct AndroidKeyAttestation: AttestationProtocol {
    static func verify(
        attStmt: CBOR,
        authenticatorData: AuthenticatorData,
        clientDataHash: Data,
        credentialPublicKey: CredentialPublicKey,
        rootCertificates: [Certificate]
    ) async throws -> (AttestationResult.AttestationType, [Certificate]) {
        guard let algCBOR = attStmt["alg"],
            case let .negativeInt(algorithmNegative) = algCBOR,
            let alg = COSEAlgorithmIdentifier(rawValue: -1 - Int(algorithmNegative)) else {
            throw WebAuthnError.invalidAttestationSignatureAlgorithm
        }
        guard let sigCBOR = attStmt["sig"], case let .byteString(sig) = sigCBOR else {
            throw WebAuthnError.invalidSignature
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

        let verificationData = authenticatorData.rawData + clientDataHash
        // Verify signature
        let leafCertificatePublicKey: Certificate.PublicKey = leafCertificate.publicKey
        guard try leafCertificatePublicKey.verifySignature(
            Data(sig),
            algorithm: alg,
            data: verificationData) else {
            throw WebAuthnError.invalidVerificationData
        }

        // We need to verify that the authenticator certificate's public key matches the public key present in
        // authenticatorData.attestedData (credentialPublicKey).
        // We can't directly compare two public keys, so instead we verify the signature with both keys:
        // the authenticator cert (previous step above) and credentialPublicKey (below).
        guard let _ = try? credentialPublicKey.verify(signature: Data(sig), data: verificationData) else {
            throw WebAuthnError.attestationPublicKeyMismatch
        }

        var verifier = Verifier(rootCertificates: rootCertificatesStore) {
            AndroidKeyVerificationPolicy(clientDataHash: clientDataHash)
        }
        let verifierResult: VerificationResult = await verifier.validate(
            leafCertificate: leafCertificate,
            intermediates: intermediates
        )
        guard case .validCertificate(let chain) = verifierResult else {
            throw WebAuthnError.invalidTrustPath
        }
        
        return (.basicFull, chain)
    }
}

