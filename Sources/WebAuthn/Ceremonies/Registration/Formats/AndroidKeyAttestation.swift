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
import SwiftASN1

// https://www.w3.org/TR/webauthn-2/#sctn-android-key-attestation
struct AndroidKeyAttestation: AttestationProtocol {
    enum AndroidKeyAttestationError: Error {
        case invalidSig
        case invalidX5C
        case invalidTrustPath
        // Authenticator data cannot be verified
        case invalidVerificationData
        case credentialPublicKeyMismatch
    }

    static func verify(
        attStmt: CBOR,
        authenticatorData: AuthenticatorData,
        clientDataHash: Data,
        credentialPublicKey: CredentialPublicKey,
        pemRootCertificates: [Data]
    ) async throws -> [Certificate] {
        guard let sigCBOR = attStmt["sig"], case let .byteString(sig) = sigCBOR else {
            throw AndroidKeyAttestationError.invalidSig
        }
        
        guard let x5cCBOR = attStmt["x5c"], case let .array(x5cCBOR) = x5cCBOR else {
                throw AndroidKeyAttestationError.invalidX5C
        }

        let x5c: [Certificate] = try x5cCBOR.map {
            guard case let .byteString(certificate) = $0 else {
                throw AndroidKeyAttestationError.invalidX5C
            }
            return try Certificate(derEncoded: certificate)
        }

        guard let leafCertificate = x5c.first else { throw AndroidKeyAttestationError.invalidX5C }
        let intermediates = CertificateStore(x5c[1...])
        let rootCertificates = CertificateStore(
            try pemRootCertificates.map { try Certificate(derEncoded: [UInt8]($0)) }
        )

        let verificationData = authenticatorData.rawData + clientDataHash
        // Verify signature
        let leafCertificatePublicKey: Certificate.PublicKey = leafCertificate.publicKey
        guard try leafCertificatePublicKey.verifySignature(
            Data(sig),
            algorithm: leafCertificate.signatureAlgorithm,
            data: verificationData) else {
            throw AndroidKeyAttestationError.invalidVerificationData
        }

        // We need to verify that the authenticator certificate's public key matches the public key present in
        // authenticatorData.attestedData (credentialPublicKey).
        // We can't directly compare two public keys, so instead we verify the signature with both keys:
        // the authenticator cert (previous step above) and credentialPublicKey (below).
        guard let _ = try? credentialPublicKey.verify(signature: Data(sig), data: verificationData) else {
            throw AndroidKeyAttestationError.credentialPublicKeyMismatch
        }

        var verifier = Verifier(rootCertificates: rootCertificates) {
            AndroidKeyVerificationPolicy()
        }
        let verifierResult: VerificationResult = await verifier.validate(
            leafCertificate: leafCertificate,
            intermediates: intermediates,
            diagnosticCallback: { result in
                print("\n •••• \(Self.self) result=\(result)")
            }
        )
        guard case .validCertificate(let chain) = verifierResult else {
            throw AndroidKeyAttestationError.invalidTrustPath
        }
        
        return chain
    }
}

