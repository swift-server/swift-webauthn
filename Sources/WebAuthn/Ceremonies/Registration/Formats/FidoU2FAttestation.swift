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
import Crypto

struct FidoU2FAttestation {
    enum FidoU2FAttestationError: Error {
        case invalidSig
        case invalidX5C
        case invalidLeafCertificate
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
    ) async throws {
        guard let sigCBOR = attStmt["sig"], case let .byteString(sig) = sigCBOR else {
            throw FidoU2FAttestationError.invalidSig
        }

        guard let attestedData = authenticatorData.attestedData else {
            throw FidoU2FAttestationError.missingAttestedCredential
        }
        
        guard case let .ec2(key) = credentialPublicKey else {
            throw FidoU2FAttestationError.invalidAttestationKeyType
        }
        
        // With U2F, the public key format used when calculating the signature (`sig`) was encoded in ANSI X9.62 format
        let ansiPublicKey = [0x04] + key.xCoordinate + key.yCoordinate
        // https://fidoalliance.org/specs/fido-u2f-v1.1-id-20160915/fido-u2f-raw-message-formats-v1.1-id-20160915.html#registration-response-message-success
        let verificationData = Data([0x00] + authenticatorData.relyingPartyIDHash + Array(clientDataHash) + attestedData.credentialID + ansiPublicKey)

        guard let x5cCBOR = attStmt["x5c"], case let .array(x5cCBOR) = x5cCBOR else {
                throw FidoU2FAttestationError.invalidX5C
        }

        let x5c: [Certificate] = try x5cCBOR.map {
            guard case let .byteString(certificate) = $0 else {
                throw FidoU2FAttestationError.invalidX5C
            }
            return try Certificate(derEncoded: certificate)
        }

        guard let leafCertificate = x5c.first else { throw FidoU2FAttestationError.invalidX5C }
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
            throw FidoU2FAttestationError.invalidLeafCertificate
        }

        // 2. Verify signature
        // 2.1 Determine key type (with new Swift ASN.1/ Certificates library)
        // 2.2 Create corresponding public key object (EC2PublicKey/RSAPublicKey/OKPPublicKey)
        // 2.3 Call verify method on public key with signature + data
        let leafCertificatePublicKey: Certificate.PublicKey = leafCertificate.publicKey
        guard try leafCertificatePublicKey.verifySignature(Data(sig), algorithm: .ecdsaWithSHA256, data: verificationData) else {
            throw FidoU2FAttestationError.invalidVerificationData
        }
        print("\n••••• Verified FidoU2FAttestation !!!! ••••")

        
    }
}

