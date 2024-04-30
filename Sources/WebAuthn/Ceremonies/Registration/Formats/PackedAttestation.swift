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

struct PackedAttestation {
    enum PackedAttestationError: Error {
        case invalidAlg
        case invalidSig
        case invalidX5C
        case invalidTrustPath
        case algDoesNotMatch
        case missingAttestedCredential
        // Authenticator data cannot be verified
        case invalidVerificationData
        case invalidCertAaguid
        case aaguidMismatch
    }

    static func verify(
        attStmt: CBOR,
        authenticatorData: Data,
        clientDataHash: Data,
        credentialPublicKey: CredentialPublicKey,
        pemRootCertificates: [Data]
    ) async throws -> [Certificate] {
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
            guard let attestnCert = x5c.first else { throw PackedAttestationError.invalidX5C }
            let intermediates = CertificateStore(x5c[1...])
            let rootCertificates = CertificateStore(
                try pemRootCertificates.map { try Certificate(derEncoded: [UInt8]($0)) }
            )

            var verifier = Verifier(rootCertificates: rootCertificates) {
                // TODO: do we really want to validate a cert expiry for devices that cannot be updated?
                // An expired device cert just means that the device is "old". 
                //RFC5280Policy(validationTime: Date())
                PackedVerificationPolicy()
            }
            let verifierResult: VerificationResult = await verifier.validate(
                leafCertificate: attestnCert,
                intermediates: intermediates
            )
            guard case .validCertificate(let chain) = verifierResult else {
                throw PackedAttestationError.invalidTrustPath
            }
            
            // 2. Verify signature
            // 2.1 Determine key type (with new Swift ASN.1/ Certificates library)
            // 2.2 Create corresponding public key object (EC2PublicKey/RSAPublicKey/OKPPublicKey)
            // 2.3 Call verify method on public key with signature + data
            let leafCertificatePublicKey: Certificate.PublicKey = attestnCert.publicKey
            guard try leafCertificatePublicKey.verifySignature(
                Data(sig),
                algorithm: attestnCert.signatureAlgorithm,
                data: verificationData) else {
                throw PackedAttestationError.invalidVerificationData
            }
            
            // Verify that the value of the aaguid extension, if present, matches aaguid in authenticatorData
            if let certAAGUID = attestnCert.extensions.first(
                where: {$0.oid == .idFidoGenCeAaguid}
            ) {
                // The AAGUID is wrapped in two OCTET STRINGS
                let derValue = try DER.parse(certAAGUID.value)
                guard case .primitive(let certAaguidValue) = derValue.content else {
                    throw PackedAttestationError.invalidCertAaguid
                }
                
                let authenticatorData = try AuthenticatorData(bytes: Array(authenticatorData))
                guard let attestedData = authenticatorData.attestedData,
                      attestedData.aaguid == Array(certAaguidValue) else {
                    throw PackedAttestationError.aaguidMismatch
                }
            }
            
            return chain
        } else { // self attestation is in use
            guard credentialPublicKey.key.algorithm == alg else {
                throw PackedAttestationError.algDoesNotMatch
            }

            try credentialPublicKey.verify(signature: Data(sig), data: verificationData)
            return []
        }
    }
}
