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

struct TPMAttestation: AttestationProtocol {
    enum TPMAttestationError: Error {
        case pubAreaInvalid
        case certInfoInvalid
        /// Invalid or unsupported attestation signature algorithm
        case invalidAlg
        /// Unsupported TPM version
        case invalidVersion
        case invalidX5c
        case invalidPublicKey
        case invalidTrustPath
        case attestationCertificateSubjectNotEmpty
        case attestationCertificateMissingTcgKpAIKCertificate
        /// A leaf (atte4station) cert must not have the CA flag set.
        case attestationCertificateIsCA
        case invalidCertAaguid
        case aaguidMismatch
        case pubAreaExponentDoesNotMatchPubKeyExponent
        case invalidPubAreaCurve
        case extraDataDoesNotMatchAttToBeSignedHash
    }

    static func verify(
        attStmt: CBOR,
        authenticatorData: AuthenticatorData,
        clientDataHash: Data,
        credentialPublicKey: CredentialPublicKey,
        pemRootCertificates: [Data]
    ) async throws -> [Certificate] {
        // Verify version
        guard let verCBOR = attStmt["ver"],
            case let .utf8String(ver) = verCBOR,
            ver == "2.0" else {
            throw TPMAttestationError.invalidVersion
        }

        guard let x5cCBOR = attStmt["x5c"],
            case let .array(x5cCBOR) = x5cCBOR else {
                throw TPMAttestationError.invalidX5c
        }
        
        // Verify certificate chain
        let x5c: [Certificate] = try x5cCBOR.map {
            guard case let .byteString(certificate) = $0 else {
                throw TPMAttestationError.invalidX5c
            }
            return try Certificate(derEncoded: certificate)
        }
        
        guard let aikCert = x5c.first else { throw TPMAttestationError.invalidX5c }
        let intermediates = CertificateStore(x5c[1...])
        let rootCertificates = CertificateStore(
            try pemRootCertificates.map { try Certificate(derEncoded: [UInt8]($0)) }
        )

        var verifier = Verifier(rootCertificates: rootCertificates) {
            RFC5280Policy(validationTime: Date())
            TPMVerificationPolicy()
        }
        let verifierResult: VerificationResult = await verifier.validate(
            leafCertificate: aikCert,
            intermediates: intermediates
        )
        guard case .validCertificate(let chain) = verifierResult else {
            throw TPMAttestationError.invalidTrustPath
        }
        
        // Verify that the value of the aaguid extension, if present, matches aaguid in authenticatorData
        if let certAAGUID = aikCert.extensions.first(
            where: {$0.oid == .idFidoGenCeAaguid}
        ) {
            // The AAGUID is wrapped in two OCTET STRINGS
            let derValue = try DER.parse(certAAGUID.value)
            guard case .primitive(let certAaguidValue) = derValue.content else {
                throw TPMAttestationError.invalidCertAaguid
            }
            
            guard authenticatorData.attestedData?.aaguid == Array(certAaguidValue) else {
                throw TPMAttestationError.aaguidMismatch
            }
        }

        // Verify pubArea
        guard let pubAreaCBOR = attStmt["pubArea"],
            case let .byteString(pubAreaRaw) = pubAreaCBOR,
            let pubArea = PubArea(from: Data(pubAreaRaw)) else {
            throw TPMAttestationError.pubAreaInvalid
        }
        switch pubArea.parameters {
        case let .rsa(rsaParameters):
           guard case let .rsa(rsaPublicKeyData) = credentialPublicKey,
               Array(pubArea.unique.data) == rsaPublicKeyData.n else {
               throw TPMAttestationError.invalidPublicKey
           }
           var pubAreaExponent: Int = rsaParameters.exponent.toInteger(endian: .big)
           if pubAreaExponent == 0 {
               // "When zero, indicates that the exponent is the default of 2^16 + 1"
               pubAreaExponent = 65537
           }

           let pubKeyExponent: Int = rsaPublicKeyData.e.toInteger(endian: .big)
           guard pubAreaExponent == pubKeyExponent else {
               throw TPMAttestationError.pubAreaExponentDoesNotMatchPubKeyExponent
           }
        case let .ecc(eccParameters):
           guard case let .ec2(ec2PublicKeyData) = credentialPublicKey,
               Array(pubArea.unique.data) == ec2PublicKeyData.rawRepresentation else {
               throw TPMAttestationError.invalidPublicKey
           }

           guard let pubAreaCrv = COSECurve(from: eccParameters.curveID),
               pubAreaCrv == ec2PublicKeyData.curve else {
               throw TPMAttestationError.invalidPubAreaCurve
           }
        }
        // Verify certInfo
        guard let certInfoCBOR = attStmt["certInfo"],
            case let .byteString(certInfo) = certInfoCBOR,
            let parsedCertInfo = CertInfo(fromBytes: Data(certInfo)) else {
            throw TPMAttestationError.certInfoInvalid
        }

        try parsedCertInfo.verify(pubArea: Data(pubAreaRaw))

        guard let algCBOR = attStmt["alg"],
            case let .negativeInt(algorithmNegative) = algCBOR,
            let alg = COSEAlgorithmIdentifier(rawValue: -1 - Int(algorithmNegative)) else {
            throw TPMAttestationError.invalidAlg
        }

        // Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg"
        let attToBeSigned = authenticatorData.rawData + clientDataHash
        guard alg.hashAndCompare(data: attToBeSigned, to: parsedCertInfo.extraData) else {
            throw TPMAttestationError.extraDataDoesNotMatchAttToBeSignedHash
        }
        
        return chain
    }
}
