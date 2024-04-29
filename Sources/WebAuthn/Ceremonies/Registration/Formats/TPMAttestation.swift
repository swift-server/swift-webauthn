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

struct TPMAttestation {
    enum TPMAttestationError: Error {
        case pubAreaInvalid
        case certInfoInvalid
        case invalidAlg
        case invalidVersion
        case invalidX5c
        case invalidPublicKey
        case invalidLeafCertificate
        case attestationCertificateSubjectNotEmpty
        case attestationCertificateMissingTcgKpAIKCertificate
        case attestationCertificateIsCA
        case invalidCertAaguid
        case aaguidMismatch
        case pubAreaExponentDoesNotMatchPubKeyExponent
        case invalidPubAreaCurve
        case extraDataDoesNotMatchAttToBeSignedHash
    }

    static func verify(
        attStmt: CBOR,
        authenticatorData: Data,
        attestedCredentialData: AttestedCredentialData,
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
        /*let x5c: [Certificate] = try x5cCBOR.map {
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

        // TPM Attestation Statement Certificate Requirements
        // Subject field MUST be set to empty.
        guard aikCert.subject.isEmpty else {
            throw TPMAttestationError.attestationCertificateSubjectNotEmpty
        }
        // The Extended Key Usage extension MUST contain the OID 2.23.133.8.3
        guard aikCert.extensions.contains(where: {$0.oid == .tcgKpAIKCertificate}) else {
            throw TPMAttestationError.attestationCertificateMissingTcgKpAIKCertificate
        }
        // The Basic Constraints extension MUST have the CA component set to false.
        guard case .notCertificateAuthority = try aikCert.extensions.basicConstraints  else {
            throw TPMAttestationError.attestationCertificateIsCA
        }
        
        
        var verifier = Verifier(rootCertificates: rootCertificates) {
            // TODO: do we really want to validate a cert expiry for devices that cannot be updated?
            // An expired device cert just means that the device is "old".
            RFC5280Policy(validationTime: Date())
        }
        let verifierResult: VerificationResult = await verifier.validate(
            leafCertificate: aikCert,
            intermediates: intermediates
        )
        guard case .validCertificate(let chain) = verifierResult else {
            throw TPMAttestationError.invalidLeafCertificate
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
            
            let authenticatorData = try AuthenticatorData(bytes: Array(authenticatorData))
            guard let attestedData = authenticatorData.attestedData,
                  attestedData.aaguid == Array(certAaguidValue) else {
                throw TPMAttestationError.aaguidMismatch
            }
        }*/

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
        let attToBeSigned = authenticatorData + clientDataHash
        guard alg.hashAndCompare(data: attToBeSigned, to: parsedCertInfo.extraData) else {
            throw TPMAttestationError.extraDataDoesNotMatchAttToBeSignedHash
        }
        
        return [] //chain
    }
}
