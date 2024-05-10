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

// https://www.w3.org/TR/webauthn-2/#sctn-tpm-attestation
struct TPMAttestation: AttestationProtocol {
    static func verify(
        attStmt: CBOR,
        authenticatorData: AuthenticatorData,
        clientDataHash: Data,
        credentialPublicKey: CredentialPublicKey,
        rootCertificates: [Certificate]
    ) async throws -> (AttestationResult.AttestationType, [Certificate]) {
        // Verify version
        guard let verCBOR = attStmt["ver"],
            case let .utf8String(ver) = verCBOR,
            ver == "2.0" else {
            throw WebAuthnError.tpmInvalidVersion
        }

        guard let x5cCBOR = attStmt["x5c"],
            case let .array(x5cCBOR) = x5cCBOR else {
                throw WebAuthnError.invalidAttestationCertificate
        }
        
        // Verify certificate chain
        let x5c: [Certificate] = try x5cCBOR.map {
            guard case let .byteString(certificate) = $0 else {
                throw WebAuthnError.invalidAttestationCertificate
            }
            return try Certificate(derEncoded: certificate)
        }
        
        guard let aikCert = x5c.first else { throw WebAuthnError.invalidAttestationCertificate }
        let intermediates = CertificateStore(x5c[1...])
        let rootCertificatesStore = CertificateStore(rootCertificates)

        var verifier = Verifier(rootCertificates: rootCertificatesStore) {
            RFC5280Policy(validationTime: Date())
            TPMVerificationPolicy()
        }
        let verifierResult: VerificationResult = await verifier.validate(
            leafCertificate: aikCert,
            intermediates: intermediates
            /*diagnosticCallback: { result in
                print("\n •••• \(Self.self) result=\(result)")
            }*/
        )
        guard case .validCertificate(let chain) = verifierResult else {
            throw WebAuthnError.invalidTrustPath
        }
        
        // Verify that the value of the aaguid extension, if present, matches aaguid in authenticatorData
        if let certAAGUID = aikCert.extensions.first(
            where: {$0.oid == .idFidoGenCeAaguid}
        ) {
            // The AAGUID is wrapped in two OCTET STRINGS
            let derValue = try DER.parse(certAAGUID.value)
            guard case .primitive(let certAaguidValue) = derValue.content else {
                throw WebAuthnError.tpmInvalidCertAaguid
            }
            
            guard authenticatorData.attestedData?.aaguid == Array(certAaguidValue) else {
                throw WebAuthnError.aaguidMismatch
            }
        }

        if let pubAreaCBOR = attStmt["pubArea"], case let .byteString(pubAreaRaw) = pubAreaCBOR {
            let pubArea = PubArea(from: Data(pubAreaRaw))
        }
        // Verify pubArea
        guard let pubAreaCBOR = attStmt["pubArea"],
            case let .byteString(pubAreaRaw) = pubAreaCBOR,
            let pubArea = PubArea(from: Data(pubAreaRaw)) else {
            throw WebAuthnError.tpmInvalidPubArea
        }
        switch pubArea.parameters {
        case let .rsa(rsaParameters):
            if case let .rsa(rsaPublicKeyData) = credentialPublicKey {
            }
            guard case let .rsa(rsaPublicKeyData) = credentialPublicKey,
                Array(pubArea.unique.data) == rsaPublicKeyData.n else {
                throw WebAuthnError.tpmInvalidPubAreaPublicKey
            }
            var pubAreaExponent: Int = rsaParameters.exponent.toInteger(endian: .big)
            if pubAreaExponent == 0 {
                // "When zero, indicates that the exponent is the default of 2^16 + 1"
                pubAreaExponent = 65537
            }

            let pubKeyExponent: Int = rsaPublicKeyData.e.toInteger(endian: .big)
            guard pubAreaExponent == pubKeyExponent else {
                throw WebAuthnError.tpmPubAreaExponentDoesNotMatchPubKeyExponent
            }
        case let .ecc(eccParameters):
            guard case let .ec2(ec2PublicKeyData) = credentialPublicKey,
                Array(pubArea.unique.data) == ec2PublicKeyData.rawRepresentation else {
                throw WebAuthnError.tpmInvalidPubAreaPublicKey
            }

            guard let pubAreaCrv = COSECurve(from: eccParameters.curveID),
                pubAreaCrv == ec2PublicKeyData.curve else {
                throw WebAuthnError.tpmInvalidPubAreaCurve
            }
        }

        // Verify certInfo
        guard let certInfoCBOR = attStmt["certInfo"],
            case let .byteString(certInfo) = certInfoCBOR,
            let parsedCertInfo = CertInfo(fromBytes: Data(certInfo)) else {
            throw WebAuthnError.tpmCertInfoInvalid
        }

        try parsedCertInfo.verify(pubArea: Data(pubAreaRaw))

        guard let algCBOR = attStmt["alg"],
            case let .negativeInt(algorithmNegative) = algCBOR,
            let alg = COSEAlgorithmIdentifier(rawValue: -1 - Int(algorithmNegative)) else {
            throw WebAuthnError.invalidAttestationSignatureAlgorithm
        }

        // Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg"
        let attToBeSigned = authenticatorData.rawData + clientDataHash
        guard try alg.hashAndCompare(data: attToBeSigned, to: parsedCertInfo.extraData) else {
            throw WebAuthnError.tpmExtraDataDoesNotMatchAttToBeSignedHash
        }
        
        return (.attCA, chain)
    }
}
