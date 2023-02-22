import Foundation
import SwiftCBOR

struct TPMAttestation {
    enum TPMAttestationError: Error {
        case pubAreaInvalid
        case certInfoInvalid
        case invalidAlg
        case invalidVersion
        case invalidX5c
        case invalidPublicKey
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
    ) throws {
        // Verify version
        guard let verCBOR = attStmt["ver"],
            case let .utf8String(ver) = verCBOR,
            ver == "2.0" else {
            throw TPMAttestationError.invalidVersion
        }

        // Verify certificate chain
        guard let x5cCBOR = attStmt["x5c"],
            case let .array(x5cArray) = x5cCBOR,
            case let .byteString(aikCert) = x5cArray.first else {
            throw TPMAttestationError.invalidX5c
        }
        let certificateChain = try x5cArray[1...].map {
            guard case let .byteString(caCert) = $0 else { throw TPMAttestationError.invalidX5c }
            return caCert
        }

        // TODO: Validate certificate chain
        // try CertificateChain.validate(
        //    x5c: aikCert + certificateChain,
        //    pemRootCertificates: pemRootCertificates
        // )

        // Verify pubArea
        guard let pubAreaCBOR = attStmt["pubArea"],
            case let .byteString(pubArea) = pubAreaCBOR,
            let pubArea = PubArea(from: Data(pubArea)) else {
            throw TPMAttestationError.pubAreaInvalid
        }
        switch pubArea.parameters {
        case let .rsa(rsaParameters):
            guard case let .rsa(rsaPublicKeyData) = credentialPublicKey,
                pubArea.unique.data == rsaPublicKeyData.n else {
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
                pubArea.unique.data == ec2PublicKeyData.rawRepresentation else {
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
        try parsedCertInfo.verify()

        let attToBeSigned = authenticatorData + clientDataHash

        guard let algCBOR = attStmt["alg"],
            case let .negativeInt(algorithmNegative) = algCBOR,
            let alg = COSEAlgorithmIdentifier(rawValue: -1 - Int(algorithmNegative)) else {
            throw TPMAttestationError.invalidAlg
        }

        guard alg.hashAndCompare(data: attToBeSigned, to: parsedCertInfo.extraData) else {
            throw TPMAttestationError.extraDataDoesNotMatchAttToBeSignedHash
        }
    }
}
