import Foundation
import SwiftCBOR

struct TPMAttestation {
    enum TPMAttestationError: Error {
        case pubAreaInvalid
        case certInfoInvalid
        case invalidAlg
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
        guard let pubAreaCBOR = attStmt["pubArea"],
            case let .byteString(pubArea) = pubAreaCBOR,
            pubArea == attestedCredentialData.publicKey else {
            throw TPMAttestationError.pubAreaInvalid
        }
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

        let attToBeSignedHash = alg.matchWithSHAAndHash(data: attToBeSigned)
        guard parsedCertInfo.extraData == attToBeSignedHash else {
            throw TPMAttestationError.extraDataDoesNotMatchAttToBeSignedHash
        }
    }
}

extension TPMAttestation {
    enum CertInfoError: Error {
        case magicInvalid
        case typeInvalid
        case dataTooShort
        case tpmImplementationIsWIP
    }

    struct AttestationInformation {
        let name: Data
        let qualifiedName: Data
    }

    struct CertInfo {
        let magic: Data
        let type: Data
        let qualifiedSigner: Data
        let extraData: Data
        let clockInfo: Data
        let firmwareVersion: Data
        let attested: AttestationInformation

        init?(fromBytes data: Data) {
            var pointer = 0

            guard let magic = data[safe: pointer..<(pointer + 4)] else { return nil }
            self.magic = magic
            pointer += 4

            guard let type = data[safe: pointer..<(pointer + 2)] else { return nil }
            self.type = type
            pointer += 2

            guard let qualifiedSignerLengthData = data[safe: pointer..<(pointer + 2)] else { return nil }
            pointer += 2
            let qualifiedSignerLength: Int = qualifiedSignerLengthData.toInteger(endian: .big)
            guard let qualifiedSigner = data[safe: pointer..<(pointer + qualifiedSignerLength)] else { return nil }
            self.qualifiedSigner = qualifiedSigner
            pointer += qualifiedSignerLength

            guard let extraDataLengthData = data[safe: pointer..<(pointer + 2)] else { return nil }
            pointer += 2
            let extraDataLength: Int = extraDataLengthData.toInteger(endian: .big)
            guard let extraData = data[safe: pointer..<(pointer + extraDataLength)] else { return nil }
            self.extraData = extraData
            pointer += extraDataLength

            guard let clockInfo = data[safe: pointer..<(pointer + 17)] else { return nil }
            self.clockInfo = clockInfo
            pointer += 17

            guard let firmwareVersion = data[safe: pointer..<(pointer + 8)] else { return nil }
            self.firmwareVersion = firmwareVersion
            pointer += 8

            guard let attestedNameLengthData = data[safe: pointer..<(pointer + 2)] else { return nil }
            pointer += 2
            let attestedNameLength: Int = attestedNameLengthData.toInteger(endian: .big)
            guard let attestedName = data[safe: pointer..<(pointer + attestedNameLength)] else { return nil }
            pointer += attestedNameLength

            guard let qualifiedNameLengthData = data[safe: pointer..<(pointer + 2)] else { return nil }
            pointer += 2
            let qualifiedNameLength: Int = qualifiedNameLengthData.toInteger(endian: .big)
            guard let qualifiedName = data[safe: pointer..<(pointer + qualifiedNameLength)] else { return nil }
            pointer += qualifiedNameLength

            attested = AttestationInformation(name: attestedName, qualifiedName: qualifiedName)
        }

        func verify() throws {
            let tpmGeneratedValue = 0xFF544347
            guard magic.toInteger(endian: .big) == tpmGeneratedValue else {
                throw CertInfoError.magicInvalid
            }

            let tpmStAttestCertify = 0x8017
            guard type.toInteger(endian: .big) == tpmStAttestCertify else {
                throw CertInfoError.typeInvalid
            }

            throw CertInfoError.tpmImplementationIsWIP
        }
    }
}
