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

        guard alg.hashAndCompare(data: attToBeSigned, to: parsedCertInfo.extraData) else {
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

    enum PubAreaParameters {
        case rsa(PubAreaParametersRSA)
        case ecc (PubAreaParametersECC)
    }

    struct PubArea {
        let type: Data
        let nameAlg: Data
        let objectAttributes: Data
        let authPolicy: Data
        let parameters: PubAreaParameters

        let mappedType: TPMAlg

        init?(from data: Data) {
            var pointer = 0

            guard let type = data.safeSlice(length: 2, using: &pointer),
                let mappedType = TPMAlg(from: type),
                let nameAlg = data.safeSlice(length: 2, using: &pointer),
                let objectAttributes = data.safeSlice(length: 4, using: &pointer),
                let authPolicyLength: Int = data.safeSlice(length: 2, using: &pointer)?.toInteger(endian: .big),
                let authPolicy = data.safeSlice(length: authPolicyLength, using: &pointer) else {
                return nil
            }

            self.type = type
            self.nameAlg = nameAlg
            self.objectAttributes = objectAttributes
            self.authPolicy = authPolicy

            self.mappedType = mappedType

            switch mappedType {
            case .rsa:
                guard let rsa = data.safeSlice(length: 10, using: &pointer),
                    let parameters = PubAreaParametersRSA(from: rsa) else { return nil }
                self.parameters = .rsa(parameters)
            case .ecc:
                guard let ecc = data.safeSlice(length: 8, using: &pointer),
                    let parameters = PubAreaParametersECC(from: ecc) else { return nil }
                self.parameters = .ecc(parameters)
            default:
                return nil
            }
        }
    }
}
