import Foundation
import SwiftCBOR

struct TPMAttestation {
    enum TPMAttestationError: Error {
        case pubAreaInvalid
        case certInfoInvalid
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
    }
}

extension TPMAttestation {
    enum CertInfoError: Error {
        case magicInvalid
        case typeInvalid
        case tpmImplementationIsWIP
    }

    struct CertInfo {
        let magic: Data
        let type: Data
        let qualifiedSigner: Data
        let extraData: Data

        init?(fromBytes data: Data) {
            // TODO: Add safety checks before accessing data[x...y]
            var pointer = 0

            magic = data[pointer..<(pointer + 4)]
            pointer += 4

            type = data[pointer..<(pointer + 2)]
            pointer += 2

            let qualifiedSignerLengthData = data[pointer..<(pointer + 2)]
            pointer += 2
            let qualifiedSignerLength = Int(
                bigEndian: qualifiedSignerLengthData.withUnsafeBytes({ $0.load(as: Int.self) })
            )
            qualifiedSigner = data[pointer..<(pointer + qualifiedSignerLength)]
            pointer += qualifiedSignerLength

            let extraDataLengthData = data[pointer..<(pointer + 2)]
            pointer += 2
            let extraDataLength = Int(
                bigEndian: extraDataLengthData.withUnsafeBytes({ $0.load(as: Int.self) })
            )
            extraData = data[pointer..<(pointer + extraDataLength)]
            pointer += extraDataLength
        }

        func verify() throws {
            let tpmGeneratedValue = 0xFF544347
            guard Int(bigEndian: magic.withUnsafeBytes({ $0.load(as: Int.self) })) == tpmGeneratedValue else {
                throw CertInfoError.magicInvalid
            }

            let tpmStAttestCertify = 0x8017
            guard Int(bigEndian: type.withUnsafeBytes({ $0.load(as: Int.self) })) == tpmStAttestCertify else {
                throw CertInfoError.typeInvalid
            }

            throw CertInfoError.tpmImplementationIsWIP
        }
    }
}
