import Foundation
import SwiftCBOR

struct PackedAttestation {
    enum PackedAttestationError: Error {
        case parsingAttStmtFailed
        case invalidAlg
        case invalidSig
        case invalidX5C
    }
    struct PackedAttestationStatement: Codable {
        let alg: COSEAlgorithmIdentifier
        let sig: Data
        let x5c: [Data]
    }

    static func verify(attStmt: Data, authenticatorData: Data, clientDataHash: Data) throws -> Bool {
        guard let parsedAttStmt: CBOR = try CBOR.decode([UInt8](attStmt)) else {
            throw PackedAttestationError.parsingAttStmtFailed
        }
        guard let algCBOR = parsedAttStmt["alg"], case let .byteString(alg) = algCBOR else {
            throw PackedAttestationError.invalidAlg
        }
        guard let sigCBOR = parsedAttStmt["sig"], case let .byteString(sig) = sigCBOR else {
            throw PackedAttestationError.invalidSig
        }

        let verificationData = authenticatorData + clientDataHash

        if let x5cCBOR = parsedAttStmt["x5c"] {
            guard case let .array(x5cCBOR) = x5cCBOR else {
                throw PackedAttestationError.invalidX5C
            }

            let x5c: [Data] = try x5cCBOR.map {
                guard case let .byteString(certificate) = $0 else {
                    throw PackedAttestationError.invalidX5C
                }
                return Data(certificate)
            }

            // 1. Validate certificate chain
            try CertificateChain.validate(x5c: x5c, pemRootCertificateBytes: nil)

            // 2. Verify signature

        } else { // self attestation is in use
            // 1. Verify signature

        }

        return false
    }
}
