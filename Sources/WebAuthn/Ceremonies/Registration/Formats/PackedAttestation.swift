import Foundation
import SwiftCBOR

struct PackedAttestation {
    enum PackedAttestationError: Error {
        case invalidAlg
        case invalidSig
        case invalidX5C
        case missingAttestationCertificate
        case algDoesNotMatch
        case missingAttestedCredential
        case notImplemented
    }
    struct PackedAttestationStatement: Codable {
        let alg: COSEAlgorithmIdentifier
        let sig: Data
        let x5c: [Data]
    }

    static func verify(
        attStmt: CBOR,
        authenticatorData: Data,
        clientDataHash: Data,
        credentialPublicKey: CredentialPublicKey,
        pemRootCertificates: [Data]
    ) throws {
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

            let x5c: [Data] = try x5cCBOR.map {
                guard case let .byteString(certificate) = $0 else {
                    throw PackedAttestationError.invalidX5C
                }
                return Data(certificate)
            }

            // 1. Validate certificate chain
            // Waiting for Swift Certificates...
            // something like: try CertificateChain.validate(x5c: x5c, pemRootCertificates: pemRootCertificates)

            guard let attestationCertificate = x5c.first else {
                throw PackedAttestationError.missingAttestationCertificate
            }

            // 2. Verify signature

            // 2.1 Determine key type (with new Swift ASN.1/ Certificates library)
            // 2.2 Create corresponding public key object (EC2PublicKey/RSAPublicKey/OKPPublicKey)
            // 2.3 Call verify method on public key with signature + data
            throw PackedAttestationError.notImplemented
        } else { // self attestation is in use
            guard credentialPublicKey.key.algorithm == alg else {
                throw PackedAttestationError.algDoesNotMatch
            }

            try credentialPublicKey.verify(signature: Data(sig), data: verificationData)
        }
    }
}
