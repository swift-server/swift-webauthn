// 🚨 WIP

import Foundation
import SwiftCBOR
import X509
import Crypto

/// 🚨 WIP
struct PackedAttestation {
    enum PackedAttestationError: Error {
        case invalidAlg
        case invalidSig
        case invalidX5C
        case invalidLeafCertificate
        case missingAttestationCertificate
        case algDoesNotMatch
        case missingAttestedCredential
        case notImplemented
    }

    static func verify(
        attStmt: CBOR,
        authenticatorData: Data,
        clientDataHash: Data,
        credentialPublicKey: CredentialPublicKey,
        pemRootCertificates: [Data]
    ) async throws {
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
            guard let leafCertificate = x5c.first else { throw PackedAttestationError.invalidX5C }
            let intermediates = CertificateStore(x5c[1...])
            let rootCertificates = CertificateStore(
                try pemRootCertificates.map { try Certificate(derEncoded: [UInt8]($0)) }
            )

            var verifier = Verifier(rootCertificates: rootCertificates, policy: .init(policies: []))
            let verifierResult: VerificationResult = await verifier.validate(
                leafCertificate: leafCertificate,
                intermediates: intermediates
            )
            guard case .validCertificate = verifierResult else {
                throw PackedAttestationError.invalidLeafCertificate
            }

            // 2. Verify signature
            // let leafCertificatePublicKey: Certificate.PublicKey = leafCertificate.publicKey

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

extension Certificate.PublicKey {
//    func verifySignature(_ signature: Data, algorithm: COSEAlgorithmIdentifier, data: Data) throws -> Bool {
//        switch algorithm {
//
//        case .algES256:
//            guard case let .p256(key) = backing else { return false }
//            let signature = try P256.Signing.ECDSASignature(derRepresentation: signature)
//            return key.isValidSignature(signature, for: data)
//        case .algES384:
//            guard case let .p384(key) = backing else { return false }
//            let signature = try P384.Signing.ECDSASignature(derRepresentation: signature)
//            return key.isValidSignature(signature, for: data)
//        case .algES512:
//            guard case let .p521(key) = backing else { return false }
//            let signature = try P521.Signing.ECDSASignature(derRepresentation: signature)
//            return key.isValidSignature(signature, for: data)
//        case .algPS256:
//        case .algPS384:
//        case .algPS512:
//        case .algRS1:
//        case .algRS256:
//        case .algRS384:
//        case .algRS512:
//}
//        switch backing {
//        case let .p256(key):
//            try EC2PublicKey(rawRepresentation: key.rawRepresentation, algorithm: algorithm)
//                .verify(signature: signature, data: data)
//        case let .p384(key):
//            try EC2PublicKey(rawRepresentation: key.rawRepresentation, algorithm: algorithm)
//                .verify(signature: signature, data: data)
//        case let .p521(key):
//            try EC2PublicKey(rawRepresentation: key.rawRepresentation, algorithm: algorithm)
//                .verify(signature: signature, data: data)
//        case let .rsa(key):
//            try RSAPublicKeyData(rawRepresentation: key.derRepresentation, algorithm: algorithm)
//                .verify(signature: signature, data: data)
//        }
//    }
}
