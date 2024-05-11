//===----------------------------------------------------------------------===//
//
// This source file is part of the WebAuthn Swift open source project
//
// Copyright (c) 2022 the WebAuthn Swift project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of WebAuthn Swift project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import Crypto
import SwiftCBOR
import X509

/// Contains the cryptographic attestation that a new key pair was created by that authenticator.
public struct AttestationObject {
    let authenticatorData: AuthenticatorData
    let rawAuthenticatorData: [UInt8]
    let format: AttestationFormat
    let attestationStatement: CBOR
    var trustPath: [Certificate] = []

    func verify(
        relyingPartyID: String,
        verificationRequired: Bool,
        clientDataHash: SHA256.Digest,
        supportedPublicKeyAlgorithms: [PublicKeyCredentialParameters],
        rootCertificatesByFormat: [AttestationFormat: [Certificate]] = [:]
    ) async throws -> AttestationResult {
        let relyingPartyIDHash = SHA256.hash(data: relyingPartyID.data(using: .utf8)!)

        guard relyingPartyIDHash == authenticatorData.relyingPartyIDHash else {
            throw WebAuthnError.relyingPartyIDHashDoesNotMatch
        }

        guard authenticatorData.flags.userPresent else {
            throw WebAuthnError.userPresentFlagNotSet
        }

        if verificationRequired {
            guard authenticatorData.flags.userVerified else {
                throw WebAuthnError.userVerificationRequiredButFlagNotSet
            }
        }

        guard let attestedCredentialData = authenticatorData.attestedData else {
            throw WebAuthnError.attestedCredentialDataMissing
        }

        // Step 17.
        let credentialPublicKey = try CredentialPublicKey(publicKeyBytes: attestedCredentialData.publicKey)
        guard supportedPublicKeyAlgorithms.map(\.alg).contains(credentialPublicKey.key.algorithm) else {
            throw WebAuthnError.unsupportedCredentialPublicKeyAlgorithm
        }

        let rootCertificates = rootCertificatesByFormat[format] ?? []
        var attestationType: AttestationResult.AttestationType = .none
        var trustedPath: [Certificate] = []

        switch format {
        case .none:
            // if format is `none` statement must be empty
            guard attestationStatement == .map([:]) else {
                throw WebAuthnError.attestationStatementMustBeEmpty
            }
        case .packed:
            (attestationType, trustedPath) = try await PackedAttestation.verify(
                attStmt: attestationStatement,
                authenticatorData: authenticatorData,
                clientDataHash: Data(clientDataHash),
                credentialPublicKey: credentialPublicKey,
                rootCertificates: rootCertificates
            )
        case .tpm:
            (attestationType, trustedPath) = try await TPMAttestation.verify(
                attStmt: attestationStatement,
                authenticatorData: authenticatorData,
                clientDataHash: Data(clientDataHash),
                credentialPublicKey: credentialPublicKey,
                rootCertificates: rootCertificates
            )
        case .androidKey:
            (attestationType, trustedPath) = try await AndroidKeyAttestation.verify(
                attStmt: attestationStatement,
                authenticatorData: authenticatorData,
                clientDataHash: Data(clientDataHash),
                credentialPublicKey: credentialPublicKey,
                rootCertificates: rootCertificates
            )
        // Legacy format used mostly by older authenticators
        case .fidoU2F:
            (attestationType, trustedPath) = try await FidoU2FAttestation.verify(
                attStmt: attestationStatement,
                authenticatorData: authenticatorData,
                clientDataHash: Data(clientDataHash),
                credentialPublicKey: credentialPublicKey,
                rootCertificates: rootCertificates
            )
        default:
            throw WebAuthnError.attestationVerificationNotSupported
        }
        
        return AttestationResult(
            format: format,
            type: attestationType,
            trustChain: trustedPath,
            attestedCredentialData: attestedCredentialData
        )
    }
}
