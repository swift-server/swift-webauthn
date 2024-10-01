//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift WebAuthn open source project
//
// Copyright (c) 2022 the Swift WebAuthn project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Swift WebAuthn project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import Crypto
@preconcurrency import SwiftCBOR

/// Contains the cryptographic attestation that a new key pair was created by that authenticator.
public struct AttestationObject: Sendable {
    var authenticatorData: AuthenticatorData
    var rawAuthenticatorData: [UInt8]
    var format: AttestationFormat
    var attestationStatement: CBOR
    
    init(
        authenticatorData: AuthenticatorData,
        rawAuthenticatorData: [UInt8],
        format: AttestationFormat,
        attestationStatement: CBOR
    ) {
        self.authenticatorData = authenticatorData
        self.rawAuthenticatorData = rawAuthenticatorData
        self.format = format
        self.attestationStatement = attestationStatement
    }
    
    public init(
        authenticatorData: AuthenticatorData,
        format: AttestationFormat,
        attestationStatement: CBOR
    ) {
        self.authenticatorData = authenticatorData
        self.rawAuthenticatorData = authenticatorData.bytes
        self.format = format
        self.attestationStatement = attestationStatement
    }
    
    init(bytes: [UInt8]) throws {
        guard let decodedAttestationObject = try? CBOR.decode(bytes, options: CBOROptions(maximumDepth: 16))
        else { throw WebAuthnError.invalidAttestationObject }

        guard 
            let authData = decodedAttestationObject["authData"],
            case let .byteString(authDataBytes) = authData
        else { throw WebAuthnError.invalidAuthData }
        self.authenticatorData = try AuthenticatorData(bytes: authDataBytes)
        self.rawAuthenticatorData = authDataBytes
        
        guard
            let formatCBOR = decodedAttestationObject["fmt"],
            case let .utf8String(format) = formatCBOR,
            let attestationFormat = AttestationFormat(rawValue: format)
        else { throw WebAuthnError.invalidFmt }
        self.format = attestationFormat

        guard let attestationStatement = decodedAttestationObject["attStmt"]
        else { throw WebAuthnError.missingAttStmt }
        self.attestationStatement = attestationStatement
    }
    
    var bytes: [UInt8] {
        CBOR.encode([
            "authData": CBOR.byteString(authenticatorData.bytes),
            "fmt": CBOR.utf8String(format.rawValue),
            "attStmt": attestationStatement,
        ])
    }

    func verify(
        relyingPartyID: String,
        verificationRequired: Bool,
        clientDataHash: SHA256.Digest,
        supportedPublicKeyAlgorithms: [PublicKeyCredentialParameters],
        pemRootCertificatesByFormat: [AttestationFormat: [Data]] = [:]
    ) async throws -> AttestedCredentialData {
        let relyingPartyIDHash = SHA256.hash(data: Data(relyingPartyID.utf8))

        guard relyingPartyIDHash == authenticatorData.relyingPartyIDHash else {
            throw WebAuthnError.relyingPartyIDHashDoesNotMatch
        }

        // TODO: Make flag
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

        // let pemRootCertificates = pemRootCertificatesByFormat[format] ?? []
        switch format {
        case .none:
            // if format is `none` statement must be empty
            guard attestationStatement == .map([:]) else {
                throw WebAuthnError.attestationStatementMustBeEmpty
            }
        // case .packed:
        //     try await PackedAttestation.verify(
        //         attStmt: attestationStatement,
        //         authenticatorData: rawAuthenticatorData,
        //         clientDataHash: Data(clientDataHash),
        //         credentialPublicKey: credentialPublicKey,
        //         pemRootCertificates: pemRootCertificates
        //     )
        // case .tpm:
        //     try TPMAttestation.verify(
        //         attStmt: attestationStatement,
        //         authenticatorData: rawAuthenticatorData,
        //         attestedCredentialData: attestedCredentialData,
        //         clientDataHash: Data(clientDataHash),
        //         credentialPublicKey: credentialPublicKey,
        //         pemRootCertificates: pemRootCertificates
        //     )
        default:
            throw WebAuthnError.attestationVerificationNotSupported
        }

        return attestedCredentialData
    }
}
