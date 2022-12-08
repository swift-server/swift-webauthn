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
import SwiftCBOR

/// From $ 5.2.1 (https://w3c.github.io/webauthn/#authenticatorattestationresponse)
/// The unprocessed response from the authenticator for the creation of a new public key credential.
/// It contains information about the new credential that can be used to identify it for later use, and
/// metadata that can be used by the WebAuthn Relying Party to assess the characteristics of the credential during
/// registration.
public struct AuthenticatorAttestationResponse: Codable {
    let clientDataJSON: URLEncodedBase64
    let attestationObject: String
}

struct ParsedAuthenticatorAttestationResponse {
    let clientData: CollectedClientData
    let attestationObject: AttestationObject

    init(from rawResponse: AuthenticatorAttestationResponse) throws {
        // assembling clientData
        guard let clientDataJSONData = rawResponse.clientDataJSON.base64URLDecodedData else {
            throw WebAuthnError.invalidClientDataJSON
        }
        let clientData = try JSONDecoder().decode(CollectedClientData.self, from: clientDataJSONData)
        self.clientData = clientData

        // assembling attestationObject
        guard let attestationData = rawResponse.attestationObject.base64URLDecodedData,
            let decodedAttestationObject = try CBOR.decode([UInt8](attestationData)) else {
            throw WebAuthnError.cborDecodingAttestationDataFailed
        }

        guard let authData = decodedAttestationObject["authData"], case let .byteString(authDataBytes) = authData else {
            throw WebAuthnError.authDataInvalidOrMissing
        }
        guard let formatCBOR = decodedAttestationObject["fmt"], case let .utf8String(format) = formatCBOR else {
            throw WebAuthnError.formatError
        }
        let attestationStatement = decodedAttestationObject["attStmt"]

        guard let attestationFormat = AttestationFormat(rawValue: format) else {
            throw WebAuthnError.unsupportedAttestationFormat
        }

        attestationObject = AttestationObject(
            authenticatorData: try ParsedAuthenticatorAttestationResponse.parseAuthenticatorData(authDataBytes),
            rawAuthenticatorData: authDataBytes,
            format: attestationFormat,
            attestationStatement: [:]
        )
    }

    private static func parseAuthenticatorData(_ bytes: [UInt8]) throws -> AuthenticatorData {
        let minAuthDataLength = 37
        guard bytes.count >= minAuthDataLength else {
            throw WebAuthnError.authDataTooShort
        }

        let relyingPartyIDHash = Array(bytes[..<32])
        let flags = AuthenticatorFlags(bytes[32])
        let counter: UInt32 = Data(bytes[33..<37]).toInteger(endian: .big)

        var remainingCount = bytes.count - minAuthDataLength

        var attestedCredentialData: AttestedCredentialData?
        // For attestation signatures, the authenticator MUST set the AT flag and include the attestedCredentialData.
        if flags.attestedCredentialData {
            let minAttestedAuthLength = 55
            guard bytes.count > minAttestedAuthLength else {
                throw WebAuthnError.attestedCredentialDataMissing
            }
            let (data, length) = try parseAttestedData(bytes)
            attestedCredentialData = data
            remainingCount -= length
        // For assertion signatures, the AT flag MUST NOT be set and the attestedCredentialData MUST NOT be included.
        } else {
            if !flags.extensionDataIncluded && bytes.count != minAuthDataLength {
                throw WebAuthnError.attestedCredentialFlagNotSet
            }
        }

        var extensionData: [UInt8]?
        if flags.extensionDataIncluded {
            guard remainingCount != 0 else {
                throw WebAuthnError.extensionDataMissing
            }
            extensionData = Array(bytes[(bytes.count - remainingCount)...])
            remainingCount -= extensionData!.count
        }

        guard remainingCount == 0 else {
            throw WebAuthnError.leftOverBytes
        }

        return AuthenticatorData(
            relyingPartyIDHash: relyingPartyIDHash,
            flags: flags,
            counter: counter,
            attestedData: attestedCredentialData,
            extData: extensionData
        )
    }

    /// Returns: Attested credentials data and the length
    private static func parseAttestedData(_ data: [UInt8]) throws -> (AttestedCredentialData, Int) {
        // We've parsed the first 37 bytes so far, the next bytes now should be the attested credential data
        // See https://w3c.github.io/webauthn/#sctn-attested-credential-data
        let aaguidLength = 16
        let aaguid = data[37..<(37 + aaguidLength)]  // To byte at index 52

        let idLengthBytes = data[53..<55]  // Length is 2 bytes
        let idLengthData = Data(idLengthBytes)
        let idLength: UInt16 = idLengthData.toInteger(endian: .big)
        let credentialIDEndIndex = Int(idLength) + 55

        let credentialID = data[55..<credentialIDEndIndex]
        let publicKeyBytes = data[credentialIDEndIndex...]

        let data = AttestedCredentialData(
            aaguid: Array(aaguid),
            credentialID: Array(credentialID),
            publicKey: Array(publicKeyBytes)
        )

        // 2 is the bytes storing the size of the credential ID
        let length = data.aaguid.count + 2 + data.credentialID.count + data.publicKey.count

        return (data, length)
    }
}