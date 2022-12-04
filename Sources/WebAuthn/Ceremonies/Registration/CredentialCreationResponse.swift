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

import Crypto
import Foundation
import SwiftCBOR

/// The unprocessed response we receive from the relying party.
public struct CredentialCreationResponse: Codable {
    let id: String
    let type: String
    let rawID: URLEncodedBase64
    /// Likely the wrong datatype, it should be more like [String: Any]?
    let clientExtensionResults: [String: String]?
    let attestationResponse: AuthenticatorAttestationResponse

    enum CodingKeys: String, CodingKey {
        case id
        case type
        case rawID = "rawId"
        case clientExtensionResults
        case attestationResponse = "response"
    }
}

/// The processed response received from the relying party that needs to be verified.
struct ParsedCredentialCreationResponse {
    let id: String
    let rawID: Data
    /// Value will always be "public-key" (for now)
    let type: String
    let clientExtensionResults: [String: String]?
    let raw: AuthenticatorAttestationResponse
    let response: ParsedAuthenticatorAttestationResponse

    init(from rawResponse: CredentialCreationResponse) throws {
        id = rawResponse.id

        guard let decodedRawID = rawResponse.rawID.base64URLDecodedData else {
            throw WebAuthnError.invalidRawID
        }
        rawID = decodedRawID

        guard rawResponse.type == "public-key" else {
            throw WebAuthnError.invalidCredentialCreationType
        }
        type = rawResponse.type

        clientExtensionResults = rawResponse.clientExtensionResults

        raw = rawResponse.attestationResponse

        guard let clientDataJSONData = raw.clientDataJSON.base64URLDecodedData else {
            throw WebAuthnError.invalidClientDataJSON
        }
        let clientData = try JSONDecoder().decode(CollectedClientData.self, from: clientDataJSONData)

        guard let attestationData = raw.attestationObject.base64URLDecodedData,
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

        let attestationObject = AttestationObject(
            authenticatorData: try ParsedCredentialCreationResponse.parseAuthenticatorData(authDataBytes),
            rawAuthenticatorData: authDataBytes,
            format: AttestationFormat(rawValue: format),
            attestationStatement: [:]
        )

        let parsedAuthenticatorAttestationResponse = ParsedAuthenticatorAttestationResponse(
            clientData: clientData,
            attestationObject: attestationObject
        )

        response = parsedAuthenticatorAttestationResponse
    }

    func verify(storedChallenge: String, verifyUser: Bool, relyingPartyID: String, relyingPartyOrigin: String) throws {
        // Step 7. - 9.
        try response.clientData.verify(
            storedChallenge: storedChallenge,
            ceremonyType: .create,
            relyingPartyOrigin: relyingPartyOrigin
        )

        // Step 10.
        // guard let clientData = raw.clientDataJSON.base64URLDecodedData else {
        //     throw WebAuthnError.hashingClientDataJSONFailed
        // }
        // let hash = SHA256.hash(data: clientData)

        try response.attestationObject.verify(
            relyingPartyID: relyingPartyID,
            verificationRequired: verifyUser
        )
    }

    private static func parseAuthenticatorData(_ bytes: [UInt8]) throws -> AuthenticatorData {
        let minAuthDataLength = 37
        guard bytes.count >= minAuthDataLength else { throw WebAuthnError.authDataTooShort }

        let relyingPartyIDHash = Array(bytes[..<32])
        let flags = AuthenticatorFlags(bytes[32])
        let counter: UInt32 = Data(bytes[33..<37]).toInteger(endian: .big)

        var remainingCount = bytes.count - minAuthDataLength

        var attestedCredentialData: AttestedCredentialData?
        // For attestation signatures, the authenticator MUST set the AT flag and include the attestedCredentialData.
        if flags.attestedCredentialData {
            let minAttestedAuthLength = 55
            guard bytes.count > minAttestedAuthLength else { throw WebAuthnError.attestedCredentialDataMissing }
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
            guard remainingCount != 0 else { throw WebAuthnError.extensionDataMissing }
            extensionData = Array(bytes[(bytes.count - remainingCount)...])
            remainingCount -= extensionData!.count
        }

        guard remainingCount == 0 else { throw WebAuthnError.leftOverBytes }

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
