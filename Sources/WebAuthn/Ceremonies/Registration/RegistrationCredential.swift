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

/// The unprocessed response received from `navigator.credentials.create()`.
///
/// When decoding using `Decodable`, the `rawID` is decoded from base64url to bytes.
public struct RegistrationCredential: Sendable {
    /// The credential ID of the newly created credential.
    public let id: URLEncodedBase64

    /// Value will always be ``CredentialType/publicKey`` (for now)
    public let type: CredentialType

    /// The raw credential ID of the newly created credential.
    public let rawID: [UInt8]

    /// The attestation response from the authenticator.
    public let attestationResponse: AuthenticatorAttestationResponse
}

extension RegistrationCredential: Decodable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        id = try container.decode(URLEncodedBase64.self, forKey: .id)
        type = try container.decode(CredentialType.self, forKey: .type)
        guard let rawID = try container.decode(URLEncodedBase64.self, forKey: .rawID).decodedBytes else {
            throw DecodingError.dataCorruptedError(
                forKey: .rawID,
                in: container,
                debugDescription: "Failed to decode base64url encoded rawID into bytes"
            )
        }
        self.rawID = rawID
        attestationResponse = try container.decode(AuthenticatorAttestationResponse.self, forKey: .attestationResponse)
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case type
        case rawID = "rawId"
        case attestationResponse = "response"
    }
}

/// The processed response received from `navigator.credentials.create()`.
struct ParsedCredentialCreationResponse {
    let id: URLEncodedBase64
    let rawID: Data
    /// Value will always be ``CredentialType/publicKey`` (for now)
    let type: CredentialType
    let raw: AuthenticatorAttestationResponse
    let response: ParsedAuthenticatorAttestationResponse

    /// Create a `ParsedCredentialCreationResponse` from a raw `CredentialCreationResponse`.
    init(from rawResponse: RegistrationCredential) throws {
        id = rawResponse.id
        rawID = Data(rawResponse.rawID)

        guard rawResponse.type == .publicKey 
        else { throw WebAuthnError.invalidCredentialCreationType }
        type = rawResponse.type

        raw = rawResponse.attestationResponse
        response = try ParsedAuthenticatorAttestationResponse(from: raw)
    }

    // swiftlint:disable:next function_parameter_count
    func verify(
        storedChallenge: [UInt8],
        verifyUser: Bool,
        relyingPartyID: String,
        relyingPartyOrigin: String,
        supportedPublicKeyAlgorithms: [PublicKeyCredentialParameters],
        pemRootCertificatesByFormat: [AttestationFormat: [Data]]
    ) async throws -> AttestedCredentialData {
        // Step 7. - 9.
        try response.clientData.verify(
            storedChallenge: storedChallenge,
            ceremonyType: .create,
            relyingPartyOrigin: relyingPartyOrigin
        )

        // Step 10.
        let hash = SHA256.hash(data: Data(raw.clientDataJSON))

        // CBOR decoding happened already. Skipping Step 11.

        // Step 12. - 17.
        let attestedCredentialData = try await response.attestationObject.verify(
            relyingPartyID: relyingPartyID,
            verificationRequired: verifyUser,
            clientDataHash: hash,
            supportedPublicKeyAlgorithms: supportedPublicKeyAlgorithms,
            pemRootCertificatesByFormat: pemRootCertificatesByFormat
        )

        // Step 23.
        guard rawID.count <= 1023 else {
            throw WebAuthnError.credentialRawIDTooLong
        }

        return attestedCredentialData
    }
}
