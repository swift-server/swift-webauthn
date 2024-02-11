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
import PotentCBOR

/// The response from the authenticator device for the creation of a new public key credential.
///
/// When decoding using `Decodable`, `clientDataJSON` and `attestationObject` are decoded from base64url to bytes.
public struct AuthenticatorAttestationResponse {
    /// The client data that was passed to the authenticator during the creation ceremony.
    ///
    /// When decoding using `Decodable`, this is decoded from base64url to bytes.
    public let clientDataJSON: [UInt8]

    /// Contains both attestation data and attestation statement.
    ///
    /// When decoding using `Decodable`, this is decoded from base64url to bytes.
    public let attestationObject: [UInt8]
}

extension AuthenticatorAttestationResponse: Decodable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        clientDataJSON = try container.decodeBytesFromURLEncodedBase64(forKey: .clientDataJSON)
        attestationObject = try container.decodeBytesFromURLEncodedBase64(forKey: .attestationObject)
    }

    private enum CodingKeys: String, CodingKey {
        case clientDataJSON
        case attestationObject
    }
}

/// A parsed version of `AuthenticatorAttestationResponse`
struct ParsedAuthenticatorAttestationResponse {
    let clientData: CollectedClientData
    let attestationObject: AttestationObject

    init(from rawResponse: AuthenticatorAttestationResponse) throws {
        // assembling clientData
        let clientData = try JSONDecoder().decode(CollectedClientData.self, from: Data(rawResponse.clientDataJSON))
        self.clientData = clientData

        // Step 11. (assembling attestationObject)
        let attestationObjectData = Data(rawResponse.attestationObject)
        guard let decodedAttestationObject = try? CBORSerialization.cbor(from: attestationObjectData) else {
            throw WebAuthnError.invalidAttestationObject
        }

        guard let authData = decodedAttestationObject["authData"]?.bytesStringValue else {
            throw WebAuthnError.invalidAuthData
        }

        guard let format = decodedAttestationObject["fmt"]?.utf8StringValue,
            let attestationFormat = AttestationFormat(rawValue: format)
        else {
            throw WebAuthnError.invalidFmt
        }

        guard let attestationStatement = decodedAttestationObject["attStmt"] else {
            throw WebAuthnError.missingAttStmt
        }

        attestationObject = AttestationObject(
            authenticatorData: try AuthenticatorData(bytes: authData),
            rawAuthenticatorData: authData,
            format: attestationFormat,
            attestationStatement: attestationStatement
        )
    }
}
