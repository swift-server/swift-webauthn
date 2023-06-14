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

/// The response from the authenticator device for the creation of a new public key credential.
public struct AuthenticatorAttestationResponse {
    public let clientDataJSON: [UInt8]
    public let attestationObject: [UInt8]
}

extension AuthenticatorAttestationResponse: Decodable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        guard let clientDataJSON = try container.decode(
            URLEncodedBase64.self,
            forKey: .clientDataJSON
        ).decodedBytes else {
            throw DecodingError.dataCorruptedError(
                forKey: .clientDataJSON,
                in: container,
                debugDescription: "Failed to decode base64url encoded clientDataJSON into bytes"
            )
        }
        self.clientDataJSON = clientDataJSON

        guard let attestationObject = try container.decode(
            URLEncodedBase64.self,
            forKey: .attestationObject
        ).decodedBytes else {
            throw DecodingError.dataCorruptedError(
                forKey: .attestationObject,
                in: container,
                debugDescription: "Failed to decode base64url encoded attestationObject into bytes"
            )
        }
        self.attestationObject = attestationObject
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
        guard let decodedAttestationObject = try? CBOR.decode([UInt8](attestationObjectData)) else {
            throw WebAuthnError.invalidAttestationObject
        }

        guard let authData = decodedAttestationObject["authData"],
            case let .byteString(authDataBytes) = authData else {
            throw WebAuthnError.invalidAuthData
        }
        guard let formatCBOR = decodedAttestationObject["fmt"],
            case let .utf8String(format) = formatCBOR,
            let attestationFormat = AttestationFormat(rawValue: format) else {
            throw WebAuthnError.invalidFmt
        }

        guard let attestationStatement = decodedAttestationObject["attStmt"] else {
            throw WebAuthnError.missingAttStmt
        }

        attestationObject = AttestationObject(
            authenticatorData: try AuthenticatorData(bytes: Data(authDataBytes)),
            rawAuthenticatorData: Data(authDataBytes),
            format: attestationFormat,
            attestationStatement: attestationStatement
        )
    }
}
