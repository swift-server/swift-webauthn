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
public struct AuthenticatorAttestationResponse: AuthenticatorResponse, Codable {
    public let clientDataJSON: URLEncodedBase64
    public let attestationObject: String
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

        // Step 11. (assembling attestationObject)
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

        guard let attestationStatement = decodedAttestationObject["attStmt"] else {
            throw WebAuthnError.missingAttestationFormat
        }

        guard let attestationFormat = AttestationFormat(rawValue: format) else {
            throw WebAuthnError.unsupportedAttestationFormat
        }

        attestationObject = AttestationObject(
            authenticatorData: try AuthenticatorData(bytes: Data(authDataBytes)),
            rawAuthenticatorData: authDataBytes,
            format: attestationFormat,
            attestationStatement: attestationStatement
        )
    }

    private static func parseAttestationStatement(format: AttestationFormat, statement: CBOR) throws {

    }
}
