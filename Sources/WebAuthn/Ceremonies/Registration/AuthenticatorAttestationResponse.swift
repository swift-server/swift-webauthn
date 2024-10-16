//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift WebAuthn open source project
//
// Copyright (c) 2022 the Swift WebAuthn project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import SwiftCBOR

/// The response from the authenticator device for the creation of a new public key credential.
///
/// When decoding using `Decodable`, `clientDataJSON` and `attestationObject` are decoded from base64url to bytes.
public struct AuthenticatorAttestationResponse: Sendable {
    /// The client data that was passed to the authenticator during the creation ceremony.
    ///
    /// When decoding using `Decodable`, this is decoded from base64url to bytes.
    public let clientDataJSON: [UInt8]

    /// Contains both attestation data and attestation statement.
    ///
    /// When decoding using `Decodable`, this is decoded from base64url to bytes.
    public let attestationObject: [UInt8]
}

extension AuthenticatorAttestationResponse: Codable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        clientDataJSON = try container.decodeBytesFromURLEncodedBase64(forKey: .clientDataJSON)
        attestationObject = try container.decodeBytesFromURLEncodedBase64(forKey: .attestationObject)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        try container.encode(clientDataJSON.base64URLEncodedString(), forKey: .clientDataJSON)
        try container.encode(attestationObject.base64URLEncodedString(), forKey: .attestationObject)
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
        attestationObject = try AttestationObject(bytes: rawResponse.attestationObject)
    }
}
