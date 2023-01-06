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

/// The unprocessed response received from `navigator.credentials.create()`.
/// Internally this will be parsed into a more readable `ParsedCredentialCreationResponse`.
public struct RegistrationResponse {
    public let id: String
    public let type: String
    public let rawID: URLEncodedBase64
    /// Likely the wrong datatype, it should be more like [String: Any]?
    public let clientExtensionResults: [String: String]?
    public let attestationResponse: AuthenticatorAttestationResponse

    public init(
        id: String,
        type: String,
        rawID: URLEncodedBase64,
        clientExtensionResults: [String: String]?,
        attestationResponse: AuthenticatorAttestationResponse
    ) {
        self.id = id
        self.type = type
        self.rawID = rawID
        self.clientExtensionResults = clientExtensionResults
        self.attestationResponse = attestationResponse
    }

    enum CodingKeys: String, CodingKey {
        case id
        case type
        case rawID = "rawId"
        case clientExtensionResults
        case attestationResponse = "response"
    }
}

extension RegistrationResponse: Codable {}
