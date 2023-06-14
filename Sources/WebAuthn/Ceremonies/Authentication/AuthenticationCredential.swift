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

/// The unprocessed response received from `navigator.credentials.get()`.
public struct AuthenticationCredential: Encodable {
    public let id: URLEncodedBase64
    public let rawID: [UInt8]
    public let response: AuthenticatorAssertionResponse
    public let authenticatorAttachment: String?
    public let type: String

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        try container.encode(id, forKey: .id)
        try container.encode(rawID.base64URLEncodedString(), forKey: .rawID)
        try container.encode(response, forKey: .response)
        try container.encodeIfPresent(authenticatorAttachment, forKey: .authenticatorAttachment)
        try container.encode(type, forKey: .type)
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case rawID = "rawId"
        case response
        case authenticatorAttachment
        case type
    }
}
