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
public struct AuthenticationCredential: Codable {
    public let id: URLEncodedBase64
    public let response: AuthenticatorAssertionResponse
    public let authenticatorAttachment: String?
    public let type: String

    enum CodingKeys: String, CodingKey {
        case id
        case response
        case authenticatorAttachment
        case type
    }
}
