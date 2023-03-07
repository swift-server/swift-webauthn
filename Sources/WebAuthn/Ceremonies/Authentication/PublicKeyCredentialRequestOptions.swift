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

/// The `PublicKeyCredentialRequestOptions` gets passed to the WebAuthn API (`navigator.credentials.get()`)
public struct PublicKeyCredentialRequestOptions: Codable {
    public let challenge: EncodedBase64
    public let timeout: TimeInterval?
    public let rpId: String?
    public let allowCredentials: [PublicKeyCredentialDescriptor]?
    public let userVerification: UserVerificationRequirement?
    // let extensions: [String: Any]
}

public struct PublicKeyCredentialDescriptor: Codable, Equatable {
    public enum AuthenticatorTransport: String, Codable, Equatable {
        case usb
        case nfc
        case ble
        case hybrid
        case `internal`
    }

    enum CodingKeys: String, CodingKey {
        case type, id, transports
    }

    public let type: String
    public let id: [UInt8]
    public let transports: [AuthenticatorTransport]

    public init(type: String, id: [UInt8], transports: [AuthenticatorTransport] = []) {
        self.type = type
        self.id = id
        self.transports = transports
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        try container.encode(type, forKey: .type)
        try container.encode(id.base64EncodedString(), forKey: .id)
        try container.encode(transports, forKey: .transports)
    }
}

public enum UserVerificationRequirement: String, Codable {
    case required
    case preferred
    case discouraged
}
