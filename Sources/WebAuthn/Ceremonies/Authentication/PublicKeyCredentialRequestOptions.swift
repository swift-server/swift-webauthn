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

public struct PublicKeyCredentialRequestOptions: Codable {
    public let challenge: String
    public let timeout: TimeInterval?
    public let rpId: String?
    public let allowCredentials: [PublicKeyCredentialDescriptor]?
    public let userVerification: UserVerificationRequirement?
    public let attestation: String?
    public let attestationFormats: [String]?
    // let extensions: [String: Any]
}

public struct PublicKeyCredentialDescriptor: Codable {
    public let type: String
    public let id: [UInt8]
    public let transports: [AuthenticatorTransport]

    public init(type: String, id: [UInt8], transports: [AuthenticatorTransport] = []) {
        self.type = type
        self.id = id
        self.transports = transports
    }

    enum CodingKeys: String, CodingKey {
        case type, id, transports
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        try container.encode(type, forKey: .type)
        try container.encode(id.base64EncodedString(), forKey: .id)
        try container.encode(transports, forKey: .transports)
    }
}
