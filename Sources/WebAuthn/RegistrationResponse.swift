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

public struct RegistrationResponse: Codable {
    public let id: String
    let rawID: String
    /// This is the public-key
    let type: String
    let response: AuthenticatorAttestationResponse

    enum CodingKeys: String, CodingKey {
        case id
        case rawID = "rawId"
        case type
        case response
    }
}

public struct AuthenticatorAttestationResponse: Codable {
    let clientDataJSON: String
    let attestationObject: String
}
