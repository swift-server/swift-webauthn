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

/// SessionData is the data that should be stored by the Relying Party for the duration of the web authentication
/// ceremony
public struct SessionData {
    /// Base64url-encoded challenge string
    public let challenge: String
    /// Plain user id (not encoded)
    public let userID: String

    public init(challenge: String, userID: String) {
        self.challenge = challenge
        self.userID = userID
    }
}
