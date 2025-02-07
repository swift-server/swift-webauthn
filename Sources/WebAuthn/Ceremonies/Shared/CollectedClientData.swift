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

/// A parsed version of the `clientDataJSON` received from the authenticator. The `clientDataJSON` is a
/// representation of the options we passed to the WebAuthn API (`.get()`/ `.create()`).
public struct CollectedClientData: Codable, Hashable, Sendable {
    enum CollectedClientDataVerifyError: Error {
        case ceremonyTypeDoesNotMatch
        case challengeDoesNotMatch
        case originDoesNotMatch
    }

    public enum CeremonyType: String, Codable, Sendable {
        case create = "webauthn.create"
        case assert = "webauthn.get"
    }

    /// Contains the string "webauthn.create" when creating new credentials,
    /// and "webauthn.get" when getting an assertion from an existing credential
    public let type: CeremonyType
    /// The challenge that was provided by the Relying Party
    public let challenge: URLEncodedBase64
    public let origin: String

    func verify(storedChallenge: [UInt8], ceremonyType: CeremonyType, relyingPartyOrigin: String) throws(CollectedClientDataVerifyError) {
        guard type == ceremonyType else { throw .ceremonyTypeDoesNotMatch }
        guard challenge == storedChallenge.base64URLEncodedString() else {
            throw .challengeDoesNotMatch
        }
        guard origin == relyingPartyOrigin else { throw .originDoesNotMatch }
    }
}
