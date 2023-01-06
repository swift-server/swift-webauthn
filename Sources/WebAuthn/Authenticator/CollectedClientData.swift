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

/// https://www.w3.org/TR/webauthn/#dictionary-client-data
/// The client data represents the contextual bindings of both the WebAuthn Relying Party and the client.
public struct CollectedClientData: Codable, Hashable {
    enum CollectedClientDataVerifyError: Error {
        case ceremonyTypeDoesNotMatch
        case challengeDoesNotMatch
        case originDoesNotMatch
    }

    /// Contains the string "webauthn.create" when creating new credentials,
    /// and "webauthn.get" when getting an assertion from an existing credential
    let type: CeremonyType
    /// Contains the base64url encoding of the challenge provided by the Relying Party
    let challenge: URLEncodedBase64
    let origin: String
    // TODO: Token binding

    func verify(storedChallenge: URLEncodedBase64, ceremonyType: CeremonyType, relyingPartyOrigin: String) throws {
        guard type == ceremonyType else { throw CollectedClientDataVerifyError.ceremonyTypeDoesNotMatch }
        guard challenge == storedChallenge else { throw CollectedClientDataVerifyError.challengeDoesNotMatch }
        guard origin == relyingPartyOrigin else { throw CollectedClientDataVerifyError.originDoesNotMatch }
    }
}