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

/// This is what the authenticator device returned after we requested it to authenticate a user.
public struct AuthenticatorAssertionResponse: Codable {
    /// Representation of what we passed to `navigator.credentials.get()`
    public let clientDataJSON: URLEncodedBase64
    /// Contains the authenticator data returned by the authenticator.
    public let authenticatorData: URLEncodedBase64
    /// Contains the raw signature returned from the authenticator
    public let signature: URLEncodedBase64
    /// Contains the user handle returned from the authenticator, or null if the authenticator did not return
    /// a user handle. Used by to give scope to credentials.
    public let userHandle: String?
    /// Contains an attestation object, if the authenticator supports attestation in assertions.
    /// The attestation object, if present, includes an attestation statement. Unlike the attestationObject
    /// in an AuthenticatorAttestationResponse, it does not contain an authData key because the authenticator
    /// data is provided directly in an AuthenticatorAssertionResponse structure.
    public let attestationObject: String?
}
