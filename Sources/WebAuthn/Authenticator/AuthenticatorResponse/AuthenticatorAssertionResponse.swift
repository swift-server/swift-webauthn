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

/// From §5.2.2
/// The AuthenticatorAssertionResponse interface represents an authenticator's response to a client’s request for
/// generation of a new authentication assertion given the WebAuthn Relying Party's challenge and OPTIONAL list of
/// credentials it is aware of. This response contains a cryptographic signature proving possession of the credential
/// private key, and optionally evidence of user consent to a specific transaction.
public struct AuthenticatorAssertionResponse: AuthenticatorResponse, Codable {
    public let clientDataJSON: URLEncodedBase64
    /// Contains the authenticator data returned by the authenticator.
    public let authenticatorData: URLEncodedBase64
    /// Contains the raw signature returned from the authenticator
    public let signature: String
    /// Contains the user handle returned from the authenticator, or null if the authenticator did not return
    /// a user handle.
    public let userHandle: String?
    /// Contains an attestation object, if the authenticator supports attestation in assertions.
    /// The attestation object, if present, includes an attestation statement. Unlike the attestationObject
    /// in an AuthenticatorAttestationResponse, it does not contain an authData key because the authenticator
    /// data is provided directly in an AuthenticatorAssertionResponse structure.
    public let attestationObject: String?
}

public struct ParsedAuthenticatorAssertionResponse {

}