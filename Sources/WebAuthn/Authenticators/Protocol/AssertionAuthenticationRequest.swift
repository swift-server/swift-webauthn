//===----------------------------------------------------------------------===//
//
// This source file is part of the WebAuthn Swift open source project
//
// Copyright (c) 2024 the WebAuthn Swift project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of WebAuthn Swift project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@preconcurrency import Crypto

public struct AssertionAuthenticationRequest: Sendable {
    public var options: PublicKeyCredentialRequestOptions
    public var clientDataHash: SHA256Digest
    public var attemptAuthentication: Callback
    
    init(
        options: PublicKeyCredentialRequestOptions,
        clientDataHash: SHA256Digest,
        attemptAuthentication: @Sendable @escaping (_ assertionResults: Results) async throws -> ()
    ) {
        self.options = options
        self.clientDataHash = clientDataHash
        self.attemptAuthentication = Callback(callback: attemptAuthentication)
    }
}

extension AssertionAuthenticationRequest {
    public struct Callback: Sendable {
        /// The internal callback the attestation should call.
        var callback: @Sendable (_ assertionResults: Results) async throws -> ()
        
        /// Submit the results of asserting a user's authentication request.
        ///
        /// Authenticators should call this to submit a successful authentication and cancel any other pending authenticators.
        ///
        /// - SeeAlso: https://w3c.github.io/webauthn/#sctn-generating-an-attestation-object
        public func submitAssertionResults(
            credentialID: [UInt8],
            authenticatorData: [UInt8],
            signature: [UInt8],
            userHandle: [UInt8]?,
            authenticatorAttachment: AuthenticatorAttachment
        ) async throws {
            try await callback(Results(
                credentialID: credentialID,
                authenticatorData: authenticatorData,
                signature: signature,
                userHandle: userHandle,
                authenticatorAttachment: authenticatorAttachment
            ))
        }
    }
}

extension AssertionAuthenticationRequest {
    struct Results {
        var credentialID: [UInt8]
        var authenticatorData: [UInt8]
        var signature: [UInt8]
        var userHandle: [UInt8]?
        var authenticatorAttachment: AuthenticatorAttachment
    }
}
