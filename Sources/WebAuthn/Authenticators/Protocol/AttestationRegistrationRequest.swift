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
import SwiftCBOR

public struct AttestationRegistrationRequest: Sendable {
    var options: PublicKeyCredentialCreationOptions
    var publicKeyCredentialParameters: [PublicKeyCredentialParameters]
    var clientDataHash: SHA256Digest
    var attemptRegistration: Callback
    
    init(
        options: PublicKeyCredentialCreationOptions,
        publicKeyCredentialParameters: [PublicKeyCredentialParameters],
        clientDataHash: SHA256Digest,
        attemptRegistration: @Sendable @escaping (_ attestationObject: AttestationObject) async throws -> ()
    ) {
        self.options = options
        self.publicKeyCredentialParameters = publicKeyCredentialParameters
        self.clientDataHash = clientDataHash
        self.attemptRegistration = Callback(callback: attemptRegistration)
    }
}

extension AttestationRegistrationRequest {
    public struct Callback: Sendable {
        /// The internal callback the attestation should call.
        var callback: @Sendable (_ attestationObject: AttestationObject) async throws -> ()
        
        /// Generate an attestation object for registration and submit it.
        ///
        /// Authenticators should call this to submit a successful registration and cancel any other pending authenticators.
        ///
        /// - SeeAlso: https://w3c.github.io/webauthn/#sctn-generating-an-attestation-object
        public func submitAttestationObject(
            attestationFormat: AttestationFormat,
            authenticatorData: AuthenticatorData,
            attestationStatement: CBOR
        ) async throws {
            try await callback(AttestationObject(
                authenticatorData: authenticatorData,
                format: attestationFormat,
                attestationStatement: attestationStatement
            ))
        }
    }
}
