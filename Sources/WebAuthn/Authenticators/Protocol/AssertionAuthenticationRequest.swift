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
    
    init(
        options: PublicKeyCredentialRequestOptions,
        clientDataHash: SHA256Digest
    ) {
        self.options = options
        self.clientDataHash = clientDataHash
    }
}

extension AssertionAuthenticationRequest {
    public struct Results: Sendable {
        public var credentialID: [UInt8]
        public var authenticatorData: [UInt8]
        public var signature: [UInt8]
        public var userHandle: [UInt8]?
        public var authenticatorAttachment: AuthenticatorAttachment
        
        public init(
            credentialID: [UInt8],
            authenticatorData: [UInt8],
            signature: [UInt8],
            userHandle: [UInt8]? = nil,
            authenticatorAttachment: AuthenticatorAttachment
        ) {
            self.credentialID = credentialID
            self.authenticatorData = authenticatorData
            self.signature = signature
            self.userHandle = userHandle
            self.authenticatorAttachment = authenticatorAttachment
        }
    }
}
