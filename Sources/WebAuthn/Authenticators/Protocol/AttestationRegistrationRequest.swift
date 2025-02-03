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
    
    init(
        options: PublicKeyCredentialCreationOptions,
        publicKeyCredentialParameters: [PublicKeyCredentialParameters],
        clientDataHash: SHA256Digest
    ) {
        self.options = options
        self.publicKeyCredentialParameters = publicKeyCredentialParameters
        self.clientDataHash = clientDataHash
    }
}
