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

/// The type of credential being used.
///
/// Only ``CredentialType/publicKey`` is supported by WebAuthn.
/// - SeeAlso: [Credential Management Level 1 Editor's Draft §2.1.2. Credential Type Registry](https://w3c.github.io/webappsec-credential-management/#sctn-cred-type-registry)
/// - SeeAlso: [WebAuthn Level 3 Editor's Draft §5.1. PublicKeyCredential Interface](https://w3c.github.io/webauthn/#iface-pkcredential)
public struct CredentialType: UnreferencedStringEnumeration, Sendable {
    public var rawValue: String
    public init(_ rawValue: String) {
        self.rawValue = rawValue
    }
    
    /// A public key credential.
    /// - SeeAlso: [WebAuthn Level 3 Editor's Draft §5.1. PublicKeyCredential Interface](https://w3c.github.io/webauthn/#iface-pkcredential)
    public static let publicKey: Self = "public-key"
}
