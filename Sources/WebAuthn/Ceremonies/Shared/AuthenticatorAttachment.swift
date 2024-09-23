//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift WebAuthn open source project
//
// Copyright (c) 2024 the Swift WebAuthn project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Swift WebAuthn project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

/// An authenticators' attachment modalities.
///
/// Relying Parties use this to express a preferred authenticator attachment modality when registering a credential, and clients use this to report the authenticator attachment modality used to complete a registration or authentication ceremony.
/// - SeeAlso: [WebAuthn Level 3 Editor's Draft §5.4.5. Authenticator Attachment Enumeration (enum AuthenticatorAttachment)](https://w3c.github.io/webauthn/#enum-attachment)
/// - SeeAlso: [WebAuthn Level 3 Editor's Draft §6.2.1. Authenticator Attachment Modality](https://w3c.github.io/webauthn/#sctn-authenticator-attachment-modality)
///
public struct AuthenticatorAttachment: UnreferencedStringEnumeration, Sendable {
    public var rawValue: String
    public init(_ rawValue: String) {
        self.rawValue = rawValue
    }
    
    /// A platform authenticator is attached using a client device-specific transport, called platform attachment, and is usually not removable from the client device. A public key credential bound to a platform authenticator is called a platform credential.
    /// - SeeAlso: [WebAuthn Level 3 Editor's Draft §6.2.1. Authenticator Attachment Modality](https://w3c.github.io/webauthn/#platform-attachment)
    public static let platform: Self = "platform"
    
    /// A roaming authenticator is attached using cross-platform transports, called cross-platform attachment. Authenticators of this class are removable from, and can "roam" between, client devices. A public key credential bound to a roaming authenticator is called a roaming credential.
    /// - SeeAlso: [WebAuthn Level 3 Editor's Draft §6.2.1. Authenticator Attachment Modality](https://w3c.github.io/webauthn/#cross-platform-attachment)
    public static let crossPlatform: Self = "cross-platform"
}
