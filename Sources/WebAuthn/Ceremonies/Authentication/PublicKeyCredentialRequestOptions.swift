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

/// The `PublicKeyCredentialRequestOptions` gets passed to the WebAuthn API (`navigator.credentials.get()`)
///
/// When encoding using `Encodable`, the byte arrays are encoded as base64url.
///
/// - SeeAlso: https://www.w3.org/TR/webauthn-2/#dictionary-assertion-options
public struct PublicKeyCredentialRequestOptions: Encodable {
    /// A challenge that the authenticator signs, along with other data, when producing an authentication assertion
    ///
    /// When encoding using `Encodable` this is encoded as base64url.
    public let challenge: [UInt8]

    /// A time, in seconds, that the caller is willing to wait for the call to complete. This is treated as a
    /// hint, and may be overridden by the client.
    ///
    /// - Note: When encoded, this value is represented in milleseconds as a ``UInt32``.
    /// See https://www.w3.org/TR/webauthn-2/#dictionary-assertion-options
    public let timeout: Duration?

    /// The Relying Party ID.
    public let rpId: String?

    /// Optionally used by the client to find authenticators eligible for this authentication ceremony.
    public let allowCredentials: [PublicKeyCredentialDescriptor]?

    /// Specifies whether the user should be verified during the authentication ceremony.
    public let userVerification: UserVerificationRequirement?

    // let extensions: [String: Any]

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        try container.encode(challenge.base64URLEncodedString(), forKey: .challenge)
        try container.encodeIfPresent(timeout?.milliseconds, forKey: .timeout)
        try container.encodeIfPresent(rpId, forKey: .rpId)
        try container.encodeIfPresent(allowCredentials, forKey: .allowCredentials)
        try container.encodeIfPresent(userVerification, forKey: .userVerification)
    }

    private enum CodingKeys: String, CodingKey {
        case challenge
        case timeout
        case rpId
        case allowCredentials
        case userVerification
    }
}

/// Information about a generated credential.
///
/// When encoding using `Encodable`, `id` is encoded as base64url.
public struct PublicKeyCredentialDescriptor: Equatable, Encodable {
    /// Defines hints as to how clients might communicate with a particular authenticator in order to obtain an
    /// assertion for a specific credential
    public enum AuthenticatorTransport: String, Equatable, Encodable {
        /// Indicates the respective authenticator can be contacted over removable USB.
        case usb
        /// Indicates the respective authenticator can be contacted over Near Field Communication (NFC).
        case nfc
        /// Indicates the respective authenticator can be contacted over Bluetooth Smart (Bluetooth Low Energy / BLE).
        case ble
        /// Indicates the respective authenticator can be contacted using a combination of (often separate)
        /// data-transport and proximity mechanisms. This supports, for example, authentication on a desktop
        /// computer using a smartphone.
        case hybrid
        /// Indicates the respective authenticator is contacted using a client device-specific transport, i.e., it is
        /// a platform authenticator. These authenticators are not removable from the client device.
        case `internal`
    }

    /// Will always be 'public-key'
    public let type: String

    /// The sequence of bytes representing the credential's ID
    ///
    /// When encoding using `Encodable`, this is encoded as base64url.
    public let id: [UInt8]

    /// The types of connections to the client/browser the authenticator supports
    public let transports: [AuthenticatorTransport]

    public init(type: String, id: [UInt8], transports: [AuthenticatorTransport] = []) {
        self.type = type
        self.id = id
        self.transports = transports
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        try container.encode(type, forKey: .type)
        try container.encode(id.base64URLEncodedString(), forKey: .id)
        try container.encodeIfPresent(transports, forKey: .transports)
    }

    private enum CodingKeys: String, CodingKey {
        case type
        case id
        case transports
    }
}

/// The Relying Party may require user verification for some of its operations but not for others, and may use this
/// type to express its needs.
public enum UserVerificationRequirement: String, Encodable {
    /// The Relying Party requires user verification for the operation and will fail the overall ceremony if the
    /// user wasn't verified.
    case required
    /// The Relying Party prefers user verification for the operation if possible, but will not fail the operation.
    case preferred
    /// The Relying Party does not want user verification employed during the operation (e.g., in the interest of
    /// minimizing disruption to the user interaction flow).
    case discouraged
}
