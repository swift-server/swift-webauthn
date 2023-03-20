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
public struct PublicKeyCredentialRequestOptions: Codable {
    /// A challenge that the authenticator signs, along with other data, when producing an authentication assertion
    public let challenge: EncodedBase64
    /// A `TimeInterval`, that the Relying Party is willing to wait for the call to complete. The value is treated
    /// as a hint, and may be overridden by the client.
    public let timeout: TimeInterval?
    /// The Relying Party ID.
    public let rpId: String?
    /// Optionally used by the client to find authenticators eligible for this authentication ceremony.
    public let allowCredentials: [PublicKeyCredentialDescriptor]?
    /// Specifies whether the user should be verified during the authentication ceremony.
    public let userVerification: UserVerificationRequirement?
    // let extensions: [String: Any]
}

/// Information about a generated credential.
public struct PublicKeyCredentialDescriptor: Codable, Equatable {
    /// Defines hints as to how clients might communicate with a particular authenticator in order to obtain an
    /// assertion for a specific credential
    public enum AuthenticatorTransport: String, Codable, Equatable {
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

    enum CodingKeys: String, CodingKey {
        case type, id, transports
    }

    /// Will always be 'public-key'
    public let type: String
    /// The sequence of bytes representing the credential's ID
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
        try container.encode(id.base64EncodedString(), forKey: .id)
        try container.encode(transports, forKey: .transports)
    }
}

/// The Relying Party may require user verification for some of its operations but not for others, and may use this
/// type to express its needs.
public enum UserVerificationRequirement: String, Codable {
    /// The Relying Party requires user verification for the operation and will fail the overall ceremony if the
    /// user wasn't verified.
    case required
    /// The Relying Party prefers user verification for the operation if possible, but will not fail the operation.
    case preferred
    /// The Relying Party does not want user verification employed during the operation (e.g., in the interest of
    /// minimizing disruption to the user interaction flow).
    case discouraged
}
