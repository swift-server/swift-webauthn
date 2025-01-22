//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift WebAuthn open source project
//
// Copyright (c) 2022 the Swift WebAuthn project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import SwiftOpenAPI

/// The `PublicKeyCredentialRequestOptions` gets passed to the WebAuthn API (`navigator.credentials.get()`)
///
/// When encoding using `Encodable`, the byte arrays are encoded as base64url.
///
/// - SeeAlso: https://www.w3.org/TR/webauthn-2/#dictionary-assertion-options
@OpenAPIDescriptable
public struct PublicKeyCredentialRequestOptions: Codable, Sendable {
    /// A challenge that the authenticator signs, along with other data, when producing an authentication assertion
    ///
    /// When encoding using `Encodable` this is encoded as base64url.
    public var challenge: [UInt8]

    /// A time, in seconds, that the caller is willing to wait for the call to complete. This is treated as a
    /// hint, and may be overridden by the client.
    ///
    /// - Note: When encoded, this value is represented in milleseconds as a ``UInt32``.
    /// See https://www.w3.org/TR/webauthn-2/#dictionary-assertion-options
    public var timeout: Duration?

    /// The ID of the Relying Party making the request.
    ///
    /// This is configured on ``WebAuthnManager`` before its ``WebAuthnManager/beginAuthentication(timeout:allowCredentials:userVerification:)`` method is called.
    /// - Note: When encoded, this field appears as `rpId` to match the expectations of `navigator.credentials.get()`.
    public var relyingPartyID: String

    /// Optionally used by the client to find authenticators eligible for this authentication ceremony.
    public var allowCredentials: [PublicKeyCredentialDescriptor]?

    /// Specifies whether the user should be verified during the authentication ceremony.
    public var userVerification: UserVerificationRequirement?

    // let extensions: [String: Any]

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        try container.encode(challenge.base64URLEncodedString(), forKey: .challenge)
        try container.encodeIfPresent(timeout?.milliseconds, forKey: .timeout)
        try container.encode(relyingPartyID, forKey: .relyingPartyID)
        try container.encodeIfPresent(allowCredentials, forKey: .allowCredentials)
        try container.encodeIfPresent(userVerification, forKey: .userVerification)
    }
    
    public init(challenge: [UInt8], timeout: Duration?, relyingPartyID: String, allowCredentials: [PublicKeyCredentialDescriptor]?, userVerification: UserVerificationRequirement?) {
        self.challenge = challenge
        self.timeout = timeout
        self.relyingPartyID = relyingPartyID
        self.allowCredentials = allowCredentials
        self.userVerification = userVerification
    }

    public init(_ src : PublicKeyCredentialRequestOptions) {
        self.challenge=src.challenge
        self.timeout=src.timeout
        self.relyingPartyID=src.relyingPartyID
        self.allowCredentials=src.allowCredentials
        self.userVerification = src.userVerification
    }
    
    public init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)

        self.challenge = try values.decodeBytesFromURLEncodedBase64(forKey: .challenge)

        if let timeout = try values.decodeIfPresent(UInt32.self, forKey:.timeout) {
            self.timeout=Duration.milliseconds(timeout)
        }
        self.relyingPartyID=try values.decode(String.self, forKey:.relyingPartyID)
        self.allowCredentials=try values.decodeIfPresent([PublicKeyCredentialDescriptor].self,forKey: .allowCredentials)
        self.userVerification=try values.decodeIfPresent(UserVerificationRequirement.self,forKey: .userVerification)
    }

    private enum CodingKeys: String, CodingKey {
        case challenge
        case timeout
        case relyingPartyID = "rpId"
        case allowCredentials
        case userVerification
    }
}

/// Information about a generated credential.
///
/// When encoding using `Encodable`, `id` is encoded as base64url.
public struct PublicKeyCredentialDescriptor: Equatable, Codable, Sendable {
    /// Defines hints as to how clients might communicate with a particular authenticator in order to obtain an
    /// assertion for a specific credential
    public enum AuthenticatorTransport: String, Equatable, Codable, Sendable {
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

    /// Will always be ``CredentialType/publicKey``
    public let type: CredentialType

    /// The sequence of bytes representing the credential's ID
    ///
    /// When encoding using `Encodable`, this is encoded as base64url.
    public let id: [UInt8]

    /// The types of connections to the client/browser the authenticator supports
    public let transports: [AuthenticatorTransport]

    public init(
        type: CredentialType = .publicKey,
        id: [UInt8],
        transports: [AuthenticatorTransport] = []
    ) {
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
    
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type = try container.decode(CredentialType.self,forKey: .type)
        let id = try container.decodeBytesFromURLEncodedBase64( forKey: .id)
        let transports = try container.decodeIfPresent([AuthenticatorTransport].self,forKey:.transports) ?? []
        self.init(type: type, id:id, transports: transports)
    }

    private enum CodingKeys: String, CodingKey {
        case type
        case id
        case transports
    }
}

/// The Relying Party may require user verification for some of its operations but not for others, and may use this
/// type to express its needs.
public enum UserVerificationRequirement: String, Codable, Sendable {
    /// The Relying Party requires user verification for the operation and will fail the overall ceremony if the
    /// user wasn't verified.
    case required
    /// The Relying Party prefers user verification for the operation if possible, but will not fail the operation.
    case preferred
    /// The Relying Party does not want user verification employed during the operation (e.g., in the interest of
    /// minimizing disruption to the user interaction flow).
    case discouraged
}
