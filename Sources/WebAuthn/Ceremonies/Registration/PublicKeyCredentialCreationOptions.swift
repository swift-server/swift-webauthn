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

/// The `PublicKeyCredentialCreationOptions` gets passed to the WebAuthn API (`navigator.credentials.create()`)
///
/// Generally this should not be created manually. Instead use `RelyingParty.beginRegistration()`. When encoding using
/// `Encodable` byte arrays are base64url encoded.
///
/// - SeeAlso: https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions
public struct PublicKeyCredentialCreationOptions: Encodable, Sendable {
    
    /// A byte array randomly generated by the Relying Party. Should be at least 16 bytes long to ensure sufficient
    /// entropy.
    ///
    /// The Relying Party should store the challenge temporarily until the registration flow is complete. When
    /// encoding using `Encodable`, the challenge is base64url encoded.
    public let challenge: [UInt8]

    /// Contains names and an identifier for the user account performing the registration
    public let user: PublicKeyCredentialUserEntity

    /// Contains a name and an identifier for the Relying Party responsible for the request
    public let relyingParty: PublicKeyCredentialRelyingPartyEntity

    /// A list of key types and signature algorithms the Relying Party supports. Ordered from most preferred to least
    /// preferred.
    public let publicKeyCredentialParameters: [PublicKeyCredentialParameters]

    /// A time, in seconds, that the caller is willing to wait for the call to complete. This is treated as a
    /// hint, and may be overridden by the client.
    public let timeout: Duration?

    /// Sets the Relying Party's preference for attestation conveyance. At the time of writing only `none` is
    /// supported.
    public let attestation: AttestationConveyancePreference
    
    /// Use this enumeration to communicate hints to the user-agent about how a request may be best completed. These hints are not requirements, and do not bind the user-agent, but may guide it in providing the best experience by using contextual information that the Relying Party has about the request.
    /// https://www.w3.org/TR/webauthn-3/#enum-hints
    let hints: [Hint]
    
    /// This client registration extension facilitates reporting certain credential properties known by the client to the requesting WebAuthn Relying Party upon creation of a public key credential source as a result of a registration ceremony.
    /// https://www.w3.org/TR/webauthn-2/#sctn-extensions-inputs-outputs
    let extensions: Extensions
    
    /// This member is intended for use by Relying Parties that wish to limit the creation of multiple credentials for the same account on a single authenticator
    /// https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-excludecredentials
    let excludeCredentials: [PublicKeyCredentialDescriptor]
    
    /// This member is intended for use by Relying Parties that wish to select the appropriate authenticators to participate in the create() operation.
    /// https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-authenticatorselection
    let authenticatorSelection:  AuthenticatorSelectionCriteria

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        try container.encode(challenge.base64URLEncodedString(), forKey: .challenge)
        try container.encode(user, forKey: .user)
        try container.encode(relyingParty, forKey: .relyingParty)
        try container.encode(publicKeyCredentialParameters, forKey: .publicKeyCredentialParameters)
        try container.encodeIfPresent(timeout?.milliseconds, forKey: .timeout)
        try container.encode(attestation, forKey: .attestation)
        try container.encode(authenticatorSelection, forKey: .authenticatorSelection)
        try container.encode(hints, forKey: .hints)
        try container.encode(extensions, forKey: .extensions)
        try container.encode(excludeCredentials, forKey: .excludeCredentials)
    }

    private enum CodingKeys: String, CodingKey {
        case challenge
        case user
        case relyingParty = "rp"
        case publicKeyCredentialParameters = "pubKeyCredParams"
        case timeout
        case attestation
        case authenticatorSelection
        case hints
        case extensions
        case excludeCredentials
    }
}

// MARK: - Credential parameters
/// From §5.3 (https://w3c.github.io/TR/webauthn/#dictionary-credential-params)
public struct PublicKeyCredentialParameters: Equatable, Encodable, Sendable {
    /// The type of credential to be created. At the time of writing always ``CredentialType/publicKey``.
    public let type: CredentialType
    /// The cryptographic signature algorithm with which the newly generated credential will be used, and thus also
    /// the type of asymmetric key pair to be generated, e.g., RSA or Elliptic Curve.
    public let alg: COSEAlgorithmIdentifier

    /// Creates a new `PublicKeyCredentialParameters` instance.
    ///
    /// - Parameters:
    ///   - type: The type of credential to be created. At the time of writing always ``CredentialType/publicKey``.
    ///   - alg: The cryptographic signature algorithm to be used with the newly generated credential.
    ///     For example RSA or Elliptic Curve.
    public init(type: CredentialType = .publicKey, alg: COSEAlgorithmIdentifier) {
        self.type = type
        self.alg = alg
    }
}

extension Array where Element == PublicKeyCredentialParameters {
    /// A list of `PublicKeyCredentialParameters` WebAuthn Swift currently supports.
    public static var supported: [Element] {
        COSEAlgorithmIdentifier.allCases.map {
            Element.init(type: .publicKey, alg: $0)
        }
    }
}

// MARK: - Credential entities

/// From §5.4.2 (https://www.w3.org/TR/webauthn/#sctn-rp-credential-params).
/// The PublicKeyCredentialRelyingPartyEntity dictionary is used to supply additional Relying Party attributes when
/// creating a new credential.
public struct PublicKeyCredentialRelyingPartyEntity: Encodable, Sendable {
    /// A unique identifier for the Relying Party entity.
    public let id: String

    /// A human-readable identifier for the Relying Party, intended only for display. For example, "ACME Corporation",
    /// "Wonderful Widgets, Inc." or "ОАО Примертех".
    public let name: String

}

 /// From §5.4.3 (https://www.w3.org/TR/webauthn/#dictionary-user-credential-params)
 /// The PublicKeyCredentialUserEntity dictionary is used to supply additional user account attributes when
 /// creating a new credential.
 ///
 /// When encoding using `Encodable`, `id` is base64url encoded.
public struct PublicKeyCredentialUserEntity: Encodable, Sendable {
    /// Generated by the Relying Party, unique to the user account, and must not contain personally identifying
    /// information about the user.
    ///
    /// When encoding this is base64url encoded.
    public let id: [UInt8]

    /// A human-readable identifier for the user account, intended only for display. It helps the user to
    /// distinguish between user accounts with similar `displayName`s. For example, two different user accounts
    /// might both have the same `displayName`, "Alex P. Müller", but might have different `name` values "alexm",
    /// "alex.mueller@example.com" or "+14255551234".
    public let name: String

    /// A human-readable name for the user account, intended only for display. For example, "Alex P. Müller" or
    /// "田中 倫"
    public let displayName: String

    /// Creates a new ``PublicKeyCredentialUserEntity`` from id, name and displayName
    public init(id: [UInt8], name: String, displayName: String) {
        self.id = id
        self.name = name
        self.displayName = displayName
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        try container.encode(id.base64URLEncodedString(), forKey: .id)
        try container.encode(name, forKey: .name)
        try container.encode(displayName, forKey: .displayName)
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case name
        case displayName
    }
}

public struct Hint: UnreferencedStringEnumeration, Sendable {
    public var rawValue: String
    public init(_ rawValue: String) {
        self.rawValue = rawValue
    }
    
    /// Indicates that the Relying Party believes that users will satisfy this request with a platform authenticator attached to the client device.
    public static let clientDevice: Self = "client-device"
    
    /// Indicates that the Relying Party believes that users will satisfy this request with a physical security key
    public static let securityKey: Self = "security-key"
    
    /// Indicates that the Relying Party believes that users will satisfy this request with general-purpose authenticators such as smartphones.
    public static let hybrid: Self = "hybrid"
}


struct Extensions: Encodable {
    /// Indicate that this extension is requested by the Relying Party.
    /// https://www.w3.org/TR/webauthn-3/#sctn-authenticator-credential-properties-extension
    let credProps: Bool
}

struct  AuthenticatorSelectionCriteria: Encodable {
    /// Specifies the extent to which the Relying Party desires to create a client-side discoverable credential.
    /// https://www.w3.org/TR/webauthn-3/#dom-authenticatorselectioncriteria-residentkey
    let residentKey: ResidentKeyRequirement
    
    /// Relying Parties SHOULD set this to true if, and only if, `residentKey` is set to `required`.
    /// https://www.w3.org/TR/webauthn-3/#dom-authenticatorselectioncriteria-requireresidentkey
    let requireResidentKey: Bool
    
    /// This member specifies the Relying Party's requirements regarding user verification for the create() operation.
    /// https://www.w3.org/TR/webauthn-3/#dom-authenticatorselectioncriteria-userverification
    let userVerification: UserVerificationRequirement
}


public struct ResidentKeyRequirement: UnreferencedStringEnumeration, Sendable {
    public var rawValue: String
    public init(_ rawValue: String) {
        self.rawValue = rawValue
    }
    
    /// The Relying Party requires a client-side discoverable credential.
    /// https://www.w3.org/TR/webauthn-3/#dom-residentkeyrequirement-required
    public static let required: Self = "required"
    
    /// The Relying Party strongly prefers creating a client-side discoverable credential, but will accept a server-side credential.
    /// https://www.w3.org/TR/webauthn-3/#dom-residentkeyrequirement-preferred
    public static let preferred: Self = "preferred"
    
    /// The Relying Party prefers creating a server-side credential, but will accept a client-side discoverable credential.
    /// https://www.w3.org/TR/webauthn-3/#dom-residentkeyrequirement-discouraged
    public static let discouraged: Self = "discouraged"
}
