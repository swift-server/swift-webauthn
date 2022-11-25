/// From §5.4.1 (https://www.w3.org/TR/webauthn/#dictionary-pkcredentialentity).
/// `PublicKeyCredentialEntity`` describes a user account, or a WebAuthn Relying Party,
/// with which a public key credential is associated.
public protocol PublicKeyCredentialEntity: Codable {
    var name: String { get }
}

/// From §5.4.2 (https://www.w3.org/TR/webauthn/#sctn-rp-credential-params).
/// The PublicKeyCredentialRpEntity dictionary is used to supply additional Relying Party attributes when creating a
/// new credential.
public struct PublicKeyCredentialRpEntity: PublicKeyCredentialEntity, Codable {
    public let name: String

    public let id: String
}

/// From §5.4.3 (https://www.w3.org/TR/webauthn/#dictionary-user-credential-params)
/// The PublicKeyCredentialUserEntity dictionary is used to supply additional user account attributes when creating a
/// new credential.
public struct PublicKeyCredentialUserEntity: PublicKeyCredentialEntity, Codable {
    public let name: String

    public let id: String
    public let displayName: String
}