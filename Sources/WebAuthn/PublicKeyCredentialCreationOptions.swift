/// See §5.4. https://www.w3.org/TR/webauthn/#dictionary-makecredentialoptions
/// Contains a PublicKeyCredentialCreationOptions object specifying the desired attributes of the
/// to-be-created public key credential.
public struct PublicKeyCredentialCreationOptions: Codable {
    public let challenge: String
    public let user: PublicKeyCredentialUserEntity
    public let relyingParty: PublicKeyCredentialRpEntity
}