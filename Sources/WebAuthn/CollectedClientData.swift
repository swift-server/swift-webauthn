import Foundation

/// https://www.w3.org/TR/webauthn/#dictionary-client-data
/// The client data represents the contextual bindings of both the WebAuthn Relying Party and the client.
struct CollectedClientData: Codable, Hashable {
    enum CollectedClientDataVerifyError: Error {
        case ceremonyTypeDoesNotMatch
        case challengeDoesNotMatch
        case originDoesNotMatch
    }

    let type: CeremonyType
    let challenge: String
    let origin: String
    // TODO: Token binding


    func verify(storedChallenge: String, ceremonyType: CeremonyType, relyingPartyOrigin: String) throws {
        guard type == ceremonyType else { throw CollectedClientDataVerifyError.ceremonyTypeDoesNotMatch }
        guard challenge == storedChallenge else { throw CollectedClientDataVerifyError.challengeDoesNotMatch }
        guard origin == relyingPartyOrigin else { throw CollectedClientDataVerifyError.originDoesNotMatch }
    }
}