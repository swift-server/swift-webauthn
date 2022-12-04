/// SessionData is the data that should be stored by the Relying Party for the duration of the web authentication
/// ceremony
public struct SessionData {
    /// Base64url-encoded challenge string
    public let challenge: String
    /// Plain user id (not encoded)
    public let userID: String

    public init(challenge: String, userID: String) {
        self.challenge = challenge
        self.userID = userID
    }
}