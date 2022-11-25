/// SessionData is the data that should be stored by the Relying Party for the duration of the web authentication
/// ceremony
public struct SessionData {
    public let challenge: String
    public let userID: String
}