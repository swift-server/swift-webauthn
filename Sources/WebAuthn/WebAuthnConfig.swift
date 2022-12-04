import Foundation

public struct WebAuthnConfig {
    public let relyingPartyDisplayName: String
    public let relyingPartyID: String
    public let relyingPartyOrigin: String
    public let timeout: TimeInterval

    public init(
        relyingPartyDisplayName: String,
        relyingPartyID: String,
        relyingPartyOrigin: String,
        timeout: TimeInterval
    ) {
        self.relyingPartyDisplayName = relyingPartyDisplayName
        self.relyingPartyID = relyingPartyID
        self.relyingPartyOrigin = relyingPartyOrigin
        self.timeout = timeout
    }
}
