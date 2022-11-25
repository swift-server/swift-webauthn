public struct Config {
    public let relyingPartyDisplayName: String
    public let relyingPartyID: String

    public init(relyingPartyDisplayName: String, relyingPartyID: String) {
        self.relyingPartyDisplayName = relyingPartyDisplayName
        self.relyingPartyID = relyingPartyID
    }
}

public var config: Config!