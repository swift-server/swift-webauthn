import Foundation

public struct AssertionCredential: Codable {
    public let id: String
    public let type: String
    public let response: AssertionCredentialResponse
    public let rawID: String
    
    enum CodingKeys: String, CodingKey {
        case id
        case rawID = "rawId"
        case type
        case response
    }
}

public struct AssertionCredentialResponse: Codable {
    let authenticatorData: String
    let clientDataJSON: String
    let signature: String
    let userHandle: String
}
