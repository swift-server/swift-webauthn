import Foundation

public struct RegisterWebAuthnCredentialData: Codable {
    public let id: String
    let rawID: String
    let type: String
    let response: RegisterCredentialsResponse
    
    enum CodingKeys: String, CodingKey {
        case id
        case rawID = "rawId"
        case type
        case response
    }
}

public struct RegisterCredentialsResponse: Codable {
    let attestationObject: String
    let clientDataJSON: String
}
