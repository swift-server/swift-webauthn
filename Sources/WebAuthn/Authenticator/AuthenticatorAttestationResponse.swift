import Foundation

public struct AuthenticatorAttestationResponse: Codable {
    let clientDataJSON: String
    let attestationObject: String
}

public struct ParsedAuthenticatorAttestationResponse {
    let clientData: CollectedClientData
    let attestationObject: AttestationObject
}