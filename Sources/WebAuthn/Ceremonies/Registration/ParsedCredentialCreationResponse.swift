import SwiftCBOR
import Foundation
import Crypto

/// The processed response received from `navigator.credentials.create()`.
struct ParsedCredentialCreationResponse {
    let id: String
    let rawID: Data
    /// Value will always be "public-key" (for now)
    let type: String
    let clientExtensionResults: [String: String]?
    let raw: AuthenticatorAttestationResponse
    let response: ParsedAuthenticatorAttestationResponse

    /// Create a `ParsedCredentialCreationResponse` from a raw `CredentialCreationResponse`.
    init(from rawResponse: CredentialCreationResponse) throws {
        id = rawResponse.id

        guard let decodedRawID = rawResponse.rawID.base64URLDecodedData else { throw WebAuthnError.invalidRawID }
        rawID = decodedRawID

        guard rawResponse.type == "public-key" else { throw WebAuthnError.invalidCredentialCreationType }
        type = rawResponse.type

        clientExtensionResults = rawResponse.clientExtensionResults
        raw = rawResponse.attestationResponse
        response = try ParsedAuthenticatorAttestationResponse(from: raw)
    }

    func verify(storedChallenge: String, verifyUser: Bool, relyingPartyID: String, relyingPartyOrigin: String) throws {
        // Step 7. - 9.
        try response.clientData.verify(
            storedChallenge: storedChallenge,
            ceremonyType: .create,
            relyingPartyOrigin: relyingPartyOrigin
        )

        // Step 10.
        guard let clientData = raw.clientDataJSON.data(using: .utf8) else {
            throw WebAuthnError.hashingClientDataJSONFailed
        }
        let hash = SHA256.hash(data: clientData)

        // CBOR decoding happened already. Skipping Step 11.

        // Step 12. - 17.
        try response.attestationObject.verify(
            relyingPartyID: relyingPartyID,
            verificationRequired: verifyUser
        )
    }
}
