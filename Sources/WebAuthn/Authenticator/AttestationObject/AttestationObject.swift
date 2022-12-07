import Crypto

struct AttestationObject {
    let authenticatorData: AuthenticatorData
    let rawAuthenticatorData: [UInt8]
    let format: AttestationFormat
    let attestationStatement: [String: Any]

    func verify(relyingPartyID: String, verificationRequired: Bool) throws {
        let relyingPartyIDHash = SHA256.hash(data: relyingPartyID.data(using: .utf8)!)

        try authenticatorData.verify(
            relyingPartyIDHash: relyingPartyIDHash,
            requireUserVerification: verificationRequired
        )

        if format == .iana(.none) {
            guard attestationStatement.isEmpty else {
                throw WebAuthnError.attestationStatementMissing
            }
        }

        // TODO: Verify attestationStatement is valid
    }
}
