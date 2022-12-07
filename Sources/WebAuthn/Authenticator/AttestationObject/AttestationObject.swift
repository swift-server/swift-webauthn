import Crypto

struct AttestationObject {
    let authenticatorData: AuthenticatorData
    let rawAuthenticatorData: [UInt8]
    let format: AttestationFormat
    let attestationStatement: [String: Any]

    func verify(relyingPartyID: String, verificationRequired: Bool) throws {
        let relyingPartyIDHash = SHA256.hash(data: relyingPartyID.data(using: .utf8)!)

        // Step 12.
        guard relyingPartyIDHash == authenticatorData.relyingPartyIDHash else {
            throw WebAuthnError.relyingPartyIDHashDoesNotMatch
        }

        // Step 13.
        guard authenticatorData.flags.userPresent else {
            throw WebAuthnError.userPresentFlagNotSet
        }

        // Step 14.
        if verificationRequired {
            guard authenticatorData.flags.userVerified else {
                throw WebAuthnError.userVerificationRequiredButFlagNotSet
            }
        }

        // Step 15.
        if authenticatorData.flags.isBackupEligible {
            fatalError("Not implemented yet")
        }

        // Step 16.
        if authenticatorData.flags.isCurrentlyBackedUp {
            fatalError("Not implemented yet")
        }

        // Step 17. happening somewhere else (maybe we can move it here?)

        // Attestation format already determined. Skipping step 19.

        // Step 20.
        // TODO: Implement case .packed first! fatalError the rest
        // switch format {
        // case .androidKey:
        // case .androidSafetynet:
        // case .apple:
        // case .fidoU2F:
        // case .packed:
        // case .tpm:
        // case .none:
        //     guard attestationStatement.isEmpty else { throw WebAuthnError.attestationStatementMissing }
        // }
    }
}
