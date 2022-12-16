//===----------------------------------------------------------------------===//
//
// This source file is part of the WebAuthn Swift open source project
//
// Copyright (c) 2022 the WebAuthn Swift project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of WebAuthn Swift project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import SwiftCBOR

struct AttestationObject {
    let authenticatorData: AuthenticatorData
    let rawAuthenticatorData: [UInt8]
    let format: AttestationFormat
    let attestationStatement: CBOR

    func verify(relyingPartyID: String, verificationRequired: Bool, clientDataHash: SHA256.Digest) throws {
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

        // Step 17. happening somewhere else (maybe we can move it here?)

        // Attestation format already determined. Skipping step 19.

        // Step 20.
        switch format {
        case .androidKey:
            fatalError("Not implemented")
        case .androidSafetynet:
            fatalError("Not implemented")
        case .apple:
            fatalError("Not implemented")
        case .fidoU2F:
            fatalError("Not implemented")
        case .packed:
            try AttestationStatementVerification.verifyPacked(attestationObject: self, clientDataHash: clientDataHash)
        case .tpm:
            fatalError("Not implemented")
        case .none:
            // if format is `none` statement must be empty
            guard attestationStatement == .map([:]) else {
                throw WebAuthnError.attestationStatementMissing
            }
        }
    }
}
