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

/// Contains the cryptographic attestation that a new key pair was created by that authenticator.
public struct AttestationObject: Equatable {
    let authenticatorData: AuthenticatorData
    let rawAuthenticatorData: [UInt8]
    let format: AttestationFormat
    let attestationStatement: CBOR

    func verify(relyingPartyID: String, verificationRequired: Bool, clientDataHash: SHA256.Digest) throws {
        let relyingPartyIDHash = SHA256.hash(data: relyingPartyID.data(using: .utf8)!)

        guard relyingPartyIDHash == authenticatorData.relyingPartyIDHash else {
            throw WebAuthnError.relyingPartyIDHashDoesNotMatch
        }

        guard authenticatorData.flags.userPresent else {
            throw WebAuthnError.userPresentFlagNotSet
        }

        if verificationRequired {
            guard authenticatorData.flags.userVerified else {
                throw WebAuthnError.userVerificationRequiredButFlagNotSet
            }
        }

        switch format {
        case .none:
            // if format is `none` statement must be empty
            guard attestationStatement == .map([:]) else {
                throw WebAuthnError.attestationStatementMissing
            }
        default:
            throw WebAuthnError.attestationVerificationNotSupported
        }
    }
}
