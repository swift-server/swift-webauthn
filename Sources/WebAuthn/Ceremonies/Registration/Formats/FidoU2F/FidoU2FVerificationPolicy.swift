//===----------------------------------------------------------------------===//
//
// This source file is part of the WebAuthn Swift open source project
//
// Copyright (c) 2023 the WebAuthn Swift project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of WebAuthn Swift project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import SwiftASN1
import X509

// Based on https://www.w3.org/TR/webauthn-2/#sctn-fido-u2f-attestation
struct FidoU2FVerificationPolicy: VerifierPolicy {
    let verifyingCriticalExtensions: [ASN1ObjectIdentifier] = [
        .X509ExtensionID.basicConstraints,
        .X509ExtensionID.nameConstraints,
        .X509ExtensionID.subjectAlternativeName,
        .X509ExtensionID.keyUsage,
    ]

    func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) -> PolicyEvaluationResult {
        // Check that x5c has exactly one element
        guard chain.count == 1 else {
            return .failsToMeetPolicy(
                reason: "Authenticator attestation must return exactly 1 certificate, got \(chain.count)"
            )
        }
        
        let leaf = chain.leaf
        // Certificate public key must be an Elliptic Curve (EC) public key over the P-256 curve,
        guard leaf.signatureAlgorithm == .ecdsaWithSHA256 else {
            return .failsToMeetPolicy(
                reason: "Public key must be Elliptic Curve (EC) P-256: \(leaf)"
            )
        }
        return .meetsPolicy
    }
}
