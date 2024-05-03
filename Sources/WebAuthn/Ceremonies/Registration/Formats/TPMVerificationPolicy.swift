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

/// Based on https://www.w3.org/TR/webauthn-2/#sctn-tpm-cert-requirements
/// Note: we are **not** validating the certificates dates.
struct TPMVerificationPolicy: VerifierPolicy {
    let verifyingCriticalExtensions: [ASN1ObjectIdentifier] = [
        .X509ExtensionID.basicConstraints,
        .X509ExtensionID.nameConstraints,
        // The Subject Alternative Name extension MUST be set as defined in [TPMv2-EK-Profile] section 3.2.9.
        .X509ExtensionID.subjectAlternativeName,
        .X509ExtensionID.keyUsage,
        .certificatePolicies,
    ]

    func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) -> PolicyEvaluationResult {
        let leaf = chain.leaf
        
        // Version MUST be set to 3
        guard leaf.version == .v3 else {
            return .failsToMeetPolicy(
                reason: "Version MUST be set to 3: \(leaf)"
            )
        }
        
        // The Subject Alternative Name extension MUST be set as defined in [TPMv2-EK-Profile] section 3.2.9.
        // Note: looks like some TPM attestation certs signed by Microsoft have neither subject nor SAN.
        /*guard let san = try? leaf.extensions.subjectAlternativeNames else {
            return .failsToMeetPolicy(
                reason: "Subject Alternative Name extension MUST be set: \(leaf)"
            )
        }*/
        
        // The Extended Key Usage extension MUST contain the "joint-iso-itu-t(2) internationalorganizations(23) 133 tcg-kp(8) tcg-kp-AIKCertificate(3)" OID.
        guard let eku = try? leaf.extensions.extendedKeyUsage, eku.contains(.init(oid: .tcgKpAIKCertificate)) else {
            return .failsToMeetPolicy(
                reason: "Extended Key Usage extension MUST contain the tcg-kp-AIKCertificate OID: \(leaf)"
            )
        }
        
        // The Basic Constraints extension MUST have the CA component set to false
        guard let basic = try? leaf.extensions.basicConstraints, case .notCertificateAuthority = basic else {
            return .failsToMeetPolicy(
                reason: "The Basic Constraints extension MUST have CA set to false: \(leaf)"
            )
        }
        return .meetsPolicy
    }
}
