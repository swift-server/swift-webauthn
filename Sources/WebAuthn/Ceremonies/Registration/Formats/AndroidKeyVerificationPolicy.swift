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

/// Based on https://www.w3.org/TR/webauthn-2/#sctn-fido-u2f-attestation
public struct AndroidKeyVerificationPolicy: VerifierPolicy {
    public let verifyingCriticalExtensions: [ASN1ObjectIdentifier] = [
        .X509ExtensionID.basicConstraints,
        .X509ExtensionID.nameConstraints,
        .X509ExtensionID.subjectAlternativeName,
        .X509ExtensionID.keyUsage,
    ]

    public func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) -> PolicyEvaluationResult {
        let leaf = chain.leaf
        
        return .meetsPolicy
    }
}
