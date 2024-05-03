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

import X509

public struct AttestationResult {
    public enum AttestationType {
        /// Attestation key pair validated by device manufacturer CA
        case basicFull
        /// Attestation signed by the public key generated during the registration
        case `self`
        case attCA
        case anonCA
        case none
    }
    
    public let format: AttestationFormat
    public let type: AttestationType
    public let trustChain: [Certificate]
    
    public let attestedCredentialData: AttestedCredentialData
}
