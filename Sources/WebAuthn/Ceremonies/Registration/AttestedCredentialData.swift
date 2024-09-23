//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift WebAuthn open source project
//
// Copyright (c) 2022 the Swift WebAuthn project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Swift WebAuthn project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// Contains the new public key created by the authenticator.
struct AttestedCredentialData: Equatable {
    let authenticatorAttestationGUID: AAGUID
    let credentialID: [UInt8]
    let publicKey: [UInt8]
}
