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
public struct AttestedCredentialData: Equatable, Sendable {
    var authenticatorAttestationGUID: AAGUID
    var credentialID: [UInt8]
    var publicKey: [UInt8]
}
