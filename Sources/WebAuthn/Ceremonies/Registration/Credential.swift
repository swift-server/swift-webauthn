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

import Foundation

/// After a successful registration ceremony we pass this data back to the relying party. It contains all needed
/// information about a WebAuthn credential for storage in e.g. a database.
public struct Credential: Sendable {
    /// Value will always be ``CredentialType/publicKey`` (for now)
    public let type: CredentialType

    /// base64 encoded String of the credential ID bytes
    public let id: String

    /// The public key for this certificate
    public let publicKey: [UInt8]

    /// How often the authenticator says the credential was used
    /// If this is not implemented by the authenticator this value will always be zero.
    public let signCount: UInt32

    /// Wether the public key is allowed to be backed up.
    /// If a public key is considered backup eligible it is referred to as a multi-device credential (the
    /// opposite being single-device credential)
    public let backupEligible: Bool

    /// If the public key is currently backed up (using another authenticator than the one that generated
    /// the credential)
    public let isBackedUp: Bool

    // MARK: Optional content

    public let attestationObject: AttestationObject

    public let attestationClientDataJSON: CollectedClientData
}
