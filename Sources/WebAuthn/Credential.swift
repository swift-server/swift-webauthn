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
import Foundation

/// Credential contains all needed information about a WebAuthn credential for storage
public struct Credential {
    /// base64 encoded String of the credential ID bytes
    public let id: String

    /// The public key for this certificate
    public let publicKey: P256.Signing.PublicKey

    /// The attestation format used (if any) by the authenticator when creating the credential.
    public let attestationType: AttestationFormat

    /// The Authenticator information for a given certificate
    public let authenticator: Authenticator

    init(
        id: String,
        publicKey: P256.Signing.PublicKey,
        attestationType: AttestationFormat,
        authenticator: Authenticator
    ) {
        self.id = id
        self.publicKey = publicKey
        self.attestationType = attestationType
        self.authenticator = authenticator
    }
}

extension Credential {
    init(from data: ParsedCredentialCreationResponse) throws {
        guard let attestedData = data.response.attestationObject.authenticatorData.attestedData else {
            throw WebAuthnError.missingAttestedCredentialDataForCredentialCreateFlow
        }

        self.id = attestedData.credentialID.base64URLEncodedString()
        self.publicKey = try EC2PublicKeyData(from: attestedData.publicKey).key()
        self.attestationType = data.response.attestationObject.format

        self.authenticator = Authenticator(
            aaguid: attestedData.aaguid,
            signCount: data.response.attestationObject.authenticatorData.counter
        )
    }
}
