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

import Foundation
import Crypto

/// This is what the authenticator device returned after we requested it to authenticate a user.
public struct AuthenticatorAssertionResponse: Codable {
    /// Representation of what we passed to `navigator.credentials.get()`
    public let clientDataJSON: URLEncodedBase64
    /// Contains the authenticator data returned by the authenticator.
    public let authenticatorData: URLEncodedBase64
    /// Contains the raw signature returned from the authenticator
    public let signature: URLEncodedBase64
    /// Contains the user handle returned from the authenticator, or null if the authenticator did not return
    /// a user handle. Used by to give scope to credentials.
    public let userHandle: [UInt8]?
    /// Contains an attestation object, if the authenticator supports attestation in assertions.
    /// The attestation object, if present, includes an attestation statement. Unlike the attestationObject
    /// in an AuthenticatorAttestationResponse, it does not contain an authData key because the authenticator
    /// data is provided directly in an AuthenticatorAssertionResponse structure.
    public let attestationObject: String?
}

struct ParsedAuthenticatorAssertionResponse {
    let rawClientData: Data
    let clientData: CollectedClientData
    let rawAuthenticatorData: Data
    let authenticatorData: AuthenticatorData
    let signature: URLEncodedBase64
    let userHandle: [UInt8]?

    init(from authenticatorAssertionResponse: AuthenticatorAssertionResponse) throws {
        guard let clientDataData = authenticatorAssertionResponse.clientDataJSON.urlDecoded.decoded else {
            throw WebAuthnError.invalidClientDataJSON
        }
        rawClientData = clientDataData
        clientData = try JSONDecoder().decode(CollectedClientData.self, from: clientDataData)

        guard let authenticatorDataBytes = authenticatorAssertionResponse.authenticatorData.urlDecoded.decoded else {
            throw WebAuthnError.invalidAuthenticatorData
        }
        rawAuthenticatorData = authenticatorDataBytes
        authenticatorData = try AuthenticatorData(bytes: authenticatorDataBytes)
        signature = authenticatorAssertionResponse.signature
        userHandle = authenticatorAssertionResponse.userHandle
    }

    // swiftlint:disable:next function_parameter_count
    func verify(
        expectedChallenge: URLEncodedBase64,
        relyingPartyOrigin: String,
        relyingPartyID: String,
        requireUserVerification: Bool,
        credentialPublicKey: [UInt8],
        credentialCurrentSignCount: UInt32
    ) throws {
        try clientData.verify(
            storedChallenge: expectedChallenge,
            ceremonyType: .assert,
            relyingPartyOrigin: relyingPartyOrigin
        )

        guard let expectedRpIDData = relyingPartyID.data(using: .utf8) else {
            throw WebAuthnError.invalidRelyingPartyID
        }
        let expectedRpIDHash = SHA256.hash(data: expectedRpIDData)
        guard expectedRpIDHash == authenticatorData.relyingPartyIDHash else {
            throw WebAuthnError.relyingPartyIDHashDoesNotMatch
        }

        guard authenticatorData.flags.userPresent else { throw WebAuthnError.userPresentFlagNotSet }
        if requireUserVerification {
            guard authenticatorData.flags.userVerified else { throw WebAuthnError.userVerifiedFlagNotSet }
        }

        if authenticatorData.counter > 0 || credentialCurrentSignCount > 0 {
            guard authenticatorData.counter > credentialCurrentSignCount else {
                // This is a signal that the authenticator may be cloned, i.e. at least two copies of the credential
                // private key may exist and are being used in parallel.
                throw WebAuthnError.potentialReplayAttack
            }
        }

        let clientDataHash = SHA256.hash(data: rawClientData)
        let signatureBase = rawAuthenticatorData + clientDataHash

        let credentialPublicKey = try CredentialPublicKey(publicKeyBytes: credentialPublicKey)
        guard let signatureData = signature.urlDecoded.decoded else { throw WebAuthnError.invalidSignature }
        try credentialPublicKey.verify(signature: signatureData, data: signatureBase)
    }
}
