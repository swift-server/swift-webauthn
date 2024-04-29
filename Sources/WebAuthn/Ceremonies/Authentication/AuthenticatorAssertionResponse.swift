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
///
/// When decoding using `Decodable`, byte arrays are decoded from base64url to bytes.
public struct AuthenticatorAssertionResponse: Sendable {
    /// Representation of what we passed to `navigator.credentials.get()`
    ///
    /// When decoding using `Decodable`, this is decoded from base64url to bytes.
    public let clientDataJSON: [UInt8]

    /// Contains the authenticator data returned by the authenticator.
    ///
    /// When decoding using `Decodable`, this is decoded from base64url to bytes.
    public let authenticatorData: [UInt8]

    /// Contains the raw signature returned from the authenticator
    ///
    /// When decoding using `Decodable`, this is decoded from base64url to bytes.
    public let signature: [UInt8]

    /// Contains the user handle returned from the authenticator, or null if the authenticator did not return
    /// a user handle. Used by to give scope to credentials.
    ///
    /// When decoding using `Decodable`, this is decoded from base64url to bytes.
    public let userHandle: [UInt8]?

    /// Contains an attestation object, if the authenticator supports attestation in assertions.
    /// The attestation object, if present, includes an attestation statement. Unlike the attestationObject
    /// in an AuthenticatorAttestationResponse, it does not contain an authData key because the authenticator
    /// data is provided directly in an AuthenticatorAssertionResponse structure.
    ///
    /// When decoding using `Decodable`, this is decoded from base64url to bytes.
    public let attestationObject: [UInt8]?
}

extension AuthenticatorAssertionResponse: Decodable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        clientDataJSON = try container.decodeBytesFromURLEncodedBase64(forKey: .clientDataJSON)
        authenticatorData = try container.decodeBytesFromURLEncodedBase64(forKey: .authenticatorData)
        signature = try container.decodeBytesFromURLEncodedBase64(forKey: .signature)
        userHandle = try container.decodeBytesFromURLEncodedBase64IfPresent(forKey: .userHandle)
        attestationObject = try container.decodeBytesFromURLEncodedBase64IfPresent(forKey: .attestationObject)
    }

    private enum CodingKeys: String, CodingKey {
        case clientDataJSON
        case authenticatorData
        case signature
        case userHandle
        case attestationObject
    }
}

struct ParsedAuthenticatorAssertionResponse: Sendable {
    let rawClientData: [UInt8]
    let clientData: CollectedClientData
    let rawAuthenticatorData: [UInt8]
    let authenticatorData: AuthenticatorData
    let signature: URLEncodedBase64
    let userHandle: [UInt8]?

    init(from authenticatorAssertionResponse: AuthenticatorAssertionResponse) throws {
        rawClientData = authenticatorAssertionResponse.clientDataJSON
        clientData = try JSONDecoder().decode(CollectedClientData.self, from: Data(rawClientData))

        rawAuthenticatorData = authenticatorAssertionResponse.authenticatorData
        authenticatorData = try AuthenticatorData(bytes: rawAuthenticatorData)
        signature = authenticatorAssertionResponse.signature.base64URLEncodedString()
        userHandle = authenticatorAssertionResponse.userHandle
    }

    // swiftlint:disable:next function_parameter_count
    func verify(
        expectedChallenge: [UInt8],
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

        guard let expectedRelyingPartyIDData = relyingPartyID.data(using: .utf8) else {
            throw WebAuthnError.invalidRelyingPartyID
        }
        let expectedRelyingPartyIDHash = SHA256.hash(data: expectedRelyingPartyIDData)
        guard expectedRelyingPartyIDHash == authenticatorData.relyingPartyIDHash else {
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
