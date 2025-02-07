//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift WebAuthn open source project
//
// Copyright (c) 2022 the Swift WebAuthn project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

/// An error that occured preparing or processing WebAuthn-related requests.
public struct WebAuthnError: Error, Hashable, Sendable {
    enum Reason: Error {
        // MARK: Shared
        case attestedCredentialDataMissing
        case relyingPartyIDHashDoesNotMatch
        case userPresentFlagNotSet
        case invalidSignature

        // MARK: AttestationObject
        case userVerificationRequiredButFlagNotSet
        case attestationStatementMustBeEmpty
        case attestationVerificationNotSupported

        // MARK: WebAuthnManager
        case invalidUserID
        case unsupportedCredentialPublicKeyAlgorithm
        case credentialIDAlreadyExists
        case userVerifiedFlagNotSet
        case potentialReplayAttack
        case invalidAssertionCredentialType

        // MARK: ParsedAuthenticatorAttestationResponse
        case invalidAttestationObject
        case invalidAuthData
        case invalidFmt
        case missingAttStmt
        case attestationFormatNotSupported

        // MARK: ParsedCredentialCreationResponse
        case invalidCredentialCreationType
        case credentialRawIDTooLong

        // MARK: AuthenticatorData
        case authDataTooShort
        case attestedCredentialFlagNotSet
        case extensionDataMissing
        case leftOverBytesInAuthenticatorData
        case credentialIDTooLong
        case credentialIDTooShort
        case invalidPublicKeyLength

        // MARK: CredentialPublicKey
        case badPublicKeyBytes
        case invalidKeyType
        case invalidAlgorithm
        case invalidCurve
        case invalidXCoordinate
        case invalidYCoordinate
        case unsupportedCOSEAlgorithm
        case unsupportedCOSEAlgorithmForEC2PublicKey
        case invalidModulus
        case invalidExponent
        case unsupportedCOSEAlgorithmForRSAPublicKey
        case unsupported
    }
    
    let reason: Reason
    
    init(reason: Reason) {
        self.reason = reason
    }
    
    // MARK: Shared
    public static let attestedCredentialDataMissing = Self(reason: .attestedCredentialDataMissing)
    public static let relyingPartyIDHashDoesNotMatch = Self(reason: .relyingPartyIDHashDoesNotMatch)
    public static let userPresentFlagNotSet = Self(reason: .userPresentFlagNotSet)
    public static let invalidSignature = Self(reason: .invalidSignature)

    // MARK: AttestationObject
    public static let userVerificationRequiredButFlagNotSet = Self(reason: .userVerificationRequiredButFlagNotSet)
    public static let attestationStatementMustBeEmpty = Self(reason: .attestationStatementMustBeEmpty)
    public static let attestationVerificationNotSupported = Self(reason: .attestationVerificationNotSupported)

    // MARK: WebAuthnManager
    public static let invalidUserID = Self(reason: .invalidUserID)
    public static let unsupportedCredentialPublicKeyAlgorithm = Self(reason: .unsupportedCredentialPublicKeyAlgorithm)
    public static let credentialIDAlreadyExists = Self(reason: .credentialIDAlreadyExists)
    public static let userVerifiedFlagNotSet = Self(reason: .userVerifiedFlagNotSet)
    public static let potentialReplayAttack = Self(reason: .potentialReplayAttack)
    public static let invalidAssertionCredentialType = Self(reason: .invalidAssertionCredentialType)

    // MARK: ParsedAuthenticatorAttestationResponse
    public static let invalidAttestationObject = Self(reason: .invalidAttestationObject)
    public static let invalidAuthData = Self(reason: .invalidAuthData)
    public static let invalidFmt = Self(reason: .invalidFmt)
    public static let missingAttStmt = Self(reason: .missingAttStmt)
    public static let attestationFormatNotSupported = Self(reason: .attestationFormatNotSupported)

    // MARK: ParsedCredentialCreationResponse
    public static let invalidCredentialCreationType = Self(reason: .invalidCredentialCreationType)
    public static let credentialRawIDTooLong = Self(reason: .credentialRawIDTooLong)

    // MARK: AuthenticatorData
    public static let authDataTooShort = Self(reason: .authDataTooShort)
    public static let attestedCredentialFlagNotSet = Self(reason: .attestedCredentialFlagNotSet)
    public static let extensionDataMissing = Self(reason: .extensionDataMissing)
    public static let leftOverBytesInAuthenticatorData = Self(reason: .leftOverBytesInAuthenticatorData)
    public static let credentialIDTooLong = Self(reason: .credentialIDTooLong)
    public static let credentialIDTooShort = Self(reason: .credentialIDTooShort)
    public static let invalidPublicKeyLength = Self(reason: .invalidPublicKeyLength)

    // MARK: CredentialPublicKey
    public static let badPublicKeyBytes = Self(reason: .badPublicKeyBytes)
    public static let invalidKeyType = Self(reason: .invalidKeyType)
    public static let invalidAlgorithm = Self(reason: .invalidAlgorithm)
    public static let invalidCurve = Self(reason: .invalidCurve)
    public static let invalidXCoordinate = Self(reason: .invalidXCoordinate)
    public static let invalidYCoordinate = Self(reason: .invalidYCoordinate)
    public static let unsupportedCOSEAlgorithm = Self(reason: .unsupportedCOSEAlgorithm)
    public static let unsupportedCOSEAlgorithmForEC2PublicKey = Self(reason: .unsupportedCOSEAlgorithmForEC2PublicKey)
    public static let invalidModulus = Self(reason: .invalidModulus)
    public static let invalidExponent = Self(reason: .invalidExponent)
    public static let unsupportedCOSEAlgorithmForRSAPublicKey = Self(reason: .unsupportedCOSEAlgorithmForRSAPublicKey)
    public static let unsupported = Self(reason: .unsupported)
}
