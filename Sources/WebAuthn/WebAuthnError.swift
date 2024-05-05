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

/// An error that occured preparing or processing WebAuthn-related requests.
public struct WebAuthnError: Error, Hashable {
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
        case invalidRelyingPartyID
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
        
        // MARK: Attestation
        case invalidAttestationCertificate
        case invalidTrustPath
        case invalidAttestationSignatureAlgorithm
        case invalidAttestationPublicKeyType
        case invalidVerificationData
        case attestationPublicKeyAlgorithmMismatch
        case aaguidMismatch
        case attestationPublicKeyMismatch
        case tpmInvalidVersion
        case tpmInvalidPubArea
        case tpmInvalidPubAreaPublicKey
        case tpmInvalidPubAreaCurve
        case tpmCertInfoInvalid
        case tpmInvalidCertAaguid
        case tpmPubAreaExponentDoesNotMatchPubKeyExponent
        case tpmExtraDataDoesNotMatchAttToBeSignedHash
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
    public static let invalidRelyingPartyID = Self(reason: .invalidRelyingPartyID)
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
    
    // MARK: Attestation
    /// Cannot read or parse attestation certificate from attestation statement
    public static let invalidAttestationCertificate = Self(reason: .invalidAttestationCertificate)
    /// Cannot authenticator attestation certificate trust chain up to root CA
    public static let invalidTrustPath = Self(reason: .invalidTrustPath)
    /// Attestation statement algorithm has invalid or unsupported COSE algorithm identifier
    public static let invalidAttestationSignatureAlgorithm = Self(reason: .invalidAttestationSignatureAlgorithm)
    public static let invalidAttestationPublicKeyType = Self(reason: .invalidAttestationPublicKeyType)
    /// Authenticator verification data cannot be validated against attestation signature (authenticator data has been corrupted or tampered with?)
    public static let invalidVerificationData = Self(reason: .invalidVerificationData)
    public static let attestationPublicKeyAlgorithmMismatch = Self(reason: .attestationPublicKeyAlgorithmMismatch)
    /// The authenticator certificate public key does not match the attested data public key
    public static let attestationPublicKeyMismatch = Self(reason: .attestationPublicKeyMismatch)
    /// Value of AAGUID in authenticator data doesn't match value in attestation certificate
    public static let aaguidMismatch = Self(reason: .aaguidMismatch)
    /// Invalid TPM version
    public static let tpmInvalidVersion = Self(reason: .tpmInvalidVersion)
    public static let tpmInvalidPubArea = Self(reason: .tpmInvalidPubArea)
    public static let tpmInvalidPubAreaPublicKey = Self(reason: .tpmInvalidPubAreaPublicKey)
    public static let tpmInvalidPubAreaCurve = Self(reason: .tpmInvalidPubAreaCurve)
    public static let tpmCertInfoInvalid = Self(reason: .tpmCertInfoInvalid)
    public static let tpmInvalidCertAaguid = Self(reason: .tpmInvalidCertAaguid)
    public static let tpmPubAreaExponentDoesNotMatchPubKeyExponent = Self(reason: .tpmPubAreaExponentDoesNotMatchPubKeyExponent)
    public static let tpmExtraDataDoesNotMatchAttToBeSignedHash = Self( reason: .tpmExtraDataDoesNotMatchAttToBeSignedHash)
}
