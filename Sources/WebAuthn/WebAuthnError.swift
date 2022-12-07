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

public enum WebAuthnError: Error {
    case authDataTooShort
    case extensionDataMissing
    case leftOverBytes

    case attestedCredentialFlagNotSet
    case userPresentFlagNotSet
    case userVerificationRequiredButFlagNotSet

    case attestedCredentialDataMissing
    case badRequestData
    case validationError
    case formatError
    case hashingClientDataJSONFailed
    case relyingPartyIDHashDoesNotMatch
    case attestationStatementMissing
    case missingAttestedCredentialDataForCredentialCreateFlow

    case invalidRawID
    case invalidCredentialCreationType
    case invalidClientDataJSON
    case cborDecodingAttestationDataFailed
    case authDataInvalidOrMissing

    case unsupportedCOSEAlgorithm
    case unsupportedCredentialPublicKeyAlgorithm
}
