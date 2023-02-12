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

/// The `PublicKeyCredentialCreationOptions` gets passed to the WebAuthn API (`navigator.credentials.create()`)
public struct PublicKeyCredentialCreationOptions: Codable {
    public let challenge: EncodedBase64
    public let user: PublicKeyCredentialUserEntity
    // swiftlint:disable:next identifier_name
    public let rp: PublicKeyCredentialRpEntity
    public let pubKeyCredParams: [PublicKeyCredentialParameters]
    public let timeout: TimeInterval
}

// MARK: - Credential parameters

public struct PublicKeyCredentialParameters: Equatable, Codable {
    public let type: String
    public let alg: COSEAlgorithmIdentifier

    public static var supported: [Self] {
        COSEAlgorithmIdentifier.allCases.map {
            PublicKeyCredentialParameters.init(type: "public-key", alg: $0)
        }
    }

    public init(type: String = "public-key", alg: COSEAlgorithmIdentifier) {
        self.type = type
        self.alg = alg
    }
}

// MARK: - Credential entities

/// From §5.4.2 (https://www.w3.org/TR/webauthn/#sctn-rp-credential-params).
/// The PublicKeyCredentialRpEntity dictionary is used to supply additional Relying Party attributes when
/// creating a new credential.
public struct PublicKeyCredentialRpEntity: Codable {
    public let name: String
    public let id: String
}

/// From §5.4.3 (https://www.w3.org/TR/webauthn/#dictionary-user-credential-params)
/// The PublicKeyCredentialUserEntity dictionary is used to supply additional user account attributes when
/// creating a new credential.
public struct PublicKeyCredentialUserEntity: Codable {
    public let name: String
    public let id: String
    public let displayName: String
}
