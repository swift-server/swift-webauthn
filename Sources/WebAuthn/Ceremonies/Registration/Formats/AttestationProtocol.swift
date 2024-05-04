//===----------------------------------------------------------------------===//
//
// This source file is part of the WebAuthn Swift open source project
//
// Copyright (c) 2023 the WebAuthn Swift project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of WebAuthn Swift project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import SwiftCBOR
import X509

protocol AttestationProtocol {
    static func verify(
        attStmt: CBOR,
        authenticatorData: AuthenticatorData,
        clientDataHash: Data,
        credentialPublicKey: CredentialPublicKey,
        rootCertificates: [Certificate]
    ) async throws -> (AttestationResult.AttestationType, [Certificate])
}
