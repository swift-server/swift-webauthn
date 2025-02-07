//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift WebAuthn open source project
//
// Copyright (c) 2025 the Swift WebAuthn project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation

protocol TestSigner {
    static func sign(data: Data) throws -> [UInt8]
    
    static var signature: [UInt8] { get throws }
}

struct TestKeyConfiguration {
    var signer: any TestSigner.Type
    var credentialPublicKeyBuilder: TestCredentialPublicKeyBuilder
    var authDataBuilder: TestAuthDataBuilder
    var attestationObjectBuilder: TestAttestationObjectBuilder
    
    var credentialPublicKey: [UInt8] {
        credentialPublicKeyBuilder.buildAsByteArray()
    }
    var attestationObject: [UInt8] {
        attestationObjectBuilder.build().cborEncoded
    }
}
