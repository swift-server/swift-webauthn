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

/// Options to specify the Relying Party's preference regarding attestation conveyance during credential generation.
///
/// Currently only supports `none`.
public enum AttestationConveyancePreference: String, Codable {
    /// Indicates the Relying Party is not interested in authenticator attestation.
    case none
    // case indirect
    // case direct
    // case enterprise
}
