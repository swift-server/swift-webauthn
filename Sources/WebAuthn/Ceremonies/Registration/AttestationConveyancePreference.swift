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

/// Options to specify the Relying Party's preference regarding attestation conveyance during credential generation.
///
/// Currently only supports `none`.
public enum AttestationConveyancePreference: String, Codable, Sendable {
    /// Indicates the Relying Party is not interested in authenticator attestation.
    case none
    // case indirect
    // case direct
    // case enterprise
}
