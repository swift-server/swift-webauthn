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

public enum AttestationFormat: String, RawRepresentable, Equatable, Sendable {
    case packed
    case tpm
    case androidKey = "android-key"
    case androidSafetynet = "android-safetynet"
    case fidoU2F = "fido-u2f"
    case apple
    case none
}
