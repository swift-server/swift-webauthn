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

public enum AttestationFormat: String, RawRepresentable, Equatable {
    case packed
    case tpm
    case androidKey = "android-key"
    case androidSafetynet = "android-safetynet"
    case fidoU2F = "fido-u2f"
    case apple
    case none
}
