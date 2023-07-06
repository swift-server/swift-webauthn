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

/// On successful authentication, this structure contains a summary of the authentication flow
public struct VerifiedAuthentication {
    public enum CredentialDeviceType: String {
        case singleDevice = "single_device"
        case multiDevice = "multi_device"
    }

    /// The credential id associated with the public key
    public let credentialID: URLEncodedBase64
    /// The updated sign count after the authentication ceremony
    public let newSignCount: UInt32
    /// Whether the authenticator is a single- or multi-device authenticator. This value is determined after
    /// registration and will not change afterwards.
    public let credentialDeviceType: CredentialDeviceType
    /// Whether the authenticator is known to be backed up currently
    public let credentialBackedUp: Bool
}
