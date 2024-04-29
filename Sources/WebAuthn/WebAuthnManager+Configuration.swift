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

extension WebAuthnManager {
    /// Configuration represents the WebAuthn configuration.
    public struct Configuration: Sendable {
        /// The relying party id is based on the host's domain.
        /// It does not include a scheme or port (like the `relyingPartyOrigin`).
        /// For example, if the origin is https://login.example.com:1337, then _login.example.com_ or _example.com_ are
        /// valid ids, but not _m.login.example.com_ and not _com_.
        public let relyingPartyID: String

        /// Configures the display name for the Relying Party Server. This can be any string.
        public let relyingPartyName: String

        /// The domain, with HTTP protocol (e.g. "https://example.com")
        public let relyingPartyOrigin: String

        /// Creates a new ``WebAuthnManager.Configuration`` with information about the Relying Party
        /// - Parameters:
        ///   - relyingPartyID: The relying party id is based on the host's domain. (e.g. _login.example.com_)
        ///   - relyingPartyName: Name for the Relying Party. Can be any string.
        ///   - relyingPartyOrigin: The domain, with HTTP protocol (e.g. _https://login.example.com_)
        public init(
            relyingPartyID: String,
            relyingPartyName: String,
            relyingPartyOrigin: String
        ) {
            self.relyingPartyID = relyingPartyID
            self.relyingPartyName = relyingPartyName
            self.relyingPartyOrigin = relyingPartyOrigin
        }
    }
}
