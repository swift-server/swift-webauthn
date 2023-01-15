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

/// Protocol to interact with a user throughout the registration ceremony
public protocol User {
    /// A unique identifier for the user. For privacy reasons it should NOT be something like an email address.
    var userID: String { get }
    /// A value that will help the user identify which account this credential is associated with.
    /// Can be an email address, etc...
    var name: String { get }
    /// A user-friendly representation of their account. Can be a full name ,etc...
    var displayName: String { get }
}
