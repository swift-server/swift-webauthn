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

import WebAuthn

struct MockUser: WebAuthnUser {
    var userID: String
    var name: String
    var displayName: String

    init(userID: String = "1", name: String = "John", displayName: String = "Johnny") {
        self.userID = userID
        self.name = name
        self.displayName = displayName
    }
}
