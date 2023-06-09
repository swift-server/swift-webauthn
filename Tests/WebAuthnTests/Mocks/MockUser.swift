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

struct MockUser: PublicKeyCredentialUserEntity {
    var id: [UInt8]
    var name: String
    var displayName: String

    init(id: [UInt8] = [1, 2, 3], name: String = "John", displayName: String = "Johnny") {
        self.id = id
        self.name = name
        self.displayName = displayName
    }
}
