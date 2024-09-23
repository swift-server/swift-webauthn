//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift WebAuthn open source project
//
// Copyright (c) 2023 the Swift WebAuthn project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import WebAuthn

extension PublicKeyCredentialUserEntity {
    static let mock = PublicKeyCredentialUserEntity(id: [1, 2, 3], name: "John", displayName: "Johnny")
}
