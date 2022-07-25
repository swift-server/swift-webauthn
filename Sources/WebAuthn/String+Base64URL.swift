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

extension String {
    var base64URLDecodedData: Data? {
        var result = self.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while result.count % 4 != 0 {
            result = result.appending("=")
        }
        return Data(base64Encoded: result)
    }
}