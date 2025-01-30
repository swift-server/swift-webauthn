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

import Testing
import WebAuthn

func assertThrowsError<T, E: Error>(
    _ expression: @autoclosure () throws -> T,
    _ message: @autoclosure () -> String = "",
    sourceLocation: SourceLocation = #_sourceLocation,
    _ errorHandler: (_ error: E) -> Void = { _ in }
) {
    do {
        _ = try expression()
        Issue.record("\(message())", sourceLocation: sourceLocation)
    } catch {
        guard let error = error as? E else {
            Issue.record("""
            Error was thrown, but didn't match expected type '\(E.self)'.
            Got error of type '\(type(of: error))'.
            Error: \(error)
            """)
            return
        }
        errorHandler(error)
    }
}

func assertThrowsError<T, E: Error & Equatable>(
    _ expression: @autoclosure () throws -> T,
    _ message: @autoclosure () -> String = "",
    sourceLocation: SourceLocation = #_sourceLocation,
    expect: E
) {
    try assertThrowsError(expression(), message(), sourceLocation: sourceLocation) { error in
        #expect(error == expect, Comment("\(message())"), sourceLocation: sourceLocation)
    }
}
