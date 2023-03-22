import XCTest
import WebAuthn

func assertThrowsError<T, E: Error>(
    _ expression: @autoclosure () throws -> T,
    _ message: @autoclosure () -> String = "",
    file: StaticString = #filePath,
    line: UInt = #line,
    _ errorHandler: (_ error: E) -> Void = { _ in }
) {
    do {
        _ = try expression()
        XCTFail(message(), file: file, line: line)
    } catch {
        guard let error = error as? E else {
            XCTFail("""
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
    file: StaticString = #filePath,
    line: UInt = #line,
    expect: E
) {
    try assertThrowsError(expression(), message(), file: file, line: line) { error in
        XCTAssertEqual(error, expect, message(), file: file, line: line)
    }
}
