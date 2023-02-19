import Foundation

extension Data {
    struct IndexOutOfBounds: Error {}

    subscript(safe range: Range<Int>) -> Data? {
        guard count >= range.upperBound else { return nil }
        return self[range]
    }
}
