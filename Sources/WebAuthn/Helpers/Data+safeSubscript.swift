import Foundation

extension Data {
    struct IndexOutOfBounds: Error {}

    subscript(safe range: Range<Int>) -> Data? {
        guard count >= range.upperBound else { return nil }
        return self[range]
    }

    /// Safely slices bytes from `pointer` to `pointer` + `length`. Updates the pointer afterwards.
    /// - Returns: The sliced bytes or nil if we're out of bounds.
    func safeSlice(length: Int, using pointer: inout Int) -> Data? {
        guard let value = self[safe: pointer..<(pointer + length)] else { return nil }
        pointer += length
        return value
    }
}
