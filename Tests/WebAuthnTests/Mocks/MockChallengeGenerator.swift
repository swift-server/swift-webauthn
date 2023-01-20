@testable import WebAuthn

extension ChallengeGenerator {
    static func mock(generate: [UInt8]) -> Self {
        ChallengeGenerator(generate: { generate })
    }
}
