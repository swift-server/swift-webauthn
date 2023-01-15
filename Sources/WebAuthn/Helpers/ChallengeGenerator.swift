import Foundation

public struct ChallengeGenerator {
    var generate: () -> [UInt8]

    public static var live: Self {
        .init(generate: { [UInt8].random(count: 32) })
    }
}
