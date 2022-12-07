import Foundation

public struct PublicKeyCredentialParameters: Codable {
    let type: String
    let algorithm: COSEAlgorithmIdentifier

    public static var supported: [Self] {
        COSEAlgorithmIdentifier.allCases.map {
            PublicKeyCredentialParameters.init(type: "public-key", algorithm: $0)
        }
    }
}