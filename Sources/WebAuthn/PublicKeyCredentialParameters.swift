public enum PublicKeyCredentialParameters: Codable, CaseIterable {
    case algES256
    // TODO: Add more algorithms

    enum CodingKeys: String, CodingKey {
        case alg
        case type
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard try container.decode(String.self, forKey: .type) == "public-key" else {
            throw DecodingError.dataCorruptedError(
                forKey: .type,
                in: container,
                debugDescription: "Currently only public-key is supported."
            )
        }

        let algorithm = try container.decode(String.self, forKey: .alg)
        switch algorithm {
        case "AlgES256": self = .algES256
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .alg,
                in: container,
                debugDescription: "Unsupported algorithm: \(algorithm)"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        try container.encode("public-key", forKey: .type)

        switch self {
            case .algES256: try container.encode("AlgES256", forKey: .alg)
        }
    }
}
