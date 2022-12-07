public enum AttestationFormat: RawRepresentable {
    case iana(IANAAttestationFormat)
    case custom(String)

    public var rawValue: String {
        switch self {
        case let .iana(format): return format.rawValue
        case let .custom(custom): return custom
        }
    }

    public init(rawValue: String) {
        if let ianaFormat = IANAAttestationFormat(rawValue: rawValue) {
            self = .iana(ianaFormat)
        } else {
            self = .custom(rawValue)
        }
    }

    // init(from decoder: Decoder) throws {
    //     let container = try decoder.singleValueContainer()

    //     let value = try container.decode(String.self)
    //     if let ianaFormat = IANAAttestationFormat(rawValue: value) {
    //         self = .iana(ianaFormat)
    //     } else {
    //         self = .custom(value)
    //     }
    // }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()

        switch self {
        case let .iana(format): try container.encode(format)
        case let .custom(custom): try container.encode(custom)
        }
    }
}

public enum IANAAttestationFormat: String, Codable {
    case packed
    case tpm
    case androidKey = "android-key"
    case androidSafetynet = "android-safetynet"
    case fidoU2F = "fido-u2f"
    case apple
    case none
}
