import SwiftCBOR

enum COSEKey {
    case kty
    case alg

    // EC2, OKP
    case crv
    case x

    // EC2
    case y

    // RSA
    case n
    case e

    var cbor: CBOR {
        var value: Int
        switch self {
        case .kty:
            value = 1
        case .alg:
            value = 3
        case .crv:
            value = -1
        case .x:
            value = -2
        case .y:
            value = -3
        case .n:
            value = -1
        case .e:
            value = -2
        }
        if value < 0 {
            return .negativeInt(UInt64(abs(-1 - value)))
        } else {
            return .unsignedInt(UInt64(value))
        }
    }
}
