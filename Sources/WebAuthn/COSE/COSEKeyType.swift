import Foundation

/// The Key Type derived from the IANA COSE AuthData
enum COSEKeyType: UInt64, RawRepresentable, Codable {
    /// OctetKey is an Octet Key
	case octetKey = 1
	/// EllipticKey is an Elliptic Curve Public Key
	case ellipticKey = 2
	/// RSAKey is an RSA Public Key
	case rsaKey = 3
}