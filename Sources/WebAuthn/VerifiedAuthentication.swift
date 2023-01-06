import Foundation

public struct VerifiedAuthentication {
    let credentialID: URLEncodedBase64
    let newSignCount: UInt32
    let credentialDeviceType: CredentialDeviceType
    let credentialBackedUp: Bool
}

public enum CredentialDeviceType: String, Codable {
    case singleDevice = "single_device"
    case multiDevice = "multi_device"
}
