public enum AttestationFormat: String, RawRepresentable {
    case packed
    case tpm
    case androidKey = "android-key"
    case androidSafetynet = "android-safetynet"
    case fidoU2F = "fido-u2f"
    case apple
    case none
}
