import Foundation

struct TestAuthDataFlags {
    let userPresent: Bool
    let reservedForFuture: Bool
    let userVerified: Bool
    let backupEligible: Bool
    let backupState: Bool
    let reservedForFuture2: Bool
    let attestedCredentialDataIncluded: Bool
    let extensionDataIncluded: Bool

    /// Defaults all properties to `false`
    init(
        userPresent: Bool = false,
        reservedForFuture: Bool = false,
        userVerified: Bool = false,
        backupEligible: Bool = false,
        backupState: Bool = false,
        reservedForFuture2: Bool = false,
        attestedCredentialDataIncluded: Bool = false,
        extensionDataIncluded: Bool = false
    ) {
        self.userPresent = userPresent
        self.reservedForFuture = reservedForFuture
        self.userVerified = userVerified
        self.backupEligible = backupEligible
        self.backupState = backupState
        self.reservedForFuture2 = reservedForFuture2
        self.attestedCredentialDataIncluded = attestedCredentialDataIncluded
        self.extensionDataIncluded = extensionDataIncluded
    }
}
