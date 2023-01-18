import XCTest
@testable import WebAuthn

// swiftlint:disable line_length

final class AuthenticatorDataTests: XCTestCase {
    // Information about authenticator data: https://w3c.github.io/webauthn/#authenticator-data

    func testInitFromBytesFailsIfAuthDataIsTooShort() throws {
        let tooManyBytes = [UInt8](repeating: 1, count: 36)
        XCTAssertThrowsError(try AuthenticatorData(bytes: Data(tooManyBytes))) { error in
            XCTAssertEqual(error as? WebAuthnError, .authDataTooShort)
        }
    }

    func testInitFromBytesFailsIfAttestedCredentialDataFlagIsSetButDataIsActuallyNotThere() throws {
        let rpIdHash = [UInt8](repeating: 0, count: 32)
        let flagsByte: [UInt8] = [0b01000000] // "attested credential data included"
        let signCount = [UInt8](repeating: 0, count: 4)

        let bytes = rpIdHash + flagsByte + signCount

        XCTAssertThrowsError(try AuthenticatorData(bytes: Data(bytes))) { error in
            XCTAssertEqual(error as? WebAuthnError, .attestedCredentialDataMissing)
        }
    }

    func testInitFromBytesFailsIfAttestedCredentialDataFlagIsNotSetButThereActuallyIsData() throws {
        let rpIdHash = [UInt8](repeating: 0, count: 32)
        let flagsByte: [UInt8] = [0b00000000] // "attested credential data included"
        let signCount = [UInt8](repeating: 0, count: 4)
        let fakeAttestedCredentialData: [UInt8] = [UInt8](repeating: 0, count: 4)

        let bytes = rpIdHash + flagsByte + signCount + fakeAttestedCredentialData

        XCTAssertThrowsError(try AuthenticatorData(bytes: Data(bytes))) { error in
            XCTAssertEqual(error as? WebAuthnError, .attestedCredentialFlagNotSet)
        }
    }
}
