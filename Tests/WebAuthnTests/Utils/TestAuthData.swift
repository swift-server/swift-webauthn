import Foundation
import Crypto

struct TestAuthData {
    var rpIDHash: [UInt8]?
    var flags: UInt8?
    var counter: [UInt8]?
    var attestedCredData: [UInt8]?
    var extensions: [UInt8]?

    var byteArrayRepresentation: [UInt8] {
        var value: [UInt8] = []
        if let rpIDHash {
            value += rpIDHash
        }
        if let flags {
            value += [flags]
        }
        if let counter {
            value += counter
        }
        if let attestedCredData {
            value += attestedCredData
        }
        if let extensions {
            value += extensions
        }
        return value
    }
}

struct TestAuthDataBuilder {
    private var wrapped: TestAuthData

    init(wrapped: TestAuthData = TestAuthData()) {
        self.wrapped = wrapped
    }

    func build() -> TestAuthData {
        return wrapped
    }

    func validBase() -> Self {
        self
            .rpIDHash(fromRpID: "example.com")
            .flags(0b10100010)
            .counter([0b00000000, 0b00000000, 0b00000000, 0b00000000])
            .attestedCredData(
                aaguid: [UInt8](repeating: 0, count: 16),
                credentialIDLength: [0b00000000, 0b00000001],
                credentialID: [0b00000001],
                credentialPublicKey: [] // TODO: This is not a valid credentialPublicKey
            )
    }

    func rpIDHash(fromRpID rpID: String) -> Self {
        let rpIDData = rpID.data(using: .utf8)!
        let rpIDHash = SHA256.hash(data: rpIDData)
        var temp = self
        temp.wrapped.rpIDHash = [UInt8](rpIDHash)
        return temp
    }

    ///           ED AT __ BS BE UV __ UP
    /// e.g.: 0b  0  1  0  0  0  0  0  1
    func flags(_ byte: UInt8) -> Self {
        var temp = self
        temp.wrapped.flags = byte
        return temp
    }

    func counter(_ counter: [UInt8]) -> Self {
        var temp = self
        temp.wrapped.counter = counter
        return temp
    }

    /// aaguid length = 16
    /// credentialIDLength length = 2
    /// credentialID length = credentialIDLength
    /// credentialPublicKey = variable
    func attestedCredData(
        aaguid: [UInt8],
        credentialIDLength: [UInt8],
        credentialID: [UInt8],
        credentialPublicKey: [UInt8]
    ) -> Self {
        var temp = self
        temp.wrapped.attestedCredData = aaguid + credentialIDLength + credentialID + credentialPublicKey
        return temp
    }

    func noAttestedCredentialData() -> Self {
        var temp = self
        temp.wrapped.attestedCredData = nil
        return temp
    }

    func extensions(_ extensions: [UInt8]) -> Self {
        var temp = self
        temp.wrapped.extensions = extensions
        return temp
    }
}

extension TestAuthData {
    static var valid: Self {
        TestAuthData(
            rpIDHash: [1],
            flags: 1,
            counter: [1],
            attestedCredData: [2],
            extensions: [1]
        )
    }
}
