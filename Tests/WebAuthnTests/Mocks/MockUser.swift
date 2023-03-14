import WebAuthn

struct MockUser: WebAuthnUser {
    var userID: String
    var name: String
    var displayName: String

    init(userID: String = "1", name: String = "John", displayName: String = "Johnny") {
        self.userID = userID
        self.name = name
        self.displayName = displayName
    }
}
