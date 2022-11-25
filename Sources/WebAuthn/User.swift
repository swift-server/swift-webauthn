public struct User {
    public let id: String
    public let name: String
    public let displayName: String

    public init(id: String, name: String, displayName: String) {
        self.id = id
        self.name = name
        self.displayName = displayName
    }
}