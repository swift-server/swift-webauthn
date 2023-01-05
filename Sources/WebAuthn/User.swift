/// Protocol to interact with a user throughout the registration ceremony
public protocol User {
    var userID: String { get }
    var name: String { get }
    var displayName: String { get }
}