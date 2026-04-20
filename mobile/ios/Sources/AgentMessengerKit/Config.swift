import Foundation

/// Configuration for the Agent Messenger client.
/// Persisted to UserDefaults with the bundle identifier prefix.
struct AppConfig: Codable, Equatable {
    var serverURL: String
    var apiURL: String
    var username: String
    var password: String

    static let defaults = UserDefaults.standard
    private static let key = "app_config"

    init(
        serverURL: String = "ws://localhost:8080",
        apiURL: String = "http://localhost:8080",
        username: String = "",
        password: String = ""
    ) {
        self.serverURL = serverURL
        self.apiURL = apiURL
        self.username = username
        self.password = password
    }

    // MARK: - Persistence

    func save() {
        if let data = try? JSONEncoder().encode(self) {
            Self.defaults.set(data, forKey: Self.key)
        }
    }

    static func load() -> AppConfig {
        guard let data = Self.defaults.data(forKey: Self.key),
              let config = try? JSONDecoder().decode(AppConfig.self, from: data) else {
            return AppConfig()
        }
        return config
    }

    static func delete() {
        Self.defaults.removeObject(forKey: Self.key)
    }

    var isConfigured: Bool {
        !username.isEmpty && !password.isEmpty && !serverURL.isEmpty
    }
}