import SwiftUI

/// Main app entry point.
@main
struct AgentMessengerApp: App {
    @StateObject private var appState = AppState()

    var body: some Scene {
        WindowGroup {
            if appState.isLoggedIn {
                MainTabView()
                    .environmentObject(appState)
            } else {
                LoginView()
                    .environmentObject(appState)
            }
        }
    }
}

/// Shared app state managing authentication, WebSocket, and API connections.
@MainActor
class AppState: ObservableObject {
    @Published var config: AppConfig
    @Published var isLoggedIn = false
    @Published var userID: String?
    @Published var isLoading = false
    @Published var errorMessage: String?

    let apiClient: APIClient
    let wsClient: WebSocketClient

    var currentConversationID: String?

    init() {
        let config = AppConfig.load()
        self.config = config
        self.apiClient = APIClient(config: config)
        self.wsClient = WebSocketClient(config: config)
        self.isLoggedIn = config.isConfigured && !config.email.isEmpty

        // Wire up WebSocket callbacks
        setupWSCallbacks()
    }

    private func setupWSCallbacks() {
        wsClient.onConnected = { [weak self] in
            self?.errorMessage = nil
        }
        wsClient.onDisconnected = { [weak self] in
            // Auto-reconnect is handled by WebSocketClient
        }
    }

    // MARK: - Authentication

    func login(email: String, password: String) async {
        isLoading = true
        errorMessage = nil

        // Update config with new credentials
        config.email = email
        config.password = password
        config.save()

        do {
            let authResponse = try await apiClient.login(email: email, password: password)
            self.userID = authResponse.user_id
            self.isLoggedIn = true

            // Connect WebSocket
            wsClient.connect(userID: authResponse.user_id, token: authResponse.token)
        } catch {
            // If login fails, try registering
            do {
                let registerResponse = try await apiClient.register(email: email, password: password)
                // Then login
                let authResponse = try await apiClient.login(email: email, password: password)
                self.userID = authResponse.user_id
                self.isLoggedIn = true
                wsClient.connect(userID: authResponse.user_id, token: authResponse.token)
            } catch let registerError {
                errorMessage = registerError.localizedDescription
            }
        }

        isLoading = false
    }

    func logout() {
        wsClient.disconnect()
        config.email = ""
        config.password = ""
        config.save()
        userID = nil
        isLoggedIn = false
    }
}