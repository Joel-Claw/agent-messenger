import SwiftUI

/// Main app entry point.
@main
struct AgentMessengerApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
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

/// Shared app state managing authentication, WebSocket, API connections, and notifications.
@MainActor
class AppState: ObservableObject {
    @Published var config: AppConfig
    @Published var isLoggedIn = false
    @Published var userID: String?
    @Published var isLoading = false
    @Published var errorMessage: String?

    let apiClient: APIClient
    let wsClient: WebSocketClient
    let notificationManager = NotificationManager()

    var currentConversationID: String?

    init() {
        let config = AppConfig.load()
        self.config = config
        self.apiClient = APIClient(config: config)
        self.wsClient = WebSocketClient(config: config)
        self.isLoggedIn = config.isConfigured && !config.username.isEmpty

        // Wire up notification manager
        notificationManager.configure(apiClient: apiClient)

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

    func login(username: String, password: String) async {
        isLoading = true
        errorMessage = nil

        // Update config with new credentials
        config.username = username
        config.password = password
        config.save()

        do {
            let authResponse = try await apiClient.login(username: username, password: password)
            self.userID = authResponse.user_id
            self.isLoggedIn = true

            // Connect WebSocket
            wsClient.connect(userID: authResponse.user_id, token: authResponse.token)

            // Request push notification authorization
            Task {
                _ = await notificationManager.requestAuthorization()
            }
        } catch {
            // If login fails, try registering
            do {
                let registerResponse = try await apiClient.register(username: username, password: password)
                // Then login
                let authResponse = try await apiClient.login(username: username, password: password)
                self.userID = authResponse.user_id
                self.isLoggedIn = true
                wsClient.connect(userID: authResponse.user_id, token: authResponse.token)

                // Request push notification authorization
                Task {
                    _ = await notificationManager.requestAuthorization()
                }
            } catch let registerError {
                errorMessage = registerError.localizedDescription
            }
        }

        isLoading = false
    }

    func logout() {
        wsClient.disconnect()
        Task { await notificationManager.unregisterDeviceToken() }
        config.username = ""
        config.password = ""
        config.save()
        userID = nil
        isLoggedIn = false
    }
}