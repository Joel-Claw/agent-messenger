import Foundation
import UserNotifications

/// Manages push notification registration and handling for iOS.
/// Requires the "aps-environment" entitlement and a valid APNs certificate.
@MainActor
final class NotificationManager: NSObject, ObservableObject {
    
    /// The current device token (nil if not registered)
    @Published var deviceToken: String?
    
    /// Whether push notifications are authorized
    @Published var isAuthorized: Bool = false
    
    /// The API client for registering tokens with the server
    private weak var apiClient: APIClient?
    
    /// Initialize with an API client
    func configure(apiClient: APIClient) {
        self.apiClient = apiClient
    }
    
    /// Request notification authorization from the user
    func requestAuthorization() async -> Bool {
        do {
            let center = UNUserNotificationCenter.current()
            let granted = try await center.requestAuthorization(options: [.alert, .badge, .sound])
            await MainActor.run {
                self.isAuthorized = granted
            }
            return granted
        } catch {
            print("Notification authorization error: \(error)")
            return false
        }
    }
    
    /// Register for remote notifications (call from AppDelegate didRegisterForRemoteNotificationsWithDeviceToken)
    func registerDeviceToken(_ data: Data) {
        let token = data.map { String(format: "%02x", $0) }.joined()
        self.deviceToken = token
        print("APNs device token: \(token.prefix(16))...")
        
        // Register with server
        Task {
            await registerTokenWithServer(token)
        }
    }
    
    /// Handle registration failure
    func registrationFailed(_ error: Error) {
        print("APNs registration failed: \(error)")
    }
    
    /// Register the device token with the Agent Messenger server
    private func registerTokenWithServer(_ token: String) async {
        guard let client = apiClient else {
            print("NotificationManager: no API client configured")
            return
        }
        
        do {
            let body: [String: String] = [
                "device_token": token,
                "platform": "ios"
            ]
            let data = try JSONSerialization.data(withJSONObject: body)
            let _ = try await client.request("/push/register", method: "POST", body: data)
            print("Device token registered with server")
        } catch {
            print("Failed to register device token with server: \(error)")
        }
    }
    
    /// Unregister the device token (call on logout)
    func unregisterDeviceToken() async {
        guard let token = deviceToken, let client = apiClient else { return }
        
        do {
            let body: [String: String] = [
                "device_token": token,
                "platform": "ios"
            ]
            let data = try JSONSerialization.data(withJSONObject: body)
            let _ = try await client.request("/push/unregister", method: "DELETE", body: data)
            print("Device token unregistered from server")
        } catch {
            print("Failed to unregister device token: \(error)")
        }
        
        self.deviceToken = nil
    }
    
    /// Handle incoming push notification while app is in foreground
    func handleForegroundNotification(userInfo: [AnyHashable: Any]) {
        // Extract conversation ID for navigation
        if let conversationID = userInfo["conversation_id"] as? String {
            print("Foreground notification for conversation: \(conversationID)")
            // Post notification for SwiftUI to handle navigation
            NotificationCenter.default.post(
                name: .pushNotificationReceived,
                object: nil,
                userInfo: ["conversation_id": conversationID]
            )
        }
    }
    
    /// Handle notification tap (app opened from notification)
    func handleNotificationTap(userInfo: [AnyHashable: Any]) {
        if let conversationID = userInfo["conversation_id"] as? String {
            print("Notification tap for conversation: \(conversationID)")
            NotificationCenter.default.post(
                name: .pushNotificationReceived,
                object: nil,
                userInfo: ["conversation_id": conversationID]
            )
        }
    }
}

// MARK: - Notification Names

extension Notification.Name {
    static let pushNotificationReceived = Notification.Name("pushNotificationReceived")
}