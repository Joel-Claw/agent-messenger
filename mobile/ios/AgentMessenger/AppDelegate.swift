import UIKit
import UserNotifications

/// AppDelegate handles APNs registration callbacks.
/// In SwiftUI, we use UIApplicationDelegateAdaptor to bridge this.
final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    
    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        // Set ourselves as the notification delegate
        UNUserNotificationCenter.current().delegate = self
        return true
    }
    
    func application(_ application: UIApplication,
                     didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        // Forward to NotificationManager via NotificationCenter
        NotificationCenter.default.post(
            name: .apnsDeviceTokenRegistered,
            object: nil,
            userInfo: ["deviceToken": deviceToken]
        )
    }
    
    func application(_ application: UIApplication,
                     didFailToRegisterForRemoteNotificationsWithError error: Error) {
        print("APNs registration failed: \(error)")
        NotificationCenter.default.post(
            name: .apnsRegistrationFailed,
            object: nil,
            userInfo: ["error": error]
        )
    }
    
    // Handle notifications while app is in the foreground
    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        let userInfo = notification.request.content.userInfo
        NotificationCenter.default.post(
            name: .pushNotificationReceived,
            object: nil,
            userInfo: userInfo
        )
        completionHandler([.banner, .sound, .badge])
    }
    
    // Handle notification tap
    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        let userInfo = response.notification.request.content.userInfo
        NotificationCenter.default.post(
            name: .pushNotificationReceived,
            object: nil,
            userInfo: userInfo
        )
        completionHandler()
    }
}

// MARK: - Notification Names for APNs

extension Notification.Name {
    static let apnsDeviceTokenRegistered = Notification.Name("apnsDeviceTokenRegistered")
    static let apnsRegistrationFailed = Notification.Name("apnsRegistrationFailed")
}