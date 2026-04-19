import SwiftUI

/// Main tab view showing conversations and agents.
struct MainTabView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        TabView {
            ConversationsView()
                .tabItem {
                    Label("Chats", systemImage: "bubble.left.and.bubble.right")
                }

            AgentsView()
                .tabItem {
                    Label("Agents", systemImage: "cpu")
                }

            SettingsView()
                .tabItem {
                    Label("Settings", systemImage: "gear")
                }
        }
    }
}

#Preview {
    MainTabView()
        .environmentObject(AppState())
}