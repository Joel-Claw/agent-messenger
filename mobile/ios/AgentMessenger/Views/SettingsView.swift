import SwiftUI

/// Settings view for app configuration.
struct SettingsView: View {
    @EnvironmentObject var appState: AppState
    @State private var serverURL = ""
    @State private var apiURL = ""
    @State private var showLogoutConfirmation = false

    var body: some View {
        NavigationView {
            Form {
                Section("Connection") {
                    VStack(alignment: .leading, spacing: 4) {
                        Label("WebSocket", systemImage: "antenna.radiowaves")
                            .font(.subheadline)
                        Text(appState.wsClient.connectionState == .connected ? "Connected" : "Disconnected")
                            .font(.caption)
                            .foregroundStyle(
                                appState.wsClient.connectionState == .connected ? .green : .red
                            )
                    }

                    VStack(alignment: .leading, spacing: 4) {
                        Text("Server URL")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        TextField("ws://host:port", text: $serverURL)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .keyboardType(.URL)
                    }

                    VStack(alignment: .leading, spacing: 4) {
                        Text("API URL")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        TextField("http://host:port", text: $apiURL)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .keyboardType(.URL)
                    }

                    Button("Save Changes") {
                        appState.config.serverURL = serverURL
                        appState.config.apiURL = apiURL
                        appState.config.save()
                    }
                    .disabled(serverURL == appState.config.serverURL && apiURL == appState.config.apiURL)
                }

                Section("Account") {
                    HStack {
                        Text("Email")
                        Spacer()
                        Text(appState.config.email)
                            .foregroundStyle(.secondary)
                    }

                    HStack {
                        Text("User ID")
                        Spacer()
                        Text(appState.userID ?? "—")
                            .foregroundStyle(.secondary)
                            .font(.caption)
                    }

                    Button("Sign Out", role: .destructive) {
                        showLogoutConfirmation = true
                    }
                }

                Section("About") {
                    HStack {
                        Text("Version")
                        Spacer()
                        Text("1.0.0")
                            .foregroundStyle(.secondary)
                    }

                    Link("GitHub", destination: URL(string: "https://github.com/Joel-Claw/agent-messenger")!)
                }
            }
            .navigationTitle("Settings")
            .onAppear {
                serverURL = appState.config.serverURL
                apiURL = appState.config.apiURL
            }
            .alert("Sign Out", isPresented: $showLogoutConfirmation) {
                Button("Cancel", role: .cancel) {}
                Button("Sign Out", role: .destructive) {
                    appState.logout()
                }
            } message: {
                Text("Are you sure you want to sign out?")
            }
        }
    }
}

#Preview {
    SettingsView()
        .environmentObject(AppState())
}