import SwiftUI

/// Login form for email/password authentication.
struct LoginView: View {
    @EnvironmentObject var appState: AppState
    @State private var email = ""
    @State private var password = ""
    @State private var serverURL = ""
    @State private var showServerSettings = false

    var body: some View {
        NavigationView {
            VStack(spacing: 20) {
                // Logo / Title
                Image(systemName: "bubble.left.and.bubble.right.fill")
                    .font(.system(size: 60))
                    .foregroundStyle(.tint)
                    .padding(.bottom, 8)

                Text("Agent Messenger")
                    .font(.largeTitle)
                    .fontWeight(.bold)

                Text("Connect to AI agents")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)

                // Login Form
                VStack(spacing: 16) {
                    TextField("Email", text: $email)
                        .textFieldStyle(.roundedBorder)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.emailAddress)
                        .autocorrectionDisabled()

                    SecureField("Password", text: $password)
                        .textFieldStyle(.roundedBorder)

                    if appState.isLoading {
                        ProgressView()
                            .padding()
                    } else {
                        Button(action: doLogin) {
                            Text("Sign In")
                                .frame(maxWidth: .infinity)
                                .padding()
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(email.isEmpty || password.isEmpty)
                    }

                    if let error = appState.errorMessage {
                        Text(error)
                            .font(.caption)
                            .foregroundStyle(.red)
                            .multilineTextAlignment(.center)
                    }
                }
                .padding(.horizontal, 24)
                .padding(.top, 24)

                Spacer()

                Button("Server Settings") {
                    serverURL = appState.config.serverURL
                    showServerSettings = true
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            .padding()
            .sheet(isPresented: $showServerSettings) {
                ServerSettingsView(serverURL: $serverURL, apiURL: Binding(
                    get: { appState.config.apiURL },
                    set: { appState.config.apiURL = $0 }
                )) {
                    appState.config.serverURL = serverURL
                    appState.config.save()
                    showServerSettings = false
                }
            }
            .onAppear {
                email = appState.config.email
            }
        }
    }

    private func doLogin() {
        Task {
            await appState.login(email: email, password: password)
        }
    }
}

/// Server settings sheet for configuring connection URLs.
struct ServerSettingsView: View {
    @Binding var serverURL: String
    @Binding var apiURL: String
    let onSave: () -> Void

    var body: some View {
        NavigationView {
            Form {
                Section("WebSocket Server") {
                    TextField("ws://host:port", text: $serverURL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                }

                Section("API Server") {
                    TextField("http://host:port", text: $apiURL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                }

                Section {
                    Button("Save") {
                        onSave()
                    }
                    .frame(maxWidth: .infinity)
                }
            }
            .navigationTitle("Server Settings")
            .navigationBarTitleDisplayMode(.inline)
        }
    }
}

#Preview {
    LoginView()
        .environmentObject(AppState())
}