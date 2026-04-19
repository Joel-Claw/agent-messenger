import SwiftUI

/// New conversation creation sheet.
struct NewConversationView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) private var dismiss

    @State private var agents: [Agent] = []
    @State private var selectedAgent: Agent?
    @State private var isLoading = false
    @State private var errorMessage: String?

    let onCreate: (Conversation) -> Void

    var body: some View {
        NavigationView {
            Group {
                if isLoading && agents.isEmpty {
                    ProgressView("Loading agents...")
                } else {
                    List(agents) { agent in
                        Button(action: { selectedAgent = agent }) {
                            AgentRow(agent: agent)
                        }
                        .listRowBackground(
                            selectedAgent?.id == agent.id
                                ? Color.accentColor.opacity(0.15)
                                : Color.clear
                        )
                    }
                }
            }
            .navigationTitle("New Conversation")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Create") {
                        createConversation()
                    }
                    .disabled(selectedAgent == nil)
                }
            }
            .task {
                await loadAgents()
            }
            .alert("Error", isPresented: .constant(errorMessage != nil), actions: {
                Button("OK") { errorMessage = nil }
            }, message: {
                Text(errorMessage ?? "")
            })
        }
    }

    private func loadAgents() async {
        isLoading = true
        do {
            agents = try await appState.apiClient.listAgents()
        } catch {
            errorMessage = error.localizedDescription
        }
        isLoading = false
    }

    private func createConversation() {
        guard let agent = selectedAgent, let userID = appState.userID else { return }

        Task {
            do {
                let conversation = try await appState.apiClient.createConversation(
                    userID: userID,
                    agentID: agent.id
                )
                onCreate(conversation)
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}

#Preview {
    NewConversationView { _ in }
        .environmentObject(AppState())
}