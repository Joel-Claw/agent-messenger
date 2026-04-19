import SwiftUI

/// List of available agents with status indicators.
struct AgentsView: View {
    @EnvironmentObject var appState: AppState
    @State private var agents: [Agent] = []
    @State private var isLoading = false
    @State private var errorMessage: String?

    var body: some View {
        NavigationView {
            Group {
                if isLoading && agents.isEmpty {
                    ProgressView("Loading agents...")
                } else if agents.isEmpty {
                    ContentUnavailableView(
                        "No Agents",
                        systemImage: "cpu",
                        description: Text("No AI agents are currently available")
                    )
                } else {
                    List(agents) { agent in
                        NavigationLink(value: agent) {
                            AgentRow(agent: agent)
                        }
                    }
                    .refreshable {
                        await loadAgents()
                    }
                }
            }
            .navigationTitle("Agents")
            .task {
                await loadAgents()
            }
            .alert("Error", isPresented: .constant(errorMessage != nil), actions: {
                Button("OK") { errorMessage = nil }
            }, message: {
                Text(errorMessage ?? "")
            })
            .navigationDestination(for: Agent.self) { agent in
                AgentDetailView(agent: agent)
                    .environmentObject(appState)
            }
        }
    }

    private func loadAgents() async {
        isLoading = true
        do {
            agents = try await appState.apiClient.listAgents()
            // Update statuses from WebSocket
            for (agentID, status) in appState.wsClient.agentStatuses {
                if let index = agents.firstIndex(where: { $0.id == agentID }) {
                    agents[index] = Agent(
                        id: agents[index].id,
                        name: agents[index].name,
                        model: agents[index].model,
                        personality: agents[index].personality,
                        specialty: agents[index].specialty,
                        status: status
                    )
                }
            }
        } catch {
            errorMessage = error.localizedDescription
        }
        isLoading = false
    }
}

/// Single agent row showing name, model, and status.
struct AgentRow: View {
    let agent: Agent

    var statusColor: Color {
        switch agent.status {
        case "online": return .green
        case "busy": return .orange
        case "idle": return .yellow
        default: return .gray
        }
    }

    var body: some View {
        HStack(spacing: 12) {
            // Status indicator
            Circle()
                .fill(statusColor)
                .frame(width: 12, height: 12)
                .overlay(
                    Circle()
                        .stroke(Color.primary.opacity(0.2), lineWidth: 1)
                )

            VStack(alignment: .leading, spacing: 3) {
                Text(agent.name)
                    .font(.headline)

                HStack(spacing: 8) {
                    Text(agent.model)
                        .font(.caption)
                        .foregroundStyle(.secondary)

                    if !agent.specialty.isEmpty {
                        Text("·")
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                        Text(agent.specialty)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }

            Spacer()

            Text(agent.status.capitalized)
                .font(.caption)
                .fontWeight(.medium)
                .foregroundStyle(statusColor)
        }
        .padding(.vertical, 4)
    }
}

/// Detailed view of an agent with the ability to start a conversation.
struct AgentDetailView: View {
    let agent: Agent
    @EnvironmentObject var appState: AppState
    @State private var isCreatingConversation = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Agent header
                HStack(spacing: 16) {
                    Image(systemName: "cpu")
                        .font(.system(size: 48))
                        .foregroundStyle(.tint)

                    VStack(alignment: .leading, spacing: 4) {
                        Text(agent.name)
                            .font(.title2)
                            .fontWeight(.bold)

                        Text(agent.status.capitalized)
                            .font(.subheadline)
                            .foregroundStyle(agent.status == "online" ? .green : .secondary)
                    }
                }
                .padding()

                // Details
                Group {
                    DetailRow(label: "Model", value: agent.model)
                    DetailRow(label: "Personality", value: agent.personality)
                    DetailRow(label: "Specialty", value: agent.specialty)
                    DetailRow(label: "Status", value: agent.status.capitalized)
                }
                .padding(.horizontal)

                // Start conversation button
                Button(action: startConversation) {
                    if isCreatingConversation {
                        ProgressView()
                            .frame(maxWidth: .infinity)
                            .padding()
                    } else {
                        Text("Start Conversation")
                            .font(.headline)
                            .frame(maxWidth: .infinity)
                            .padding()
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(isCreatingConversation)
                .padding(.horizontal)
            }
        }
        .navigationTitle(agent.name)
        .navigationBarTitleDisplayMode(.inline)
    }

    private func startConversation() {
        guard let userID = appState.userID else { return }
        isCreatingConversation = true

        Task {
            do {
                let conversation = try await appState.apiClient.createConversation(
                    userID: userID,
                    agentID: agent.id
                )
                // Navigate to chat view (handled by parent)
                isCreatingConversation = false
            } catch {
                isCreatingConversation = false
            }
        }
    }
}

struct DetailRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack {
            Text(label)
                .font(.subheadline)
                .foregroundStyle(.secondary)
            Spacer()
            Text(value)
                .font(.subheadline)
                .fontWeight(.medium)
        }
        .padding(.vertical, 4)
    }
}

#Preview {
    AgentsView()
        .environmentObject(AppState())
}