import SwiftUI

/// List of conversations with the ability to create new ones.
struct ConversationsView: View {
    @EnvironmentObject var appState: AppState
    @State private var conversations: [Conversation] = []
    @State private var isLoading = false
    @State private var showNewConversation = false
    @State private var errorMessage: String?

    var body: some View {
        NavigationView {
            Group {
                if isLoading && conversations.isEmpty {
                    ProgressView("Loading conversations...")
                } else if conversations.isEmpty {
                    ContentUnavailableView(
                        "No Conversations",
                        systemImage: "bubble.left",
                        description: Text("Start a new conversation with an agent")
                    )
                } else {
                    List(conversations) { conversation in
                        NavigationLink(value: conversation) {
                            ConversationRow(conversation: conversation)
                        }
                    }
                    .refreshable {
                        await loadConversations()
                    }
                }
            }
            .navigationTitle("Chats")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: { showNewConversation = true }) {
                        Image(systemName: "plus.message")
                    }
                }
            }
            .sheet(isPresented: $showNewConversation) {
                NewConversationView { conversation in
                    conversations.append(conversation)
                    showNewConversation = false
                }
            }
            .navigationDestination(for: Conversation.self) { conversation in
                ChatView(conversation: conversation)
                    .environmentObject(appState)
            }
            .task {
                await loadConversations()
            }
            .alert("Error", isPresented: .constant(errorMessage != nil), actions: {
                Button("OK") { errorMessage = nil }
            }, message: {
                Text(errorMessage ?? "")
            })
        }
    }

    private func loadConversations() async {
        isLoading = true
        do {
            conversations = try await appState.apiClient.listConversations()
        } catch {
            errorMessage = error.localizedDescription
        }
        isLoading = false
    }
}

/// Single conversation row in the list.
struct ConversationRow: View {
    let conversation: Conversation

    var body: some View {
        HStack {
            Image(systemName: "bubble.left.fill")
                .foregroundStyle(.tint)
                .font(.title3)

            VStack(alignment: .leading, spacing: 2) {
                Text(conversation.displayName)
                    .font(.headline)

                Text("Agent: \(conversation.agent_id)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            Text(conversation.created_at.prefix(10))
                .font(.caption2)
                .foregroundStyle(.tertiary)
        }
        .padding(.vertical, 4)
    }
}

#Preview {
    ConversationsView()
        .environmentObject(AppState())
}