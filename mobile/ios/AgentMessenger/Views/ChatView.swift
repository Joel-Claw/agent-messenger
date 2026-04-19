import SwiftUI

/// Chat view for a single conversation.
/// Displays message history and input field.
struct ChatView: View {
    let conversation: Conversation
    @EnvironmentObject var appState: AppState
    @State private var inputText = ""
    @State private var messages: [Message] = []
    @State private var isLoading = false
    @State private var isSending = false

    var body: some View {
        VStack(spacing: 0) {
            // Connection status bar
            ConnectionStatusBar(state: appState.wsClient.connectionState)

            // Messages
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 8) {
                        if isLoading {
                            ProgressView()
                                .frame(maxWidth: .infinity)
                                .padding()
                        }

                        ForEach(messages) { message in
                            MessageBubble(message: message)
                                .id(message.id ?? message.content.hashValue)
                        }

                        // Typing indicator
                        if !appState.wsClient.typingAgents.isEmpty {
                            TypingIndicatorView()
                                .id("typing")
                        }
                    }
                    .padding()
                }
                .onChange(of: messages.count) { _, _ in
                    withAnimation {
                        proxy.scrollTo(messages.last?.id ?? messages.count, anchor: .bottom)
                    }
                }
                .onChange(of: appState.wsClient.typingAgents.isEmpty) { _, isNotTyping in
                    if !isNotTyping {
                        withAnimation {
                            proxy.scrollTo("typing", anchor: .bottom)
                        }
                    }
                }
            }

            Divider()

            // Input bar
            HStack(alignment: .bottom) {
                TextField("Message...", text: $inputText, axis: .vertical)
                    .textFieldStyle(.plain)
                    .lineLimit(1...5)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .background(Color(.systemGray6))
                    .clipShape(RoundedRectangle(cornerRadius: 20))

                Button(action: sendMessage) {
                    Image(systemName: "arrow.up.circle.fill")
                        .font(.title2)
                        .foregroundStyle(.tint)
                }
                .disabled(inputText.trimmingCharacters(in: .whitespaces).isEmpty || isSending)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
        }
        .navigationTitle("Chat")
        .navigationBarTitleDisplayMode(.inline)
        .task {
            await loadHistory()
            appState.currentConversationID = conversation.id
        }
        .onDisappear {
            appState.currentConversationID = nil
        }
        .onReceive(appState.wsClient.$messages) { _ in
            // Sync new messages from WebSocket
            syncMessages()
        }
    }

    private func loadHistory() async {
        isLoading = true
        do {
            let history = try await appState.apiClient.getMessages(conversationID: conversation.id)
            messages = history
        } catch {
            // History load failure is not critical
        }
        isLoading = false
    }

    private func syncMessages() {
        // Only add messages for this conversation that we don't already have
        let existingIDs = Set(messages.compactMap { $0.id })
        let existingContents = Set(messages.map { "\($0.content)-\($0.sender_type)-\($0.timestamp ?? "")" })

        for msg in appState.wsClient.messages {
            if msg.conversation_id == conversation.id {
                let key = "\(msg.content)-\(msg.sender_type)-\(msg.timestamp ?? "")"
                if !existingContents.contains(key) {
                    messages.append(msg)
                }
            }
        }
    }

    private func sendMessage() {
        let text = inputText.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else { return }

        inputText = ""
        isSending = true

        // Optimistically add to local messages
        let localMsg = Message(
            id: "local-\(Date().timeIntervalSince1970)",
            conversation_id: conversation.id,
            content: text,
            sender_type: "client",
            sender_id: appState.userID ?? "",
            timestamp: ISO8601DateFormatter().string(from: Date())
        )
        messages.append(localMsg)

        appState.wsClient.sendMessage(conversationID: conversation.id, content: text)
        isSending = false
    }
}

/// Connection status indicator.
struct ConnectionStatusBar: View {
    let state: ConnectionState

    var color: Color {
        switch state {
        case .connected: return .green
        case .connecting, .reconnecting: return .orange
        case .disconnected: return .red
        }
    }

    var label: String {
        switch state {
        case .connected: return "Connected"
        case .connecting: return "Connecting..."
        case .reconnecting: return "Reconnecting..."
        case .disconnected: return "Disconnected"
        }
    }

    var body: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(color)
                .frame(width: 8, height: 8)
            Text(label)
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 4)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(color.opacity(0.08))
    }
}

/// Single message bubble.
struct MessageBubble: View {
    let message: Message

    var body: some View {
        HStack {
            if message.isFromUser { Spacer(minLength: 48) }

            VStack(alignment: message.isFromUser ? .trailing : .leading, spacing: 4) {
                Text(message.content)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 10)
                    .background(
                        message.isFromUser
                            ? Color.accentColor.opacity(0.9)
                            : Color(.systemGray5)
                    )
                    .foregroundStyle(
                        message.isFromUser ? .white : .primary
                    )
                    .clipShape(BubbleShape(isUser: message.isFromUser))

                if let time = message.formattedTime, !time.isEmpty {
                    Text(time)
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
            }

            if !message.isFromUser { Spacer(minLength: 48) }
        }
    }
}

/// Custom bubble shape for messages.
struct BubbleShape: Shape {
    let isUser: Bool

    func path(in rect: CGRect) -> Path {
        let radius: CGFloat = 16
        let tailSize: CGFloat = 4
        var path = Path()

        if isUser {
            // Right-aligned bubble with bottom-right tail
            path.addRoundedRect(
                in: rect.insetBy(dx: 0, dy: 0),
                cornerRadii: RectangleCornerRadii(
                    topLeading: radius,
                    bottomLeading: radius,
                    bottomTrailing: radius - tailSize,
                    topTrailing: radius
                )
            )
        } else {
            // Left-aligned bubble with bottom-left tail
            path.addRoundedRect(
                in: rect.insetBy(dx: 0, dy: 0),
                cornerRadii: RectangleCornerRadii(
                    topLeading: radius,
                    bottomLeading: radius - tailSize,
                    bottomTrailing: radius,
                    topTrailing: radius
                )
            )
        }

        return path
    }
}

/// Typing indicator animation.
struct TypingIndicatorView: View {
    @State private var isAnimating = false

    var body: some View {
        HStack(spacing: 4) {
            ForEach(0..<3, id: \.self) { index in
                Circle()
                    .fill(Color.secondary)
                    .frame(width: 8, height: 8)
                    .offset(y: isAnimating ? -4 : 4)
                    .animation(
                        .easeInOut(duration: 0.4)
                            .repeatForever()
                            .delay(Double(index) * 0.15),
                        value: isAnimating
                    )
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(Color(.systemGray5))
        .clipShape(RoundedRectangle(cornerRadius: 16))
        .onAppear { isAnimating = true }
    }
}

#Preview {
    NavigationView {
        ChatView(conversation: Conversation(
            id: "conv1",
            user_id: "user1",
            agent_id: "agent1",
            created_at: "2026-04-19",
            updated_at: "2026-04-19"
        ))
        .environmentObject(AppState())
    }
}