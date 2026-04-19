import Foundation
import Combine

/// WebSocket client for Agent Messenger.
/// Uses URLSessionWebSocketTask (iOS 13+ native, no third-party dependencies).
/// Supports auto-reconnect with exponential backoff.

enum ConnectionState: Equatable {
    case disconnected
    case connecting
    case connected
    case reconnecting
}

@MainActor
class WebSocketClient: NSObject, ObservableObject {
    @Published var connectionState: ConnectionState = .disconnected
    @Published var messages: [Message] = []
    @Published var typingAgents: Set<String> = []   // agent IDs currently typing
    @Published var agentStatuses: [String: String] = [:] // agent_id -> status

    private var webSocketTask: URLSessionWebSocketTask?
    private var urlSession: URLSession!
    private let config: AppConfig
    private var token: String?
    private var userID: String?
    private var retryCount: Int = 0
    private let maxRetries: Int = 10
    private var reconnectTask: Task<Void, Never>?
    private var isManualDisconnect = false

    // Callbacks for delegates
    var onMessage: ((Message) -> Void)?
    var onTyping: ((TypingIndicator) -> Void)?
    var onStatus: ((StatusUpdate) -> Void)?
    var onConnected: (() -> Void)?
    var onDisconnected: (() -> Void)?

    init(config: AppConfig) {
        self.config = config
        super.init()
        let sessionConfig = URLSessionConfiguration.default
        urlSession = URLSession(configuration: sessionConfig, delegate: self, delegateQueue: nil)
    }

    // MARK: - Connection

    func connect(userID: String, token: String) {
        self.userID = userID
        self.token = token
        self.isManualDisconnect = false
        self.retryCount = 0
        establishConnection()
    }

    func disconnect() {
        isManualDisconnect = true
        reconnectTask?.cancel()
        reconnectTask = nil
        webSocketTask?.cancel(with: .normalClosure, reason: nil)
        webSocketTask = nil
        connectionState = .disconnected
        onDisconnected?()
    }

    private func establishConnection() {
        guard let userID = userID, let token = token else { return }
        guard let url = URL(string: "\(config.serverURL)/client/connect?user_id=\(userID)&token=\(token)") else {
            return
        }

        connectionState = .connecting
        webSocketTask = urlSession.webSocketTask(with: url)
        webSocketTask?.resume()

        // Start receiving messages
        receiveMessage()
    }

    private func reconnect() {
        guard !isManualDisconnect else { return }
        guard retryCount < maxRetries else {
            connectionState = .disconnected
            return
        }

        connectionState = .reconnecting
        let delay = pow(2.0, Double(retryCount)) // Exponential backoff: 1s, 2s, 4s, ...
        retryCount += 1

        reconnectTask = Task {
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            guard !Task.isCancelled else { return }
            establishConnection()
        }
    }

    // MARK: - Sending

    func sendMessage(conversationID: String, content: String) {
        let msg = WSMessage(
            type: "message",
            data: WSMessageData(
                conversation_id: conversationID,
                content: content,
                sender_type: nil,
                sender_id: nil,
                agent_id: nil,
                status: nil,
                message: nil
            )
        )
        sendWSMessage(msg)
    }

    func sendTyping(conversationID: String) {
        let msg = WSMessage(
            type: "typing",
            data: WSMessageData(
                conversation_id: conversationID,
                content: nil,
                sender_type: nil,
                sender_id: nil,
                agent_id: nil,
                status: nil,
                message: nil
            )
        )
        sendWSMessage(msg)
    }

    private func sendWSMessage(_ msg: WSMessage) {
        guard let webSocketTask = webSocketTask else { return }
        do {
            let data = try JSONEncoder().encode(msg)
            let string = String(data: data, encoding: .utf8) ?? "{}"
            webSocketTask.send(.string(string)) { [weak self] error in
                if let error = error {
                    print("[WS] Send error: \(error.localizedDescription)")
                    Task { @MainActor in
                        self?.handleConnectionFailure()
                    }
                }
            }
        } catch {
            print("[WS] Encode error: \(error)")
        }
    }

    // MARK: - Receiving

    private func receiveMessage() {
        guard let webSocketTask = webSocketTask else { return }

        webSocketTask.receive { [weak self] result in
            switch result {
            case .success(let message):
                Task { @MainActor in
                    self?.handleMessage(message)
                    self?.receiveMessage()  // Continue receiving
                }
            case .failure(let error):
                Task { @MainActor in
                    print("[WS] Receive error: \(error.localizedDescription)")
                    self?.handleConnectionFailure()
                }
            }
        }
    }

    private func handleMessage(_ message: URLSessionWebSocketTask.Message) {
        let jsonString: String
        switch message {
        case .string(let str):
            jsonString = str
        case .data(let data):
            jsonString = String(data: data, encoding: .utf8) ?? "{}"
        @unknown default:
            return
        }

        guard let jsonData = jsonString.data(using: .utf8),
              let wsMessage = try? JSONDecoder().decode(WSMessage.self, from: jsonData) else {
            print("[WS] Failed to decode message: \(jsonString.prefix(200))")
            return
        }

        switch wsMessage.type {
        case "connected":
            connectionState = .connected
            retryCount = 0
            onConnected?()

        case "message", "agent_message":
            if let data = wsMessage.data {
                let msg = Message(
                    id: nil,
                    conversation_id: data.conversation_id ?? "",
                    content: data.content ?? "",
                    sender_type: data.sender_type ?? "agent",
                    sender_id: data.sender_id ?? "",
                    timestamp: nil
                )
                messages.append(msg)
                onMessage?(msg)
            }

        case "message_sent":
            // Acknowledgment - no action needed
            break

        case "typing":
            if let data = wsMessage.data,
               let agentID = data.sender_id ?? data.agent_id {
                typingAgents.insert(agentID)
                // Auto-remove typing indicator after 3 seconds
                Task {
                    try? await Task.sleep(nanoseconds: 3_000_000_000)
                    self.typingAgents.remove(agentID)
                }
                let indicator = TypingIndicator(
                    conversation_id: data.conversation_id ?? "",
                    sender_type: data.sender_type ?? "agent",
                    sender_id: agentID
                )
                onTyping?(indicator)
            }

        case "status":
            if let data = wsMessage.data {
                let agentID = data.sender_id ?? data.agent_id ?? ""
                let status = data.status ?? "offline"
                agentStatuses[agentID] = status
                let update = StatusUpdate(
                    conversation_id: data.conversation_id,
                    status: status,
                    sender_type: data.sender_type ?? "agent",
                    sender_id: agentID
                )
                onStatus?(update)
            }

        case "error":
            if let data = wsMessage.data {
                print("[WS] Server error: \(data.message ?? data.content ?? "unknown")")
            }

        default:
            print("[WS] Unknown message type: \(wsMessage.type)")
        }
    }

    private func handleConnectionFailure() {
        webSocketTask?.cancel(with: .abnormalClosure, reason: nil)
        webSocketTask = nil
        reconnect()
    }
}

// MARK: - URLSessionWebSocketDelegate

extension WebSocketClient: URLSessionWebSocketDelegate {
    nonisolated func urlSession(
        _ session: URLSession,
        webSocketTask: URLSessionWebSocketTask,
        didOpenWithProtocol protocol: String?
    ) {
        Task { @MainActor in
            self.connectionState = .connected
            self.retryCount = 0
        }
    }

    nonisolated func urlSession(
        _ session: URLSession,
        webSocketTask: URLSessionWebSocketTask,
        didCloseWith closeCode: URLSessionWebSocketTask.CloseCode,
        reason: Data?
    ) {
        Task { @MainActor in
            self.webSocketTask = nil
            if !self.isManualDisconnect {
                self.reconnect()
            } else {
                self.connectionState = .disconnected
            }
        }
    }
}