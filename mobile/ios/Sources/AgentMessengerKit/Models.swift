import Foundation

/// Data models for the Agent Messenger API.

// MARK: - Authentication

struct AuthResponse: Codable {
    let token: String
    let user_id: String
    let username: String
}

struct RegisterResponse: Codable {
    let user_id: String
    let username: String
}

struct ErrorResponse: Codable {
    let error: String
    let status: String?
}

// MARK: - Agent

struct Agent: Codable, Identifiable, Hashable {
    let id: String
    let name: String
    let model: String
    let personality: String
    let specialty: String
    let status: String

    var statusIcon: String {
        switch status {
        case "online": return "circle.fill"
        case "busy": return "moon.fill"
        case "idle": return "circle.dashed"
        default: return "circle"
        }
    }

    var statusColor: String {
        switch status {
        case "online": return "green"
        case "busy": return "orange"
        case "idle": return "yellow"
        default: return "gray"
        }
    }
}

// MARK: - Conversation

struct Conversation: Codable, Identifiable, Hashable {
    let id: String
    let user_id: String
    let agent_id: String
    let created_at: String
    let updated_at: String

    var displayName: String {
        "Conversation with \(agent_id)"
    }
}

// MARK: - Message

struct Message: Codable, Identifiable, Hashable {
    let id: String?
    let conversation_id: String
    let content: String
    let sender_type: String  // "client" or "agent"
    let sender_id: String
    let timestamp: String?

    var isFromUser: Bool {
        sender_type == "client"
    }

    var formattedTime: String {
        guard let ts = timestamp else { return "" }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        guard let date = formatter.date(from: ts) else { return "" }
        let display = DateFormatter()
        display.dateStyle = .none
        display.timeStyle = .short
        return display.string(from: date)
    }
}

// MARK: - WebSocket Messages

struct WSMessage: Codable {
    let type: String
    let data: WSMessageData?

    enum CodingKeys: String, CodingKey {
        case type, data
    }
}

struct WSMessageData: Codable {
    let conversation_id: String?
    let content: String?
    let sender_type: String?
    let sender_id: String?
    let agent_id: String?
    let status: String?

    // For connected/disconnected messages
    let message: String?
}

struct TypingIndicator: Codable {
    let conversation_id: String
    let sender_type: String
    let sender_id: String
}

struct StatusUpdate: Codable {
    let conversation_id: String?
    let status: String
    let sender_type: String
    let sender_id: String
}