import Foundation
import Combine

/// REST API client for Agent Messenger server.
/// Handles authentication, agent listing, conversation management.

enum APIError: LocalizedError {
    case invalidURL
    case networkError(Error)
    case unauthorized
    case serverError(String)
    case decodingError

    var errorDescription: String? {
        switch self {
        case .invalidURL: return "Invalid server URL"
        case .networkError(let e): return "Network error: \(e.localizedDescription)"
        case .unauthorized: return "Invalid credentials"
        case .serverError(let msg): return msg
        case .decodingError: return "Failed to parse server response"
        }
    }
}

@MainActor
class APIClient: ObservableObject {
    private let config: AppConfig
    private var token: String?

    init(config: AppConfig) {
        self.config = config
    }

    // MARK: - Authentication

    /// Register a new user account.
    func register(username: String, password: String) async throws -> RegisterResponse {
        guard let url = URL(string: "\(config.apiURL)/auth/user") else {
            throw APIError.invalidURL
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        let body = "username=\(urlEncode(username))&password=\(urlEncode(password))"
        request.httpBody = body.data(using: .utf8)

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw APIError.networkError(URLError(.badServerResponse))
        }

        if httpResponse.statusCode == 401 || httpResponse.statusCode == 403 {
            throw APIError.unauthorized
        }

        if httpResponse.statusCode >= 400 {
            if let errorResp = try? JSONDecoder().decode(ErrorResponse.self, from: data) {
                throw APIError.serverError(errorResp.error)
            }
            throw APIError.serverError("Server error (\(httpResponse.statusCode))")
        }

        guard let registerResp = try? JSONDecoder().decode(RegisterResponse.self, from: data) else {
            throw APIError.decodingError
        }

        return registerResp
    }

    /// Login with existing credentials. Returns JWT token.
    func login(username: String, password: String) async throws -> AuthResponse {
        guard let url = URL(string: "\(config.apiURL)/auth/login") else {
            throw APIError.invalidURL
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        let body = "username=\(urlEncode(username))&password=\(urlEncode(password))"
        request.httpBody = body.data(using: .utf8)

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw APIError.networkError(URLError(.badServerResponse))
        }

        if httpResponse.statusCode == 401 {
            throw APIError.unauthorized
        }

        if httpResponse.statusCode >= 400 {
            if let errorResp = try? JSONDecoder().decode(ErrorResponse.self, from: data) {
                throw APIError.serverError(errorResp.error)
            }
            throw APIError.serverError("Server error (\(httpResponse.statusCode))")
        }

        guard let authResp = try? JSONDecoder().decode(AuthResponse.self, from: data) else {
            throw APIError.decodingError
        }

        self.token = authResp.token
        return authResp
    }

    // MARK: - Agents

    /// List all available agents.
    func listAgents() async throws -> [Agent] {
        guard let url = URL(string: "\(config.apiURL)/agents") else {
            throw APIError.invalidURL
        }

        var request = URLRequest(url: url)
        if let token = token {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw APIError.networkError(URLError(.badServerResponse))
        }

        if httpResponse.statusCode == 401 {
            throw APIError.unauthorized
        }

        guard let agents = try? JSONDecoder().decode([Agent].self, from: data) else {
            throw APIError.decodingError
        }

        return agents
    }

    // MARK: - Conversations

    /// Create a new conversation with an agent.
    func createConversation(userID: String, agentID: String) async throws -> Conversation {
        guard let url = URL(string: "\(config.apiURL)/conversations/create") else {
            throw APIError.invalidURL
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("Bearer \(token ?? "")", forHTTPHeaderField: "Authorization")
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        let body = "user_id=\(urlEncode(userID))&agent_id=\(urlEncode(agentID))"
        request.httpBody = body.data(using: .utf8)

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw APIError.networkError(URLError(.badServerResponse))
        }

        if httpResponse.statusCode >= 400 {
            throw APIError.serverError("Failed to create conversation (\(httpResponse.statusCode))")
        }

        guard let conversation = try? JSONDecoder().decode(Conversation.self, from: data) else {
            throw APIError.decodingError
        }

        return conversation
    }

    /// List all conversations for the current user.
    func listConversations() async throws -> [Conversation] {
        guard let url = URL(string: "\(config.apiURL)/conversations/list") else {
            throw APIError.invalidURL
        }

        var request = URLRequest(url: url)
        request.setValue("Bearer \(token ?? "")", forHTTPHeaderField: "Authorization")

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw APIError.networkError(URLError(.badServerResponse))
        }

        if httpResponse.statusCode == 401 {
            throw APIError.unauthorized
        }

        guard let conversations = try? JSONDecoder().decode([Conversation].self, from: data) else {
            throw APIError.decodingError
        }

        return conversations
    }

    /// Get messages for a conversation.
    func getMessages(conversationID: String) async throws -> [Message] {
        guard let url = URL(string: "\(config.apiURL)/conversations/messages?conversation_id=\(urlEncode(conversationID))") else {
            throw APIError.invalidURL
        }

        var request = URLRequest(url: url)
        request.setValue("Bearer \(token ?? "")", forHTTPHeaderField: "Authorization")

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw APIError.networkError(URLError(.badServerResponse))
        }

        if httpResponse.statusCode == 401 {
            throw APIError.unauthorized
        }

        guard let messages = try? JSONDecoder().decode([Message].self, from: data) else {
            throw APIError.decodingError
        }

        return messages
    }

    // MARK: - Helpers

    private func urlEncode(_ string: String) -> String {
        string.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? string
    }
}