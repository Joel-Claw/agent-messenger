import XCTest
@testable import AgentMessengerKit

final class ModelTests: XCTestCase {

    // MARK: - Agent

    func testAgentStatusIcon() {
        let onlineAgent = Agent(id: "a1", name: "Bot", model: "gpt-4", personality: "helpful", specialty: "coding", status: "online")
        XCTAssertEqual(onlineAgent.statusIcon, "circle.fill")

        let offlineAgent = Agent(id: "a2", name: "Bot", model: "gpt-4", personality: "helpful", specialty: "coding", status: "offline")
        XCTAssertEqual(offlineAgent.statusIcon, "circle")

        let busyAgent = Agent(id: "a3", name: "Bot", model: "gpt-4", personality: "helpful", specialty: "coding", status: "busy")
        XCTAssertEqual(busyAgent.statusIcon, "moon.fill")

        let idleAgent = Agent(id: "a4", name: "Bot", model: "gpt-4", personality: "helpful", specialty: "coding", status: "idle")
        XCTAssertEqual(idleAgent.statusIcon, "circle.dashed")
    }

    func testAgentStatusColor() {
        let onlineAgent = Agent(id: "a1", name: "Bot", model: "gpt-4", personality: "helpful", specialty: "coding", status: "online")
        XCTAssertEqual(onlineAgent.statusColor, "green")

        let offlineAgent = Agent(id: "a2", name: "Bot", model: "gpt-4", personality: "helpful", specialty: "coding", status: "offline")
        XCTAssertEqual(offlineAgent.statusColor, "gray")
    }

    func testAgentCodable() throws {
        let agent = Agent(id: "agent-1", name: "Helper", model: "gpt-4", personality: "friendly", specialty: "coding", status: "online")
        let data = try JSONEncoder().encode(agent)
        let decoded = try JSONDecoder().decode(Agent.self, from: data)
        XCTAssertEqual(decoded.id, agent.id)
        XCTAssertEqual(decoded.name, agent.name)
        XCTAssertEqual(decoded.model, agent.model)
        XCTAssertEqual(decoded.status, agent.status)
    }

    // MARK: - Message

    func testMessageIsFromUser() {
        let userMsg = Message(id: "1", conversation_id: "conv1", content: "Hi", sender_type: "client", sender_id: "user1", timestamp: nil)
        XCTAssertTrue(userMsg.isFromUser)

        let agentMsg = Message(id: "2", conversation_id: "conv1", content: "Hello!", sender_type: "agent", sender_id: "agent1", timestamp: nil)
        XCTAssertFalse(agentMsg.isFromUser)
    }

    func testMessageCodable() throws {
        let msg = Message(
            id: "msg-1",
            conversation_id: "conv-1",
            content: "Hello world",
            sender_type: "client",
            sender_id: "user-1",
            timestamp: "2026-04-19T00:00:00Z"
        )
        let data = try JSONEncoder().encode(msg)
        let decoded = try JSONDecoder().decode(Message.self, from: data)
        XCTAssertEqual(decoded.id, msg.id)
        XCTAssertEqual(decoded.content, msg.content)
        XCTAssertEqual(decoded.sender_type, msg.sender_type)
    }

    // MARK: - Conversation

    func testConversationDisplayName() {
        let conv = Conversation(id: "conv1", user_id: "u1", agent_id: "helper-bot", created_at: "2026-04-19", updated_at: "2026-04-19")
        XCTAssertEqual(conv.displayName, "Conversation with helper-bot")
    }

    // MARK: - WSMessage

    func testWSMessageDecoding() throws {
        let json = """
        {"type": "message", "data": {"conversation_id": "conv1", "content": "Hello", "sender_type": "agent", "sender_id": "bot1"}}
        """.data(using: .utf8)!

        let msg = try JSONDecoder().decode(WSMessage.self, from: json)
        XCTAssertEqual(msg.type, "message")
        XCTAssertEqual(msg.data?.conversation_id, "conv1")
        XCTAssertEqual(msg.data?.content, "Hello")
        XCTAssertEqual(msg.data?.sender_type, "agent")
    }

    func testWSMessageConnected() throws {
        let json = """
        {"type": "connected", "data": {"message": "Connected successfully"}}
        """.data(using: .utf8)!

        let msg = try JSONDecoder().decode(WSMessage.self, from: json)
        XCTAssertEqual(msg.type, "connected")
        XCTAssertEqual(msg.data?.message, "Connected successfully")
    }

    // MARK: - Auth Response

    func testAuthResponseDecoding() throws {
        let json = """
        {"token": "jwt-token-123", "user_id": "user-1", "username": "testuser"}
        """.data(using: .utf8)!

        let resp = try JSONDecoder().decode(AuthResponse.self, from: json)
        XCTAssertEqual(resp.token, "jwt-token-123")
        XCTAssertEqual(resp.user_id, "user-1")
        XCTAssertEqual(resp.username, "testuser")
    }

    func testRegisterResponseDecoding() throws {
        let json = """
        {"user_id": "new-user-1", "username": "newuser"}
        """.data(using: .utf8)!

        let resp = try JSONDecoder().decode(RegisterResponse.self, from: json)
        XCTAssertEqual(resp.user_id, "new-user-1")
        XCTAssertEqual(resp.username, "newuser")
    }

    func testErrorResponseDecoding() throws {
        let json = """
        {"error": "Unauthorized", "status": "Unauthorized"}
        """.data(using: .utf8)!

        let resp = try JSONDecoder().decode(ErrorResponse.self, from: json)
        XCTAssertEqual(resp.error, "Unauthorized")
        XCTAssertEqual(resp.status, "Unauthorized")
    }
}