import XCTest
@testable import AgentMessengerKit

final class WebSocketClientTests: XCTestCase {

    func testInitialState() async {
        let config = AppConfig()
        let client = WebSocketClient(config: config)

        XCTAssertEqual(client.connectionState, .disconnected)
        XCTAssertTrue(client.messages.isEmpty)
        XCTAssertTrue(client.typingAgents.isEmpty)
        XCTAssertTrue(client.agentStatuses.isEmpty)
    }

    func testDisconnectSetsState() async {
        let config = AppConfig()
        let client = WebSocketClient(config: config)

        await MainActor.run {
            client.disconnect()
            XCTAssertEqual(client.connectionState, .disconnected)
        }
    }

    func testMessageIsFromUser() {
        let userMsg = Message(
            id: nil,
            conversation_id: "conv1",
            content: "Hi",
            sender_type: "client",
            sender_id: "user1",
            timestamp: nil
        )
        XCTAssertTrue(userMsg.isFromUser)

        let agentMsg = Message(
            id: nil,
            conversation_id: "conv1",
            content: "Hello",
            sender_type: "agent",
            sender_id: "agent1",
            timestamp: nil
        )
        XCTAssertFalse(agentMsg.isFromUser)
    }

    func testConnectionStateEquality() {
        // ConnectionState is an enum with Equatable
        XCTAssertEqual(ConnectionState.disconnected, .disconnected)
        XCTAssertEqual(ConnectionState.connecting, .connecting)
        XCTAssertEqual(ConnectionState.connected, .connected)
        XCTAssertEqual(ConnectionState.reconnecting, .reconnecting)
        XCTAssertNotEqual(ConnectionState.disconnected, .connected)
    }
}