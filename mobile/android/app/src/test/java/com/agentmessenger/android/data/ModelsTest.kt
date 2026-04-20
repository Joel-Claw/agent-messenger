package com.agentmessenger.android.data

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.*
import org.junit.Test

class ModelsTest {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    // Agent
    @Test
    fun agent_defaultValues() {
        val agent = Agent(id = "a1", name = "TestAgent")
        assertEquals("a1", agent.id)
        assertEquals("TestAgent", agent.name)
        assertEquals("", agent.model)
        assertEquals("", agent.personality)
        assertEquals("", agent.specialty)
        assertEquals("offline", agent.status)
        assertNull(agent.connectedAt)
    }

    @Test
    fun agent_fullConstructor() {
        val agent = Agent(
            id = "a1", name = "GPT-5", model = "gpt-5",
            personality = "helpful", specialty = "coding",
            status = "online", connectedAt = "2026-04-20T00:00:00Z"
        )
        assertEquals("online", agent.status)
        assertEquals("coding", agent.specialty)
    }

    @Test
    fun agent_serialization_roundTrip() {
        val agent = Agent(
            id = "a1", name = "TestAgent", model = "gpt-5",
            personality = "helpful", specialty = "general",
            status = "online", connectedAt = "2026-04-20T00:00:00Z"
        )
        val serialized = json.encodeToString(agent)
        val deserialized = json.decodeFromString<Agent>(serialized)
        assertEquals(agent, deserialized)
    }

    @Test
    fun agent_serialization_jsonKeys() {
        val agent = Agent(id = "a1", name = "Test", status = "online", connectedAt = "2026-01-01T00:00:00Z")
        val jsonString = json.encodeToString(agent)
        assertTrue(jsonString.contains("\"connected_at\""))
        assertTrue(jsonString.contains("\"sender_type\"").not()) // Not in Agent
    }

    // Conversation
    @Test
    fun conversation_serialization_roundTrip() {
        val conv = Conversation(
            id = "c1", userId = "u1", agentId = "a1",
            createdAt = "2026-04-20T00:00:00Z", updatedAt = "2026-04-20T00:00:00Z"
        )
        val serialized = json.encodeToString(conv)
        val deserialized = json.decodeFromString<Conversation>(serialized)
        assertEquals(conv, deserialized)
    }

    @Test
    fun conversation_serialization_jsonKeys() {
        val conv = Conversation(id = "c1", userId = "u1", agentId = "a1",
            createdAt = "2026-01-01T00:00:00Z", updatedAt = "2026-01-01T00:00:00Z")
        val jsonString = json.encodeToString(conv)
        assertTrue(jsonString.contains("\"user_id\""))
        assertTrue(jsonString.contains("\"agent_id\""))
        assertTrue(jsonString.contains("\"created_at\""))
        assertTrue(jsonString.contains("\"updated_at\""))
    }

    // Message
    @Test
    fun message_defaultValues() {
        val msg = Message(
            conversationId = "c1", senderType = "user",
            senderId = "u1", content = "Hello"
        )
        assertNull(msg.id)
        assertNull(msg.createdAt)
    }

    @Test
    fun message_serialization_roundTrip() {
        val msg = Message(
            id = "m1", conversationId = "c1", senderType = "user",
            senderId = "u1", content = "Hello", createdAt = "2026-04-20T00:00:00Z"
        )
        val serialized = json.encodeToString(msg)
        val deserialized = json.decodeFromString<Message>(serialized)
        assertEquals(msg, deserialized)
    }

    // AuthResponse
    @Test
    fun authResponse_serialization() {
        val auth = AuthResponse(token = "jwt-token-123", userId = "user-456")
        val jsonString = json.encodeToString(auth)
        assertTrue(jsonString.contains("\"token\""))
        assertTrue(jsonString.contains("\"user_id\""))

        val deserialized = json.decodeFromString<AuthResponse>(jsonString)
        assertEquals("jwt-token-123", deserialized.token)
        assertEquals("user-456", deserialized.userId)
    }

    // LoginRequest / RegisterRequest
    @Test
    fun loginRequest_serialization() {
        val login = LoginRequest(username = "testuser", password = "secret123")
        val jsonString = json.encodeToString(login)
        assertTrue(jsonString.contains("\"username\""))
        assertTrue(jsonString.contains("\"password\""))
    }

    @Test
    fun registerRequest_serialization() {
        val reg = RegisterRequest(username = "newuser", password = "pass123")
        val jsonString = json.encodeToString(reg)
        assertTrue(jsonString.contains("\"username\""))
        assertTrue(jsonString.contains("\"password\""))
    }

    // ConversationCreateRequest
    @Test
    fun conversationCreateRequest_serialization() {
        val req = ConversationCreateRequest(agentId = "agent-1")
        val jsonString = json.encodeToString(req)
        assertTrue(jsonString.contains("\"agent_id\""))
        assertTrue(jsonString.contains("\"agent-1\""))
    }

    // PushRegisterRequest
    @Test
    fun pushRegisterRequest_defaultPlatform() {
        val req = PushRegisterRequest(deviceToken = "fcm-token-abc")
        assertEquals("android", req.platform)
    }

    @Test
    fun pushRegisterRequest_customPlatform() {
        val req = PushRegisterRequest(deviceToken = "token123", platform = "ios")
        assertEquals("ios", req.platform)
    }

    // WsMessage
    @Test
    fun wsMessage_serialization_message() {
        val msg = WsMessage(
            type = "message",
            data = WsMessageData(
                conversationId = "c1",
                content = "Hello",
                senderType = "user",
                senderId = "u1"
            )
        )
        val jsonString = json.encodeToString(WsMessage.serializer(), msg)
        assertTrue(jsonString.contains("\"type\":\"message\""))
        assertTrue(jsonString.contains("\"conversation_id\""))
    }

    @Test
    fun wsMessage_serialization_typing() {
        val msg = WsMessage(
            type = "typing",
            data = WsMessageData(conversationId = "c1", typing = true)
        )
        val jsonString = json.encodeToString(WsMessage.serializer(), msg)
        assertTrue(jsonString.contains("\"type\":\"typing\""))
        assertTrue(jsonString.contains("\"typing\":true"))
    }

    @Test
    fun wsMessage_deserialization_fromJson() {
        val jsonString = """{"type":"message","data":{"conversation_id":"c1","content":"Hi","sender_type":"agent","sender_id":"a1"}}"""
        val msg = json.decodeFromString<WsMessage>(jsonString)
        assertEquals("message", msg.type)
        assertEquals("c1", msg.data?.conversationId)
        assertEquals("Hi", msg.data?.content)
        assertEquals("agent", msg.data?.senderType)
    }

    @Test
    fun wsMessage_nullData() {
        val msg = WsMessage(type = "ping")
        val jsonString = json.encodeToString(WsMessage.serializer(), msg)
        val deserialized = json.decodeFromString<WsMessage>(jsonString)
        assertNull(deserialized.data)
    }

    // WsMessageData null fields
    @Test
    fun wsMessageData_nullFields() {
        val data = WsMessageData()
        assertNull(data.conversationId)
        assertNull(data.content)
        assertNull(data.senderType)
        assertNull(data.senderId)
        assertNull(data.typing)
        assertNull(data.status)
    }
}