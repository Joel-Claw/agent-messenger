package com.agentmessenger.android.data

import org.junit.Assert.*
import org.junit.Test

class ModelsTest {

    @Test
    fun agent_defaultValues() {
        val agent = Agent(id = "agent-1", name = "TestAgent")
        assertEquals("agent-1", agent.id)
        assertEquals("TestAgent", agent.name)
        assertEquals("", agent.model)
        assertEquals("", agent.personality)
        assertEquals("", agent.specialty)
        assertEquals("offline", agent.status)
        assertNull(agent.connectedAt)
    }

    @Test
    fun agent_allFields() {
        val agent = Agent(
            id = "agent-1",
            name = "Joel",
            model = "glm-5.1",
            personality = "Direct, dry humor",
            specialty = "IT and coding",
            status = "online",
            connectedAt = "2026-04-20T00:00:00Z"
        )
        assertEquals("Joel", agent.name)
        assertEquals("glm-5.1", agent.model)
        assertEquals("online", agent.status)
    }

    @Test
    fun message_fields() {
        val msg = Message(
            id = "msg-1",
            conversationId = "conv-1",
            senderType = "user",
            senderId = "user-1",
            content = "Hello",
            createdAt = "2026-04-20T00:00:00Z"
        )
        assertEquals("msg-1", msg.id)
        assertEquals("user", msg.senderType)
        assertEquals("Hello", msg.content)
    }

    @Test
    fun conversation_fields() {
        val conv = Conversation(
            id = "conv-1",
            userId = "user-1",
            agentId = "agent-1",
            createdAt = "2026-04-20T00:00:00Z",
            updatedAt = "2026-04-20T00:00:00Z"
        )
        assertEquals("conv-1", conv.id)
        assertEquals("agent-1", conv.agentId)
    }

    @Test
    fun wsMessage_serialization() {
        val ws = WsMessage(
            type = "message",
            data = WsMessageData(
                conversationId = "conv-1",
                content = "Hello",
                senderType = "user"
            )
        )
        assertEquals("message", ws.type)
        assertEquals("conv-1", ws.data?.conversationId)
        assertEquals("Hello", ws.data?.content)
    }

    @Test
    fun authResponse_fields() {
        val auth = AuthResponse(token = "jwt-token", userId = "user-1")
        assertEquals("jwt-token", auth.token)
        assertEquals("user-1", auth.userId)
    }

    @Test
    fun pushRegisterRequest_defaultPlatform() {
        val req = PushRegisterRequest(deviceToken = "fcm-token-123")
        assertEquals("fcm-token-123", req.deviceToken)
        assertEquals("android", req.platform)
    }
}