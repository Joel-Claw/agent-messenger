package com.agentmessenger.android.network

import com.agentmessenger.android.data.*
import kotlinx.serialization.json.Json
import org.junit.Assert.*
import org.junit.Test

class WebSocketClientTest {

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    @Test
    fun wsMessage_serialization_roundTrip() {
        val original = WsMessage(
            type = "message",
            data = WsMessageData(
                conversationId = "conv-1",
                content = "Hello, agent!",
                senderType = "user",
                senderId = "user-1"
            )
        )
        val serialized = json.encodeToString(WsMessage.serializer(), original)
        val deserialized = json.decodeFromString(WsMessage.serializer(), serialized)
        assertEquals(original.type, deserialized.type)
        assertEquals(original.data?.conversationId, deserialized.data?.conversationId)
        assertEquals(original.data?.content, deserialized.data?.content)
    }

    @Test
    fun wsMessage_typing_serialization() {
        val msg = WsMessage(
            type = "typing",
            data = WsMessageData(
                conversationId = "conv-1",
                typing = true
            )
        )
        val serialized = json.encodeToString(WsMessage.serializer(), msg)
        assertTrue(serialized.contains("typing"))
        assertTrue(serialized.contains("conv-1"))
    }

    @Test
    fun wsMessage_status_serialization() {
        val msg = WsMessage(
            type = "status",
            data = WsMessageData(
                status = "busy"
            )
        )
        val serialized = json.encodeToString(WsMessage.serializer(), msg)
        assertTrue(serialized.contains("busy"))
    }

    @Test
    fun wsMessage_nullData() {
        val msg = WsMessage(type = "ping")
        val serialized = json.encodeToString(WsMessage.serializer(), msg)
        val deserialized = json.decodeFromString(WsMessage.serializer(), serialized)
        assertEquals("ping", deserialized.type)
        assertNull(deserialized.data)
    }

    @Test
    fun apiException_message() {
        val exc = ApiClient.ApiException(404, "Not found")
        assertEquals(404, exc.statusCode)
        assertTrue(exc.message!!.contains("404"))
        assertTrue(exc.message!!.contains("Not found"))
    }

    @Test
    fun models_jsonRoundTrip() {
        val agent = Agent(
            id = "a1",
            name = "Joel",
            model = "glm-5.1",
            personality = "Direct",
            specialty = "IT",
            status = "online",
            connectedAt = "2026-04-20T00:00:00Z"
        )
        val serialized = json.encodeToString(Agent.serializer(), agent)
        val deserialized = json.decodeFromString(Agent.serializer(), serialized)
        assertEquals(agent, deserialized)
    }
}