package com.agentmessenger.android.network

import com.agentmessenger.android.data.WsMessage
import com.agentmessenger.android.data.WsMessageData
import kotlinx.serialization.json.Json
import org.junit.Assert.*
import org.junit.Test

class WebSocketClientTest {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    // --- Message construction ---

    @Test
    fun sendMessage_constructsCorrectJson() {
        val client = WebSocketClient("http://localhost:8080")
        // Verify the client was created without errors
        assertNotNull(client)
        // Can't test actual WebSocket without a server, but we verify the data model
        val msg = WsMessage(
            type = "message",
            data = WsMessageData(
                conversationId = "conv-1",
                content = "Hello agent!",
                senderType = "user",
                senderId = "user-1"
            )
        )
        val jsonStr = json.encodeToString(WsMessage.serializer(), msg)
        assertTrue(jsonStr.contains("\"type\":\"message\""))
        assertTrue(jsonStr.contains("\"conversation_id\":\"conv-1\""))
        assertTrue(jsonStr.contains("\"content\":\"Hello agent!\""))
        assertTrue(jsonStr.contains("\"sender_type\":\"user\""))
    }

    @Test
    fun sendTyping_constructsCorrectJson() {
        val msg = WsMessage(
            type = "typing",
            data = WsMessageData(
                conversationId = "conv-1",
                typing = true
            )
        )
        val jsonStr = json.encodeToString(WsMessage.serializer(), msg)
        assertTrue(jsonStr.contains("\"type\":\"typing\""))
        assertTrue(jsonStr.contains("\"typing\":true"))
        assertTrue(jsonStr.contains("\"conversation_id\":\"conv-1\""))
    }

    // --- URL construction ---

    @Test
    fun wsUrl_httpToWs() {
        val baseUrl = "http://10.0.2.2:8080"
        val wsUrl = baseUrl.replace("http", "ws")
        assertEquals("ws://10.0.2.2:8080", wsUrl)
    }

    @Test
    fun wsUrl_httpsToWss() {
        val baseUrl = "https://agent.example.com"
        val wsUrl = baseUrl.replace("http", "ws")
        assertEquals("wss://agent.example.com", wsUrl)
    }

    @Test
    fun connectUrl_includesUserId() {
        val wsUrl = "ws://10.0.2.2:8080"
        val userId = "user-123"
        val url = "$wsUrl/client/connect?user_id=$userId"
        assertEquals("ws://10.0.2.2:8080/client/connect?user_id=user-123", url)
    }

    // --- Callbacks ---

    @Test
    fun webSocketClient_hasCallbacks() {
        val client = WebSocketClient("http://localhost:8080")
        // Verify callback properties exist and are null by default
        assertNull(client.onMessage)
        assertNull(client.onConnected)
        assertNull(client.onDisconnected)
        assertNull(client.onError)

        // Set callbacks
        var messageReceived = false
        var connectedCalled = false
        var disconnectedCalled = false
        var errorCalled = false

        client.onMessage = { messageReceived = true }
        client.onConnected = { connectedCalled = true }
        client.onDisconnected = { disconnectedCalled = true }
        client.onError = { errorCalled = true }

        assertNotNull(client.onMessage)
        assertNotNull(client.onConnected)
        assertNotNull(client.onDisconnected)
        assertNotNull(client.onError)
    }

    @Test
    fun webSocketClient_initiallyDisconnected() {
        val client = WebSocketClient("http://localhost:8080")
        assertFalse(client.isConnected())
    }

    @Test
    fun disconnect_doesNotCrash() {
        val client = WebSocketClient("http://localhost:8080")
        // Disconnect without connecting should not throw
        client.disconnect()
        assertFalse(client.isConnected())
    }

    // --- Message parsing ---

    @Test
    fun parseIncomingMessage_typeMessage() {
        val jsonStr = """{"type":"message","data":{"conversation_id":"c1","content":"Hello","sender_type":"agent","sender_id":"a1"}}"""
        val msg = json.decodeFromString<WsMessage>(jsonStr)
        assertEquals("message", msg.type)
        assertEquals("c1", msg.data?.conversationId)
        assertEquals("Hello", msg.data?.content)
        assertEquals("agent", msg.data?.senderType)
    }

    @Test
    fun parseIncomingMessage_typeTyping() {
        val jsonStr = """{"type":"typing","data":{"conversation_id":"c1","typing":true}}"""
        val msg = json.decodeFromString<WsMessage>(jsonStr)
        assertEquals("typing", msg.type)
        assertEquals("c1", msg.data?.conversationId)
        assertEquals(true, msg.data?.typing)
    }

    @Test
    fun parseIncomingMessage_typeStatus() {
        val jsonStr = """{"type":"status","data":{"status":"idle"}}"""
        val msg = json.decodeFromString<WsMessage>(jsonStr)
        assertEquals("status", msg.type)
        assertEquals("idle", msg.data?.status)
    }

    @Test
    fun parseIncomingMessage_unknownType() {
        val jsonStr = """{"type":"custom_event","data":null}"""
        val msg = json.decodeFromString<WsMessage>(jsonStr)
        assertEquals("custom_event", msg.type)
        assertNull(msg.data)
    }

    @Test
    fun parseIncomingMessage_extraFieldsIgnored() {
        val jsonStr = """{"type":"message","data":{"conversation_id":"c1","content":"Hi","sender_type":"user","sender_id":"u1","extra_field":"ignored"}}"""
        // Should parse without error (ignoreUnknownKeys = true)
        val msg = json.decodeFromString<WsMessage>(jsonStr)
        assertEquals("message", msg.type)
        assertEquals("Hi", msg.data?.content)
    }
}