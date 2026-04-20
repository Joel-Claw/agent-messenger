package com.agentmessenger.android.network

import android.util.Log
import com.agentmessenger.android.data.WsMessage
import com.agentmessenger.android.data.WsMessageData
import kotlinx.coroutines.*
import kotlinx.serialization.json.Json
import okhttp3.*

class WebSocketClient(
    private val baseUrl: String,
    private var authToken: String? = null
) {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private val client = OkHttpClient.Builder()
        .pingInterval(30, java.util.concurrent.TimeUnit.SECONDS)
        .build()

    private var webSocket: WebSocket? = null
    private var scope: CoroutineScope? = null
    private var reconnectJob: Job? = null
    private var reconnectAttempts = 0
    private val maxReconnectDelay = 30_000L // 30 seconds max

    var onMessage: ((WsMessage) -> Unit)? = null
    var onConnected: (() -> Unit)? = null
    var onDisconnected: (() -> Unit)? = null
    var onError: ((String) -> Unit)? = null

    fun connect(userId: String) {
        disconnect()
        scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        reconnectAttempts = 0
        connectInternal(userId)
    }

    private fun connectInternal(userId: String) {
        val wsUrl = baseUrl.replace("http", "ws").replace("https", "wss")
        val url = "$wsUrl/client/connect?user_id=$userId"

        val requestBuilder = Request.Builder().url(url)
        authToken?.let { requestBuilder.addHeader("Authorization", "Bearer $it") }

        webSocket = client.newWebSocket(requestBuilder.build(), object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                Log.d(TAG, "WebSocket connected")
                reconnectAttempts = 0
                onConnected?.invoke()
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                try {
                    val message = json.decodeFromString<WsMessage>(text)
                    onMessage?.invoke(message)
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to parse message: $text", e)
                }
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                webSocket.close(1000, null)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                Log.d(TAG, "WebSocket closed: $code $reason")
                onDisconnected?.invoke()
                scheduleReconnect(userId)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                Log.e(TAG, "WebSocket failure", t)
                onError?.invoke(t.message ?: "Connection failed")
                scheduleReconnect(userId)
            }
        })
    }

    fun sendMessage(conversationId: String, content: String) {
        val wsMessage = WsMessage(
            type = "message",
            data = WsMessageData(
                conversationId = conversationId,
                content = content,
                senderType = "user"
            )
        )
        val jsonStr = json.encodeToString(WsMessage.serializer(), wsMessage)
        webSocket?.send(jsonStr)
    }

    fun sendTyping(conversationId: String, typing: Boolean) {
        val wsMessage = WsMessage(
            type = "typing",
            data = WsMessageData(
                conversationId = conversationId,
                typing = typing
            )
        )
        val jsonStr = json.encodeToString(WsMessage.serializer(), wsMessage)
        webSocket?.send(jsonStr)
    }

    private fun scheduleReconnect(userId: String) {
        reconnectJob?.cancel()
        val delay = minOf(1000L * (1 shl reconnectAttempts), maxReconnectDelay)
        reconnectAttempts++
        Log.d(TAG, "Reconnecting in ${delay}ms (attempt $reconnectAttempts)")

        reconnectJob = scope?.launch {
            delay(delay)
            connectInternal(userId)
        }
    }

    fun disconnect() {
        reconnectJob?.cancel()
        webSocket?.close(1000, "Client disconnecting")
        webSocket = null
        scope?.cancel()
        scope = null
    }

    fun isConnected(): Boolean = webSocket != null

    companion object {
        private const val TAG = "WebSocketClient"
    }
}