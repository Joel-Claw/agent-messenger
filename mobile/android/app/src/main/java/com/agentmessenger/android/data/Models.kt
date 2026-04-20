package com.agentmessenger.android.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class Agent(
    val id: String,
    val name: String,
    val model: String = "",
    val personality: String = "",
    val specialty: String = "",
    val status: String = "offline",
    @SerialName("connected_at") val connectedAt: String? = null
)

@Serializable
data class Conversation(
    val id: String,
    @SerialName("user_id") val userId: String,
    @SerialName("agent_id") val agentId: String,
    @SerialName("created_at") val createdAt: String,
    @SerialName("updated_at") val updatedAt: String
)

@Serializable
data class Message(
    val id: String? = null,
    @SerialName("conversation_id") val conversationId: String,
    @SerialName("sender_type") val senderType: String, // "user" or "agent"
    @SerialName("sender_id") val senderId: String,
    val content: String,
    @SerialName("created_at") val createdAt: String? = null
)

@Serializable
data class AuthResponse(
    val token: String,
    @SerialName("user_id") val userId: String
)

@Serializable
data class RegisterRequest(
    val username: String,
    val password: String
)

@Serializable
data class LoginRequest(
    val username: String,
    val password: String
)

@Serializable
data class ConversationCreateRequest(
    @SerialName("agent_id") val agentId: String
)

@Serializable
data class PushRegisterRequest(
    @SerialName("device_token") val deviceToken: String,
    val platform: String = "android"
)

// WebSocket message types
@Serializable
data class WsMessage(
    val type: String, // "message", "typing", "status"
    val data: WsMessageData? = null
)

@Serializable
data class WsMessageData(
    @SerialName("conversation_id") val conversationId: String? = null,
    val content: String? = null,
    @SerialName("sender_type") val senderType: String? = null,
    @SerialName("sender_id") val senderId: String? = null,
    val typing: Boolean? = null,
    val status: String? = null
)