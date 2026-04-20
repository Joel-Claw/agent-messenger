package com.agentmessenger.android.network

import com.agentmessenger.android.data.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.encodeToString
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.net.URLEncoder

class ApiClient(private val baseUrl: String) {
    private val client = OkHttpClient.Builder()
        .connectTimeout(10, java.util.concurrent.TimeUnit.SECONDS)
        .readTimeout(30, java.util.concurrent.TimeUnit.SECONDS)
        .build()

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private val jsonMediaType = "application/json; charset=utf-8".toMediaType()

    private var authToken: String? = null

    fun setAuthToken(token: String?) {
        authToken = token
    }

    // Auth
    suspend fun register(email: String, password: String): AuthResponse = withContext(Dispatchers.IO) {
        val body = json.encodeToString(RegisterRequest(email, password))
        val request = buildRequest("/auth/user", "POST", body)
        val response = client.newCall(request).execute()
        checkSuccess(response)
        json.decodeFromString(response.body!!.string())
    }

    suspend fun login(email: String, password: String): AuthResponse = withContext(Dispatchers.IO) {
        val body = json.encodeToString(LoginRequest(email, password))
        val request = buildRequest("/auth/login", "POST", body)
        val response = client.newCall(request).execute()
        checkSuccess(response)
        json.decodeFromString(response.body!!.string())
    }

    // Agents
    suspend fun getAgents(): List<Agent> = withContext(Dispatchers.IO) {
        val request = buildRequest("/agents", "GET")
        val response = client.newCall(request).execute()
        checkSuccess(response)
        json.decodeFromString(response.body!!.string())
    }

    // Conversations
    suspend fun createConversation(agentId: String): Conversation = withContext(Dispatchers.IO) {
        val body = json.encodeToString(ConversationCreateRequest(agentId))
        val request = buildRequest("/conversations", "POST", body)
        val response = client.newCall(request).execute()
        checkSuccess(response)
        json.decodeFromString(response.body!!.string())
    }

    suspend fun getConversations(): List<Conversation> = withContext(Dispatchers.IO) {
        val request = buildRequest("/conversations", "GET")
        val response = client.newCall(request).execute()
        checkSuccess(response)
        json.decodeFromString(response.body!!.string())
    }

    // Messages
    suspend fun getMessages(conversationId: String, limit: Int = 50, before: String? = null): List<Message> =
        withContext(Dispatchers.IO) {
            var url = "/conversations/$conversationId/messages?limit=$limit"
            if (before != null) url += "&before=${URLEncoder.encode(before, "UTF-8")}"
            val request = buildRequest(url, "GET")
            val response = client.newCall(request).execute()
            checkSuccess(response)
            json.decodeFromString(response.body!!.string())
        }

    // Push notifications
    suspend fun registerDeviceToken(deviceToken: String): Unit = withContext(Dispatchers.IO) {
        val body = json.encodeToString(PushRegisterRequest(deviceToken))
        val request = buildRequest("/push/register", "POST", body)
        val response = client.newCall(request).execute()
        checkSuccess(response)
    }

    suspend fun unregisterDeviceToken(deviceToken: String): Unit = withContext(Dispatchers.IO) {
        val body = json.encodeToString(PushRegisterRequest(deviceToken))
        val request = buildRequest("/push/unregister", "DELETE", body)
        val response = client.newCall(request).execute()
        checkSuccess(response)
    }

    // Internal
    private fun buildRequest(path: String, method: String, body: String? = null): Request {
        val requestBody = body?.toRequestBody(jsonMediaType)
        return Request.Builder()
            .url("$baseUrl$path")
            .method(method, requestBody)
            .apply {
                authToken?.let { addHeader("Authorization", "Bearer $it") }
                if (body != null) addHeader("Content-Type", "application/json")
            }
            .build()
    }

    private fun checkSuccess(response: okhttp3.Response) {
        if (!response.isSuccessful) {
            val errorBody = response.body?.string() ?: "Unknown error"
            throw ApiException(response.code, errorBody)
        }
    }

    class ApiException(val statusCode: Int, message: String) : Exception("API error $statusCode: $message")
}