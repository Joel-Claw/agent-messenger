package com.agentmessenger.android.network

import com.agentmessenger.android.data.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.mockwebserver.*
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.util.concurrent.TimeUnit

class ApiClientTest {
    private lateinit var mockWebServer: MockWebServer
    private lateinit var apiClient: ApiClient
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    @Before
    fun setUp() {
        mockWebServer = MockWebServer()
        mockWebServer.start()
        apiClient = ApiClient(mockWebServer.url("/").toString())
    }

    @After
    fun tearDown() {
        mockWebServer.shutdown()
    }

    // --- Auth ---

    @Test
    fun login_success() = kotlinx.coroutines.test.runTest {
        val authResponse = AuthResponse(token = "jwt-token-123", userId = "user-1")
        mockWebServer.enqueue(
            MockResponse()
                .setBody(json.encodeToString(authResponse))
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
        )

        val result = apiClient.login("test@example.com", "password123")
        assertEquals("jwt-token-123", result.token)
        assertEquals("user-1", result.userId)

        val request = mockWebServer.takeRequest(1, TimeUnit.SECONDS)
        assertNotNull(request)
        assertEquals("POST", request!!.method)
        assertTrue(request.path!!.startsWith("/auth/login"))
        val body = request.body.readUtf8()
        assertTrue(body.contains("test@example.com"))
        assertTrue(body.contains("password123"))
    }

    @Test
    fun login_failure_throwsException() = kotlinx.coroutines.test.runTest {
        mockWebServer.enqueue(
            MockResponse()
                .setResponseCode(401)
                .setBody("""{"error":"invalid credentials"}""")
        )

        try {
            apiClient.login("bad@example.com", "wrong")
            fail("Expected ApiException")
        } catch (e: ApiClient.ApiException) {
            assertEquals(401, e.statusCode)
        }
    }

    @Test
    fun register_success() = kotlinx.coroutines.test.runTest {
        val authResponse = AuthResponse(token = "jwt-new-user", userId = "user-2")
        mockWebServer.enqueue(
            MockResponse()
                .setBody(json.encodeToString(authResponse))
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
        )

        val result = apiClient.register("new@example.com", "newpass123")
        assertEquals("jwt-new-user", result.token)
        assertEquals("user-2", result.userId)

        val request = mockWebServer.takeRequest(1, TimeUnit.SECONDS)
        assertEquals("POST", request!!.method)
        assertTrue(request.path!!.startsWith("/auth/user"))
    }

    // --- Auth header ---

    @Test
    fun authenticated_requests_includeBearerToken() = kotlinx.coroutines.test.runTest {
        apiClient.setAuthToken("my-jwt-token")

        // Return empty list for agents
        mockWebServer.enqueue(
            MockResponse()
                .setBody("[]")
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
        )

        apiClient.getAgents()

        val request = mockWebServer.takeRequest(1, TimeUnit.SECONDS)
        assertEquals("Bearer my-jwt-token", request!!.getHeader("Authorization"))
    }

    @Test
    fun unauthenticated_requests_noBearerToken() = kotlinx.coroutines.test.runTest {
        mockWebServer.enqueue(
            MockResponse()
                .setBody("[]")
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
        )

        apiClient.getAgents()

        val request = mockWebServer.takeRequest(1, TimeUnit.SECONDS)
        assertNull(request!!.getHeader("Authorization"))
    }

    // --- Agents ---

    @Test
    fun getAgents_success() = kotlinx.coroutines.test.runTest {
        val agents = listOf(
            Agent(id = "a1", name = "GPT-5", model = "gpt-5", status = "online"),
            Agent(id = "a2", name = "Claude", model = "claude-4", status = "busy", specialty = "reasoning")
        )
        mockWebServer.enqueue(
            MockResponse()
                .setBody(json.encodeToString(agents))
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
        )

        val result = apiClient.getAgents()
        assertEquals(2, result.size)
        assertEquals("GPT-5", result[0].name)
        assertEquals("online", result[0].status)
        assertEquals("reasoning", result[1].specialty)
    }

    @Test
    fun getAgents_empty() = kotlinx.coroutines.test.runTest {
        mockWebServer.enqueue(
            MockResponse()
                .setBody("[]")
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
        )

        val result = apiClient.getAgents()
        assertTrue(result.isEmpty())
    }

    // --- Conversations ---

    @Test
    fun createConversation_success() = kotlinx.coroutines.test.runTest {
        val conv = Conversation(
            id = "conv-1", userId = "user-1", agentId = "agent-1",
            createdAt = "2026-04-20T00:00:00Z", updatedAt = "2026-04-20T00:00:00Z"
        )
        mockWebServer.enqueue(
            MockResponse()
                .setBody(json.encodeToString(conv))
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
        )

        val result = apiClient.createConversation("agent-1")
        assertEquals("conv-1", result.id)
        assertEquals("agent-1", result.agentId)

        val request = mockWebServer.takeRequest(1, TimeUnit.SECONDS)
        assertEquals("POST", request!!.method)
        assertTrue(request.path!!.startsWith("/conversations"))
    }

    @Test
    fun getConversations_success() = kotlinx.coroutines.test.runTest {
        val convs = listOf(
            Conversation(id = "c1", userId = "u1", agentId = "a1",
                createdAt = "2026-04-20T00:00:00Z", updatedAt = "2026-04-20T00:00:00Z"),
            Conversation(id = "c2", userId = "u1", agentId = "a2",
                createdAt = "2026-04-19T00:00:00Z", updatedAt = "2026-04-19T00:00:00Z")
        )
        mockWebServer.enqueue(
            MockResponse()
                .setBody(json.encodeToString(convs))
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
        )

        val result = apiClient.getConversations()
        assertEquals(2, result.size)
        assertEquals("c1", result[0].id)
    }

    // --- Messages ---

    @Test
    fun getMessages_success() = kotlinx.coroutines.test.runTest {
        val msgs = listOf(
            Message(id = "m1", conversationId = "c1", senderType = "user",
                senderId = "u1", content = "Hello", createdAt = "2026-04-20T00:00:00Z"),
            Message(id = "m2", conversationId = "c1", senderType = "agent",
                senderId = "a1", content = "Hi there!", createdAt = "2026-04-20T00:00:01Z")
        )
        mockWebServer.enqueue(
            MockResponse()
                .setBody(json.encodeToString(msgs))
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
        )

        val result = apiClient.getMessages("c1")
        assertEquals(2, result.size)
        assertEquals("Hello", result[0].content)
        assertEquals("Hi there!", result[1].content)
    }

    @Test
    fun getMessages_withPagination() = kotlinx.coroutines.test.runTest {
        mockWebServer.enqueue(
            MockResponse()
                .setBody("[]")
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
        )

        apiClient.getMessages("c1", limit = 20, before = "2026-04-19T00:00:00Z")

        val request = mockWebServer.takeRequest(1, TimeUnit.SECONDS)
        val path = request!!.path!!
        assertTrue(path.contains("limit=20"))
        assertTrue(path.contains("before="))
    }

    // --- Push Notifications ---

    @Test
    fun registerDeviceToken_success() = kotlinx.coroutines.test.runTest {
        mockWebServer.enqueue(
            MockResponse()
                .setResponseCode(200)
        )
        apiClient.setAuthToken("jwt-token")

        apiClient.registerDeviceToken("fcm-token-123")

        val request = mockWebServer.takeRequest(1, TimeUnit.SECONDS)
        assertEquals("POST", request!!.method)
        assertTrue(request.path!!.startsWith("/push/register"))
        val body = request.body.readUtf8()
        assertTrue(body.contains("fcm-token-123"))
        assertTrue(body.contains("android"))
    }

    @Test
    fun unregisterDeviceToken_success() = kotlinx.coroutines.test.runTest {
        mockWebServer.enqueue(
            MockResponse()
                .setResponseCode(200)
        )
        apiClient.setAuthToken("jwt-token")

        apiClient.unregisterDeviceToken("fcm-token-123")

        val request = mockWebServer.takeRequest(1, TimeUnit.SECONDS)
        assertEquals("DELETE", request!!.method)
        assertTrue(request.path!!.startsWith("/push/unregister"))
    }

    // --- Error handling ---

    @Test
    fun apiError_throwsApiException() = kotlinx.coroutines.test.runTest {
        mockWebServer.enqueue(
            MockResponse()
                .setResponseCode(404)
                .setBody("""{"error":"not found"}""")
        )

        try {
            apiClient.getAgents()
            fail("Expected ApiException")
        } catch (e: ApiClient.ApiException) {
            assertEquals(404, e.statusCode)
            assertTrue(e.message!!.contains("not found"))
        }
    }

    @Test
    fun serverError_throwsApiException() = kotlinx.coroutines.test.runTest {
        mockWebServer.enqueue(
            MockResponse()
                .setResponseCode(500)
                .setBody("Internal Server Error")
        )

        try {
            apiClient.getAgents()
            fail("Expected ApiException")
        } catch (e: ApiClient.ApiException) {
            assertEquals(500, e.statusCode)
        }
    }
}