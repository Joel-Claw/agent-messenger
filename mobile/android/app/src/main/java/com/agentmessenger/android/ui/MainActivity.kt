package com.agentmessenger.android.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Chat
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.SmartToy
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import com.agentmessenger.android.data.*
import com.agentmessenger.android.network.ApiClient
import com.agentmessenger.android.network.WebSocketClient
import com.agentmessenger.android.ui.theme.AgentMessengerTheme
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        // Handle push notification tap
        val conversationId = intent?.getStringExtra("conversation_id")

        setContent {
            AgentMessengerTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    AgentMessengerApp(initialConversationId = conversationId)
                }
            }
        }
    }
}

// Navigation state
sealed class Screen {
    data object Login : Screen()
    data object Agents : Screen()
    data class Chat(val conversationId: String, val agent: Agent) : Screen()
    data object Conversations : Screen()
    data object Settings : Screen()
}

@Composable
fun AgentMessengerApp(initialConversationId: String? = null) {
    val scope = rememberCoroutineScope()

    // State
    var isLoggedIn by remember { mutableStateOf(ConfigManager.isLoggedIn()) }
    var currentScreen by remember { mutableStateOf<Screen>(if (isLoggedIn) Screen.Agents else Screen.Login) }
    var agents by remember { mutableStateOf<List<Agent>>(emptyList()) }
    var conversations by remember { mutableStateOf<List<Conversation>>(emptyList()) }
    var messages by remember { mutableStateOf<List<Message>>(emptyList()) }
    var isTyping by remember { mutableStateOf(false) }
    var currentAgent by remember { mutableStateOf<Agent?>(null) }
    var currentConversationId by remember { mutableStateOf<String?>(null) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    // Agent names map for conversation list
    val agentNames = remember(agents) {
        agents.associate { it.id to it.name }
    }

    // API client
    val apiClient = remember {
        ApiClient(ConfigManager.serverUrl).apply {
            ConfigManager.authToken?.let { setAuthToken(it) }
        }
    }

    // WebSocket client
    val wsClient = remember {
        WebSocketClient(ConfigManager.serverUrl).apply {
            ConfigManager.authToken?.let { authToken = it }
            onMessage = { wsMessage ->
                when (wsMessage.type) {
                    "message" -> {
                        wsMessage.data?.let { data ->
                            val msg = Message(
                                conversationId = data.conversationId ?: "",
                                senderType = data.senderType ?: "agent",
                                senderId = data.senderId ?: "",
                                content = data.content ?: "",
                                createdAt = java.time.Instant.now().toString()
                            )
                            messages = (messages + msg).sortedBy { it.createdAt }
                        }
                    }
                    "typing" -> {
                        if (wsMessage.data?.conversationId == currentConversationId) {
                            isTyping = wsMessage.data?.typing ?: false
                        }
                    }
                    "status" -> {
                        // Refresh agent list when status changes
                        scope.launch {
                            try { agents = apiClient.getAgents() } catch (_: Exception) {}
                        }
                    }
                }
            }
            onConnected = {
                scope.launch {
                    try { agents = apiClient.getAgents() } catch (_: Exception) {}
                }
            }
        }
    }

    // Connect WebSocket when logged in
    LaunchedEffect(isLoggedIn) {
        if (isLoggedIn) {
            ConfigManager.userId?.let { userId ->
                wsClient.connect(userId)
            }
            try {
                agents = apiClient.getAgents()
                conversations = apiClient.getConversations()
            } catch (_: Exception) {}
        }
    }

    // Handle initial conversation from push notification
    LaunchedEffect(initialConversationId) {
        if (initialConversationId != null && isLoggedIn) {
            try {
                val msgs = apiClient.getMessages(initialConversationId)
                messages = msgs
                currentConversationId = initialConversationId
            } catch (_: Exception) {}
        }
    }

    // Navigation
    when (val screen = currentScreen) {
        is Screen.Login -> {
            LoginScreen(
                onLoginSuccess = {
                    isLoggedIn = true
                    ConfigManager.authToken?.let { apiClient.setAuthToken(it) }
                    ConfigManager.authToken?.let { wsClient.authToken = it }
                    currentScreen = Screen.Agents
                }
            )
        }

        is Screen.Agents -> {
            AgentsScreen(
                agents = agents,
                onAgentSelected = { agent ->
                    scope.launch {
                        try {
                            val conversation = apiClient.createConversation(agent.id)
                            currentConversationId = conversation.id
                            currentAgent = agent
                            messages = emptyList()

                            // Load existing messages
                            try {
                                messages = apiClient.getMessages(conversation.id)
                            } catch (_: Exception) {}

                            currentScreen = Screen.Chat(conversation.id, agent)
                        } catch (e: Exception) {
                            errorMessage = "Failed to start conversation: ${e.message}"
                        }
                    }
                },
                onLogout = {
                    wsClient.disconnect()
                    scope.launch {
                        ConfigManager.clear()
                        isLoggedIn = false
                        agents = emptyList()
                        conversations = emptyList()
                        messages = emptyList()
                        currentScreen = Screen.Login
                    }
                },
                onNavigateConversations = {
                    scope.launch {
                        try { conversations = apiClient.getConversations() } catch (_: Exception) {}
                    }
                    currentScreen = Screen.Conversations
                },
                onNavigateSettings = { currentScreen = Screen.Settings }
            )
        }

        is Screen.Chat -> {
            ChatScreen(
                agentName = screen.agent.name,
                messages = messages.filter { it.conversationId == screen.conversationId },
                isTyping = isTyping,
                onSendMessage = { content ->
                    screen.conversationId.let { convId ->
                        wsClient.sendMessage(convId, content)
                    }
                },
                onBack = {
                    currentConversationId = null
                    currentAgent = null
                    isTyping = false
                    currentScreen = Screen.Agents
                }
            )
        }

        is Screen.Conversations -> {
            ConversationsScreen(
                conversations = conversations,
                agentNames = agentNames,
                onConversationSelected = { conv ->
                    currentConversationId = conv.id
                    scope.launch {
                        try {
                            messages = apiClient.getMessages(conv.id)
                            val agent = agents.find { it.id == conv.agentId }
                            if (agent != null) {
                                currentAgent = agent
                                currentScreen = Screen.Chat(conv.id, agent)
                            }
                        } catch (e: Exception) {
                            errorMessage = "Failed to load conversation: ${e.message}"
                        }
                    }
                },
                onBack = { currentScreen = Screen.Agents }
            )
        }

        is Screen.Settings -> {
            SettingsScreen(
                onBack = { currentScreen = Screen.Agents },
                onLogout = {
                    wsClient.disconnect()
                    scope.launch {
                        ConfigManager.clear()
                        isLoggedIn = false
                        agents = emptyList()
                        conversations = emptyList()
                        messages = emptyList()
                        currentScreen = Screen.Login
                    }
                }
            )
        }
    }

    // Error snackbar
    errorMessage?.let { error ->
        Snackbar(
            modifier = Modifier.padding(16.dp),
            action = {
                TextButton(onClick = { errorMessage = null }) {
                    Text("Dismiss")
                }
            }
        ) {
            Text(error)
        }
        LaunchedEffect(error) {
            kotlinx.coroutines.delay(5000)
            errorMessage = null
        }
    }
}