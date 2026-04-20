package com.agentmessenger.android.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Chat
import androidx.compose.material.icons.filled.Logout
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.agentmessenger.android.data.Agent

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AgentsScreen(
    agents: List<Agent>,
    onAgentSelected: (Agent) -> Unit,
    onLogout: () -> Unit,
    onNavigateConversations: () -> Unit = {},
    onNavigateSettings: () -> Unit = {}
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Agent Messenger") },
                actions = {
                    IconButton(onClick = onNavigateConversations) {
                        Icon(Icons.Filled.Chat, contentDescription = "Conversations")
                    }
                    IconButton(onClick = onNavigateSettings) {
                        Icon(Icons.Filled.Settings, contentDescription = "Settings")
                    }
                }
            )
        }
    ) { padding ->
        if (agents.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        text = "No agents online",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Waiting for agents to connect...",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(horizontal = 16.dp)
            ) {
                items(agents) { agent ->
                    AgentCard(
                        agent = agent,
                        onClick = { onAgentSelected(agent) }
                    )
                }
            }
        }
    }
}

@Composable
private fun AgentCard(
    agent: Agent,
    onClick: () -> Unit
) {
    val statusColor = when (agent.status) {
        "online" -> MaterialTheme.colorScheme.primary
        "busy" -> androidx.compose.ui.graphics.Color(0xFFD29922)
        "idle" -> MaterialTheme.colorScheme.onSurfaceVariant
        else -> MaterialTheme.colorScheme.outline
    }

    val statusLabel = when (agent.status) {
        "online" -> "Online"
        "busy" -> "Busy"
        "idle" -> "Idle"
        else -> "Offline"
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
            .clickable(onClick = onClick)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Status indicator
            Surface(
                modifier = Modifier.size(12.dp),
                shape = androidx.compose.foundation.shape.CircleShape,
                color = statusColor
            ) {}

            Spacer(modifier = Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = agent.name,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
                if (agent.specialty.isNotBlank()) {
                    Text(
                        text = agent.specialty,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                if (agent.model.isNotBlank()) {
                    Text(
                        text = agent.model,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.outline
                    )
                }
            }

            Column(horizontalAlignment = Alignment.End) {
                AssistChip(
                    onClick = onClick,
                    label = { Text("Chat") },
                    leadingIcon = {
                        Icon(
                            Icons.Filled.Add,
                            contentDescription = "Start conversation",
                            modifier = Modifier.size(18.dp)
                        )
                    }
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = statusLabel,
                    style = MaterialTheme.typography.labelSmall,
                    color = statusColor
                )
            }
        }
    }
}