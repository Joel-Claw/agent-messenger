package com.agentmessenger.android.notification

import android.util.Log
import com.agentmessenger.android.data.ConfigManager
import com.agentmessenger.android.network.ApiClient
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import kotlinx.coroutines.runBlocking

class AgentMessengerFirebaseMessagingService : FirebaseMessagingService() {

    override fun onCreate() {
        super.onCreate()
        NotificationHelper.createChannel(this)
    }

    override fun onNewToken(token: String) {
        Log.d(TAG, "FCM token refreshed: ${token.take(8)}...")
        ConfigManager.fcmToken = token
        registerToken(token)
    }

    override fun onMessageReceived(message: RemoteMessage) {
        val title = message.data["title"] ?: "New message"
        val body = message.data["body"] ?: ""
        val conversationId = message.data["conversation_id"] ?: ""

        Log.d(TAG, "Push received: $title")
        NotificationHelper.showMessageNotification(this, title, body, conversationId)
    }

    private fun registerToken(token: String) {
        val apiClient = ApiClient(ConfigManager.serverUrl)
        ConfigManager.authToken?.let { authToken ->
            apiClient.setAuthToken(authToken)
            try {
                runBlocking { apiClient.registerDeviceToken(token) }
                Log.d(TAG, "FCM token registered with server")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to register FCM token", e)
            }
        }
    }

    companion object {
        private const val TAG = "FCMService"
    }
}