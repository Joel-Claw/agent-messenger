package com.agentmessenger.android.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.runBlocking

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "agent_messenger_config")

object ConfigManager {
    private lateinit var appContext: Context

    // DataStore keys
    private val KEY_SERVER_URL = stringPreferencesKey("server_url")
    private val KEY_WS_URL = stringPreferencesKey("ws_url")
    private val KEY_AUTH_TOKEN = stringPreferencesKey("auth_token")
    private val KEY_USER_ID = stringPreferencesKey("user_id")
    private val KEY_USER_EMAIL = stringPreferencesKey("user_email")
    private val KEY_FCM_TOKEN = stringPreferencesKey("fcm_token")

    fun init(context: Context) {
        appContext = context.applicationContext
    }

    val dataStore: DataStore<Preferences>
        get() = appContext.dataStore

    // Server URLs
    var serverUrl: String
        get() = runBlocking { appContext.dataStore.data.map { it[KEY_SERVER_URL] ?: "http://10.0.2.2:8080" }.first() }
        set(value) = runBlocking { appContext.dataStore.edit { it[KEY_SERVER_URL] = value } }

    var wsUrl: String
        get() = runBlocking { appContext.dataStore.data.map { it[KEY_WS_URL] ?: "ws://10.0.2.2:8080" }.first() }
        set(value) = runBlocking { appContext.dataStore.edit { it[KEY_WS_URL] = value } }

    // Auth
    var authToken: String?
        get() = runBlocking { appContext.dataStore.data.map { it[KEY_AUTH_TOKEN] }.first() }
        set(value) = runBlocking { appContext.dataStore.edit { if (value != null) it[KEY_AUTH_TOKEN] = value else it.remove(KEY_AUTH_TOKEN) } }

    var userId: String?
        get() = runBlocking { appContext.dataStore.data.map { it[KEY_USER_ID] }.first() }
        set(value) = runBlocking { appContext.dataStore.edit { if (value != null) it[KEY_USER_ID] = value else it.remove(KEY_USER_ID) } }

    var userEmail: String?
        get() = runBlocking { appContext.dataStore.data.map { it[KEY_USER_EMAIL] }.first() }
        set(value) = runBlocking { appContext.dataStore.edit { if (value != null) it[KEY_USER_EMAIL] = value else it.remove(KEY_USER_EMAIL) } }

    // FCM
    var fcmToken: String?
        get() = runBlocking { appContext.dataStore.data.map { it[KEY_FCM_TOKEN] }.first() }
        set(value) = runBlocking { appContext.dataStore.edit { if (value != null) it[KEY_FCM_TOKEN] = value else it.remove(KEY_FCM_TOKEN) } }

    fun isLoggedIn(): Boolean = authToken != null

    suspend fun clear() {
        appContext.dataStore.edit { it.clear() }
    }
}