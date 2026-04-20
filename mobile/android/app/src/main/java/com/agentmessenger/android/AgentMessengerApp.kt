package com.agentmessenger.android

import android.app.Application
import com.agentmessenger.android.data.ConfigManager

class AgentMessengerApp : Application() {
    override fun onCreate() {
        super.onCreate()
        ConfigManager.init(this)
    }
}