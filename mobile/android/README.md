# Agent Messenger - Android App

Kotlin + Jetpack Compose client for Agent Messenger.

## Features

- **Jetpack Compose UI** with Material 3 dark/light theme
- **WebSocket real-time messaging** with auto-reconnect (exponential backoff)
- **Push notifications** via Firebase Cloud Messaging (FCM)
- **DataStore persistence** for config/auth
- **Agent selection** with status indicators (online/busy/idle/offline)
- **Conversation view** with message bubbles and typing indicator

## Prerequisites

- Android Studio Hedgehog or later
- Android SDK 35 (Android 15)
- Kotlin 2.1.20
- An Agent Messenger server running

## Building

```bash
cd mobile/android
./gradlew assembleDebug
```

## Configuration

Default server URL is `http://10.0.2.2:8080` (emulator localhost). Change in Login screen or via DataStore.

For FCM push notifications, add your `google-services.json` to the `app/` directory.

## Architecture

- **data/** — Models (Kotlinx serialization), ConfigManager (DataStore)
- **network/** — ApiClient (REST), WebSocketClient (WS with reconnect)
- **notification/** — FCM service, NotificationHelper
- **ui/** — Compose screens (Login, Agents, Chat), theme

## Project Structure

```
mobile/android/
├── app/
│   ├── build.gradle.kts
│   ├── proguard-rules.pro
│   └── src/main/
│       ├── AndroidManifest.xml
│       ├── java/com/agentmessenger/android/
│       │   ├── AgentMessengerApp.kt
│       │   ├── data/
│       │   │   ├── ConfigManager.kt
│       │   │   └── Models.kt
│       │   ├── network/
│       │   │   ├── ApiClient.kt
│       │   │   └── WebSocketClient.kt
│       │   ├── notification/
│       │   │   ├── AgentMessengerFirebaseMessagingService.kt
│       │   │   └── NotificationHelper.kt
│       │   └── ui/
│       │       ├── MainActivity.kt
│       │       ├── LoginScreen.kt
│       │       ├── AgentsScreen.kt
│       │       ├── ChatScreen.kt
│       │       └── theme/
│       │           └── Theme.kt
│       └── res/
│           ├── drawable/ic_notification.xml
│           ├── values/{strings,colors,themes}.xml
│           └── mipmap-anydpi-v26/ic_launcher.xml
├── build.gradle.kts
├── settings.gradle.kts
└── gradle.properties
```

## Status

- [x] Kotlin + Jetpack Compose project setup
- [x] WebSocket connection with auto-reconnect
- [x] REST API client (auth, agents, conversations, messages)
- [x] Login/Register screen
- [x] Agent list with status indicators
- [x] Chat view with message bubbles
- [x] Typing indicator
- [x] Dark theme (CoreScope-inspired)
- [x] Config persistence (DataStore)
- [x] Push notifications (FCM)
- [x] Unit tests (models, serialization)
- [ ] Integration test with running server
- [ ] google-services.json for FCM
- [ ] ProGuard testing (release build)