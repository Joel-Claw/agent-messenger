# Agent Messenger - Android App

Kotlin + Jetpack Compose client for Agent Messenger.

## Features

- **Jetpack Compose UI** with Material 3 dynamic theming
- **WebSocket** real-time messaging with auto-reconnect
- **Conversation list** with agent selection
- **Push notifications** via Firebase Cloud Messaging (FCM)
- **Config persistence** using DataStore
- **Dark mode** support with dynamic color
- **Typing indicators** and agent status (online/offline/busy/idle)

## Requirements

- Android Studio Hedgehog (2023.1.1) or later
- Android SDK 35
- Kotlin 2.1.20
- Min SDK 29 (Android 10)
- A running Agent Messenger server

## Building

1. Open the `mobile/android` directory in Android Studio
2. Sync Gradle
3. Build and run on an emulator or device

For command-line builds:
```bash
./gradlew assembleDebug
```

## Configuration

Default server URLs target the Android emulator:
- API: `http://10.0.2.2:8080`
- WebSocket: `ws://10.0.2.2:8080`

For physical devices, change the server URL in Settings or in `ConfigManager.kt` defaults.

## Push Notifications (FCM)

1. Create a Firebase project at [console.firebase.google.com](https://console.firebase.google.com)
2. Add an Android app with package name `com.agentmessenger.android`
3. Download `google-services.json` and place it in `app/`
4. Add the `google-services` Gradle plugin to the project-level `build.gradle.kts`:
   ```kotlin
   id("com.google.gms.google-services") version "4.4.2" apply false
   ```
5. Add to `app/build.gradle.kts`:
   ```kotlin
   plugins {
       id("com.google.gms.google-services")
   }
   ```
6. The server must also be configured with FCM credentials (see server push config)

## Project Structure

```
app/src/main/java/com/agentmessenger/android/
├── AgentMessengerApp.kt              # Application class (ConfigManager init)
├── data/
│   ├── ConfigManager.kt              # DataStore persistence for settings/auth
│   └── Models.kt                     # Serializable data models
├── network/
│   ├── ApiClient.kt                  # REST API client (OkHttp)
│   └── WebSocketClient.kt            # WebSocket client with reconnect
├── notification/
│   ├── AgentMessengerFirebaseMessagingService.kt  # FCM push handler
│   └── NotificationHelper.kt         # Notification channel + display
└── ui/
    ├── MainActivity.kt               # Main activity + navigation
    ├── LoginScreen.kt                 # Login/register form
    ├── AgentsScreen.kt               # Agent list + status
    ├── ChatScreen.kt                  # Message view + input
    ├── ConversationsScreen.kt         # Conversation list
    ├── SettingsScreen.kt              # Server config + logout
    └── theme/
        └── Theme.kt                   # Material 3 theme
```

## Testing

```bash
# Unit tests
./gradlew test

# Instrumented tests (requires emulator/device)
./gradlew connectedAndroidTest
```

Unit tests cover:
- Model serialization/deserialization (21 tests)
- API client mock server tests (14 tests)
- WebSocket client message construction (11 tests)
- Config defaults (5 tests)

## Architecture

- **UI**: Jetpack Compose with `@Composable` functions
- **State**: Mutable state hoisted in `AgentMessengerApp` composable
- **Networking**: OkHttp for REST + WebSocket
- **Persistence**: DataStore Preferences for settings/auth
- **Push**: FCM via `FirebaseMessagingService`

No ViewModel or DI framework yet — suitable for MVP. Future iterations can add
ViewModel, Room for local message cache, Hilt for DI, and Compose Navigation.