# Agent Messenger - iOS Client

SwiftUI-based iOS client for Agent Messenger, supporting iPhone and iPad.

## Features

- SwiftUI + iOS 16+ (native, no third-party dependencies)
- WebSocket connection using URLSessionWebSocketTask
- Conversation view with message bubbles
- Agent discovery and listing with status indicators
- Auto-reconnect with exponential backoff
- Login / registration form (email → JWT)
- Typing indicator with animation
- Dark mode support (system preference)
- Conversation history loading
- Config persistence (UserDefaults)
- Push notifications (APNs) - *planned*

## Requirements

- Xcode 15.0+
- iOS 16.0+
- Swift 5.9+

## Project Structure

```
ios/
├── AgentMessenger.xcodeproj/   # Xcode project
├── Package.swift                # Swift Package Manager config
├── AgentMessenger/
│   ├── Info.plist               # App configuration
│   ├── AgentMessengerApp.swift  # App entry point + AppState
│   └── Views/
│       ├── LoginView.swift          # Login / registration form
│       ├── MainTabView.swift        # Tab navigation (Chats, Agents, Settings)
│       ├── ConversationsView.swift  # Conversation list
│       ├── ChatView.swift           # Chat view with message bubbles
│       ├── AgentsView.swift         # Agent list and detail view
│       ├── NewConversationView.swift # Start new conversation
│       ├── SettingsView.swift        # Settings and logout
│       └── LaunchScreen.swift        # Launch screen
├── Sources/AgentMessengerKit/
│   ├── Config.swift             # Configuration and persistence
│   ├── Models.swift             # Data models (Agent, Message, Conversation, etc.)
│   ├── WebSocketClient.swift    # WebSocket client with reconnect
│   └── APIClient.swift          # REST API client (auth, agents, conversations)
└── Tests/AgentMessengerKitTests/
    ├── ConfigTests.swift            # Config persistence tests
    ├── ModelTests.swift             # Model encoding/decoding tests
    ├── APIClientTests.swift         # API client unit tests
    └── WebSocketClientTests.swift   # WebSocket client unit tests
```

## Building

1. Open `AgentMessenger.xcodeproj` in Xcode
2. Select the "AgentMessenger" target
3. Build & Run (⌘R)

## Testing

### Unit Tests

```bash
# From Xcode: Product → Test (⌘U)
# Or via command line:
xcodebuild test -project AgentMessenger.xcodeproj -scheme AgentMessenger -destination 'platform=iOS Simulator,name=iPhone 16'
```

### Integration Tests

Integration tests require a running Agent Messenger server:

```bash
# Start the server
cd ../../server && go run . -port 8080

# Set the integration flag in Xcode scheme environment variables:
# AM_INTEGRATION=1
```

## Configuration

The app connects to `ws://localhost:8080` by default. Change this in:
- **Settings tab** within the app
- **Server Settings** on the login screen

Config is persisted to `UserDefaults` with key `app_config`.

## Architecture

- **AppState** (@MainActor ObservableObject): Central state managing auth, WebSocket, and API
- **WebSocketClient**: Native URLSessionWebSocketTask with auto-reconnect
- **APIClient**: Async/await REST client for authentication, agents, and conversations
- **Views**: SwiftUI views with `@EnvironmentObject` injection of `AppState`

### Message Flow

1. User authenticates via `APIClient.login()` → JWT token
2. `WebSocketClient.connect(userID:token:)` opens WebSocket
3. Server sends `{type: "connected"}` acknowledgment
4. User selects agent → `APIClient.createConversation()` → conversation ID
5. Messages flow bidirectionally through WebSocket
6. Typing indicators and status updates are handled in real-time