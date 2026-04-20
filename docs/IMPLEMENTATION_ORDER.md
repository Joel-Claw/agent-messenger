# Implementation Roadmap

## Phase 1: Core Server (MVP)

**Goal**: Basic message relay between agent and user

### Server (Go)

1. WebSocket server with agent/client separation
2. SQLite message storage
3. API key authentication for agents
4. JWT authentication for users
5. Simple message routing (no push notifications yet)

### Agent Gateway (OpenClaw Plugin)

1. WebSocket client that connects to server
2. Send messages from OpenClaw to server
3. Receive user messages and emit events

### WebChat (React)

1. Minimal web client for testing
2. User login
3. Conversation view
4. Message input

**Deliverable**: Joel can send messages to WebChat and receive replies.

---

## Phase 2: Mobile Apps

### iOS App

1. SwiftUI app
2. WebSocket connection
3. Push notifications (APNs)
4. Conversation list
5. Message thread view

### Android App

1. Kotlin/Jetpack Compose
2. WebSocket connection
3. Push notifications (FCM)
4. Same as iOS features

**Deliverable**: User can install native app and receive push notifications.

---

## Phase 3: Multi-Tenant

### Server Enhancements

1. User registration (username/password, OAuth)
2. Agent registration (API key issuance)
3. One user, multiple agents
4. Conversation history API
5. Admin panel (optional)

**Deliverable**: Multiple users, multiple agents on one server.

---

## Phase 4: Advanced Features

1. E2E encryption (Signal protocol)
2. Media attachments (images, files)
3. Voice messages
4. Agent presence/status
5. Typing indicators
6. Read receipts
7. Search message history
8. Export conversations
9. Audit logs UI

---

## Phase 5: Polish

1. Error handling
2. Reconnection logic
3. Offline support
4. Accessibility
5. Internationalization
6. Dark mode
7. Settings sync
8. Notification customization

---

## Estimated Timeline

- **Phase 1**: 2-4 weeks (one developer, part-time)
- **Phase 2**: 4-6 weeks (mobile apps are complex)
- **Phase 3**: 2-3 weeks
- **Phase 4**: 6-8 weeks (E2E encryption is hard)
- **Phase 5**: 2-3 weeks

**Total**: ~16-24 weeks for full feature set

**MVP usable**: After Phase 1 (~4 weeks)