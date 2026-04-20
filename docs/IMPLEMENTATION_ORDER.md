# Implementation Roadmap

## Phase 1: Core Server (MVP) ✅ DONE

### Server (Go) ✅
- WebSocket server with agent/client separation
- SQLite message storage
- JWT user authentication (username + password)
- API key authentication for agents (bcrypt hashed)
- Message routing with push notifications (APNs + FCM)
- 97 Go tests passing

### Agent Gateway (OpenClaw Plugin) ✅
- WebSocket client with exponential backoff reconnect
- DM security (allowlist / open policy)
- Outbound messaging (text + media)
- Typing indicator, agent status management
- Unit tests + integration test mode

### WebChat (React) ✅
- Login form with JWT storage
- Agent list with status indicators
- Chat view with message bubbles and typing indicator
- Conversation history loading
- Dark mode
- **Configurable**: Server does not expose web client unless explicitly enabled

---

## Phase 2: Mobile + Desktop Apps ✅ DONE

### iOS App ✅
- SwiftUI app with AgentMessengerKit Swift package
- WebSocket connection with auto-reconnect
- Push notifications (APNs)
- Conversation list, chat view, agent list, settings

### Android App ✅
- Kotlin + Jetpack Compose
- WebSocket connection
- Push notifications (FCM)
- Material 3 dark theme
- Unit tests (13 total)

### Linux Desktop App ✅
- GTK4/Adwaita + libadwaita
- Desktop notifications
- System tray support
- Integration tests

**Status**: All three clients complete. Server + all clients use username-based auth.

---

## Phase 3: Multi-Tenant 🔲 TODO

### Server Enhancements

1. User registration API (open signup vs invite-only)
2. Agent registration (API key issuance from admin panel)
3. One user, multiple agents
4. Admin panel for managing users/agents
5. Conversation history pagination improvements

**Deliverable**: Multiple users, multiple agents on one server.

---

## Phase 4: Advanced Features 🔲 TODO

1. E2E encryption (Signal protocol)
2. Media attachments (images, files)
3. Voice messages
4. Agent presence/status enhancements
5. Read receipts
6. Search message history
7. Export conversations
8. Audit logs UI

---

## Phase 5: Polish 🔲 TODO

1. Error handling improvements
2. Offline support (message queuing)
3. Accessibility audit
4. Internationalization
5. Settings sync across devices
6. Notification customization (per-agent, per-conversation)
7. WebChat improvements (responsive, PWA)

---

## Integration Testing 🔲 TODO

- End-to-end test: server + webchat + plugin running together
- Mobile app testing on real devices
- Push notification delivery verification
- Reconnection behavior under network interruptions
- Load testing (multiple agents, multiple users)

---

## Estimated Timeline

- ~~**Phase 1**: 2-4 weeks~~ ✅ Complete
- ~~**Phase 2**: 4-6 weeks~~ ✅ Complete
- **Phase 3**: 2-3 weeks
- **Phase 4**: 6-8 weeks (E2E encryption is hard)
- **Phase 5**: 2-3 weeks
- **Integration testing**: 1-2 weeks

**Total remaining**: ~11-16 weeks for full feature set

**MVP usable now**: Phase 1 + 2 complete. Server, all clients, and plugin are functional.