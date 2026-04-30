# Changelog

All notable changes to Agent Messenger are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-04-30

### Added

#### Server
- PostgreSQL support alongside SQLite (DATABASE_DRIVER env, parameterized queries, driver-agnostic schema init)
- File/image attachment support (upload, download, per-message attachment metadata, MAX_UPLOAD_SIZE env with B/KB/MB/GB/TB units)
- E2E encryption key exchange (X25519 key bundles, one-time pre-keys, /keys/upload, /keys/bundle, /keys/otpk-count)
- Message edit support (PATCH /messages/edit, edited_at column, message_edited WebSocket event)
- Message soft delete (DELETE /messages/delete, deleted_at column, message_deleted WebSocket event)
- Message reactions (POST /messages/react, GET /messages/reactions, reaction_added/reaction_removed WebSocket events)
- Message search (GET /messages/search with full-text LIKE query across user's conversations)
- Message read receipts (POST /conversations/mark-read, read_receipt WebSocket event, read_at column)
- Conversation deletion (DELETE /conversations/delete with cascade)
- Conversation tags/labels (POST /conversations/tags/add, /tags/remove, GET /conversations/tags)
- Conversation metadata (last_message preview, unread_count in conversation listing)
- User password change (POST /auth/change-password)
- Multi-device sync (same user on multiple clients simultaneously, device_id param, per-device connection tracking)
- User presence (online/offline/last-seen, presence_update WebSocket events, GET /presence, GET /presence/user)
- Agent presence heartbeat (configurable AGENT_HEARTBEAT_INTERVAL/TIMEOUT/ENABLED, stale disconnection, heartbeat_ack)
- WebSocket sub-protocol versioning (negotiate version on upgrade, version in welcome message)
- API rate limiting tiers (free/pro/enterprise, DB-persisted in user_rate_limit_tiers, X-RateLimit-* headers)
- Tiered rate limit middleware for HTTP API endpoints
- Admin endpoints for rate limit tiers (POST/GET /admin/rate-limit/tier)
- Per-user rate limiting (120/min alongside per-connection 60/min)
- CORS middleware (configurable CORS_ALLOWED_ORIGINS, defaults to *)
- WebSocket origin validation against CORS_ALLOWED_ORIGINS
- Server version in /health and /metrics responses
- Offline message queue (100 msgs/recipient, 7-day TTL, replay on reconnect)
- DB migration tool (am-migrate CLI: up, down, status, create)
- Schema migrations table for versioned DB evolution

#### Push Notifications
- APNs push for iOS (device token registration, /push/register, /push/unregister)
- FCM push for Android (firebase.google.com/go/v4, platform-aware routing)
- Web push notifications (VAPID, /push/vapid-key, /push/web-subscribe, /push/web-unsubscribe)
- Push notification on offline message delivery

#### WebChat
- Attachment upload UI (file picker + drag-and-drop, XHR with progress, inline image/audio/video preview)
- E2E encryption UI (X25519 key generation via Web Crypto API, X3DH key agreement, AES-256-GCM, E2ESettings modal, per-chat E2E toggle)
- Push notification subscription (PushSubscription component, VAPID key fetch, browser permission flow)
- Conversation list sidebar (last message preview, unread badges, agent name resolution)
- Message ID sync (server-assigned IDs for edit/delete/reactions support)
- WebSocket handlers (reaction_added, reaction_removed, message_edited, message_deleted, read_receipt, presence_update)
- Agent list with presence polling (online/offline + last seen)
- Reactions in ChatView (emoji picker + reaction chips)
- Message edit/delete context menu
- Read receipts (✓/✓✓ indicators)
- Edited message label
- Notification sounds on agent messages (Web Audio API two-tone beep)
- Desktop notification support
- Date separators in ChatView (Today/Yesterday/date)
- Smart auto-scroll (only scrolls when near bottom, force on send)
- Auto mark conversation as read on selection
- Service worker (sw.js) with push event handler, notification click routing, subscription change

#### Client SDKs
- JavaScript/TypeScript SDK (auth, agents, conversations, messages, WebSocket, attachments, E2E keys, web push — 43 tests)
- Python SDK (auth, agents, conversations, messages, WebSocket, attachments, E2E keys, web push — 50 tests)
- Both SDKs: web push support (getVAPIDKey, webPushSubscribe, webPushUnsubscribe)
- Both SDKs: fixed push field names (device_token, platform enum with ios/android/web)

#### Deployment
- Helm chart for Kubernetes (deployment, service, ingress, HPA, PVC, serviceaccount)
- Docker Compose with CORS, VAPID, upload size env vars
- Systemd service file + install script
- Environment file template (deploy/env.example)
- Makefile (build, test, docker, deploy, health, metrics, migrate)
- Caddy reverse proxy config example

#### CI/CD
- GitHub Actions CI (Go vet/test, WebChat lint/build, OpenClaw plugin test, Docker build, Linux client lint, GoSec scan)
- k6 load test script (p95=175ms, 49 req/s, 15 VUs, rate limiting verified)

#### Documentation
- OpenAPI/Swagger spec for all REST endpoints
- Protocol spec updated to v0.2.0
- README updated with all Phase 3+4 features

### Changed
- Auth redesign: per-agent bcrypt API keys → shared AGENT_SECRET with self-registration
- Duplicate user registration now returns 409 Conflict (was 500)
- Hub tracks clients as user_id → []*Connection (multi-device) instead of user_id → Connection
- WebChat build and TypeScript type-check now passing cleanly

### Fixed
- WebChat service worker pushsubscriptionchange bug (was passing pushManager as applicationServerKey)
- SDK push field name mismatches (device_token, platform)

## [0.1.0] - 2026-04-20

### Added
- Go WebSocket server with SQLite persistence (97 tests)
- JWT user authentication (register, login, token validation)
- API key authentication for agents (bcrypt hashed)
- Real-time WebSocket messaging with ping/pong heartbeat
- Conversation management (create, list, message history with pagination)
- Multi-agent support (name, model, personality, specialty)
- Agent status tracking (online, busy, idle, offline)
- Push notifications via APNs (iOS) and FCM (Android)
- Platform-aware push routing (APNs for iOS, FCM for Android)
- Rate limiting (messages per minute per IP)
- Health check endpoint (uptime, memory, connection counts, message counters)
- Prometheus-compatible metrics endpoint
- Graceful reconnection with connection replacement
- OpenClaw channel plugin (TypeScript) with WebSocket client, DM security, typing/status
- React WebChat client with dark mode, agent list, real-time messaging
- iOS app (Swift/SwiftUI) with APNs push, auto-reconnect, agent selection
- Android app (Kotlin/Jetpack Compose) with FCM push, Material 3, DataStore
- Linux desktop app (GTK4/Adwaita) with system tray, notifications, .desktop install
- Documentation: README, CONTRIBUTING, SECURITY, User Manual, Protocol spec

[Unreleased]: https://github.com/Joel-Claw/agent-messenger/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Joel-Claw/agent-messenger/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Joel-Claw/agent-messenger/releases/tag/v0.1.0