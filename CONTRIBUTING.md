# Contributing to Agent Messenger

Thanks for your interest. Agent Messenger is a self-hosted messaging platform for humans to talk to their AI agents. Here's how to contribute effectively.

## Project Overview

The project has 6 components, each in its own directory:

- **`server/`** — Go backend (WebSocket, REST API, SQLite, push notifications)
- **`plugins/openclaw/`** — TypeScript OpenClaw channel plugin
- **`webchat/`** — React + TypeScript browser client
- **`mobile/ios/`** — Swift/SwiftUI iOS app
- **`mobile/android/`** — Kotlin/Compose Android app
- **`linux/`** — GTK4/Adwaita Python desktop app

You don't need to work on all of them. Pick the component you're comfortable with.

## Setup

### Server

```bash
cd server
go mod download
go test ./...
go build -o agent-messenger .
```

Requires Go 1.21+. SQLite database is created automatically on first run.

### OpenClaw Plugin

```bash
cd plugins/openclaw
npm install
npm test
```

Requires Node.js 18+. The plugin runs inside OpenClaw, not standalone.

### WebChat

```bash
cd webchat
npm install
npm start
```

Requires Node.js 18+. The dev server proxies API requests to the Go server.

### iOS App

```bash
cd mobile/ios
open AgentMessenger.xcodeproj
```

Requires Xcode 15+, iOS 17+ deployment target. AgentMessengerKit is a local Swift package.

### Android App

```bash
cd mobile/android
./gradlew build
./gradlew test
```

Requires Android Studio, Kotlin 1.9+, Compose compiler. FCM requires a `google-services.json` file.

### Linux App

```bash
cd linux
pip install -r requirements.txt
pytest
```

Requires Python 3.10+, GTK4, Adwaita. Works on X11 and Wayland.

## How to Contribute

1. **Fork** the repository
2. **Create a branch** from `main` — use a descriptive name like `fix/websocket-reconnect` or `feat/conversation-search`
3. **Write code** following the style guide below
4. **Write tests** — every component has existing tests, add to them
5. **Run the full test suite** for the component you're changing
6. **Submit a PR** with a clear description of what and why

## Code Style

### Go (Server)

- Run `gofmt` and `goimports` before committing
- Follow [Effective Go](https://go.dev/doc/effective_go)
- Comment all exported functions and types
- Error handling: use `fmt.Errorf("context: %w", err)` for wrapping
- No `init()` functions that do I/O
- Table-driven tests preferred (`t.Run` subtests)
- Handler functions use `writeJSONError()` for error responses, not `sendError()`
- JWT validation uses `ValidateJWT()`, not `authenticateRequest()`

### TypeScript (OpenClaw Plugin + WebChat)

- Follow existing patterns in the codebase
- Strict mode enabled — no `any` types without justification
- Use `async/await` over `.then()` chains
- Write tests for new functionality — the plugin uses Jest, WebChat uses React Testing Library

### Swift (iOS)

- Follow SwiftLint conventions
- Use SwiftUI for all new views
- Async/await for all API calls (no completion handlers)
- Document public APIs with `///` doc comments
- AgentMessengerKit is a local Swift Package — add new types there, not in the app target

### Kotlin (Android)

- Follow the existing code style in the repo
- Use Jetpack Compose for UI
- kotlinx.serialization for JSON (not Gson or Moshi)
- Use `ConfigManager` for persisted settings (DataStore backing)
- Hilt for dependency injection where applicable

### Python (Linux App)

- Follow PEP 8
- Type hints on all function signatures
- Use GObject-style conventions for GTK signal handlers
- Tests use `unittest` (stdlib) + `pytest` runner
- GLib.idle_add for any UI updates from background threads

## Commit Messages

```
type(scope): brief description

Optional longer explanation. Wrap at 72 characters.

Fixes #123
```

Types:
- `feat` — new feature
- `fix` — bug fix
- `docs` — documentation
- `refactor` — code restructure without behavior change
- `test` — adding or fixing tests
- `chore` — build, CI, dependencies

Scopes match the component: `server`, `plugin`, `webchat`, `ios`, `android`, `linux`.

Examples:
```
feat(server): add conversation search endpoint
fix(plugin): handle WebSocket reconnect after server restart
docs(webchat): update setup instructions for proxy config
test(android): add WebSocketClient reconnection tests
```

## Testing

Every component has tests. Run them before submitting a PR:

| Component | Command | Test Count |
|-----------|---------|------------|
| Server | `cd server && go test ./...` | 97 |
| Linux | `cd linux && pytest` | 57 |
| Plugin | `cd plugins/openclaw && npm test` | 50 |
| Android | `cd mobile/android && ./gradlew test` | 13 |
| iOS | Xcode Cmd+U | 4 files |

If you're adding functionality, add tests. If you're fixing a bug, add a test that catches the bug first, then fix it.

## Architecture Notes

### Authentication Flow

- **Users**: Register via `POST /auth/user`, login via `POST /auth/login` → receive JWT. JWT goes in `Authorization: Bearer <token>` header for REST, and as a query param `?token=<jwt>` for WebSocket connections.
- **Agents**: Authenticate with shared AGENT_SECRET. Agents connect via WebSocket to `/agent/connect?agent_id=<id>&agent_secret=<secret>`. They self-register on first connect. Rate limiting per agent_id (10 attempts/minute).
- **Admin**: AGENT_SECRET for admin operations (listing agents with connection details).

### WebSocket Protocol

Agents and users connect to different WebSocket endpoints:

- Users → `/client/connect?user_id=<id>&token=<jwt>`
- Agents → `/agent/connect?agent_id=<id>&agent_secret=<secret>` (shared AGENT_SECRET, self-registers on connect)

Messages flow through the server hub, which routes them to the correct WebSocket connection based on conversation membership.

### Push Notifications

- iOS: APNs with `.p8` key (token-based, not certificate-based)
- Android: FCM with service account JSON
- Device tokens are registered via `POST /push/register` and cleaned up on `DELETE /push/unregister`
- The server sends push when a recipient has no active WebSocket connection

### Data Storage

SQLite for everything. The database file is created automatically on first run. No migration tool — schema is managed in `db.go` initialization.

## Security Vulnerabilities

Open a GitHub issue. This is an open source project — public disclosure helps everyone. See [SECURITY.md](SECURITY.md) for details.

## Questions?

Open a GitHub Discussion for general questions. Open an Issue for bugs or feature requests.