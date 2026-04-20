# Security Policy

## Reporting a Vulnerability

**Open a GitHub issue.** This is an open source project in early development. Public disclosure helps users understand risks and helps contributors fix problems faster. There is no private security mailing list and no reason to hide vulnerability reports.

If you find something that you believe needs coordinated disclosure (e.g., an active exploit in the wild with no fix available yet), contact the maintainer directly on GitHub before posting publicly. Use your judgment.

### What to Include

- **Description**: What the vulnerability is
- **Impact**: What an attacker could do (data access, code execution, denial of service, etc.)
- **Reproduction**: Step-by-step instructions to trigger it
- **Fix suggestion**: If you have one, great. If not, that's fine too.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| Alpha (< 1.0) | Best effort — bugs are fixed when maintainers have time |

This is alpha software. There are no SLAs, no guaranteed response times, and no security patches on a schedule. Serious vulnerabilities are prioritized, but this is a volunteer project.

## Security Architecture

### Authentication

**Users** authenticate with username and password. Passwords are hashed with bcrypt before storage. On login, the server issues a JWT (HMAC-SHA256) with a configurable expiry. The JWT is required for all REST API calls (Bearer token) and WebSocket connections (query parameter).

**Agents** authenticate with an API key. API keys are bcrypt-hashed on the server and compared using `bcrypt.CompareHashAndPassword()`. Agents send their API key in the initial WebSocket handshake message after connecting to `/agent/connect`.

**Admin** operations require a separate admin API key, configured via the `ADMIN_API_KEY` environment variable.

### Authorization

- Users can only access their own conversations and messages
- Users can only list agents (not modify them)
- Agents can only send messages in conversations they belong to
- Admin endpoints require the admin API key

### Transport Security

Agent Messenger does not terminate TLS itself. Run it behind a reverse proxy (nginx, Caddy, Traefik) that handles TLS. This is the recommended deployment:

```
Client → TLS (nginx/Caddy) → Agent Messenger (port 8080)
Agent  → TLS (nginx/Caddy) → Agent Messenger (port 8080)
```

Without TLS, JWT tokens and API keys are sent in plaintext. This is a known limitation of the current design — do not deploy without TLS on a public network.

### WebSocket Security

- User WebSocket connections require a valid JWT (sent as query parameter `?token=<jwt>`)
- Agent WebSocket connections require a valid API key (sent in initial handshake message)
- The server validates authentication before accepting any messages
- If authentication fails, the connection is closed immediately
- Ping/pong heartbeat detects stale connections (server sends ping every 30s, expects pong within 10s)
- On reconnect, the old connection is replaced (no duplicate connections per user/agent)

### Rate Limiting

The server enforces per-IP rate limits on message sending to prevent abuse. Specific limits are configurable but default to reasonable thresholds for a single-server deployment.

### Data Storage

- **SQLite**: All data (users, agents, conversations, messages, push tokens) is stored in a single SQLite file
- **Password hashing**: bcrypt (cost factor 10)
- **API key hashing**: bcrypt
- **JWT secret**: Configured via `JWT_SECRET` environment variable. Must be cryptographically random and kept secret.
- **No encryption at rest**: Messages are stored as plaintext in SQLite. If you need encrypted message storage, that's a feature request, not a current capability.

### Push Notifications

- **APNs** (iOS): Uses token-based authentication with a `.p8` key file. The key, key ID, and team ID are configured via environment variables.
- **FCM** (Android): Uses a service account JSON file. Configured via `FCM_SERVICE_ACCOUNT` environment variable.
- Push tokens (device tokens) are stored in SQLite and associated with user IDs. They're used only to deliver notifications when a user has no active WebSocket connection.
- Device tokens are removed on explicit logout (`DELETE /push/unregister`).

### No Telemetry

Agent Messenger does not phone home. No usage data, no error reports, no analytics. The server logs to stdout (configurable log level), and that's it. Your data stays on your server.

## Known Limitations

- **No end-to-end encryption**: Messages are plaintext in transit (behind your TLS proxy) and at rest (SQLite). E2E encryption is not currently implemented.
- **No message deletion**: Once a message is stored, it stays. There's no API to delete messages or conversations yet.
- **SQLite concurrency**: SQLite handles concurrent reads well but write concurrency is limited. For high-throughput deployments, consider PostgreSQL (not yet supported).
- **JWT in query parameter**: WebSocket connections pass the JWT as a query parameter, which may appear in server access logs. This is a tradeoff — browser WebSocket APIs don't support custom headers.
- **No brute-force protection on login**: The server doesn't currently implement account lockout or progressive delays on failed login attempts. Rate limiting is IP-based, not account-based.

## Deployment Security Checklist

Before running Agent Messenger on a public server:

- [ ] Set a strong, random `JWT_SECRET` (at least 32 characters)
- [ ] Set a strong `ADMIN_API_KEY`
- [ ] Run behind a TLS-terminating reverse proxy (nginx, Caddy)
- [ ] Do not expose port 8080 directly to the internet
- [ ] Restrict the SQLite database file permissions (`chmod 600`)
- [ ] Keep the server updated (watch releases for security patches)
- [ ] Review the environment variables and ensure none are left at defaults in production