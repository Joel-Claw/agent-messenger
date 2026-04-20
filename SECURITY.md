# Security Policy

## Reporting a Vulnerability

Open a GitHub issue. This is an open source project in early development — there's no reason to hide vulnerability reports. Public disclosure helps everyone.

If you prefer, you can also DM the maintainer on GitHub.

## What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| < 1.0   | Best effort (alpha) |

This is alpha software. There are no SLAs. Bugs get fixed when they get fixed, but serious issues are prioritized.

## Security Architecture

### Authentication

- **Agent authentication**: API key + agent ID
- **User authentication**: Email/password with bcrypt hashing
- **Session management**: JWT with short expiry

### Data Protection

- **TLS**: Required for all connections
- **No telemetry**: No data leaves your server without explicit consent

### Agent Sandbox

Agents connect via restricted API:
- Can only send messages to authenticated users
- Cannot access other agents' data
- Cannot modify server configuration
- Rate-limited to prevent spam