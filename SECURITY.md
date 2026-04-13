# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| < 1.0   | :x: (development)  |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

**Do NOT report security vulnerabilities through public GitHub issues.**

### How to Report

1. **Email**: security@agent-messenger.org
2. **GitHub Security Advisory**: Use "Report a vulnerability" button in Security tab

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 7 days
- **Fix timeline**: Depends on severity
  - Critical: 7 days
  - High: 14 days
  - Medium: 30 days
  - Low: Next release

### Disclosure Policy

- We follow **coordinated disclosure**
- Reporter gets credit (if desired)
- CVE assigned for significant vulnerabilities
- Security advisory published after fix is released

## Security Architecture

### Authentication

- **Agent authentication**: API key + agent ID
- **User authentication**: Email/password with bcrypt hashing
- **Session management**: JWT with short expiry, refresh tokens
- **Rate limiting**: Prevent brute force attacks

### Data Protection

- **TLS**: Required for all connections
- **Message storage**: Encrypted at rest (optional, user choice)
- **E2E encryption**: Optional, using Signal protocol or similar
- **No telemetry**: No data leaves your server without explicit consent

### Agent Sandbox

Agents connect via restricted API:
- Can only send messages to authenticated users
- Cannot access other agents' data
- Cannot modify server configuration
- Rate-limited to prevent spam

### Audit Logging

All actions are logged:
- User logins/logouts
- Message sent/received
- Agent connections
- Configuration changes

Logs are:
- Tamper-evident (append-only)
- Retained for 90 days (configurable)
- Available for export

## Dependency Security

- We use Dependabot for automated dependency updates
- All dependencies are pinned to specific versions
- Vulnerabilities in dependencies are patched within 7 days of disclosure
- No auto-merge of dependency updates - all are reviewed

## Supply Chain Security

### Code Review

- All code is reviewed before merge
- At least one maintainer must approve
- Security-related changes require two approvals

### Commit Signing

Maintainers sign commits with GPG keys. Verified commits only.

### Release Process

1. Code is reviewed and merged to `develop`
2. `develop` is tested and merged to `main`
3. Release is tagged with signed tag
4. Artifacts are built and signed
5. Checksums published

## Contact

Security concerns: security@agent-messenger.org

General questions: Open a GitHub Discussion