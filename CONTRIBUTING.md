# Contributing to Agent Messenger

Thank you for your interest in contributing! This project is open source and community-driven.

## Security First

**This is a security-critical project.** Agent Messenger handles authentication, messaging, and runs on user infrastructure. We take code quality seriously.

### Malicious Code Policy

- **All code submissions are reviewed** before merge
- **No exceptions** - even "fix typo" PRs are reviewed
- Suspicious code patterns will be flagged and discussed
- Attempts to inject malicious code will result in permanent ban

### What Counts as Malicious Code

- Backdoors or remote access mechanisms
- Data exfiltration (phone home, telemetry without consent)
- Cryptographic weaknesses intentionally introduced
- Hardcoded credentials or API keys
- Obfuscated code that hides behavior
- Dependency confusion attacks
- Code that runs arbitrary commands from external input
- Anything that compromises user privacy or security

## Development Process

### Branch Strategy

```
main ───────► production-ready code
              │
              └── develop ───► integration branch
                    │
                    └── feature/* ───► individual features
                    └── fix/* ───────► bug fixes
                    └── security/* ──► security patches (priority)
```

### Pull Request Process

1. **Fork** the repository
2. **Create a branch** from `develop` (use `feature/`, `fix/`, or `security/` prefix)
3. **Write code** following our style guide
4. **Write tests** - code without tests won't merge
5. **Document** your changes
6. **Submit PR** with clear description
7. **Address review feedback** - all comments must be resolved

### Required Reviews

- **Regular PRs**: 1 approval from a maintainer
- **Security-related PRs**: 2 approvals, including from security-focused maintainer
- **Dependency updates**: Approval required (no Dependabot auto-merge)

### CI/CD Requirements

All PRs must pass:
- [ ] Linting / formatting checks
- [ ] Unit tests
- [ ] Integration tests (where applicable)
- [ ] Security scan (dependency vulnerabilities)
- [ ] CodeQL or similar static analysis

## Code Style

### Go (Server)
- Use `gofmt` and `goimports`
- Follow [Effective Go](https://golang.org/doc/effective_go)
- Comment public functions
- No `init()` functions that do I/O

### Rust (Server - alternative)
- Use `cargo fmt` and `cargo clippy`
- Document public APIs with `///` comments
- Prefer `Result<T, E>` over panics

### Swift (iOS)
- Follow SwiftLint rules
- Use SwiftUI for new views
- Document with Swift DocC

### Kotlin (Android)
- Follow Kotlin style guide
- Use Jetpack Compose
- Document with KDoc

## Commit Messages

```
type(scope): brief description

Longer explanation if needed. Wrap at 72 characters.

Fixes #123
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `security`, `chore`

## Security Vulnerabilities

**Do NOT open a public issue for security vulnerabilities.**

Email: security@agent-messenger.org (or use GitHub Security Advisories)

We will:
1. Acknowledge within 48 hours
2. Investigate and fix
3. Release patch
4. Credit reporter (if desired)

## Code of Conduct

Be respectful. Be constructive. We're building something useful together.

## Questions?

Open a Discussion (not an Issue) for general questions.