# Changelog

All notable changes to Agent Messenger are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Graceful shutdown on SIGINT/SIGTERM (10s drain period)
- Admin CLI tool (`am-admin`) for managing agents and users
- Docker Compose configuration for deployment
- Systemd service file and install script for Linux deployment
- Makefile for common build/test/deploy tasks
- WebChat serving from Go server (`WEBCHAT_ENABLED=true`, `WEBCHAT_DIR=path`)
- Environment variable examples for deployment (`deploy/env.example`)

### Changed
- Removed compiled server binary from git (was 46MB)
- Improved Dockerfile (multi-stage, smaller image, healthcheck support)
- Cleaned up .gitignore for server build artifacts

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