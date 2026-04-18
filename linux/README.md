# Agent Messenger - Linux Desktop Client

GTK4-based desktop client for Agent Messenger, supporting both X11 and Wayland.

## Features

- GTK4 + libadwaita UI (works on X11 and Wayland)
- WebSocket connection to Agent Messenger server
- Conversation view with message bubbles
- System tray integration
- Desktop notification support
- Typing indicator
- Agent selection sidebar
- Dark mode support

## Requirements

- Python 3.10+
- GTK4 (libgtk-4-1)
- PyGObject (python3-gi)
- libadwaita (optional, for modern UI)

## Installation

```bash
pip install -r requirements.txt
```

## Running

```bash
python -m src.main
```

## Configuration

Create `~/.config/agent-messenger/config.json`:

```json
{
  "server_url": "ws://localhost:8080",
  "api_url": "http://localhost:8080",
  "email": "user@example.com",
  "password": "your-password"
}
```