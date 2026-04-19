# Agent Messenger - Linux Desktop Client

GTK4-based desktop client for Agent Messenger, supporting both X11 and Wayland.

## Features

- GTK4 + libadwaita UI (works on X11 and Wayland)
- WebSocket connection to Agent Messenger server
- Conversation view with message bubbles
- System tray / background mode (close-to-hide)
- Desktop notifications (Gio.Notification)
- Typing indicator
- Agent selection sidebar with status indicators
- Conversation history loading
- Auto-reconnect with exponential backoff
- Dark mode (Adwaita)
- Config persistence (`~/.config/agent-messenger/config.json`)

## Requirements

- Python 3.10+
- GTK4 (`libgtk-4-1`, `gir1.2-gtk-4.0`)
- libadwaita (`libadwaita-1-0`, `gir1.2-adw-1`)
- PyGObject (`python3-gi`, `python3-gi-cairo`)
- websocket-client (`pip install websocket-client`)
- requests (`pip install requests`)

### Debian/Ubuntu

```bash
sudo apt install python3-gi python3-gi-cairo gir1.2-gtk-4.0 gir1.2-adw-1
pip3 install --user websocket-client requests
```

## Quick Start

### Run from source

```bash
cd linux/
pip3 install --user -r requirements.txt
python3 -m src.main
```

### Install as desktop app

```bash
cd linux/
./install.sh
```

This will:
- Install Python dependencies
- Create a wrapper script in `~/.local/bin/`
- Install `.desktop` file to `~/.local/share/applications/`
- Install the app icon
- Make "Agent Messenger" appear in your application menu

### Uninstall

```bash
./install.sh --uninstall
```

## Configuration

Configuration is stored at `~/.config/agent-messenger/config.json`:

```json
{
  "server_url": "ws://localhost:8080",
  "api_url": "http://localhost:8080",
  "email": "user@example.com",
  "password": "your-password"
}
```

You can also configure these via the login form in the app.

## Testing

### Unit Tests

```bash
cd linux/
python3 -m pytest tests/ -v
```

### Integration Tests (requires running server)

```bash
# Build the server first
cd ../server && go build -o agent-messenger-server .

# Run integration tests
cd ../linux/
AM_INTEGRATION=1 python3 -m pytest tests/test_integration.py -v
```

## Project Structure

```
linux/
├── data/
│   ├── com.joelclaw.agentmessenger.desktop      # Desktop entry file
│   └── com.joelclaw.agentmessenger.metainfo.xml # AppStream metadata
├── src/
│   ├── __init__.py
│   ├── main.py           # Application entry point
│   ├── window.py         # Main window (chat UI)
│   ├── client.py         # WebSocket client
│   ├── config.py         # Configuration management
│   ├── notifications.py  # Desktop notifications
│   ├── styles.py         # CSS styles
│   └── tray.py           # System tray / background mode
├── tests/
│   ├── test_app.py           # App metadata tests
│   ├── test_client.py        # WebSocket client tests
│   ├── test_config.py        # Config persistence tests
│   ├── test_integration.py   # Integration tests (AM_INTEGRATION=1)
│   ├── test_notifications.py # Notification tests
│   └── test_tray.py          # System tray tests
├── install.sh            # Desktop installation script
├── pyproject.toml        # Python project config
├── requirements.txt      # Python dependencies
└── README.md
```