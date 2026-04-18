"""
WebSocket client for Agent Messenger server.

Handles connection, reconnection, and message routing.
"""

import json
import threading
import time
import websocket


class AgentMessengerClient:
    """WebSocket client that connects to the Agent Messenger server."""

    def __init__(self, config, window=None):
        self.config = config
        self.window = window
        self.ws = None
        self.connected = False
        self._reconnect_attempts = 0
        self._max_reconnect_attempts = 10
        self._reconnect_timer = None
        self._thread = None
        self._stop_event = threading.Event()
        self._jwt_token = None
        self._user_id = None
        self._on_message_callback = None
        self._on_typing_callback = None
        self._on_status_callback = None

    def set_on_message(self, callback):
        """Set callback for incoming messages: callback(msg_dict)"""
        self._on_message_callback = callback

    def set_on_typing(self, callback):
        """Set callback for typing indicators: callback(conversation_id, typing)"""
        self._on_typing_callback = callback

    def set_on_status(self, callback):
        """Set callback for agent status updates: callback(agent_id, status)"""
        self._on_status_callback = callback

    def connect(self):
        """Authenticate and connect to the server."""
        if not self.config.email or not self.config.password:
            print('[AgentMessenger] No credentials configured, skipping auth')
            return False

        # Authenticate via REST
        try:
            import requests
            resp = requests.post(
                f'{self.config.api_url}/auth/login',
                data={'email': self.config.email, 'password': self.config.password},
            )
            if resp.status_code != 200:
                print(f'[AgentMessenger] Auth failed: {resp.status_code} {resp.text}')
                return False
            data = resp.json()
            self._jwt_token = data.get('token')
            self._user_id = data.get('user_id')
            print(f'[AgentMessenger] Authenticated as {self._user_id}')
        except Exception as e:
            print(f'[AgentMessenger] Auth error: {e}')
            return False

        # Connect WebSocket
        self._connect_ws()
        return True

    def _connect_ws(self):
        """Start WebSocket connection in a background thread."""
        self._stop_event.clear()
        url = f'{self.config.server_url}/client/connect?user_id={self._user_id}'

        self.ws = websocket.WebSocketApp(
            url,
            on_open=self._on_open,
            on_message=self._on_message,
            on_error=self._on_error,
            on_close=self._on_close,
        )

        self._thread = threading.Thread(target=self.ws.run_forever, daemon=True)
        self._thread.start()

    def _on_open(self, ws):
        """Called when WebSocket connection opens."""
        print('[AgentMessenger] Connected to server')
        self.connected = True
        self._reconnect_attempts = 0

        if self.window:
            from gi.repository import GLib
            GLib.idle_add(self.window.on_connected)

    def _on_message(self, ws, raw_data):
        """Called when a message is received from the server."""
        try:
            msg = json.loads(raw_data)
        except json.JSONDecodeError as e:
            print(f'[AgentMessenger] Failed to parse message: {e}')
            return

        msg_type = msg.get('type')

        if msg_type == 'agent_message':
            if self._on_message_callback:
                self._on_message_callback(msg)
        elif msg_type == 'typing':
            if self._on_typing_callback:
                conv_id = msg.get('data', {}).get('conversation_id', msg.get('conversation_id'))
                typing = msg.get('data', {}).get('typing', msg.get('typing', False))
                self._on_typing_callback(conv_id, typing)
        elif msg_type == 'status':
            if self._on_status_callback:
                agent_id = msg.get('data', {}).get('agent_id', msg.get('agent_id'))
                status = msg.get('data', {}).get('status', msg.get('status'))
                self._on_status_callback(agent_id, status)
        elif msg_type == 'error':
            error_msg = msg.get('data', {}).get('error', 'Unknown error')
            print(f'[AgentMessenger] Server error: {error_msg}')
        elif msg_type == 'connected':
            print('[AgentMessenger] Server confirmed connection')
        else:
            print(f'[AgentMessenger] Unknown message type: {msg_type}')

    def _on_error(self, ws, error):
        """Called when a WebSocket error occurs."""
        print(f'[AgentMessenger] WebSocket error: {error}')

    def _on_close(self, ws, close_status_code, close_msg):
        """Called when WebSocket connection closes."""
        print(f'[AgentMessenger] Connection closed: {close_status_code} {close_msg}')
        self.connected = False

        if self.window:
            from gi.repository import GLib
            GLib.idle_add(self.window.on_disconnected)

        # Schedule reconnect
        if not self._stop_event.is_set():
            self._schedule_reconnect()

    def _schedule_reconnect(self):
        """Schedule a reconnection attempt with exponential backoff."""
        if self._reconnect_attempts >= self._max_reconnect_attempts:
            print('[AgentMessenger] Max reconnect attempts reached')
            return

        self._reconnect_attempts += 1
        delay = min(1000 * (2 ** self._reconnect_attempts), 30000) / 1000.0

        print(f'[AgentMessenger] Reconnecting in {delay:.1f}s (attempt {self._reconnect_attempts}/{self._max_reconnect_attempts})')

        self._reconnect_timer = threading.Timer(delay, self._reconnect)
        self._reconnect_timer.daemon = True
        self._reconnect_timer.start()

    def _reconnect(self):
        """Attempt to reconnect."""
        if self._stop_event.is_set():
            return
        self._connect_ws()

    def send_message(self, conversation_id, content):
        """Send a text message to a conversation."""
        if not self.ws or not self.connected:
            print('[AgentMessenger] Not connected, cannot send message')
            return False

        msg = {
            'type': 'message',
            'data': {
                'conversation_id': conversation_id,
                'content': content,
            },
        }
        self.ws.send(json.dumps(msg))
        return True

    def disconnect(self):
        """Disconnect from the server."""
        self._stop_event.set()
        if self._reconnect_timer:
            self._reconnect_timer.cancel()
            self._reconnect_timer = None
        self._reconnect_attempts = self._max_reconnect_attempts
        if self.ws:
            self.ws.close()
        self.connected = False