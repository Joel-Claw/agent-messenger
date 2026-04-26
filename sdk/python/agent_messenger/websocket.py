"""
Agent Messenger SDK — WebSocket clients for real-time messaging.

Provides ClientWS (for users) and AgentWS (for AI agents).
Uses the `websockets` library for Python 3.7+.
"""

from __future__ import annotations

import json
import asyncio
import threading
from typing import Any, Callable, Dict, List, Optional, Set

try:
    import websockets
    import websockets.client
    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False

from .types import (
    AgentConfig,
    ClientConfig,
    WSChatData,
    WSConnectedData,
    WSErrorData,
    WSMessage,
    WSMessageSentData,
    WSReadReceiptData,
    WSReactionData,
    WSStatusData,
    WSTypingData,
    WSEventType,
)


class WebSocketError(Exception):
    """WebSocket connection error."""
    pass


class BaseWS:
    """Base WebSocket client with event handling and auto-reconnect."""

    def __init__(
        self,
        base_url: str,
        auto_reconnect: bool = True,
        max_reconnect_attempts: int = 10,
        reconnect_base_delay: float = 1.0,
    ):
        if not HAS_WEBSOCKETS:
            raise ImportError(
                "The 'websockets' package is required. Install it with: pip install agent-messenger[ws]"
            )
        self.base_url = base_url.rstrip("/")
        self.auto_reconnect = auto_reconnect
        self.max_reconnect_attempts = max_reconnect_attempts
        self.reconnect_base_delay = reconnect_base_delay
        self._ws: Optional[Any] = None
        self._connected = False
        self._reconnect_attempts = 0
        self._handlers: Dict[str, Set[Callable]] = {}
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._stop_event = threading.Event()

    @property
    def connected(self) -> bool:
        return self._connected

    def on(self, event: str, handler: Callable) -> None:
        """Register an event handler."""
        if event not in self._handlers:
            self._handlers[event] = set()
        self._handlers[event].add(handler)

    def off(self, event: str, handler: Callable) -> None:
        """Remove an event handler."""
        if event in self._handlers:
            self._handlers[event].discard(handler)

    def _emit(self, event: str, data: Any = None) -> None:
        """Emit an event to all registered handlers."""
        for handler in self._handlers.get(event, set()):
            try:
                handler(data)
            except Exception:
                pass  # Don't let handler errors break the event loop

    def _parse_message(self, raw: str) -> WSMessage:
        """Parse a raw WebSocket message."""
        d = json.loads(raw)
        return WSMessage(type=d.get("type", ""), data=d.get("data", {}))

    def _handle_message(self, msg: WSMessage, resolve: Optional[Callable] = None) -> None:
        """Handle a parsed WebSocket message."""
        msg_type = msg.type
        data = msg.data

        if msg_type == "connected":
            self._connected = True
            self._reconnect_attempts = 0
            connected_data = WSConnectedData(
                id=data.get("id", ""),
                status=data.get("status", "connected"),
                protocol_version=data.get("protocol_version", "v1"),
                supported_versions=data.get("supported_versions", ["v1"]),
                device_id=data.get("device_id", ""),
            )
            self._emit("connected", connected_data)
            if resolve:
                resolve(connected_data)

        elif msg_type == "message":
            self._emit("message", WSChatData(
                conversation_id=data.get("conversation_id", ""),
                content=data.get("content", ""),
                sender_type=data.get("sender_type", ""),
                sender_id=data.get("sender_id", ""),
                message_id=data.get("message_id", ""),
                timestamp=data.get("timestamp", ""),
                metadata=data.get("metadata", {}),
            ))

        elif msg_type == "message_sent":
            self._emit("message_sent", WSMessageSentData(
                message_id=data.get("message_id", ""),
                conversation_id=data.get("conversation_id", ""),
                timestamp=data.get("timestamp", ""),
            ))

        elif msg_type == "typing":
            self._emit("typing", WSTypingData(
                conversation_id=data.get("conversation_id", ""),
                sender_type=data.get("sender_type", ""),
                sender_id=data.get("sender_id", ""),
            ))

        elif msg_type == "status":
            self._emit("status", WSStatusData(
                conversation_id=data.get("conversation_id", ""),
                sender_type=data.get("sender_type", ""),
                sender_id=data.get("sender_id", ""),
                status=data.get("status", ""),
            ))

        elif msg_type == "read_receipt":
            self._emit("read_receipt", WSReadReceiptData(
                conversation_id=data.get("conversation_id", ""),
                read_by=data.get("read_by", ""),
                count=data.get("count", 0),
            ))

        elif msg_type == "reaction_added":
            self._emit("reaction_added", WSReactionData(
                message_id=data.get("message_id", ""),
                emoji=data.get("emoji", ""),
                user_id=data.get("user_id", ""),
                action="added",
            ))

        elif msg_type == "reaction_removed":
            self._emit("reaction_removed", WSReactionData(
                message_id=data.get("message_id", ""),
                emoji=data.get("emoji", ""),
                user_id=data.get("user_id", ""),
                action="removed",
            ))

        elif msg_type == "error":
            self._emit("error", WSErrorData(error=data.get("error", "")))

        else:
            self._emit(msg_type, data)


class ClientWS(BaseWS):
    """WebSocket client for users. Connects to /client/connect."""

    def __init__(self, config: ClientConfig):
        super().__init__(
            base_url=config.base_url,
            auto_reconnect=config.auto_reconnect,
            max_reconnect_attempts=config.max_reconnect_attempts,
            reconnect_base_delay=config.reconnect_base_delay,
        )
        self.config = config

    def set_token(self, token: str) -> None:
        """Update the stored JWT token."""
        self.config.token = token

    def connect(self) -> WSConnectedData:
        """Connect to the server synchronously (blocking)."""
        result: Optional[WSConnectedData] = None
        error: Optional[Exception] = None

        def run():
            nonlocal result, error
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                self._loop = loop
                result = loop.run_until_complete(self._connect_async())
            except Exception as e:
                error = e

        # Start background listener
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_listener, daemon=True)
        self._thread.start()

        # Wait for connected or error
        import time
        timeout = 10
        start = time.time()
        while time.time() - start < timeout:
            if self._connected:
                break
            if error:
                raise error
            time.sleep(0.05)

        if not self._connected and not error:
            raise WebSocketError("Connection timeout")

        return result or WSConnectedData(id="", status="connected")

    async def _connect_async(self) -> WSConnectedData:
        """Connect asynchronously."""
        params = {"token": self.config.token}
        if self.config.device_id:
            params["device_id"] = self.config.device_id

        ws_url = self.base_url.replace("http", "ws").replace("https", "wss")
        ws_url += f"/client/connect?{self._urlencode(params)}"

        ws = await websockets.connect(
            ws_url,
            additional_headers={"Authorization": f"Bearer {self.config.token}"},
        )
        self._ws = ws

        # Wait for welcome message
        raw = await asyncio.wait_for(ws.recv(), timeout=10)
        msg = self._parse_message(raw)
        if msg.type != "connected":
            await ws.close()
            raise WebSocketError(f"Expected connected message, got: {msg.type}")

        data = msg.data
        connected_data = WSConnectedData(
            id=data.get("id", ""),
            status=data.get("status", "connected"),
            protocol_version=data.get("protocol_version", "v1"),
            supported_versions=data.get("supported_versions", ["v1"]),
            device_id=data.get("device_id", ""),
        )
        self._connected = True
        self._reconnect_attempts = 0
        return connected_data

    def _run_listener(self) -> None:
        """Run the WebSocket listener in a background thread."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop

        async def listen():
            try:
                connected_data = await self._connect_async()
                self._emit("connected", connected_data)
            except Exception as e:
                self._emit("error", WSErrorData(error=str(e)))
                return

            try:
                async for raw in self._ws:
                    try:
                        msg = self._parse_message(raw)
                        self._handle_message(msg)
                    except Exception:
                        pass
            except websockets.ConnectionClosed:
                self._connected = False
                self._emit("disconnect", None)
                if self.auto_reconnect:
                    self._schedule_reconnect()
            except Exception as e:
                self._connected = False
                self._emit("error", WSErrorData(error=str(e)))

        loop.run_until_complete(listen())

    def _schedule_reconnect(self) -> None:
        """Schedule a reconnection attempt."""
        if self._reconnect_attempts >= self.max_reconnect_attempts:
            self._emit("error", WSErrorData(error="Max reconnect attempts reached"))
            return
        self._reconnect_attempts += 1
        delay = min(self.reconnect_base_delay * (2 ** (self._reconnect_attempts - 1)), 30)
        self._stop_event.wait(delay)
        if not self._stop_event.is_set():
            self._run_listener()

    def disconnect(self) -> None:
        """Disconnect from the server."""
        self._stop_event.set()
        self._connected = False
        if self._ws:
            asyncio.run_coroutine_threadsafe(self._ws.close(), self._loop) if self._loop else None

    def send_message(self, conversation_id: str, content: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Send a chat message."""
        data: Dict[str, Any] = {"conversation_id": conversation_id, "content": content}
        if metadata:
            data["metadata"] = metadata
        self._send({"type": "message", "data": data})

    def send_typing(self, conversation_id: str) -> None:
        """Send a typing indicator."""
        self._send({"type": "typing", "data": {"conversation_id": conversation_id}})

    def send_status(self, conversation_id: str, status: str) -> None:
        """Send a status update."""
        self._send({"type": "status", "data": {"conversation_id": conversation_id, "status": status}})

    def _send(self, msg: Dict[str, Any]) -> None:
        """Send a raw WebSocket message."""
        if not self._ws or not self._connected:
            raise WebSocketError("Not connected")
        if self._loop:
            asyncio.run_coroutine_threadsafe(
                self._ws.send(json.dumps(msg)), self._loop
            )

    @staticmethod
    def _urlencode(params: Dict[str, str]) -> str:
        from urllib.parse import urlencode
        return urlencode(params)


class AgentWS(BaseWS):
    """WebSocket client for AI agents. Connects to /agent/connect."""

    def __init__(self, config: AgentConfig):
        super().__init__(
            base_url=config.base_url,
            auto_reconnect=config.auto_reconnect,
            max_reconnect_attempts=config.max_reconnect_attempts,
            reconnect_base_delay=config.reconnect_base_delay,
        )
        self.config = config

    def connect(self) -> WSConnectedData:
        """Connect to the server synchronously (blocking)."""
        import time

        result: Optional[WSConnectedData] = None
        error: Optional[Exception] = None

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_listener, daemon=True)
        self._thread.start()

        timeout = 10
        start = time.time()
        while time.time() - start < timeout:
            if self._connected:
                break
            if error:
                raise error
            time.sleep(0.05)

        if not self._connected and not error:
            raise WebSocketError("Connection timeout")

        return result or WSConnectedData(id="", status="connected")

    async def _connect_async(self) -> WSConnectedData:
        """Connect asynchronously."""
        from urllib.parse import urlencode
        params: Dict[str, str] = {
            "agent_id": self.config.agent_id,
            "agent_secret": self.config.agent_secret,
        }
        if self.config.agent_name:
            params["name"] = self.config.agent_name
        if self.config.agent_model:
            params["model"] = self.config.agent_model
        if self.config.agent_personality:
            params["personality"] = self.config.agent_personality
        if self.config.agent_specialty:
            params["specialty"] = self.config.agent_specialty

        ws_url = self.base_url.replace("http", "ws").replace("https", "wss")
        ws_url += f"/agent/connect?{urlencode(params)}"

        ws = await websockets.connect(ws_url)
        self._ws = ws

        raw = await asyncio.wait_for(ws.recv(), timeout=10)
        msg = self._parse_message(raw)
        if msg.type != "connected":
            await ws.close()
            raise WebSocketError(f"Expected connected message, got: {msg.type}")

        data = msg.data
        connected_data = WSConnectedData(
            id=data.get("id", ""),
            status=data.get("status", "connected"),
            protocol_version=data.get("protocol_version", "v1"),
            supported_versions=data.get("supported_versions", ["v1"]),
        )
        self._connected = True
        self._reconnect_attempts = 0
        return connected_data

    def _run_listener(self) -> None:
        """Run WebSocket listener in background thread."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop

        async def listen():
            try:
                connected_data = await self._connect_async()
                self._emit("connected", connected_data)
            except Exception as e:
                self._emit("error", WSErrorData(error=str(e)))
                return

            try:
                async for raw in self._ws:
                    try:
                        msg = self._parse_message(raw)
                        self._handle_message(msg)
                    except Exception:
                        pass
            except websockets.ConnectionClosed:
                self._connected = False
                self._emit("disconnect", None)
                if self.auto_reconnect:
                    self._schedule_reconnect()
            except Exception as e:
                self._connected = False
                self._emit("error", WSErrorData(error=str(e)))

        loop.run_until_complete(listen())

    def disconnect(self) -> None:
        """Disconnect from the server."""
        self._stop_event.set()
        self._connected = False
        if self._ws and self._loop:
            asyncio.run_coroutine_threadsafe(self._ws.close(), self._loop)

    def send_message(self, conversation_id: str, content: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Send a chat message."""
        data: Dict[str, Any] = {"conversation_id": conversation_id, "content": content}
        if metadata:
            data["metadata"] = metadata
        self._send({"type": "message", "data": data})

    def send_typing(self, conversation_id: str) -> None:
        """Send a typing indicator."""
        self._send({"type": "typing", "data": {"conversation_id": conversation_id}})

    def send_status(self, status: str, conversation_id: str = "") -> None:
        """Send a status update."""
        data: Dict[str, str] = {"status": status}
        if conversation_id:
            data["conversation_id"] = conversation_id
        self._send({"type": "status", "data": data})

    def _send(self, msg: Dict[str, Any]) -> None:
        """Send a raw WebSocket message."""
        if not self._ws or not self._connected:
            raise WebSocketError("Not connected")
        if self._loop:
            asyncio.run_coroutine_threadsafe(
                self._ws.send(json.dumps(msg)), self._loop
            )