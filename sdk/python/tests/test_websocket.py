"""Tests for WebSocket client classes."""
import json
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from agent_messenger.types import ClientConfig, AgentConfig
from agent_messenger.websocket import ClientWS, AgentWS, WebSocketError


class TestClientWSInit:
    def test_creates_with_config(self):
        ws = ClientWS(ClientConfig(
            base_url="http://localhost:8080",
            token="jwt-token",
            auto_reconnect=False,
        ))
        assert ws.config.base_url == "http://localhost:8080"
        assert ws.config.token == "jwt-token"
        assert not ws.connected

    def test_set_token(self):
        ws = ClientWS(ClientConfig(base_url="http://localhost:8080", token="old"))
        ws.set_token("new")
        assert ws.config.token == "new"

    def test_ws_url_http(self):
        ws = ClientWS(ClientConfig(base_url="http://localhost:8080", token="jwt"))
        url = ws.base_url.replace("http", "ws")
        assert url == "ws://localhost:8080"

    def test_ws_url_https(self):
        ws = ClientWS(ClientConfig(base_url="https://example.com", token="jwt"))
        url = ws.base_url.replace("http", "ws").replace("https", "wss")
        assert url == "wss://example.com"


class TestClientWSEvents:
    def test_on_off(self):
        ws = ClientWS(ClientConfig(base_url="http://localhost:8080", token="jwt", auto_reconnect=False))
        handler = lambda data: None
        ws.on("message", handler)
        assert handler in ws._handlers.get("message", set())
        ws.off("message", handler)
        assert handler not in ws._handlers.get("message", set())

    def test_emit_calls_handlers(self):
        ws = ClientWS(ClientConfig(base_url="http://localhost:8080", token="jwt", auto_reconnect=False))
        results = []
        ws.on("message", lambda data: results.append(data))

        from agent_messenger.types import WSChatData
        ws._emit("message", WSChatData(
            conversation_id="conv_1",
            content="Hello",
            sender_type="agent",
            sender_id="agent_1",
        ))
        assert len(results) == 1
        assert results[0].content == "Hello"

    def test_emit_error(self):
        ws = ClientWS(ClientConfig(base_url="http://localhost:8080", token="jwt", auto_reconnect=False))
        results = []
        ws.on("error", lambda data: results.append(data))

        from agent_messenger.types import WSErrorData
        ws._emit("error", WSErrorData(error="something went wrong"))
        assert len(results) == 1
        assert results[0].error == "something went wrong"

    def test_emit_unknown_event(self):
        ws = ClientWS(ClientConfig(base_url="http://localhost:8080", token="jwt", auto_reconnect=False))
        results = []
        ws.on("custom", lambda data: results.append(data))
        ws._emit("custom", {"key": "value"})
        assert len(results) == 1

    def test_disconnect(self):
        ws = ClientWS(ClientConfig(base_url="http://localhost:8080", token="jwt", auto_reconnect=False))
        ws.disconnect()
        assert not ws.connected


class TestMessageParsing:
    def test_parse_connected_message(self):
        from agent_messenger.types import WSMessage
        raw = json.dumps({
            "type": "connected",
            "data": {"id": "user_1", "status": "connected", "protocol_version": "v1"},
        })
        ws = ClientWS(ClientConfig(base_url="http://localhost:8080", token="jwt", auto_reconnect=False))
        msg = ws._parse_message(raw)
        assert msg.type == "connected"
        assert msg.data["id"] == "user_1"

    def test_parse_chat_message(self):
        raw = json.dumps({
            "type": "message",
            "data": {
                "conversation_id": "conv_1",
                "content": "Hello",
                "sender_type": "agent",
                "sender_id": "agent_1",
            },
        })
        ws = ClientWS(ClientConfig(base_url="http://localhost:8080", token="jwt", auto_reconnect=False))
        msg = ws._parse_message(raw)
        assert msg.type == "message"
        assert msg.data["content"] == "Hello"

    def test_handle_connected_message(self):
        ws = ClientWS(ClientConfig(base_url="http://localhost:8080", token="jwt", auto_reconnect=False))
        results = []
        ws.on("connected", lambda data: results.append(data))

        from agent_messenger.types import WSMessage
        msg = WSMessage(type="connected", data={
            "id": "user_1", "status": "connected", "protocol_version": "v1",
            "supported_versions": ["v1"], "device_id": "dev_1",
        })
        ws._handle_message(msg)
        assert len(results) == 1
        assert results[0].id == "user_1"

    def test_handle_typing_message(self):
        ws = ClientWS(ClientConfig(base_url="http://localhost:8080", token="jwt", auto_reconnect=False))
        results = []
        ws.on("typing", lambda data: results.append(data))

        from agent_messenger.types import WSMessage
        msg = WSMessage(type="typing", data={
            "conversation_id": "conv_1", "sender_type": "agent", "sender_id": "agent_1",
        })
        ws._handle_message(msg)
        assert len(results) == 1
        assert results[0].conversation_id == "conv_1"

    def test_handle_status_message(self):
        ws = ClientWS(ClientConfig(base_url="http://localhost:8080", token="jwt", auto_reconnect=False))
        results = []
        ws.on("status", lambda data: results.append(data))

        from agent_messenger.types import WSMessage
        msg = WSMessage(type="status", data={
            "conversation_id": "conv_1", "status": "busy",
        })
        ws._handle_message(msg)
        assert len(results) == 1
        assert results[0].status == "busy"


class TestAgentWSInit:
    def test_creates_with_config(self):
        ws = AgentWS(AgentConfig(
            base_url="http://localhost:8080",
            agent_id="my-agent",
            agent_secret="secret-123",
            agent_name="HelpBot",
            agent_model="gpt-4",
            auto_reconnect=False,
        ))
        assert ws.config.agent_id == "my-agent"
        assert ws.config.agent_secret == "secret-123"
        assert not ws.connected

    def test_disconnect(self):
        ws = AgentWS(AgentConfig(
            base_url="http://localhost:8080",
            agent_id="my-agent",
            agent_secret="secret-123",
            auto_reconnect=False,
        ))
        ws.disconnect()
        assert not ws.connected