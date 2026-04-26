"""Tests for high-level client classes."""
import pytest
from agent_messenger.client import AgentMessengerClient, AgentClient
from agent_messenger.rest import RestClient


class TestAgentMessengerClient:
    def test_exposes_rest_and_ws(self):
        client = AgentMessengerClient(base_url="http://localhost:8080", token="jwt-token")
        assert isinstance(client.rest, RestClient)
        assert client.ws is not None

    def test_disconnect_no_error(self):
        client = AgentMessengerClient(base_url="http://localhost:8080", token="jwt")
        client.disconnect()
        assert not client.ws.connected


class TestAgentClient:
    def test_creates_agent_with_ws(self):
        agent = AgentClient(
            base_url="http://localhost:8080",
            agent_id="test-agent",
            agent_secret="secret",
        )
        assert agent.ws is not None

    def test_on_off_handlers(self):
        agent = AgentClient(
            base_url="http://localhost:8080",
            agent_id="test-agent",
            agent_secret="secret",
        )
        handler = lambda data: None
        agent.on("message", handler)
        assert handler in agent.ws._handlers.get("message", set())
        agent.off("message", handler)
        assert handler not in agent.ws._handlers.get("message", set())

    def test_disconnect(self):
        agent = AgentClient(
            base_url="http://localhost:8080",
            agent_id="test-agent",
            agent_secret="secret",
        )
        agent.disconnect()
        assert not agent.ws.connected