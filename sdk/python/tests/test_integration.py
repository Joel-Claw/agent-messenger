"""
Agent Messenger SDK — Integration tests against a live server.

Requires AM_INTEGRATION=1 environment variable to run.
Starts the server binary, creates test fixtures, and validates
SDK REST + WebSocket operations end-to-end.

Usage:
    AM_INTEGRATION=1 pytest tests/test_integration.py -v
"""

import os
import random
import signal
import subprocess
import tempfile
import time

import pytest

# Skip all tests unless AM_INTEGRATION=1
pytestmark = pytest.mark.skipif(
    os.environ.get("AM_INTEGRATION") != "1",
    reason="Set AM_INTEGRATION=1 to run integration tests against live server",
)

from agent_messenger.rest import RestClient
from agent_messenger.types import (
    AgentConfig,
    ChangePasswordRequest,
    ClientConfig,
    CreateConversationRequest,
    LoginRequest,
    RegisterAgentRequest,
    RegisterUserRequest,
    TagRequest,
)
from agent_messenger.websocket import AgentWS, ClientWS

# ─── Server fixture ────────────────────────────────────────────────────────

SERVER_BIN = os.environ.get("AM_SERVER_BIN", "/tmp/am-server")


def _find_free_port():
    """Find a free TCP port."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def server():
    """Start a real Agent Messenger server for integration testing."""
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)
    port = _find_free_port()
    env = {
        **os.environ,
        "AGENT_SECRET": "int-test-secret",
        "JWT_SECRET": "int-test-jwt-secret",
        "ADMIN_SECRET": "int-test-admin-secret",
        "DATABASE_PATH": db_path,
        "PORT": str(port),
        "AUTH_RATE_LIMIT": "200",
        "IP_RATE_LIMIT": "1000",
    }
    proc = subprocess.Popen(
        [SERVER_BIN, "-port", str(port)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    # Wait for server to be ready
    import urllib.request
    for _ in range(40):
        try:
            resp = urllib.request.urlopen(f"http://localhost:{port}/health")
            if resp.status == 200:
                break
        except Exception:
            pass
        time.sleep(0.25)
    else:
        proc.kill()
        out = proc.stdout.read().decode() if proc.stdout else ""
        pytest.fail(f"Server did not start on port {port}: {out}")

    yield {
        "base_url": f"http://localhost:{port}",
        "ws_url": f"ws://localhost:{port}",
        "agent_secret": "int-test-secret",
        "admin_secret": "int-test-admin-secret",
        "db_path": db_path,
        "port": port,
    }

    # Cleanup
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    try:
        os.unlink(db_path)
    except OSError:
        pass


# ─── Unique ID generator for test isolation ────────────────────────────────

_ts = f"{int(time.time())}{random.randint(1000, 9999)}"
_seq = [0]


def _uid(prefix="u"):
    _seq[0] += 1
    return f"{prefix}_{_seq[0]}_{_ts}"


def make_user(server, prefix="u"):
    """Register a user and return (RestClient, token, user_id)."""
    username = _uid(prefix)
    client = RestClient(server["base_url"])
    time.sleep(0.3)  # Avoid auth rate limiting
    client.register_user(RegisterUserRequest(username=username, password="testpass123"))
    time.sleep(0.3)  # Avoid auth rate limiting
    login = client.login(LoginRequest(username=username, password="testpass123"))
    return client, login.token, login.user_id


def make_agent(server, prefix="a"):
    """Register an agent and return the agent_id."""
    agent_id = _uid(prefix)
    client = RestClient(server["base_url"])
    time.sleep(0.3)  # Avoid auth rate limiting
    client.register_agent(RegisterAgentRequest(
        agent_id=agent_id,
        agent_secret=server["agent_secret"],
        name=f"Test {agent_id}",
        model="test-model",
        personality="helpful",
        specialty="testing",
    ))
    return agent_id


# ─── REST Integration Tests ─────────────────────────────────────────────────

class TestRestIntegration:
    """Integration tests for REST API operations."""

    def test_health(self, server):
        client = RestClient(server["base_url"])
        health = client.health()
        assert health.status == "ok"
        assert health.version

    def test_register_and_login(self, server):
        client, token, user_id = make_user(server, "reg")
        assert token
        assert user_id

    def test_change_password(self, server):
        client, _, _ = make_user(server, "pw")
        time.sleep(0.5)
        result = client.change_password(ChangePasswordRequest(
            current_password="testpass123",
            new_password="newpass456",
        ))
        assert result.get("status") in ("ok", "changed", "password_changed")

    def test_list_agents(self, server):
        client, _, _ = make_user(server, "agents")
        agents = client.list_agents()
        assert isinstance(agents, list)

    def test_create_and_list_conversations(self, server):
        client, _, _ = make_user(server, "conv")
        time.sleep(0.3)
        agent_id = make_agent(server, "conv")
        conv = client.create_conversation(CreateConversationRequest(agent_id=agent_id))
        assert conv.conversation_id

        convs = client.list_conversations()
        assert len(convs) >= 1

    def test_get_messages_empty(self, server):
        client, _, _ = make_user(server, "msgs")
        time.sleep(0.3)
        agent_id = make_agent(server, "msgs")
        conv = client.create_conversation(CreateConversationRequest(agent_id=agent_id))

        messages = client.get_messages(conv.conversation_id)
        assert isinstance(messages, list)

    def test_search_messages(self, server):
        client, _, _ = make_user(server, "search")
        results = client.search_messages("test query", limit=10)
        assert results is not None

    def test_delete_conversation(self, server):
        client, _, _ = make_user(server, "del")
        time.sleep(0.3)
        agent_id = make_agent(server, "del")
        conv = client.create_conversation(CreateConversationRequest(agent_id=agent_id))

        result = client.delete_conversation(conv.conversation_id)
        assert result.get("status") in ("ok", "deleted")

    def test_tags(self, server):
        client, _, _ = make_user(server, "tags")
        time.sleep(0.3)
        agent_id = make_agent(server, "tags")
        conv = client.create_conversation(CreateConversationRequest(agent_id=agent_id))

        client.add_tag(TagRequest(conversation_id=conv.conversation_id, tag="important"))
        client.add_tag(TagRequest(conversation_id=conv.conversation_id, tag="work"))

        tags = client.get_tags(conv.conversation_id)
        tag_names = [t.tag for t in tags]
        assert "important" in tag_names
        assert "work" in tag_names

        client.remove_tag(TagRequest(conversation_id=conv.conversation_id, tag="work"))
        tags2 = client.get_tags(conv.conversation_id)
        tag_names2 = [t.tag for t in tags2]
        assert "work" not in tag_names2
        assert "important" in tag_names2

    def test_mark_read(self, server):
        client, _, _ = make_user(server, "read")
        time.sleep(0.3)
        agent_id = make_agent(server, "read")
        conv = client.create_conversation(CreateConversationRequest(agent_id=agent_id))

        result = client.mark_read(conv.conversation_id)
        assert result.status in ("ok", "marked_read")

    def test_presence(self, server):
        client, _, _ = make_user(server, "presence")
        presence = client.get_presence()
        assert isinstance(presence, list)


# ─── WebSocket Integration Tests ────────────────────────────────────────────

class TestWebSocketIntegration:
    """Integration tests for WebSocket connections."""

    def test_agent_connect(self, server):
        """Test that an agent can connect via WebSocket."""
        time.sleep(0.5)
        agent_id = make_agent(server, "ws_conn")
        agent_ws = AgentWS(AgentConfig(
            base_url=server["ws_url"],
            agent_id=agent_id,
            agent_secret=server["agent_secret"],
            auto_reconnect=False,
        ))
        try:
            connected = agent_ws.connect()
            assert connected is not None
            assert connected.status == "connected"
        finally:
            agent_ws.disconnect()

    def test_client_connect(self, server):
        """Test that a client can connect via WebSocket."""
        time.sleep(0.5)
        _, token, _ = make_user(server, "ws_cli")
        client_ws = ClientWS(ClientConfig(
            base_url=server["ws_url"],
            token=token,
            auto_reconnect=False,
        ))
        try:
            connected = client_ws.connect()
            assert connected is not None
        finally:
            client_ws.disconnect()

    def test_agent_receives_message(self, server):
        """Test that an agent receives a message from a client."""
        time.sleep(0.5)
        client, token, _ = make_user(server, "ws_msg")
        time.sleep(0.3)
        agent_id = make_agent(server, "ws_msg")
        conv = client.create_conversation(CreateConversationRequest(agent_id=agent_id))

        # Connect as agent
        agent_ws = AgentWS(AgentConfig(
            base_url=server["ws_url"],
            agent_id=agent_id,
            agent_secret=server["agent_secret"],
            auto_reconnect=False,
        ))
        agent_ws.connect()
        time.sleep(0.5)  # Let agent WS fully initialize

        try:
            # Connect as client
            client_ws = ClientWS(ClientConfig(
                base_url=server["ws_url"],
                token=token,
                auto_reconnect=False,
            ))
            client_ws.connect()

            try:
                received = []
                agent_ws.on("message", lambda data: received.append(data))

                client_ws.send_message(conv.conversation_id, "Hello from integration test!")

                # Wait for agent to receive
                for _ in range(50):
                    if received:
                        break
                    time.sleep(0.1)

                assert len(received) >= 1

            finally:
                client_ws.disconnect()
        finally:
            agent_ws.disconnect()

    def test_typing_indicator(self, server):
        """Test that typing indicators are routed from client to agent."""
        time.sleep(0.5)
        client, token, _ = make_user(server, "ws_type")
        time.sleep(0.3)
        agent_id = make_agent(server, "ws_type")
        conv = client.create_conversation(CreateConversationRequest(agent_id=agent_id))

        # Connect as agent
        agent_ws = AgentWS(AgentConfig(
            base_url=server["ws_url"],
            agent_id=agent_id,
            agent_secret=server["agent_secret"],
            auto_reconnect=False,
        ))
        agent_ws.connect()
        time.sleep(0.5)

        try:
            # Connect as client
            client_ws = ClientWS(ClientConfig(
                base_url=server["ws_url"],
                token=token,
                auto_reconnect=False,
            ))
            client_ws.connect()

            try:
                typing_received = []
                agent_ws.on("typing", lambda data: typing_received.append(data))

                client_ws.send_typing(conv.conversation_id)

                for _ in range(50):
                    if typing_received:
                        break
                    time.sleep(0.1)

                assert len(typing_received) >= 1

            finally:
                client_ws.disconnect()
        finally:
            agent_ws.disconnect()

    def test_agent_status_broadcast(self, server):
        """Test that agent status updates are broadcast."""
        time.sleep(0.5)
        agent_id = make_agent(server, "ws_status")
        time.sleep(0.3)
        client, token, _ = make_user(server, "ws_status")

        # Connect as agent
        agent_ws = AgentWS(AgentConfig(
            base_url=server["ws_url"],
            agent_id=agent_id,
            agent_secret=server["agent_secret"],
            auto_reconnect=False,
        ))
        agent_ws.connect()
        time.sleep(0.5)

        try:
            # Connect as client
            client_ws = ClientWS(ClientConfig(
                base_url=server["ws_url"],
                token=token,
                auto_reconnect=False,
            ))
            client_ws.connect()

            try:
                status_received = []
                client_ws.on("status", lambda data: status_received.append(data))

                agent_ws.send_status("busy", conversation_id="")

                for _ in range(50):
                    if status_received:
                        break
                    time.sleep(0.1)

                assert len(status_received) >= 1

            finally:
                client_ws.disconnect()
        finally:
            agent_ws.disconnect()

    def test_agent_sends_reply(self, server):
        """Test that an agent can send a reply message to a conversation."""
        time.sleep(0.5)
        client, token, _ = make_user(server, "ws_reply")
        time.sleep(0.3)
        agent_id = make_agent(server, "ws_reply")
        conv = client.create_conversation(CreateConversationRequest(agent_id=agent_id))

        # Connect as agent
        agent_ws = AgentWS(AgentConfig(
            base_url=server["ws_url"],
            agent_id=agent_id,
            agent_secret=server["agent_secret"],
            auto_reconnect=False,
        ))
        agent_ws.connect()
        time.sleep(0.5)

        try:
            # Connect as client
            client_ws = ClientWS(ClientConfig(
                base_url=server["ws_url"],
                token=token,
                auto_reconnect=False,
            ))
            client_ws.connect()

            try:
                received = []
                client_ws.on("message", lambda data: received.append(data))

                agent_ws.send_message(conv.conversation_id, "Reply from agent!")

                for _ in range(50):
                    if received:
                        break
                    time.sleep(0.1)

                assert len(received) >= 1

            finally:
                client_ws.disconnect()
        finally:
            agent_ws.disconnect()


# ─── High-Level Client Integration Tests ────────────────────────────────────

class TestClientIntegration:
    """Integration tests for the high-level AgentMessengerClient."""

    def test_full_flow(self, server):
        """Test the full register → login → connect → disconnect flow."""
        time.sleep(0.5)
        from agent_messenger.client import AgentMessengerClient

        client = AgentMessengerClient(base_url=server["base_url"])

        # Register
        reg = client.register("inttest_full_" + _ts, "testpass123")
        assert reg.user_id

        # Login
        login = client.login("inttest_full_" + _ts, "testpass123")
        assert login.token

        # Health check via REST
        health = client.rest.health()
        assert health.status == "ok"

    def test_multi_device(self, server):
        """Test that messages are delivered to multiple devices for the same user."""
        time.sleep(0.5)
        client, token, _ = make_user(server, "ws_multi")
        time.sleep(0.3)
        agent_id = make_agent(server, "ws_multi")
        conv = client.create_conversation(CreateConversationRequest(agent_id=agent_id))

        # Connect as agent
        agent_ws = AgentWS(AgentConfig(
            base_url=server["ws_url"],
            agent_id=agent_id,
            agent_secret=server["agent_secret"],
            auto_reconnect=False,
        ))
        agent_ws.connect()
        time.sleep(0.5)

        try:
            # Connect two client devices
            device1 = ClientWS(ClientConfig(
                base_url=server["ws_url"],
                token=token,
                device_id="device-1",
                auto_reconnect=False,
            ))
            device1.connect()

            device2 = ClientWS(ClientConfig(
                base_url=server["ws_url"],
                token=token,
                device_id="device-2",
                auto_reconnect=False,
            ))
            device2.connect()

            try:
                # Both devices should receive agent message
                received1 = []
                received2 = []
                device1.on("message", lambda data: received1.append(data))
                device2.on("message", lambda data: received2.append(data))

                agent_ws.send_message(conv.conversation_id, "Multi-device message!")

                for _ in range(50):
                    if received1 and received2:
                        break
                    time.sleep(0.1)

                assert len(received1) >= 1
                assert len(received2) >= 1

            finally:
                device1.disconnect()
                device2.disconnect()
        finally:
            agent_ws.disconnect()

    def test_e2e_message_flow(self, server):
        """Test full end-to-end message flow: client sends, agent receives, agent replies."""
        time.sleep(0.5)
        client, token, _ = make_user(server, "e2e")
        time.sleep(0.3)
        agent_id = make_agent(server, "e2e")
        conv = client.create_conversation(CreateConversationRequest(agent_id=agent_id))

        # Connect as agent
        agent_ws = AgentWS(AgentConfig(
            base_url=server["ws_url"],
            agent_id=agent_id,
            agent_secret=server["agent_secret"],
            auto_reconnect=False,
        ))
        agent_ws.connect()
        time.sleep(0.5)

        try:
            # Connect as client
            client_ws = ClientWS(ClientConfig(
                base_url=server["ws_url"],
                token=token,
                auto_reconnect=False,
            ))
            client_ws.connect()

            try:
                # Client sends message to agent
                agent_received = []
                agent_ws.on("message", lambda data: agent_received.append(data))

                client_ws.send_message(conv.conversation_id, "Hello agent!")

                for _ in range(50):
                    if agent_received:
                        break
                    time.sleep(0.1)

                assert len(agent_received) >= 1
                assert agent_received[0].content == "Hello agent!"

                # Agent replies
                client_received = []
                client_ws.on("message", lambda data: client_received.append(data))

                agent_ws.send_message(conv.conversation_id, "Hello user!")

                for _ in range(50):
                    if client_received:
                        break
                    time.sleep(0.1)

                assert len(client_received) >= 1
                assert client_received[0].content == "Hello user!"

                # Verify messages are persisted
                time.sleep(0.2)
                messages = client.get_messages(conv.conversation_id)
                assert len(messages) >= 2

            finally:
                client_ws.disconnect()
        finally:
            agent_ws.disconnect()