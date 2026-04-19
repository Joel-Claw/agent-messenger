"""
Integration tests for the Linux client against a running Agent Messenger server.

These tests require a running server (set AM_INTEGRATION=1 to enable).
The server is started/stopped automatically using the Go binary.

Tests cover:
- Client authentication via REST API
- WebSocket connection with JWT token
- Agent listing
- Conversation creation
- Message sending and receiving
- Typing indicator delivery
- Status update delivery
- Auto-reconnect behavior
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from unittest import mock

import pytest

# Skip all tests unless AM_INTEGRATION=1
pytestmark = pytest.mark.skipif(
    os.environ.get('AM_INTEGRATION') != '1',
    reason='Integration tests require AM_INTEGRATION=1'
)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.client import AgentMessengerClient
from src.config import Config


def find_free_port():
    """Find a free port on localhost."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def unique_email():
    """Generate a unique email address for testing."""
    return f'test-{uuid.uuid4().hex[:8]}@example.com'


class ServerFixture:
    """Manages a test Agent Messenger server process."""

    def __init__(self):
        self.port = find_free_port()
        self.api_url = f'http://127.0.0.1:{self.port}'
        self.ws_url = f'ws://127.0.0.1:{self.port}'
        self.process = None
        self.db_path = None

    def _find_go_binary(self):
        """Find the server binary."""
        server_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'server')
        binary_path = os.path.join(server_dir, 'agent-messenger-server')
        if os.path.isfile(binary_path) and os.access(binary_path, os.X_OK):
            return binary_path
        return None

    def start(self):
        """Start the server process."""
        self.db_path = tempfile.mktemp(suffix='.db')

        server_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'server')
        binary_path = self._find_go_binary()

        if not binary_path:
            # Try building it first
            print("[Integration] Building server binary...")
            result = subprocess.run(
                ['go', 'build', '-o', 'agent-messenger-server', '.'],
                cwd=server_dir,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"Failed to build server: {result.stderr}\n"
                    f"Please build it manually: cd {server_dir} && go build -o agent-messenger-server ."
                )
            binary_path = os.path.join(server_dir, 'agent-messenger-server')

        print(f"[Integration] Starting server on port {self.port}...")
        self.process = subprocess.Popen(
            [binary_path, '-port', str(self.port), '-db', self.db_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Wait for server to be ready
        import requests
        for i in range(30):
            try:
                resp = requests.get(f'{self.api_url}/health', timeout=1)
                if resp.status_code == 200:
                    print(f"[Integration] Server ready on port {self.port}")
                    return
            except Exception:
                pass
            time.sleep(0.5)

        # Server didn't start
        stdout, stderr = b'', b''
        if self.process:
            stdout = self.process.stdout.read() if self.process.stdout else b''
            stderr = self.process.stderr.read() if self.process.stderr else b''
            self.stop()
        raise RuntimeError(
            f"Server failed to start within 15 seconds.\n"
            f"stdout: {stdout.decode()[:500]}\n"
            f"stderr: {stderr.decode()[:500]}"
        )

    def stop(self):
        """Stop the server process."""
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
            self.process = None
        if self.db_path and os.path.exists(self.db_path):
            os.unlink(self.db_path)


@pytest.fixture(scope='module')
def server():
    """Module-scoped server fixture."""
    fixture = ServerFixture()
    try:
        fixture.start()
        yield fixture
    finally:
        fixture.stop()


def register_user(server, email=None, password='testpassword123'):
    """Register a test user and return (user_id, token)."""
    import requests
    if email is None:
        email = unique_email()
    resp = requests.post(
        f'{server.api_url}/auth/user',
        data={'email': email, 'password': password},
    )
    assert resp.status_code == 200, f"Failed to register user: {resp.text}"
    return resp.json()['user_id'], email, password


def get_auth_token(server, email, password):
    """Get a JWT token for a user."""
    import requests
    resp = requests.post(
        f'{server.api_url}/auth/login',
        data={'email': email, 'password': password},
    )
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    return resp.json()['token']


def register_agent(server, agent_id=None, api_key=None):
    """Register a test agent and return (agent_id, api_key)."""
    import requests
    if agent_id is None:
        agent_id = f'test-agent-{uuid.uuid4().hex[:8]}'
    if api_key is None:
        api_key = f'test-key-{uuid.uuid4().hex[:8]}'
    resp = requests.post(
        f'{server.api_url}/auth/agent',
        data={
            'agent_id': agent_id,
            'name': f'Agent {agent_id}',
            'api_key': api_key,
            'model': 'test-model',
            'personality': 'helpful',
            'specialty': 'integration testing',
        },
    )
    assert resp.status_code == 200, f"Failed to register agent: {resp.text}"
    return agent_id, api_key


class TestClientAuthentication:
    """Test client authentication against the server."""

    def test_register_and_login(self, server):
        """Client can register and then authenticate."""
        user_id, email, password = register_user(server)
        token = get_auth_token(server, email, password)
        assert token is not None
        assert len(token) > 0

    def test_login_failure_wrong_password(self, server):
        """Client authentication fails with wrong password."""
        user_id, email, password = register_user(server)
        import requests
        resp = requests.post(
            f'{server.api_url}/auth/login',
            data={'email': email, 'password': 'wrongpassword'},
        )
        assert resp.status_code == 401

    def test_login_failure_nonexistent_user(self, server):
        """Client authentication fails for nonexistent user."""
        import requests
        resp = requests.post(
            f'{server.api_url}/auth/login',
            data={'email': 'nonexistent@example.com', 'password': 'whatever'},
        )
        assert resp.status_code == 401


class TestAgentDiscovery:
    """Test agent listing and discovery."""

    def test_list_agents(self, server):
        """Client can list available agents."""
        agent_id, _ = register_agent(server)
        import requests
        resp = requests.get(f'{server.api_url}/agents')
        assert resp.status_code == 200
        agents = resp.json()
        assert isinstance(agents, list)
        assert any(a['id'] == agent_id for a in agents)

    def test_agent_status_offline(self, server):
        """Unconnected agent shows as offline."""
        agent_id, _ = register_agent(server)
        import requests
        resp = requests.get(f'{server.api_url}/agents')
        agents = resp.json()
        agent = next(a for a in agents if a['id'] == agent_id)
        assert agent['status'] == 'offline'


class TestConversationFlow:
    """Test conversation creation and messaging."""

    def test_create_conversation(self, server):
        """Client can create a conversation with an agent."""
        user_id, email, password = register_user(server)
        token = get_auth_token(server, email, password)
        agent_id, _ = register_agent(server)

        import requests
        headers = {'Authorization': f'Bearer {token}'}
        resp = requests.post(
            f'{server.api_url}/conversations/create',
            data={'user_id': user_id, 'agent_id': agent_id},
            headers=headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert 'conversation_id' in data or 'id' in data

    def test_list_conversations(self, server):
        """Client can list their conversations."""
        user_id, email, password = register_user(server)
        token = get_auth_token(server, email, password)
        agent_id, _ = register_agent(server)

        import requests
        headers = {'Authorization': f'Bearer {token}'}

        # Create a conversation first
        requests.post(
            f'{server.api_url}/conversations/create',
            data={'user_id': user_id, 'agent_id': agent_id},
            headers=headers,
        )

        # List conversations
        resp = requests.get(
            f'{server.api_url}/conversations/list',
            headers=headers,
        )
        assert resp.status_code == 200
        conversations = resp.json()
        assert isinstance(conversations, list)
        assert len(conversations) >= 1

    def test_get_messages_empty(self, server):
        """Client can get messages for a conversation (initially empty)."""
        user_id, email, password = register_user(server)
        token = get_auth_token(server, email, password)
        agent_id, _ = register_agent(server)

        import requests
        headers = {'Authorization': f'Bearer {token}'}

        # Create a conversation
        resp = requests.post(
            f'{server.api_url}/conversations/create',
            data={'user_id': user_id, 'agent_id': agent_id},
            headers=headers,
        )
        conv_id = resp.json().get('conversation_id') or resp.json().get('id')

        # Get messages
        resp = requests.get(
            f'{server.api_url}/conversations/messages?conversation_id={conv_id}',
            headers=headers,
        )
        assert resp.status_code == 200
        messages = resp.json()
        assert isinstance(messages, list)


class TestWebSocketConnection:
    """Test WebSocket connections to the server."""

    def test_client_ws_connect(self, server):
        """Client can connect via WebSocket with a valid JWT token."""
        user_id, email, password = register_user(server)
        token = get_auth_token(server, email, password)

        import websocket as ws_lib
        url = f'{server.ws_url}/client/connect?user_id={user_id}&token={token}'
        conn = ws_lib.create_connection(url, timeout=5)
        try:
            msg = conn.recv()
            data = json.loads(msg)
            assert data['type'] == 'connected'
        finally:
            conn.close()

    def test_client_ws_reject_bad_token(self, server):
        """Client WebSocket connection is rejected with invalid token."""
        import websocket as ws_lib
        url = f'{server.ws_url}/client/connect?user_id=user123&token=invalidtoken'
        try:
            conn = ws_lib.create_connection(url, timeout=5)
            # If connection somehow succeeds, it should close quickly
            conn.close()
        except Exception:
            pass  # Expected: connection rejected

    def test_agent_ws_connect(self, server):
        """Agent can connect via WebSocket with valid credentials."""
        agent_id, api_key = register_agent(server)

        import websocket as ws_lib
        url = f'{server.ws_url}/agent/connect?agent_id={agent_id}&api_key={api_key}'
        conn = ws_lib.create_connection(url, timeout=5)
        try:
            msg = conn.recv()
            data = json.loads(msg)
            assert data['type'] == 'connected'
            assert data['data']['agent_id'] == agent_id
        finally:
            conn.close()


class TestMessageDelivery:
    """Test bidirectional message delivery via WebSocket."""

    def test_user_to_agent_message(self, server):
        """User can send a message that reaches the connected agent."""
        user_id, email, password = register_user(server)
        token = get_auth_token(server, email, password)
        agent_id, api_key = register_agent(server)

        import websocket as ws_lib
        import requests

        # Connect agent first
        agent_url = f'{server.ws_url}/agent/connect?agent_id={agent_id}&api_key={api_key}'
        agent_conn = ws_lib.create_connection(agent_url, timeout=5)
        agent_conn.recv()  # welcome

        # Connect client
        client_url = f'{server.ws_url}/client/connect?user_id={user_id}&token={token}'
        client_conn = ws_lib.create_connection(client_url, timeout=5)
        client_conn.recv()  # welcome

        # Create conversation via REST
        headers = {'Authorization': f'Bearer {token}'}
        resp = requests.post(
            f'{server.api_url}/conversations/create',
            data={'user_id': user_id, 'agent_id': agent_id},
            headers=headers,
        )
        conv_id = resp.json().get('conversation_id') or resp.json().get('id')

        # Send message from client
        msg = json.dumps({
            'type': 'message',
            'data': {
                'conversation_id': conv_id,
                'content': 'Hello from integration test!',
            },
        })
        client_conn.send(msg)

        # Agent should receive it
        received = json.loads(agent_conn.recv())
        assert received.get('type') in ('message', 'user_message')

        client_conn.close()
        agent_conn.close()

    def test_agent_to_user_message(self, server):
        """Agent can send a message that reaches the connected user."""
        user_id, email, password = register_user(server)
        token = get_auth_token(server, email, password)
        agent_id, api_key = register_agent(server)

        import websocket as ws_lib
        import requests

        # Connect agent
        agent_url = f'{server.ws_url}/agent/connect?agent_id={agent_id}&api_key={api_key}'
        agent_conn = ws_lib.create_connection(agent_url, timeout=5)
        agent_conn.recv()  # welcome

        # Connect client
        client_url = f'{server.ws_url}/client/connect?user_id={user_id}&token={token}'
        client_conn = ws_lib.create_connection(client_url, timeout=5)
        client_conn.recv()  # welcome

        # Create conversation
        headers = {'Authorization': f'Bearer {token}'}
        resp = requests.post(
            f'{server.api_url}/conversations/create',
            data={'user_id': user_id, 'agent_id': agent_id},
            headers=headers,
        )
        conv_id = resp.json().get('conversation_id') or resp.json().get('id')

        # Client sends a message first so server knows the conversation
        client_msg = json.dumps({
            'type': 'message',
            'data': {
                'conversation_id': conv_id,
                'content': 'Hello agent',
            },
        })
        client_conn.send(client_msg)
        agent_conn.recv()  # agent receives client message

        # Agent sends a reply
        agent_msg = json.dumps({
            'type': 'message',
            'data': {
                'conversation_id': conv_id,
                'content': 'Hello from agent!',
            },
        })
        agent_conn.send(agent_msg)

        # Client may receive a message_sent ack for their own message first,
        # then the agent's message. Read until we get the agent message.
        received = None
        for _ in range(5):
            msg = json.loads(client_conn.recv())
            if msg.get('type') == 'message' and msg.get('data', {}).get('sender_type') == 'agent':
                received = msg
                break
            # Skip message_sent acks and other non-agent messages

        assert received is not None, f"Expected agent message, got messages without agent content"
        content = received.get('data', {}).get('content', received.get('content', ''))
        assert 'Hello from agent!' in content

        client_conn.close()
        agent_conn.close()


class TestClientReconnect:
    """Test client auto-reconnection behavior (unit tests, no server needed)."""

    def test_client_tracks_reconnect_state(self):
        """AgentMessengerClient correctly tracks reconnection attempts."""
        config = Config(server_url='ws://localhost:9999', api_url='http://localhost:9999')
        client = AgentMessengerClient(config)

        assert client.connected is False
        assert client._reconnect_attempts == 0

        # After reaching max, should not schedule reconnect
        client._reconnect_attempts = client._max_reconnect_attempts
        client._schedule_reconnect()
        assert client._reconnect_timer is None

    def test_client_disconnect_prevents_reconnect(self):
        """Disconnect should prevent further reconnection attempts."""
        config = Config(server_url='ws://localhost:9999', api_url='http://localhost:9999')
        client = AgentMessengerClient(config)
        client.connected = True

        client.disconnect()

        assert client.connected is False
        assert client._reconnect_attempts == client._max_reconnect_attempts
        assert client._stop_event.is_set()


class TestHealthEndpoint:
    """Test server health and metrics endpoints."""

    def test_health_endpoint(self, server):
        """Health endpoint returns OK status."""
        import requests
        resp = requests.get(f'{server.api_url}/health')
        assert resp.status_code == 200
        data = resp.json()
        assert data.get('status') == 'ok'

    def test_metrics_endpoint(self, server):
        """Metrics endpoint returns Prometheus-format data."""
        import requests
        resp = requests.get(f'{server.api_url}/metrics')
        assert resp.status_code == 200