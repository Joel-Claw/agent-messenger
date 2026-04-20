"""Tests for WebSocket client module."""

import json
import os
import sys
import threading
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.client import AgentMessengerClient
from src.config import Config


class TestAgentMessengerClient:
    """Test AgentMessengerClient class."""

    def test_init_defaults(self):
        """Client should initialize with default state."""
        config = Config()
        client = AgentMessengerClient(config)
        assert client.connected is False
        assert client.ws is None
        assert client.config is config

    def test_set_on_message_callback(self):
        """Client should accept message callback."""
        config = Config()
        client = AgentMessengerClient(config)
        callback = mock.Mock()
        client.set_on_message(callback)
        assert client._on_message_callback is callback

    def test_set_on_typing_callback(self):
        """Client should accept typing callback."""
        config = Config()
        client = AgentMessengerClient(config)
        callback = mock.Mock()
        client.set_on_typing(callback)
        assert client._on_typing_callback is callback

    def test_set_on_status_callback(self):
        """Client should accept status callback."""
        config = Config()
        client = AgentMessengerClient(config)
        callback = mock.Mock()
        client.set_on_status(callback)
        assert client._on_status_callback is callback

    def test_send_message_not_connected(self):
        """send_message should return False when not connected."""
        config = Config()
        client = AgentMessengerClient(config)
        assert client.send_message('conv-1', 'hello') is False

    def test_send_message_connected(self):
        """send_message should send JSON via WebSocket when connected."""
        config = Config()
        client = AgentMessengerClient(config)
        client.connected = True

        mock_ws = mock.Mock()
        client.ws = mock_ws

        result = client.send_message('conv-123', 'Hello agent!')
        assert result is True
        mock_ws.send.assert_called_once()

        sent_data = json.loads(mock_ws.send.call_args[0][0])
        assert sent_data['type'] == 'message'
        assert sent_data['data']['conversation_id'] == 'conv-123'
        assert sent_data['data']['content'] == 'Hello agent!'

    def test_disconnect(self):
        """disconnect should clean up state."""
        config = Config()
        client = AgentMessengerClient(config)
        client.connected = True

        mock_ws = mock.Mock()
        client.ws = mock_ws

        client.disconnect()
        assert client.connected is False
        mock_ws.close.assert_called_once()

    def test_on_message_agent_message(self):
        """_on_message should call message callback for agent_message type."""
        config = Config()
        client = AgentMessengerClient(config)
        callback = mock.Mock()
        client.set_on_message(callback)

        msg = json.dumps({
            'type': 'agent_message',
            'content': 'Hello!',
            'conversation_id': 'conv-1',
        })
        client._on_message(None, msg)
        callback.assert_called_once_with({
            'type': 'agent_message',
            'content': 'Hello!',
            'conversation_id': 'conv-1',
        })

    def test_on_message_typing(self):
        """_on_message should call typing callback for typing type."""
        config = Config()
        client = AgentMessengerClient(config)
        callback = mock.Mock()
        client.set_on_typing(callback)

        msg = json.dumps({
            'type': 'typing',
            'data': {
                'conversation_id': 'conv-1',
                'typing': True,
            },
        })
        client._on_message(None, msg)
        callback.assert_called_once_with('conv-1', True)

    def test_on_message_status(self):
        """_on_message should call status callback for status type."""
        config = Config()
        client = AgentMessengerClient(config)
        callback = mock.Mock()
        client.set_on_status(callback)

        msg = json.dumps({
            'type': 'status',
            'data': {
                'agent_id': 'agent-1',
                'status': 'busy',
            },
        })
        client._on_message(None, msg)
        callback.assert_called_once_with('agent-1', 'busy')

    def test_on_message_invalid_json(self):
        """_on_message should handle invalid JSON gracefully."""
        config = Config()
        client = AgentMessengerClient(config)
        # Should not raise
        client._on_message(None, 'not valid json{{{')

    def test_on_message_unknown_type(self):
        """_on_message should handle unknown message types."""
        config = Config()
        client = AgentMessengerClient(config)
        msg = json.dumps({'type': 'unknown_type', 'data': {}})
        # Should not raise
        client._on_message(None, msg)

    def test_connect_no_credentials(self):
        """connect should return False if no credentials configured."""
        config = Config(username='', password='')
        client = AgentMessengerClient(config)
        result = client.connect()
        assert result is False

    def test_reconnect_backoff(self):
        """Reconnect attempts should respect max limit."""
        config = Config()
        client = AgentMessengerClient(config)
        client._reconnect_attempts = client._max_reconnect_attempts
        # Should not schedule reconnect when at max
        client._schedule_reconnect()
        # No timer should be set
        assert client._reconnect_timer is None