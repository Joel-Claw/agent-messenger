"""Tests for the REST client."""
import json
import pytest
from unittest.mock import patch, MagicMock
from urllib.error import HTTPError
from io import BytesIO

from agent_messenger.rest import RestClient, ApiError
from agent_messenger.types import (
    LoginRequest,
    RegisterUserRequest,
    CreateConversationRequest,
    EditMessageRequest,
    TagRequest,
    ReactRequest,
    RegisterPushRequest,
    UnregisterPushRequest,
    UploadKeyBundleRequest,
    StoreEncryptedMessageRequest,
    SetRateLimitTierRequest,
    ChangePasswordRequest,
    RegisterAgentRequest,
)


def _mock_response(data, status=200):
    """Create a mock urlopen response."""
    mock = MagicMock()
    mock.__enter__ = MagicMock(return_value=mock)
    mock.__exit__ = MagicMock(return_value=False)
    mock.read.return_value = json.dumps(data).encode()
    mock.getcode.return_value = status
    return mock


class TestRestClientInit:
    def test_strips_trailing_slashes(self):
        client = RestClient("http://localhost:8080///")
        assert client.base_url == "http://localhost:8080"

    def test_stores_token(self):
        client = RestClient("http://localhost:8080", "my-token")
        assert client.token == "my-token"

    def test_set_token(self):
        client = RestClient("http://localhost:8080")
        client.set_token("new-token")
        assert client.token == "new-token"


class TestAuth:
    @patch("agent_messenger.rest.urlopen")
    def test_login(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({
            "token": "jwt-abc",
            "user_id": "user_1",
            "username": "alice",
        })
        client = RestClient("http://localhost:8080")
        result = client.login(LoginRequest(username="alice", password="secret"))
        assert result.token == "jwt-abc"
        assert result.user_id == "user_1"
        assert result.username == "alice"
        assert client.token == "jwt-abc"  # Token should be stored

    @patch("agent_messenger.rest.urlopen")
    def test_register_user(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({
            "user_id": "user_2",
            "username": "bob",
            "status": "registered",
        })
        client = RestClient("http://localhost:8080", "token")
        result = client.register_user(RegisterUserRequest(username="bob", password="pass123"))
        assert result.user_id == "user_2"
        assert result.username == "bob"

    @patch("agent_messenger.rest.urlopen")
    def test_register_agent(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({
            "agent_id": "agent_1",
            "name": "HelpBot",
            "api_key": "key-123",
        })
        client = RestClient("http://localhost:8080", "admin-token")
        result = client.register_agent(RegisterAgentRequest(
            agent_id="agent_1", agent_secret="secret",
            name="HelpBot", model="gpt-4",
        ))
        assert result.agent_id == "agent_1"
        assert result.api_key == "key-123"

    @patch("agent_messenger.rest.urlopen")
    def test_change_password(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({"status": "changed"})
        client = RestClient("http://localhost:8080", "token")
        result = client.change_password(ChangePasswordRequest(
            current_password="old", new_password="new",
        ))
        assert result["status"] == "changed"


class TestAgents:
    @patch("agent_messenger.rest.urlopen")
    def test_list_agents(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response([
            {"agent_id": "agent_1", "name": "Bot", "model": "gpt-4",
             "personality": "friendly", "specialty": "help", "status": "online"},
        ])
        client = RestClient("http://localhost:8080", "token")
        agents = client.list_agents()
        assert len(agents) == 1
        assert agents[0].agent_id == "agent_1"
        assert agents[0].status == "online"


class TestConversations:
    @patch("agent_messenger.rest.urlopen")
    def test_create_conversation(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({
            "conversation_id": "conv_1", "user_id": "user_1", "agent_id": "agent_1",
        })
        client = RestClient("http://localhost:8080", "token")
        conv = client.create_conversation(CreateConversationRequest(agent_id="agent_1"))
        assert conv.conversation_id == "conv_1"

    @patch("agent_messenger.rest.urlopen")
    def test_list_conversations(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response([
            {"conversation_id": "conv_1", "user_id": "user_1", "agent_id": "agent_1",
             "unread_count": 3, "tags": ["important"]},
        ])
        client = RestClient("http://localhost:8080", "token")
        convs = client.list_conversations(limit=10)
        assert len(convs) == 1
        assert convs[0].unread_count == 3
        assert convs[0].tags == ["important"]

    @patch("agent_messenger.rest.urlopen")
    def test_get_messages(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response([
            {"message_id": "msg_1", "content": "hello", "sender_type": "user"},
        ])
        client = RestClient("http://localhost:8080", "token")
        msgs = client.get_messages("conv_1", limit=20)
        assert len(msgs) == 1
        assert msgs[0].content == "hello"

    @patch("agent_messenger.rest.urlopen")
    def test_delete_conversation(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({"status": "deleted"})
        client = RestClient("http://localhost:8080", "token")
        result = client.delete_conversation("conv_1")
        assert result["status"] == "deleted"

    @patch("agent_messenger.rest.urlopen")
    def test_mark_read(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({
            "status": "ok", "conversation_id": "conv_1", "count": 5,
        })
        client = RestClient("http://localhost:8080", "token")
        result = client.mark_read("conv_1")
        assert result.count == 5


class TestMessages:
    @patch("agent_messenger.rest.urlopen")
    def test_search_messages(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response([
            {"message_id": "msg_1", "content": "hello world"},
        ])
        client = RestClient("http://localhost:8080", "token")
        results = client.search_messages("hello", limit=10)
        assert len(results.results) == 1

    @patch("agent_messenger.rest.urlopen")
    def test_edit_message(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({"status": "edited"})
        client = RestClient("http://localhost:8080", "token")
        result = client.edit_message(EditMessageRequest(message_id="msg_1", content="updated"))
        assert result["status"] == "edited"

    @patch("agent_messenger.rest.urlopen")
    def test_delete_message(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({"status": "deleted"})
        client = RestClient("http://localhost:8080", "token")
        result = client.delete_message("msg_1")
        assert result["status"] == "deleted"


class TestReactions:
    @patch("agent_messenger.rest.urlopen")
    def test_react(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({"action": "added", "emoji": "👍"})
        client = RestClient("http://localhost:8080", "token")
        result = client.react("msg_1", "👍")
        assert result.action == "added"
        assert result.emoji == "👍"

    @patch("agent_messenger.rest.urlopen")
    def test_get_reactions(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response([
            {"emoji": "👍", "user_id": "user_1", "created_at": "2026-01-01T00:00:00Z"},
        ])
        client = RestClient("http://localhost:8080", "token")
        reactions = client.get_reactions("msg_1")
        assert len(reactions) == 1
        assert reactions[0].emoji == "👍"


class TestTags:
    @patch("agent_messenger.rest.urlopen")
    def test_add_and_remove_tags(self, mock_urlopen):
        mock_urlopen.side_effect = [
            _mock_response({"status": "added"}),
            _mock_response({"status": "removed"}),
            _mock_response([{"tag": "important", "created_at": "2026-01-01T00:00:00Z"}]),
        ]
        client = RestClient("http://localhost:8080", "token")
        client.add_tag(TagRequest(conversation_id="conv_1", tag="important"))
        client.remove_tag(TagRequest(conversation_id="conv_1", tag="important"))
        tags = client.get_tags("conv_1")
        assert len(tags) == 1
        assert tags[0].tag == "important"


class TestPresence:
    @patch("agent_messenger.rest.urlopen")
    def test_get_presence(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response([
            {"agent_id": "agent_1", "status": "online", "last_seen": "2026-01-01T00:00:00Z"},
        ])
        client = RestClient("http://localhost:8080", "token")
        presence = client.get_presence()
        assert len(presence) == 1
        assert presence[0].agent_id == "agent_1"


class TestE2E:
    @patch("agent_messenger.rest.urlopen")
    def test_key_bundle(self, mock_urlopen):
        mock_urlopen.side_effect = [
            _mock_response({"status": "ok"}),
            _mock_response({"identity_key": "ik", "signed_prekey": "spk",
                           "prekey_signature": "sig", "one_time_prekey": "otpk"}),
        ]
        client = RestClient("http://localhost:8080", "token")
        client.upload_key_bundle(UploadKeyBundleRequest(
            identity_key="ik", signed_prekey="spk",
            prekey_signature="sig", one_time_prekeys=["otpk1"],
        ))
        bundle = client.get_key_bundle("user_1")
        assert bundle.identity_key == "ik"

    @patch("agent_messenger.rest.urlopen")
    def test_encrypted_messages(self, mock_urlopen):
        mock_urlopen.side_effect = [
            _mock_response({"id": "enc_1"}),
            _mock_response([{"id": "enc_1", "ciphertext": "abc"}]),
        ]
        client = RestClient("http://localhost:8080", "token")
        result = client.store_encrypted_message(StoreEncryptedMessageRequest(
            conversation_id="conv_1", ciphertext="abc",
            sender_device_id="dev_1", message_type=1,
        ))
        assert result["id"] == "enc_1"
        msgs = client.get_encrypted_messages("conv_1")
        assert len(msgs) == 1


class TestPush:
    @patch("agent_messenger.rest.urlopen")
    def test_register_unregister(self, mock_urlopen):
        mock_urlopen.side_effect = [
            _mock_response({"status": "registered"}),
            _mock_response({"status": "unregistered"}),
        ]
        client = RestClient("http://localhost:8080", "token")
        client.register_device_token(RegisterPushRequest(device_token="device-123", platform="android"))
        client.unregister_device_token(UnregisterPushRequest(device_token="device-123"))

    @patch("agent_messenger.rest.urlopen")
    def test_get_vapid_key(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({"public_key": "BPxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"})
        client = RestClient("http://localhost:8080", "token")
        result = client.get_vapid_key()
        assert result.public_key == "BPxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

    @patch("agent_messenger.rest.urlopen")
    def test_web_push_subscribe(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({"status": "subscribed"})
        client = RestClient("http://localhost:8080", "token")
        from agent_messenger.types import WebPushSubscribeRequest
        result = client.web_push_subscribe(WebPushSubscribeRequest(
            endpoint="https://push.example.com/sub/123",
            keys={"p256dh": "key1", "auth": "auth1"},
        ))
        assert result.status == "subscribed"

    @patch("agent_messenger.rest.urlopen")
    def test_web_push_unsubscribe(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({"status": "unsubscribed"})
        client = RestClient("http://localhost:8080", "token")
        from agent_messenger.types import WebPushUnsubscribeRequest
        result = client.web_push_unsubscribe(WebPushUnsubscribeRequest(
            endpoint="https://push.example.com/sub/123",
        ))
        assert result.status == "unsubscribed"


class TestHealth:
    @patch("agent_messenger.rest.urlopen")
    def test_health(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({
            "status": "ok", "uptime": "1h", "version": "0.1.0",
        })
        client = RestClient("http://localhost:8080")
        health = client.health()
        assert health.status == "ok"
        assert health.version == "0.1.0"


class TestRateLimit:
    @patch("agent_messenger.rest.urlopen")
    def test_get_and_set_tier(self, mock_urlopen):
        mock_urlopen.side_effect = [
            _mock_response({"user_id": "user_1", "tier": "pro", "burst": 300, "window_sec": 60, "remaining": 299}),
            _mock_response({"status": "updated", "user_id": "user_1", "tier": "enterprise"}),
        ]
        client = RestClient("http://localhost:8080", "admin-token")
        tier_info = client.get_rate_limit_tier("user_1")
        assert tier_info.tier == "pro"
        result = client.set_rate_limit_tier(SetRateLimitTierRequest(user_id="user_1", tier="enterprise"))
        assert result["tier"] == "enterprise"


class TestErrorHandling:
    @patch("agent_messenger.rest.urlopen")
    def test_api_error(self, mock_urlopen):
        mock_urlopen.side_effect = HTTPError(
            "http://localhost/auth/login", 401, "Unauthorized", {}, None,
        )
        client = RestClient("http://localhost:8080", "bad-token")
        with pytest.raises(ApiError) as exc_info:
            client.list_agents()
        assert exc_info.value.status == 401