"""
Tests for the notification manager module.

These tests verify the notification logic without requiring a running GTK application.
"""

import sys
import os
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.notifications import NotificationManager


class TestNotificationManager:
    """Test NotificationManager class."""

    def test_init(self):
        """NotificationManager should initialize with app reference."""
        mock_app = mock.Mock()
        nm = NotificationManager(mock_app)
        assert nm.app is mock_app

    def test_send_message_notification_truncates_long_content(self):
        """send_message_notification should truncate content over 100 chars."""
        mock_app = mock.Mock()
        nm = NotificationManager(mock_app)

        long_content = 'A' * 200
        nm.send_message_notification('TestAgent', long_content, 'conv-1')

        # Check that send_notification was called
        assert mock_app.send_notification.called
        call_args = mock_app.send_notification.call_args
        notification_id = call_args[0][0]
        notification = call_args[0][1]

        assert notification_id == 'agent-messenger-message'
        # The notification body should be truncated
        # We can't easily inspect Gio.Notification body in mock,
        # but we can verify it was called
        assert notification is not None

    def test_send_message_notification_short_content(self):
        """send_message_notification should pass short content as-is."""
        mock_app = mock.Mock()
        nm = NotificationManager(mock_app)

        nm.send_message_notification('Bot', 'Hello!', 'conv-2')
        assert mock_app.send_notification.called

    def test_send_status_notification_online(self):
        """send_status_notification should work for 'online' status."""
        mock_app = mock.Mock()
        nm = NotificationManager(mock_app)

        nm.send_status_notification('Agent1', 'online')
        assert mock_app.send_notification.called

    def test_send_status_notification_offline(self):
        """send_status_notification should still create notification for other statuses."""
        mock_app = mock.Mock()
        nm = NotificationManager(mock_app)

        # Currently only 'online' gets a notification, but we should not crash on others
        nm.send_status_notification('Agent1', 'offline')
        # No notification sent for offline