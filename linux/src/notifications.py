"""
Desktop notification support for Agent Messenger.

Uses GTK4 notification API (works on X11 and Wayland).
"""

import gi
gi.require_version('Gtk', '4.0')

from gi.repository import Gtk, GLib


class NotificationManager:
    """Manages desktop notifications for incoming messages."""

    def __init__(self, app):
        """
        Initialize notification manager.

        Args:
            app: The Gtk.Application instance
        """
        self.app = app
        self._notification_id = 0

    def send_message_notification(self, agent_name, content, conversation_id=None):
        """
        Send a desktop notification for an incoming message.

        Args:
            agent_name: Name of the agent that sent the message
            content: Message content (truncated for notification)
            content_preview: Short preview of the message
            conversation_id: Optional conversation ID for click handling
        """
        # Truncate content for notification
        preview = content[:100] + ('...' if len(content) > 100 else '')

        notification = Gio.Notification.new(f'Message from {agent_name}')
        notification.set_body(preview)
        notification.set_priority(Gio.NotificationPriority.HIGH)

        # Add an icon (use application icon if available)
        # notification.set_icon(...)

        self.app.send_notification('agent-messenger-message', notification)

    def send_status_notification(self, agent_name, status):
        """Send a notification when agent status changes."""
        if status == 'online':
            notification = Gio.Notification.new(f'{agent_name} is online')
            notification.set_body(f'{agent_name} is now available for conversation')
            notification.set_priority(Gio.NotificationPriority.LOW)
            self.app.send_notification(f'agent-status-{agent_name}', notification)


# Need Gio for notifications
from gi.repository import Gio