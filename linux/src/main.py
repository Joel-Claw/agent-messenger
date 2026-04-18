"""
Agent Messenger Linux Desktop Client

GTK4-based client supporting both X11 and Wayland.
"""

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')

from gi.repository import Gtk, Adw, Gio, GLib

import json
import os
import sys
import threading
from pathlib import Path

from src.window import MainWindow
from src.client import AgentMessengerClient
from src.config import Config
from src.notifications import NotificationManager
from src.tray import SystemTray


class AgentMessengerApp(Adw.Application):
    """Main application class."""

    def __init__(self):
        super().__init__(
            application_id='com.joelclaw.agentmessenger',
            flags=Gio.ApplicationFlags.FLAGS_NONE,
        )
        self.client = None
        self.config = Config.load()
        self.window = None
        self.notifications = None
        self.tray = None

        # Add app actions
        self._add_actions()

    def _add_actions(self):
        """Add GActions for app menu."""
        show_action = Gio.SimpleAction.new('show', None)
        show_action.connect('activate', lambda *_: self._show_window())
        self.add_action(show_action)

        quit_action = Gio.SimpleAction.new('quit', None)
        quit_action.connect('activate', lambda *_: self._quit_app())
        self.add_action(quit_action)

    def _show_window(self):
        if self.window:
            self.window.set_visible(True)
            self.window.present()

    def _quit_app(self):
        if self.tray:
            self.tray.quit_app()
        else:
            self.quit()

    def do_activate(self):
        """Called when the application is activated."""
        if not self.window:
            self.window = MainWindow(application=self, config=self.config)
            self.client = AgentMessengerClient(self.config, self.window)
            self.notifications = NotificationManager(self)
            self.tray = SystemTray(self, self.window)
            self.tray.setup()
            self.window.set_client(self.client)
            self.window.set_notifications(self.notifications)

        self.window.present()

    def do_shutdown(self):
        """Clean up on shutdown."""
        if self.client:
            self.client.disconnect()
        super().do_shutdown()


def main():
    """Entry point."""
    app = AgentMessengerApp()
    return app.run(sys.argv[1:])


if __name__ == '__main__':
    sys.exit(main())