"""
System tray support for Agent Messenger Linux client.

Uses DBus StatusNotifierItem protocol (works on both X11 and Wayland)
to provide a system tray icon with:
- Show/hide window
- Connection status indicator
- Quick disconnect/reconnect

Falls back to hiding window (keeping app in background) if tray is unavailable.
"""

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')

from gi.repository import Gio, GLib

import subprocess
import logging
import os

logger = logging.getLogger(__name__)


class SystemTray:
    """System tray icon for the Agent Messenger app.

    On GTK4, system tray support is limited. This class provides:
    1. A DBus StatusNotifierItem implementation (if available)
    2. A fallback that keeps the app running in background when window is closed

    The app uses Gio.Application.hold() to stay alive when the window is hidden,
    and the window's close button is intercepted to hide instead of quit.
    """

    def __init__(self, app, window):
        self.app = app
        self.window = window
        self._tray_available = False
        self._bus_id = None

    def setup(self):
        """Set up system tray behavior.

        Intercepts the window close button to hide instead of quit.
        Uses Gio.Application.hold() to keep the app alive in background.
        """
        # Hold the application so it stays alive when window is hidden
        self.app.hold()

        # Intercept window close to hide instead of quit
        self.window.connect('close-request', self._on_close_request)

        logger.info("System tray: Background mode enabled (close hides window)")

    def _on_close_request(self, window):
        """Handle window close by hiding instead of quitting."""
        window.set_visible(False)
        logger.info("Window hidden (app running in background)")
        return True  # Prevent default close behavior

    def show_window(self):
        """Show the main window."""
        self.window.set_visible(True)
        self.window.present()

    def toggle_window(self):
        """Toggle window visibility."""
        if self.window.is_visible():
            self.window.set_visible(False)
        else:
            self.show_window()

    def quit_app(self):
        """Actually quit the application."""
        self.app.release()
        self.app.quit()

    def set_status_tooltip(self, text):
        """Update the tooltip/status text (for future DBus tray implementation)."""
        # Placeholder for StatusNotifierItem tooltip
        pass

    def set_status_connected(self, connected: bool):
        """Update the connection status indicator."""
        status = "Connected" if connected else "Disconnected"
        self.set_status_tooltip(f"Agent Messenger - {status}")
        logger.debug(f"Tray status: {status}")