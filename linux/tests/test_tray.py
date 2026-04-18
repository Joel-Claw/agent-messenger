"""
Tests for system tray module.
"""
import unittest
from unittest.mock import MagicMock, patch
from src.tray import SystemTray


class TestSystemTray(unittest.TestCase):
    """Test system tray background mode."""

    def setUp(self):
        self.mock_app = MagicMock()
        self.mock_window = MagicMock()
        self.tray = SystemTray(self.mock_app, self.mock_window)

    def test_setup_holds_app(self):
        """Setup should call app.hold() to keep app alive."""
        self.tray.setup()
        self.mock_app.hold.assert_called_once()

    def test_setup_intercepts_close(self):
        """Setup should connect to window close-request."""
        self.tray.setup()
        self.mock_window.connect.assert_called_with('close-request', self.tray._on_close_request)

    def test_close_request_hides_window(self):
        """Closing window should hide it, not quit."""
        result = self.tray._on_close_request(self.mock_window)
        self.mock_window.set_visible.assert_called_once_with(False)
        self.assertTrue(result)  # True prevents default close

    def test_show_window(self):
        """show_window should make window visible and present."""
        self.tray.show_window()
        self.mock_window.set_visible.assert_called_once_with(True)
        self.mock_window.present.assert_called_once()

    def test_toggle_window_show(self):
        """toggle_window should show when hidden."""
        self.mock_window.is_visible.return_value = False
        self.tray.toggle_window()
        self.mock_window.set_visible.assert_called_with(True)

    def test_toggle_window_hide(self):
        """toggle_window should hide when visible."""
        self.mock_window.is_visible.return_value = True
        self.tray.toggle_window()
        self.mock_window.set_visible.assert_called_with(False)

    def test_quit_app(self):
        """quit_app should release hold and quit."""
        self.tray.quit_app()
        self.mock_app.release.assert_called_once()
        self.mock_app.quit.assert_called_once()

    def test_set_status_tooltip(self):
        """set_status_tooltip should not raise (placeholder)."""
        self.tray.set_status_tooltip("Test")

    def test_set_status_connected(self):
        """set_status_connected should not raise."""
        self.tray.set_status_connected(True)
        self.tray.set_status_connected(False)


if __name__ == '__main__':
    unittest.main()