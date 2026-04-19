#!/bin/bash
# Install Agent Messenger Linux client as a desktop application.
#
# This script:
# 1. Installs Python dependencies
# 2. Copies the .desktop file to ~/.local/share/applications/
# 3. Installs the metainfo.xml
# 4. Creates a wrapper script in ~/.local/bin/
# 5. Sets up an application icon
#
# Usage: ./install.sh [--uninstall]

set -e

APP_ID="com.joelclaw.agentmessenger"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_NAME="Agent Messenger"
BIN_NAME="agent-messenger"

# Directories
DESKTOP_DIR="${HOME}/.local/share/applications"
METAINFO_DIR="${HOME}/.local/share/metainfo"
ICON_DIR="${HOME}/.local/share/icons/hicolor"
BIN_DIR="${HOME}/.local/bin"
APP_SRC_DIR="${SCRIPT_DIR}/src"

uninstall() {
    echo "Uninstalling ${APP_NAME}..."
    rm -f "${DESKTOP_DIR}/${APP_ID}.desktop"
    rm -f "${METAINFO_DIR}/${APP_ID}.metainfo.xml"
    rm -f "${BIN_DIR}/${BIN_NAME}"
    rm -f "${ICON_DIR}/scalable/apps/${APP_ID}.svg"
    rm -f "${ICON_DIR}/48x48/apps/${APP_ID}.png"
    rm -f "${ICON_DIR}/256x256/apps/${APP_ID}.png"
    echo "Uninstalled. You may also want to remove config: rm -rf ~/.config/agent-messenger"
    update-desktop-database "${DESKTOP_DIR}" 2>/dev/null || true
    exit 0
}

if [ "$1" = "--uninstall" ]; then
    uninstall
fi

echo "Installing ${APP_NAME}..."

# 1. Install Python dependencies
echo "Installing Python dependencies..."
pip3 install --user -q PyGObject websocket-client requests 2>/dev/null || {
    echo "Note: PyGObject requires system packages. On Debian/Ubuntu:"
    echo "  sudo apt install python3-gi python3-gi-cairo gir1.2-gtk-4.0 gir1.2-adw-1"
}

# 2. Create wrapper script
mkdir -p "${BIN_DIR}"
cat > "${BIN_DIR}/${BIN_NAME}" << 'WRAPPER'
#!/bin/bash
# Agent Messenger desktop client wrapper
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Find the source directory (could be installed differently)
if [ -d "/opt/agent-messenger/src" ]; then
    SRC_DIR="/opt/agent-messenger/src"
elif [ -d "${HOME}/agent-messenger/linux/src" ]; then
    SRC_DIR="${HOME}/agent-messenger/linux/src"
else
    SRC_DIR="${SCRIPT_DIR}/src"
fi

export PYTHONPATH="${SRC_DIR}/..:${PYTHONPATH}"
exec python3 -m src.main "$@"
WRAPPER
chmod +x "${BIN_DIR}/${BIN_NAME}"

# 3. Update .desktop file with correct Exec path
mkdir -p "${DESKTOP_DIR}"
sed "s|Exec=agent-messenger|Exec=${BIN_DIR}/${BIN_NAME}|" \
    "${SCRIPT_DIR}/data/${APP_ID}.desktop" > "${DESKTOP_DIR}/${APP_ID}.desktop"
chmod +x "${DESKTOP_DIR}/${APP_ID}.desktop"

# 4. Install metainfo
mkdir -p "${METAINFO_DIR}"
cp "${SCRIPT_DIR}/data/${APP_ID}.metainfo.xml" "${METAINFO_DIR}/${APP_ID}.metainfo.xml"

# 5. Create a simple SVG icon (if no icon exists)
mkdir -p "${ICON_DIR}/scalable/apps"
if [ ! -f "${ICON_DIR}/scalable/apps/${APP_ID}.svg" ]; then
    cat > "${ICON_DIR}/scalable/apps/${APP_ID}.svg" << 'SVG'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#3584e4"/>
      <stop offset="100%" style="stop-color:#1a5fb4"/>
    </linearGradient>
  </defs>
  <rect width="128" height="128" rx="24" fill="url(#bg)"/>
  <path d="M32 44 h64 a8 8 0 0 1 8 8 v28 a8 8 0 0 1 -8 8 h-20 l-12 12 v-12 h-32 a8 8 0 0 1 -8 -8 v-28 a8 8 0 0 1 8 -8z" fill="#ffffff" opacity="0.9"/>
  <circle cx="50" cy="62" r="5" fill="#3584e4"/>
  <circle cx="68" cy="62" r="5" fill="#3584e4"/>
  <circle cx="86" cy="62" r="5" fill="#3584e4"/>
</svg>
SVG
fi

# 6. Update desktop database
update-desktop-database "${DESKTOP_DIR}" 2>/dev/null || true

# 7. Update icon cache
gtk-update-icon-cache -f "${ICON_DIR}/../.." 2>/dev/null || true

echo ""
echo "✅ ${APP_NAME} installed successfully!"
echo ""
echo "You can now:"
echo "  - Find 'Agent Messenger' in your application menu"
echo "  - Run '${BIN_NAME}' from the command line"
echo "  - Configuration stored in: ~/.config/agent-messenger/"
echo ""
echo "To uninstall, run: $0 --uninstall"