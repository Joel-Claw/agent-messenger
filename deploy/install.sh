#!/bin/bash
# Install Agent Messenger as a systemd service
# Usage: sudo ./install.sh

set -euo pipefail

INSTALL_DIR="/opt/agent-messenger"
DATA_DIR="/var/lib/agent-messenger"
ENV_FILE="/etc/agent-messenger/env"
SERVICE_FILE="/etc/systemd/system/agent-messenger.service"

# Build the server
echo "Building Agent Messenger server..."
cd "$(dirname "$0")/../server"
go build -ldflags="-s -w" -o agent-messenger .

# Create user if it doesn't exist
if ! id -u agent-messenger &>/dev/null; then
    echo "Creating agent-messenger user..."
    useradd --system --no-create-home --shell /usr/sbin/nologin agent-messenger
fi

# Create directories
echo "Installing to ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}" "${DATA_DIR}"
cp agent-messenger "${INSTALL_DIR}/"
chmod +x "${INSTALL_DIR}/agent-messenger"

# Set up environment file
if [ ! -f "${ENV_FILE}" ]; then
    echo "Creating environment file at ${ENV_FILE}..."
    mkdir -p "$(dirname "${ENV_FILE}")"
    cp "$(dirname "$0")/env.example" "${ENV_FILE}"
    echo ""
    echo "⚠️  Edit ${ENV_FILE} to set your JWT_SECRET before starting the service!"
    echo ""
fi

# Install systemd service
echo "Installing systemd service..."
cp "$(dirname "$0")/agent-messenger.service" "${SERVICE_FILE}"
systemctl daemon-reload
systemctl enable agent-messenger

# Set ownership
chown -R agent-messenger:agent-messenger "${DATA_DIR}"
chown root:agent-messenger "${ENV_FILE}"
chmod 640 "${ENV_FILE}"

echo ""
echo "✅ Agent Messenger installed."
echo ""
echo "Next steps:"
echo "  1. Edit ${ENV_FILE} and set JWT_SECRET"
echo "  2. Start the service: systemctl start agent-messenger"
echo "  3. Check status: systemctl status agent-messenger"
echo "  4. View logs: journalctl -u agent-messenger -f"