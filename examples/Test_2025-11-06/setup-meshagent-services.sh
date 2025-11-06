#!/bin/bash

# MeshAgent LaunchD Service Setup Script
# Usage: ./setup-meshagent-services.sh /path/to/meshagent

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_error "This script must be run as root (use sudo)"
    exit 1
fi

# Check if meshagent path is provided
if [ -z "$1" ]; then
    print_error "Usage: $0 /path/to/meshagent"
    exit 1
fi

MESHAGENT_PATH="$1"

# Verify the meshagent binary exists
if [ ! -f "$MESHAGENT_PATH" ]; then
    print_error "MeshAgent binary not found at: $MESHAGENT_PATH"
    exit 1
fi

# Make meshagent executable
chmod +x "$MESHAGENT_PATH"

# Extract the directory path
MESHAGENT_DIR=$(dirname "$MESHAGENT_PATH")
print_info "MeshAgent directory: $MESHAGENT_DIR"

# Get the logged-in user (not root)
LOGGED_IN_USER=$(stat -f "%Su" /dev/console)
print_info "Logged-in user: $LOGGED_IN_USER"

# Get the user's UID
USER_UID=$(id -u "$LOGGED_IN_USER")
print_info "User UID: $USER_UID"

# Define plist paths
DAEMON_PLIST="/Library/LaunchDaemons/meshagent.plist"
AGENT_PLIST="/Library/LaunchAgents/meshagent-agent.plist"

# Bootout existing services
print_info "Stopping existing services..."

# Bootout daemon (as root)
if launchctl list | grep -q "meshagent$"; then
    print_info "Booting out meshagent daemon..."
    launchctl bootout system "$DAEMON_PLIST" 2>/dev/null || print_warning "Could not bootout daemon (may not be loaded)"
else
    print_warning "meshagent daemon not currently loaded"
fi

# Bootout agent (as logged-in user)
if sudo -u "$LOGGED_IN_USER" launchctl list | grep -q "meshagent-agent"; then
    print_info "Booting out meshagent-agent as user $LOGGED_IN_USER..."
    sudo -u "$LOGGED_IN_USER" launchctl bootout "gui/$USER_UID" "$AGENT_PLIST" 2>/dev/null || print_warning "Could not bootout agent (may not be loaded)"
else
    print_warning "meshagent-agent not currently loaded"
fi

# Wait a moment for services to fully stop
sleep 2

# Create LaunchDaemon plist
print_info "Creating LaunchDaemon plist at $DAEMON_PLIST..."
cat > "$DAEMON_PLIST" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Disabled</key>
	<false/>
	<key>KeepAlive</key>
	<true/>
	<key>Label</key>
	<string>meshagent</string>
	<key>ProgramArguments</key>
	<array>
		<string>$MESHAGENT_PATH</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>StandardErrorPath</key>
	<string>/tmp/meshagent-daemon.log</string>
	<key>StandardOutPath</key>
	<string>/tmp/meshagent-daemon.log</string>
	<key>WorkingDirectory</key>
	<string>$MESHAGENT_DIR</string>
</dict>
</plist>
EOF

# Set correct permissions for daemon plist
chmod 644 "$DAEMON_PLIST"
chown root:wheel "$DAEMON_PLIST"
print_info "LaunchDaemon plist created"

# Create LaunchAgent plist
print_info "Creating LaunchAgent plist at $AGENT_PLIST..."
cat > "$AGENT_PLIST" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Disabled</key>
	<false/>
	<key>KeepAlive</key>
	<false/>
	<key>Label</key>
	<string>meshagent-agent</string>
	<key>LimitLoadToSessionType</key>
	<array>
		<string>Aqua</string>
		<string>LoginWindow</string>
	</array>
	<key>ProgramArguments</key>
	<array>
		<string>$MESHAGENT_PATH</string>
		<string>-kvm1</string>
	</array>
	<key>QueueDirectories</key>
	<array>
		<string>/var/run/meshagent</string>
	</array>
	<key>StandardErrorPath</key>
	<string>/tmp/meshagent-agent.log</string>
	<key>StandardOutPath</key>
	<string>/tmp/meshagent-agent.log</string>
	<key>WorkingDirectory</key>
	<string>$MESHAGENT_DIR</string>
</dict>
</plist>
EOF

# Set correct permissions for agent plist
chmod 644 "$AGENT_PLIST"
chown root:wheel "$AGENT_PLIST"
print_info "LaunchAgent plist created"

# Create /var/run/meshagent directory if it doesn't exist
if [ ! -d "/var/run/meshagent" ]; then
    mkdir -p /var/run/meshagent
    chmod 755 /var/run/meshagent
    print_info "Created /var/run/meshagent directory"
fi

# Bootstrap daemon (as root)
print_info "Bootstrapping meshagent daemon..."
if launchctl bootstrap system "$DAEMON_PLIST"; then
    print_info "✓ Daemon bootstrapped successfully"
else
    print_error "Failed to bootstrap daemon"
    exit 1
fi

# Bootstrap agent (as logged-in user)
print_info "Bootstrapping meshagent-agent as user $LOGGED_IN_USER..."
if sudo -u "$LOGGED_IN_USER" launchctl bootstrap "gui/$USER_UID" "$AGENT_PLIST"; then
    print_info "✓ Agent bootstrapped successfully"
else
    print_error "Failed to bootstrap agent"
    exit 1
fi

# Wait a moment for services to start
sleep 2

# Verify services are running
print_info "Verifying services..."
echo ""

if launchctl list | grep -q "meshagent$"; then
    print_info "✓ meshagent daemon is running"
else
    print_warning "✗ meshagent daemon is NOT running"
fi

if sudo -u "$LOGGED_IN_USER" launchctl list | grep -q "meshagent-agent"; then
    print_info "✓ meshagent-agent is running"
else
    print_warning "✗ meshagent-agent is NOT running"
fi

echo ""
print_info "Setup complete!"
print_info "Log files:"
print_info "  Daemon: /tmp/meshagent-daemon.log"
print_info "  Agent:  /tmp/meshagent-agent.log"