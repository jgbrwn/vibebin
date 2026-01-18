#!/bin/bash
#
# shelley-lxc upgrade script
# Upgrades an existing shelley-lxc installation to the latest version
#
# Usage: ./upgrade.sh [branch]
#   branch: optional git branch to checkout (default: main)
#

set -e

BRANCH="${1:-main}"
REPO_URL="https://github.com/jgbrwn/shelley-lxc.git"
INSTALL_DIR="/usr/local/bin"
TEMP_DIR="/tmp/shelley-lxc-upgrade-$$"

echo "════════════════════════════════════════════════════════════════════"
echo "  shelley-lxc Upgrade Script"
echo "════════════════════════════════════════════════════════════════════"
echo ""
echo "  Branch: $BRANCH"
echo ""

# Check if running as root or with sudo available
if [ "$EUID" -ne 0 ]; then
    if ! command -v sudo &> /dev/null; then
        echo "❌ Error: This script requires root privileges or sudo"
        exit 1
    fi
    SUDO="sudo"
else
    SUDO=""
fi

# Check for required tools
for cmd in git go; do
    if ! command -v $cmd &> /dev/null; then
        echo "❌ Error: $cmd is required but not installed"
        exit 1
    fi
done

echo "📦 Step 1: Stopping incus-sync daemon..."
$SUDO systemctl stop incus-sync 2>/dev/null || echo "  (incus-sync was not running)"

echo ""
echo "📥 Step 2: Cloning repository..."
rm -rf "$TEMP_DIR"
git clone --branch "$BRANCH" "$REPO_URL" "$TEMP_DIR"
cd "$TEMP_DIR"

echo ""
echo "🔨 Step 3: Building binaries..."
go build -o incus_manager incus_manager.go
go build -o incus_sync_daemon incus_sync_daemon.go

echo ""
echo "📋 Step 4: Installing binaries to $INSTALL_DIR..."
$SUDO cp incus_manager incus_sync_daemon "$INSTALL_DIR/"

echo ""
echo "🚀 Step 5: Starting incus-sync daemon..."
$SUDO systemctl start incus-sync

echo ""
echo "🧹 Step 6: Cleaning up..."
cd /
rm -rf "$TEMP_DIR"

echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "  ✅ Upgrade complete!"
echo ""
echo "  Installed versions:"
echo "    incus_manager:    $INSTALL_DIR/incus_manager"
echo "    incus_sync_daemon: $INSTALL_DIR/incus_sync_daemon"
echo ""
echo "  To verify: sudo incus_manager"
echo "════════════════════════════════════════════════════════════════════"
