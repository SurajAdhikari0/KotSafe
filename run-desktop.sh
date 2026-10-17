#!/usr/bin/env bash
# ==============================================================================
# KotSafe Desktop Application Launcher
# Starts the background Vite server (if not already running) and opens KotSafe
# as a standalone, frameless desktop cybersecurity workstation.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB_DIR="${SCRIPT_DIR}/web"
PORT=3000
URL="http://localhost:${PORT}/?desktop"
USER_DATA_DIR="${HOME}/.config/kotsafe-desktop"

echo "🛡️  KotSafe Security Suite — Desktop Launcher"
echo "--------------------------------------------------"

# 1. Check if Vite dev server is running on PORT
if ! curl -s -I "http://localhost:${PORT}" >/dev/null 2>&1; then
    echo "⚡ Starting KotSafe Web Server in background..."
    cd "${WEB_DIR}"
    nohup npm run dev -- --host 127.0.0.1 --port "${PORT}" > /tmp/kotsafe-desktop-vite.log 2>&1 &
    
    # Wait for server to become responsive
    MAX_WAIT=10
    COUNT=0
    while ! curl -s -I "http://localhost:${PORT}" >/dev/null 2>&1; do
        sleep 0.5
        COUNT=$((COUNT + 1))
        if [ "$COUNT" -gt $((MAX_WAIT * 2)) ]; then
            echo "❌ Failed to start KotSafe server on port ${PORT} within ${MAX_WAIT} seconds."
            exit 1
        fi
    done
    echo "✅ KotSafe server online on port ${PORT}."
else
    echo "✅ KotSafe server is already active on port ${PORT}."
fi

# 2. Launch the desktop application window
mkdir -p "${USER_DATA_DIR}"

if command -v chromium >/dev/null 2>&1; then
    echo "🚀 Launching KotSafe Desktop Workstation via Chromium App Mode..."
    chromium --user-data-dir="${USER_DATA_DIR}" \
             --app="${URL}" \
             --window-size=1280,850 \
             --class=KotSafeDesktop \
             --ozone-platform-hint=auto \
             "$@" >/dev/null 2>&1 & disown
elif command -v google-chrome >/dev/null 2>&1; then
    echo "🚀 Launching KotSafe Desktop Workstation via Chrome App Mode..."
    google-chrome --user-data-dir="${USER_DATA_DIR}" \
                  --app="${URL}" \
                  --window-size=1280,850 \
                  --class=KotSafeDesktop \
                  "$@" >/dev/null 2>&1 & disown
else
    echo "🚀 Launching KotSafe Desktop in default browser..."
    xdg-open "${URL}" >/dev/null 2>&1 & disown
fi

echo "✨ KotSafe Desktop App is now running at ${URL}"
