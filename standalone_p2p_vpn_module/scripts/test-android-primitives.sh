#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
OUT_DIR="$(mktemp -d)"
trap 'rm -rf "$OUT_DIR"' EXIT

javac -d "$OUT_DIR" \
  "$ROOT_DIR/frontend/android/src/main/java/com/kotsafe/p2p/TunnelCipher.java" \
  "$ROOT_DIR/frontend/android/src/main/java/com/kotsafe/p2p/BufferedTunnelStream.java" \
  "$ROOT_DIR/frontend/android/src/main/java/com/kotsafe/p2p/TransportSelectionPolicy.java" \
  "$ROOT_DIR/frontend/android/src/main/java/com/kotsafe/p2p/GatewayPreferenceKeys.java" \
  "$ROOT_DIR/frontend/android/src/main/java/com/kotsafe/p2p/SecurePairingBundle.java" \
  "$ROOT_DIR/frontend/android/src/main/java/com/kotsafe/p2p/GatewaySessionController.java" \
  "$ROOT_DIR/frontend/android/src/main/java/com/kotsafe/p2p/ExitExposurePolicy.java" \
  "$ROOT_DIR/frontend/android/src/main/java/com/kotsafe/p2p/GatewayHealthMonitor.java" \
  "$ROOT_DIR/frontend/android/src/main/java/com/kotsafe/p2p/GatewayStatusFormatter.java" \
  "$ROOT_DIR/frontend/android/src/main/java/com/kotsafe/p2p/GatewayVpnRoutingPolicy.java" \
  "$ROOT_DIR/frontend/android/src/test/java/com/kotsafe/p2p/TunnelPrimitivesTest.java"
java -cp "$OUT_DIR" com.kotsafe.p2p.TunnelPrimitivesTest
