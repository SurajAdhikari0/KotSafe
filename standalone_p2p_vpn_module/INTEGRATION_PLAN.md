# Main-app integration plan (do not apply automatically)

This upgrade folder is intentionally separate. Nothing here has edited `/home/kali/Documents/KotSafe`.

## Phase 1 — close the exposed control path

1. Remove the public P2P action handling from the exported `ActionReceiver`, or make that receiver non-exported and move P2P controls behind a signature permission.
2. Delete hard-coded relay endpoints and shared secrets from Android resources/source. Provision device credentials after installation and store them in Android Keystore-backed storage.
3. Stop binding a raw exit SOCKS service to all interfaces. The only compatibility SOCKS listener should bind loopback and require an authenticated local caller.

## Phase 2 — install the new tunnel lifecycle

1. Add `TunnelCipher` and `BufferedTunnelStream` from `frontend/android/` to a new P2P package.
2. Create an Android foreground `P2PTunnelService` to own both client and exit relay connections. The settings Activity must bind/observe only; it must not unsubscribe in `onPause()`.
3. Replace the current `pipe_open` behaviour with this state machine:

```text
client sends encrypted open → exit connects and protects its socket → exit sends ready
      ↓                                                         ↓
client buffers first bytes until ready ← relay also holds bounded early bytes
```

4. Use the configured destination/port from the encrypted open request; do not retain a `127.0.0.1:8090` constant in relay mode.

## Phase 3 — connect it to VPN traffic

1. Feed the Android `VpnService` TUN packets to an audited packet engine or a maintained WireGuard-compatible component.
2. Use this P2P encrypted relay as the protected transport between the two devices.
3. On every exit outbound socket, call `VpnService.protect()` before `connect()` to prevent routing that socket back into the exit VPN.
4. Decide and implement UDP/DNS/QUIC support. A TCP SOCKS bridge alone cannot claim all-app VPN forwarding.

## Phase 3A — direct P2P with safe fallback

1. Present three choices: **Automatic** (direct first, relay fallback), **Direct only**, and **Relay only**. Use `TransportSelectionPolicy`; never silently override a Direct-only choice.
2. Gather authenticated STUN/ICE candidates over UDP and publish them through `/v1/candidates` using the device's short-lived relay session token.
3. Establish a WireGuard-compatible encrypted UDP tunnel over the winning direct candidate pair. Oracle is only a signalling server in this case.
4. If direct connection fails, Automatic may use the existing encrypted relay; Direct-only must block protected traffic and clearly show the reason. Relay-only skips the direct attempt.

## Phase 4 — release gate

Run tests on two physical phones over Wi-Fi and cellular, including backgrounding both apps, switching network during traffic, restarting the exit, blocked exit, expired token, first-packet race, IPv4/IPv6 DNS, UDP/QUIC, and kill-switch/no-fallback behavior. Conduct a new Android build and security review only after those changes are integrated.
