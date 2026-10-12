# Personal Gateway and P2P Exit Node upgrade

This design is based on the current KotSafe implementation, reviewed read-only. It is a replacement plan for the current combined `P2PExitNodeSettings` screen, not an edit to that screen.

## What the existing screen does

The current screen can enable a device as a gateway, show a QR code with address/port/token, scan an endpoint, probe direct TCP candidates, and fall back to a local SOCKS loopback over the cloud relay. It also exposes advanced controls for a public host port, UPnP, manual IP/port/token, and traffic inspection keys.

That is too much responsibility for one settings page and has unsafe failure modes: a raw server can bind to `0.0.0.0`, a manual endpoint can accidentally be trusted, the first stream data can race the host-side connect, and closing the settings screen can close the backend client link.

## Replacement screen

Use [personal_gateway_preferences.xml](frontend/android/res/xml/personal_gateway_preferences.xml) and its strings. It contains only:

1. **Enable this device as an exit** — starts a foreground exit service.
2. **Show pairing QR code** — QR contains version, room, high-entropy pairing secret, and HTTPS control URL; it never contains a host IP, a SOCKS port, or a shared server secret.
3. **Route through paired exit** — starts a foreground client service after QR pairing.
4. **Connection method** — Automatic, Direct only, or Relay only.
5. **Kill switch** — block protected traffic when no tunnel is active.
6. **Disconnect** — stop client/exit services, close streams, erase current pairing material.

Remove manual public port, UPnP, raw endpoint, raw token, and “allow decryption” settings from the user-facing Personal Gateway screen. An exit necessarily processes traffic to reach the Internet, but it must not expose an optional inspection/recording feature as though it adds tunnel security.

## Code supplied here

- `GatewaySessionController` is the lifecycle state machine. It chooses direct first only in Automatic mode, uses the relay only when permitted, discards stale connection callbacks, and never silently falls back to the client's ordinary Internet route.
- `TransportSelectionPolicy` implements the three user choices.
- `SecurePairingBundle` validates versioned HTTPS-only QR pairing data.
- `ExitExposurePolicy` rejects non-loopback compatibility listeners and unauthenticated routes.
- `BufferedTunnelStream` retains the initial SOCKS/TCP bytes until the exit confirms its outbound connection.
- `TunnelCipher` gives the relay opaque AES-GCM endpoint data. Pairing is produced by the server control plane; the Android client must not invent a room or hold the server control secret.

## Integration map to KotSafe

- `fragments/prefs/P2PExitNodeSettings.java`: Load the new Personal Gateway preference XML. Bind it to a foreground service state, not directly to a socket or backend subscription.
- `model/P2PExitNodeService.java`: Split responsibilities into persistent client and exit foreground services. Keep the network callback/republish behaviour, but do not remove all keepalive callbacks on one network change.
- `model/P2PExitNodeServer.java`: Do not expose a raw `0.0.0.0` SOCKS service. Direct peers speak an authenticated encrypted UDP tunnel. A legacy SOCKS adapter, if needed, binds only `127.0.0.1`.
- `model/backend/CustomHttpProvider.java`: Retain it only as encrypted relay fallback after adding a ready acknowledgement and configured exit port. Use an audited WireGuard-compatible UDP engine for direct/all-app packet transport.
- `CaptureService.java`: Continue protecting tunnel and exit sockets with `VpnService.protect()`. Apply kill-switch policy before giving selected app traffic any non-tunnel route.
- Exported `ActionReceiver` P2P actions: Remove them or make them non-exported/signature-protected. Never apply raw address, token, key, or backend URL values from a broadcast.

The actual main project remains unchanged. Direct P2P will work only after an Android WireGuard-compatible UDP transport plus STUN/ICE candidate gathering is added to those services. The supplied server already offers authenticated candidate signalling and encrypted relay fallback.
