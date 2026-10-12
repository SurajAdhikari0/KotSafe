# Android integration package

These are tested Java primitives, not a second Android app. Add them only after review to a new `p2p` package in the main project.

Required integration points:

1. Create a dedicated foreground `P2PTunnelService` that owns both the client and exit relay links. An Activity must only observe it; `onPause()` must never close a link.
2. For each client TCP flow, send encrypted `open`, wait for encrypted/verified `ready`, then give its local SOCKS socket a `BufferedTunnelStream`. This preserves the first SOCKS greeting.
3. On the exit, decrypt `open`, validate the destination after DNS resolution, call `VpnService.protect()` on every outbound socket, then send `ready` only after its TCP connection succeeds.
4. Bind a client SOCKS listener to `127.0.0.1` only. Do not offer any unauthenticated `0.0.0.0` listener. Use an explicit Android permission or a non-exported receiver for all P2P controls.
5. The VPN capture path is packet-level: TCP-only SOCKS cannot carry DNS, UDP, or QUIC. Use the app's packet engine or an audited WireGuard/tun2socks component for those protocols.

The primitive test can be run from the upgrade folder with `npm run test:android-primitives`.
