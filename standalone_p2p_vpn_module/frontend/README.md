# Frontend (Android client and exit)

`android/` contains dependency-free Java primitives that can be moved into the Android app. `reference-client/` is a Node endpoint used only for integration testing; it proves the same framing and encryption flow against the relay.

The Android integration must be owned by foreground services, not a settings Activity. The client VPN service captures selected/all app traffic, passes it to a packet engine, and sends it through this tunnel. The exit opens outbound sockets only after calling `VpnService.protect()` on each socket, so its own VPN never captures and loops its egress traffic.

Do not expose a LAN SOCKS listener. The only client listener should bind loopback, and all tunnel session data must be encrypted before it reaches the relay.
