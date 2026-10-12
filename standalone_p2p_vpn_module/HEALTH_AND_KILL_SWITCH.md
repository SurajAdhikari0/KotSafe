# Tunnel health, exit-IP verification, and kill switch

The new update now has the service-side state model in `GatewayHealthMonitor`, a status formatter, and a `GatewayVpnRoutingPolicy` decision. These are intentionally independent of the old settings Activity: they belong in the client foreground tunnel service.

## Required live flow

1. After a direct or relay tunnel completes its authenticated handshake, call `onTunnelConnected(DIRECT|RELAY, now)`.
2. Generate `nonce = beginEgressCheck(now)` and send an encrypted `egress_check` control message to the exit.
3. The exit opens a fixed HTTPS egress-check endpoint using an outbound socket protected with `VpnService.protect()`. The endpoint returns the source IP it sees. The exit returns `{nonce, observedExitIp}` through the encrypted tunnel.
4. Client checks it with `onEgressCheckResult`. Only an exact outstanding nonce and an IP literal make the state `VERIFIED`.
5. Send authenticated encrypted heartbeats at least every 10 seconds. Call `onHeartbeat` for each valid reply and `tick(now)` at least every 5 seconds.
6. Count encrypted payload bytes with `onTunnelBytes(toExit, fromExit)`.
7. At the VPN/TUN routing boundary, call `GatewayVpnRoutingPolicy.decide(true, health)`. `BLOCK` must drop protected packets; `TUNNEL` sends them only to the active encrypted gateway.

The status output is intentionally specific:

- `Direct connected; verifying exit IP`
- `Relay connected; verifying exit IP`
- `Direct/Relay connected • Exit IP verified: ... • bytes sent/received`
- `Blocked • Exit heartbeat timed out`

## What the verification proves

It proves that a fresh encrypted request reached the exit device and that an HTTPS server saw the exit’s public source IP. It does not magically inspect every packet. “All selected traffic” is enforced by the VPN packet-routing policy: when Personal Gateway is enabled, it may use only `TUNNEL` or `BLOCK`, never normal client Internet egress.

Use an egress endpoint under your control or a vetted HTTPS service with certificate validation. It must return the source IP of the exit’s TCP connection and echo the nonce exactly. Do not accept an IP value from an unencrypted UI, broadcast, QR code, or normal relay control message.

## Exit firewall policy

Client-side firewall rules run before client traffic enters the tunnel. Exit-side firewall rules must run in the exit gateway service before it opens any outbound destination; the exit phone’s regular VPN rules do not automatically cover remote tunnel flows. If the exit phone also has KotSafe VPN enabled, call `VpnService.protect()` on the exit’s outbound socket first, then evaluate the same firewall policy inside the gateway service so that protection does not create a routing loop.
