# Oracle/VPS blind relay

The relay accepts TLS 1.3 on TCP port 9443. It authenticates short-lived signed session tokens, keeps one exit and its paired clients per room, and forwards opaque encrypted envelopes. It has no code path that opens an Internet destination, so it cannot become an open proxy.

For an Oracle/VPS deployment, allow TCP 443 or 9443 in the cloud security list and host firewall, mount a real certificate and private key read-only, and set a unique `RELAY_SIGNING_KEY` from a secret manager. Do not use the included test certificate method in production. Use a DNS name whose certificate is valid on Android.

`start.js` intentionally refuses plaintext TCP and certificates supplied through environment variables. That prevents an accidental non-TLS deployment.

For direct P2P NAT traversal, deploy the optional Coturn service using `docker compose -f docker-compose.yml -f server/docker-compose.turn.yml up -d`. Coturn supplies STUN on UDP 3478 and authenticated TURN fallback. Its long-lived `TURN_SHARED_SECRET` must exactly match the control backend value; phones request only short-lived derived credentials from `/v1/turn-credentials`. See the root [README](../README.md) for SSH deployment.
