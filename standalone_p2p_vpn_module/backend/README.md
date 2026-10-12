# Backend control plane

This is deliberately small: it creates a one-time pairing, returns a short-lived token for the exit, and exchanges the QR pairing secret for a short-lived client token. The packet relay receives those signed tokens but cannot decrypt a tunnel payload.

It is a reference implementation, not a multi-node production database. Before scale-out, replace `MemoryPairStore` with a transactional encrypted store and rate-limit the two pairing endpoints. Keep the API bound to `127.0.0.1` and publish it only through HTTPS with a real hostname. Never put `RELAY_SIGNING_KEY` or `CONTROL_API_TOKEN` in an Android APK.
