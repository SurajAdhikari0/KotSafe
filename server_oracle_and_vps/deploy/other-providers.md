# Deploying anywhere else (DigitalOcean, Hetzner, AWS Lightsail, Fly.io, Railway, Render, a Raspberry Pi...)

The signaling-server + coturn stack in this repo is plain Docker Compose with no
Oracle-specific dependencies — the only Oracle-specific parts of `deploy/oracle-cloud.md`
are the **console click-path** and the **security list / NSG firewall rules**. Anywhere
that gives you a public IP (or a domain) and lets you run Docker works identically:

## Checklist that applies everywhere

1. A host with a public IPv4 (or IPv6) address, or a domain pointed at one.
2. Docker + Docker Compose installed.
3. Firewall open on: `80/tcp`, `443/tcp` (Caddy/TLS), `3478/tcp+udp`, `5349/tcp+udp`
   (coturn STUN/TURN), `49152–65535/udp` (coturn relay range).
4. `git clone` this repo, `cp .env.example .env`, fill in `SHARED_SECRET` and `DOMAIN`,
   fill in the matching fields in `turnserver.conf`, `docker compose up -d`.

## Provider-specific notes

**DigitalOcean / Hetzner / Linode / Vultr** — firewall is a single "Cloud Firewall"
panel per droplet/server; add the ports above as inbound rules. No separate OS-level
iptables step needed unless you've enabled `ufw` yourself (`sudo ufw allow <port>`).

**AWS Lightsail** — open ports under the instance's **Networking** tab (equivalent to a
security group). EC2 proper uses a full VPC Security Group with the same rule set.

**Fly.io / Railway / Render** — these platforms terminate TLS and route HTTP(S)/WS for
you automatically (skip the `caddy` service and `DOMAIN` var entirely; use the platform's
generated `https://...` URL directly as the app's Server URL). **Important limitation:**
most of these platforms don't expose arbitrary UDP port ranges, so **coturn will not work**
on them — you'll get signaling (candidate publish/subscribe) but no TURN relay fallback.
Fine if you only need direct/STUN paths; deploy coturn separately on a VPS if you need the
relay fallback too.

**A spare Raspberry Pi / home server** — works, but you're now responsible for your own
router port-forwarding and dynamic DNS (e.g. DuckDNS) instead of a cloud provider's static
IP — use the same UpnpPortMapper-style auto port-forwarding pattern already in the app if
you want this to stay zero-touch.

## Registering "any other platform" as a valid backend in the app

The app doesn't special-case providers by name — `CustomHttpProvider` only needs a
`wss://` URL and a shared secret that speaks the 5-operation contract in the top-level
README. As long as your deployment answers `GET /health`, `POST /pairing`, the `/ws`
publish/subscribe messages, and `DELETE /pairing/:token` the same way this repo's
`signaling-server/index.js` does, the app treats it identically to an Oracle-hosted one —
there's nothing else to register or configure on the app side beyond the wizard's URL +
secret fields.
