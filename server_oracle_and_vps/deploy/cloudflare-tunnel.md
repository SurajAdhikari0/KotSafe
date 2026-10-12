# Deploying with Cloudflare Tunnel (Zero Port-Forwarding)

Cloudflare Tunnel (`cloudflared`) connects your local signaling server securely to Cloudflare's global edge network **without opening any inbound ports on your router or firewall**, without a public IP, and with free automated SSL/TLS certificates (`wss://`).

---

## 📋 Prerequisites & Requirements

Before using Cloudflare Tunnel, make sure you have:

1. **A Free Cloudflare Account**: Sign up at [dash.cloudflare.com](https://dash.cloudflare.com/).
2. **An Active Domain on Cloudflare**: Any domain (e.g. from Namecheap, Porkbun, Freenom, GoDaddy) with DNS nameservers pointed to Cloudflare.
3. **Cloudflare Zero Trust Access** (100% Free for up to 50 users):
   - In Cloudflare dashboard, click **Zero Trust** on the left sidebar.
   - Complete the one-time free onboarding setup.
4. **WebSocket Support**: Ensure WebSockets are enabled (enabled by default in Cloudflare Dashboard → **Network** → **WebSockets** → **ON**).
5. **A Host Machine**: Any PC, laptop, Raspberry Pi, home server, or VPS with Docker installed.

---

## Method 1: Web UI Setup via Cloudflare Zero Trust (Easiest)

1. Go to the [Cloudflare Zero Trust Dashboard](https://one.dash.cloudflare.com/).
2. Navigate to **Networks** → **Tunnels** → click **Create a Tunnel**.
3. Select **Cloudflare (cloudflared)** and give it a name (e.g., `kotsafe-relay`).
4. Select your operating system (Docker, Debian/Ubuntu, macOS, Windows) and copy the one-line installation command.
5. In the **Public Hostnames** tab:
   - **Subdomain**: `relay`
   - **Domain**: `yourdomain.com` (select your domain)
   - **Service Type**: `HTTP`
   - **URL**: `localhost:8081` (or `signaling-server:8081` if running inside Docker network)
6. Click **Save Tunnel**.

Your signaling server is now instantly reachable worldwide at `wss://relay.yourdomain.com/ws` with HTTPS/WSS!

---

## Method 2: Docker Compose with Cloudflare Tunnel

If you prefer running everything in Docker without installing `cloudflared` directly on your host:

1. Copy your Cloudflare Tunnel Token from the dashboard.
2. Edit `.env` and add:
   ```env
   CLOUDFLARE_TUNNEL_TOKEN=eyJhIjoi...your_token_here...
   ```
3. Run with `docker-compose.tunnel.yml`:
   ```bash
   docker compose -f docker-compose.tunnel.yml up -d
   ```

---

## Method 3: CLI Setup (`cloudflared`)

```bash
# 1. Install cloudflared
curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i cloudflared.deb

# 2. Authenticate
cloudflared tunnel login

# 3. Create tunnel
cloudflared tunnel create kotsafe-signaling

# 4. Route DNS
cloudflared tunnel route dns kotsafe-signaling relay.yourdomain.com

# 5. Run tunnel pointing to local signaling port 8081
cloudflared tunnel run --url http://localhost:8081 kotsafe-signaling
```

---

## In the KotSafe Android App

1. Open **Settings** → **P2P Gateway & Exit Node**.
2. Tap **Set up cloud backend** under **Cloud Backend (optional)**.
3. Choose **Self-hosted server (Oracle, VPS, etc.)**.
4. Enter:
   - **Server URL**: `wss://relay.yourdomain.com/ws`
   - **Shared Secret**: the `SHARED_SECRET` you set in `.env`
5. Tap **Test connection** (`✅ Connected successfully`) → **Save**.
