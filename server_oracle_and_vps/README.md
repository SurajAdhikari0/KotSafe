# 🚀 kotsafe-relay

> **Self-hosted live signaling & STUN/TURN relay for KotSafe**  
> Enables seamless universal P2P proxying across any network topology (Wi-Fi ↔ Cellular, Carrier-Grade NAT, Dynamic IPs) with zero port-forwarding and end-to-end encryption.

---

## 🔒 Privacy & Zero-Trust Architecture

- **End-to-End Encrypted Data**: Application traffic and SOCKS5 proxy payloads are encrypted with AES-256-GCM directly between the two paired Android phones.
- **Metadata-Only Signaling**: This server **never sees, decrypts, or logs** user traffic. It only facilitates transient `{host, port, type}` network candidate exchange so phones can discover each other.
- **Zero Account Requirement**: No email, username, or login credentials needed.

---

## ⚡ 1-Command Automated Quick Start

On any Linux VPS (Oracle Cloud Always Free, DigitalOcean, Hetzner, AWS, Linode, Raspberry Pi):

```bash
curl -fsSL https://raw.githubusercontent.com/<your-username>/kotsafe-relay/main/install.sh | sudo bash
```

The interactive wizard will:
1. Detect your public IP automatically.
2. Configure Docker, ports, and certificates.
3. Output the exact **Server URL** and **Shared Secret** to enter in your phone.

---

## 🛠️ Manual Deployment Options

| Deployment Method | Platform | Cost | Best For | Guide |
|---|---|---|---|---|
| **Oracle Cloud Free Tier** | Oracle Cloud VM | **Free Forever** | 24/7 dedicated high-performance relay + STUN/TURN | [Oracle Guide](deploy/oracle-cloud.md) |
| **Cloudflare Tunnel** | Any PC / Home Server / VPS | **Free** | Zero port forwarding, automatic HTTPS/WSS (`wss://`) | [Cloudflare Guide](deploy/cloudflare-tunnel.md) |
| **Firebase Serverless** | Google Firebase | **Free Tier** | 100% serverless, zero VM management | [Firebase Guide](deploy/firebase.md) |
| **Docker Compose** | DigitalOcean / Hetzner / AWS | Low / Free | Standard containerized VPS deployment | [VPS Guide](deploy/other-providers.md) |
| **Railway / Fly.io / Render** | PaaS Cloud | Free / Low | Instant 1-click git push deployment | [PaaS Guide](deploy/other-providers.md) |

---

## 📱 How to Connect in KotSafe Android App

Once your relay is running:

1. Open **KotSafe** on both devices.
2. Go to **Settings** → **P2P Gateway & Exit Node**.
3. Scroll to the bottom section: **Cloud Backend (optional)**.
4. Tap **Set up cloud backend**.
5. Choose your backend type:
   - **Self-hosted server (Oracle, VPS, etc.)**:
     - **Server URL**: `wss://yourdomain.com/ws` (or `ws://YOUR_SERVER_IP:8081/ws`)
     - **Shared Secret**: Your configured secret key
   - **Firebase (your own project)**:
     - **Project ID**: Your Firebase project ID
     - **API Key**: Web API Key from Firebase Console
     - **App ID**: Mobile App ID from Firebase Console
6. Tap **Test connection** (`✅ Connected successfully`) → Tap **Save**.

The status indicator in the app will turn **Green (Connected)** and your exit node will automatically re-announce new IPs whenever switching between Wi-Fi and mobile data!

---

## 📂 Repository Structure

```
kotsafe-relay/
├── install.sh                  # 1-Click interactive setup wizard
├── docker-compose.yml           # Signaling server + coturn + Caddy TLS
├── docker-compose.tunnel.yml    # Cloudflare Tunnel zero-port-forwarding compose
├── turnserver.conf             # High-performance coturn STUN/TURN template
├── signaling-server/           # Node.js WebSocket + REST signaling microservice
│   ├── index.js
│   ├── package.json
│   └── Dockerfile
├── deploy/                     # Step-by-step deployment guides
│   ├── oracle-cloud.md         # Oracle Cloud Always Free complete tutorial
│   ├── cloudflare-tunnel.md    # Cloudflare Zero Trust tunnel tutorial
│   ├── firebase.md             # Firebase Firestore & Cloud Functions setup
│   └── other-providers.md      # DigitalOcean, AWS, Fly.io, Railway, Hetzner
├── firebase-functions/         # Serverless Firebase alternative
│   ├── firestore.rules
│   ├── firebase.json
│   └── functions/index.js
├── railway.json                # 1-Click Railway deployment config
├── fly.toml                    # 1-Click Fly.io deployment config
└── Caddyfile                   # Automatic Let's Encrypt TLS reverse proxy
```

---

## 📜 Wire Contract & Protocol

The signaling server exposes a lightweight, authenticated REST and WebSocket protocol:

```
POST   /pairing                  -> { token: string, expiresAt: number }
GET    /health                   -> { ok: true, version: "1.0.0", pairings: number }
DELETE /pairing/:token           -> { revoked: boolean }

WS     /ws
  -> { type: "publish",   token: string, candidates: [...] }
  -> { type: "subscribe", token: string }
  <- { type: "candidates", token: string, candidates: [...] }
  <- { type: "error",      message: string }
```

---

## 📄 License

GPL-3.0 License — KotSafe Cyber Security Project.
