================================================================================
                    KotSafe Relay - Quick Setup Guide
================================================================================

This package is the self-hosted signaling + STUN/TURN backend for KotSafe.
It enables two Android phones to discover each other automatically even when:
  • Switching between Wi-Fi and Mobile Cellular Data
  • Behind Carrier-Grade NAT (CGNAT) or Firewalls
  • Operating on Dynamic IPs without manual re-pairing

All user traffic is end-to-end encrypted on the phones with AES-256-GCM.
This relay server ONLY carries tiny connection candidate metadata.

--------------------------------------------------------------------------------
OPTION 1: AUTOMATIC 1-COMMAND SETUP (Linux / VPS / Oracle / DigitalOcean / AWS)
--------------------------------------------------------------------------------

1. Open your server terminal and run:
   chmod +x install.sh && ./install.sh

2. The script will automatically:
   • Detect your public IP
   • Check and install Docker if missing
   • Prompt for a domain (or use IP) and generate a secure Shared Secret
   • Open required firewall ports
   • Start the containers

3. At the end, copy the Server URL and Shared Secret into your KotSafe app!

--------------------------------------------------------------------------------
OPTION 2: DOCKER COMPOSE MANUAL SETUP
--------------------------------------------------------------------------------

1. Copy the environment template:
   cp .env.example .env

2. Generate a secure secret:
   openssl rand -hex 32
   (Paste this into .env as SHARED_SECRET)

3. Set your domain in .env:
   DOMAIN=relay.yourdomain.com
   (Point your domain DNS A record to your VPS Public IP)

4. Configure turnserver.conf:
   • static-auth-secret = (your SHARED_SECRET)
   • realm = (your domain or public IP)
   • external-ip = (your server's public IP)

5. Start the relay:
   docker compose up -d

--------------------------------------------------------------------------------
OPTION 3: CLOUDFLARE TUNNEL (Zero Port Forwarding / Home Server / PC)
--------------------------------------------------------------------------------

1. Create a Cloudflare Tunnel in Cloudflare Zero Trust Dashboard:
   Networks -> Tunnels -> Create Tunnel -> Point to localhost:8081

2. Add your tunnel token to .env:
   CLOUDFLARE_TUNNEL_TOKEN=your_token_here

3. Start with:
   docker compose -f docker-compose.tunnel.yml up -d

--------------------------------------------------------------------------------
OPTION 4: FIREBASE SERVERLESS (No Server Required)
--------------------------------------------------------------------------------

1. Go to console.firebase.google.com -> Create Project -> Enable Firestore.
2. Go to firebase-functions folder:
   cd firebase-functions
   firebase login
   firebase deploy --only firestore:rules,functions
3. Copy Project ID, API Key, App ID from Firebase Console into KotSafe.

--------------------------------------------------------------------------------
HOW TO CONFIGURE THE KOTSAFE ANDROID APP
--------------------------------------------------------------------------------

1. Open KotSafe on both Android devices.
2. Go to: Settings -> P2P Gateway & Exit Node.
3. Scroll down to: "Cloud Backend (optional)".
4. Tap: "Set up cloud backend".
5. Choose your backend type:
   • Self-hosted server (Oracle, VPS, etc.):
       - Server URL:   wss://relay.yourdomain.com/ws  (or ws://IP:8081/ws)
       - Shared Secret: (your configured SHARED_SECRET)
   • Firebase (your own project):
       - Project ID / API Key / App ID (from Firebase Console)
6. Tap "Test connection" (shows "Connected successfully") -> Tap "Save".
7. The status indicator will turn Green!

--------------------------------------------------------------------------------
SUPPORT & TROUBLESHOOTING
--------------------------------------------------------------------------------

• Check server logs:
  docker compose logs -f

• Check health status:
  curl http://localhost:8081/health
  (should return {"ok":true,...})

• Multi-User Setup:
  In .env, you can provide comma-separated keys for multiple users:
  SHARED_SECRET=alice_key,bob_key,charlie_key
  Or set ALLOW_ANONYMOUS=true for open community mode.
================================================================================
