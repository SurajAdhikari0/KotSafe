#!/usr/bin/env bash
# ==============================================================================
# KotSafe Relay - Automated 1-Click Installer
# Supports: Standard VPS (Oracle, DigitalOcean, AWS), Cloudflare Tunnel, Docker
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${CYAN}${BOLD}"
echo "=========================================================="
echo "      🚀 KotSafe Relay - Zero Setup Self-Host Wizard    "
echo "=========================================================="
echo -e "${NC}"

if [ "$EUID" -ne 0 ]; then
  echo -e "${YELLOW}[!] Warning: It is recommended to run this script as root or with sudo.${NC}"
fi

# 1. Detect Public IP
DETECTED_IP=$(curl -s -4 https://ifconfig.me 2>/dev/null || curl -s -4 https://api.ipify.org 2>/dev/null || echo "127.0.0.1")
echo -e "${BLUE}[*] Detected Public IP:${NC} ${BOLD}$DETECTED_IP${NC}"

# 2. Check and Install Docker if missing
if ! command -v docker &> /dev/null; then
    echo -e "${YELLOW}[*] Docker not found. Installing Docker automatically...${NC}"
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker || true
fi

# 3. Choose Deployment Mode
echo ""
echo -e "${CYAN}${BOLD}Choose your deployment type:${NC}"
echo "  1) Standard Server / VPS / Oracle Cloud (Direct ports with Caddy SSL & STUN/TURN)"
echo "  2) Cloudflare Tunnel (Zero port forwarding, works behind any NAT/CGNAT/Firewall)"
read -p "Select option [1 or 2, default: 1]: " DEPLOY_MODE

# Generate a strong 32-byte hex shared secret
GENERATED_SECRET=$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | xxd -p | head -n 1)
read -p "Enter Shared Secret [Press ENTER to use auto-generated secure secret]: " USER_SECRET
if [ -z "$USER_SECRET" ]; then
    USER_SECRET="$GENERATED_SECRET"
fi

if [ "$DEPLOY_MODE" == "2" ]; then
    # --------------------------------------------------------------------------
    # Cloudflare Tunnel Mode
    # --------------------------------------------------------------------------
    echo ""
    echo -e "${CYAN}${BOLD}Cloudflare Tunnel Requirements & Setup:${NC}"
    echo -e "  ${YELLOW}Prerequisites:${NC}"
    echo "  1. Free Cloudflare account (dash.cloudflare.com) with a domain added."
    echo "  2. Go to Cloudflare Zero Trust Dashboard -> Networks -> Tunnels -> Create Tunnel"
    echo "  3. Configure Public Hostname: Service Type = HTTP, URL = signaling-server:8081 (or localhost:8081)"
    echo "  4. Copy the Tunnel Token from the install command (starts with eyJh...)"
    echo ""
    read -p "Enter your Cloudflare Tunnel Token: " CF_TOKEN
    read -p "Enter your public domain mapped to the tunnel (e.g., relay.yourdomain.com): " CF_DOMAIN

    echo -e "${BLUE}[*] Writing Cloudflare configuration to .env...${NC}"
    cat <<EOF > .env
PORT=8081
SHARED_SECRET=$USER_SECRET
ALLOW_ANONYMOUS=false
PAIRING_TTL_SECONDS=86400
CLOUDFLARE_TUNNEL_TOKEN=$CF_TOKEN
DOMAIN=${CF_DOMAIN}
EOF

    echo -e "${BLUE}[*] Launching Cloudflare Tunnel & Signaling Docker containers...${NC}"
    docker compose -f docker-compose.tunnel.yml down 2>/dev/null || true
    docker compose -f docker-compose.tunnel.yml up -d --build

    SERVER_FINAL_URL="wss://${CF_DOMAIN}/ws"

else
    # --------------------------------------------------------------------------
    # Standard VPS Mode (Direct / Caddy / Oracle / DigitalOcean)
    # --------------------------------------------------------------------------
    echo ""
    echo -e "${CYAN}${BOLD}Standard Server Configuration:${NC}"
    read -p "Enter your domain or subdomain (e.g., relay.example.com) [leave empty to use Public IP]: " USER_DOMAIN

    echo -e "${BLUE}[*] Writing configuration to .env...${NC}"
    cat <<EOF > .env
PORT=8081
SHARED_SECRET=$USER_SECRET
ALLOW_ANONYMOUS=false
PAIRING_TTL_SECONDS=86400
DOMAIN=${USER_DOMAIN:-$DETECTED_IP}
EOF

    # Configure turnserver.conf
    echo -e "${BLUE}[*] Configuring coturn STUN/TURN server...${NC}"
    REALM_VAL="${USER_DOMAIN:-$DETECTED_IP}"
    sed -i.bak "s/CHANGE_ME_LONG_RANDOM_STRING/$USER_SECRET/g" turnserver.conf 2>/dev/null || true
    sed -i.bak "s/relay.example.com/$REALM_VAL/g" turnserver.conf 2>/dev/null || true
    sed -i.bak "s/YOUR.VM.PUBLIC.IP/$DETECTED_IP/g" turnserver.conf 2>/dev/null || true
    rm -f turnserver.conf.bak

    # Configure OS Firewall (iptables / ufw)
    echo -e "${BLUE}[*] Ensuring firewall ports are opened...${NC}"
    if command -v ufw &> /dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow 80/tcp || true
        ufw allow 443/tcp || true
        ufw allow 3478/tcp || true
        ufw allow 3478/udp || true
        ufw allow 5349/tcp || true
        ufw allow 5349/udp || true
        ufw allow 49152:65535/udp || true
    fi

    if command -v iptables &> /dev/null; then
        iptables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
        iptables -I INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
        iptables -I INPUT -p tcp --dport 3478 -j ACCEPT 2>/dev/null || true
        iptables -I INPUT -p udp --dport 3478 -j ACCEPT 2>/dev/null || true
        iptables -I INPUT -p udp --dport 49152:65535 -j ACCEPT 2>/dev/null || true
    fi

    echo -e "${BLUE}[*] Launching Docker containers...${NC}"
    docker compose down 2>/dev/null || true
    docker compose up -d --build

    if [ -n "$USER_DOMAIN" ]; then
        SERVER_FINAL_URL="wss://${USER_DOMAIN}/ws"
    else
        SERVER_FINAL_URL="ws://${DETECTED_IP}:8081/ws"
    fi
fi

echo ""
echo -e "${GREEN}${BOLD}==========================================================${NC}"
echo -e "${GREEN}${BOLD}  ✅ KotSafe Relay is successfully running!             ${NC}"
echo -e "${GREEN}${BOLD}==========================================================${NC}"
echo ""
echo -e "${BOLD}📱 Enter these values in the KotSafe Android App:${NC}"
echo -e "   1. Open ${CYAN}Settings → P2P Gateway & Exit Node${NC}"
echo -e "   2. Scroll down to ${CYAN}Cloud Backend (optional)${NC} → tap ${CYAN}Set up cloud backend${NC}"
echo -e "   3. Choose ${CYAN}Self-hosted server (Oracle, VPS, etc.)${NC}"
echo ""
echo -e "   • ${BOLD}Server URL:${NC}   ${GREEN}${SERVER_FINAL_URL}${NC}"
echo -e "   • ${BOLD}Shared Secret:${NC}${YELLOW} ${USER_SECRET} ${NC}"
echo ""
echo -e "   4. Tap ${CYAN}Test connection${NC} → ${GREEN}✅ Connected successfully${NC} → Tap ${CYAN}Save${NC}."
echo ""
