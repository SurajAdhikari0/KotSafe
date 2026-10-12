# Deploying on Oracle Cloud (Always Free tier)

Oracle's Always Free tier (an `VM.Standard.A1.Flex` ARM instance, 1–4 OCPUs / 6–24GB RAM,
free forever) is enough to run this whole stack comfortably for personal use.

## 1. Create the instance

1. Oracle Cloud Console → **Compute → Instances → Create Instance**.
2. Image: **Ubuntu 24.04** (or 22.04). Shape: **VM.Standard.A1.Flex** (Always Free eligible) —
   1 OCPU / 6GB RAM is plenty.
3. Add your SSH public key under "Add SSH keys".
4. Create, wait for it to reach **Running**, note the **public IP**.

## 2. Open the firewall (Security List / Network Security Group)

Oracle blocks everything by default at the *cloud* level, separately from the OS firewall.
Under the instance's VCN → **Security Lists** (or NSG), add **Ingress Rules**:

| Port | Protocol | Purpose |
|---|---|---|
| 22 | TCP | SSH (restrict source CIDR to your IP if possible) |
| 80 | TCP | Caddy — Let's Encrypt HTTP challenge |
| 443 | TCP | Caddy — TLS signaling endpoint |
| 3478 | TCP+UDP | coturn STUN/TURN |
| 5349 | TCP+UDP | coturn TURN-over-TLS |
| 49152–65535 | UDP | coturn relay port range |

## 3. OS-level firewall + Docker

SSH in, then:

```bash
sudo apt update && sudo apt install -y docker.io docker-compose-plugin
sudo systemctl enable --now docker

# Ubuntu ships with iptables rules via netfilter-persistent on OCI images that
# also block by default — open the same ports at the OS level:
sudo iptables -I INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 3478 -j ACCEPT
sudo iptables -I INPUT -p udp --dport 3478 -j ACCEPT
sudo iptables -I INPUT -p udp --dport 49152:65535 -j ACCEPT
sudo netfilter-persistent save   # or: sudo iptables-save > /etc/iptables/rules.v4
```

## 4. Clone and configure

```bash
git clone https://github.com/<you>/kotsafe-relay
cd kotsafe-relay
cp .env.example .env
openssl rand -hex 32   # paste into .env as SHARED_SECRET
nano .env               # set DOMAIN to a DNS A record pointing at this VM's public IP
```

Edit `turnserver.conf`:
- `static-auth-secret` → same value as `SHARED_SECRET` (or a separate long random string)
- `realm` / `server-name` → your `DOMAIN`
- `external-ip` → this VM's public IP

## 5. DNS

Point an A record (e.g. `relay.yourdomain.com`) at the instance's public IP. Caddy needs
this to auto-issue a Let's Encrypt certificate — HTTP-01 challenge requires port 80 reachable.

## 6. Start

```bash
docker compose up -d
docker compose logs -f
```

Check `https://relay.yourdomain.com/health` returns `{"ok":true,...}`.

## 7. In the app

Settings → Backend → Self-hosted → Server URL: `wss://relay.yourdomain.com/ws`,
Shared Secret: the `SHARED_SECRET` value from `.env`. Tap "Test connection" before saving.
