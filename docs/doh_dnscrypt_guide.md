# Complete Guide: Using DNS-over-HTTPS (DoH) & DNSCrypt with KotSafe

This guide explains how to secure your mobile device's domain name resolution against ISP eavesdropping, rogue Wi-Fi snooping, DNS poisoning, and censorship using **DNS-over-HTTPS (DoH / RFC 8484)** and **DNSCrypt** in **KotSafe**.

---

## 📑 Table of Contents
1. [The Critical Need for Encrypted DNS](#1-the-critical-need-for-encrypted-dns)
2. [DoH vs DNSCrypt: Architectural Comparison](#2-doh-vs-dnscrypt-architectural-comparison)
3. [KotSafe Built-In DoH Engine & Preset Benchmark](#3-kotsafe-built-in-doh-engine--preset-benchmark)
4. [Step-by-Step: Enabling DoH in KotSafe](#4-step-by-step-enabling-doh-in-kotsafe)
5. [Using DNSCrypt with KotSafe (dnscrypt-proxy)](#5-using-dnscrypt-with-kotsafe-dnscrypt-proxy)
6. [Preventing Private DNS & System Fallback Leaks](#6-preventing-private-dns--system-fallback-leaks)
7. [Verifying Encrypted DNS Operation](#7-verifying-encrypted-dns-operation)
8. [Frequently Asked Questions (FAQ)](#8-frequently-asked-questions-faq)

---

## 1. The Critical Need for Encrypted DNS

Traditional DNS transmits all query requests (e.g., `lookup: mybank.com`) in **unencrypted plaintext** over UDP or TCP port 53. This introduces severe security vulnerabilities:

```
[ Your Phone ] ── Plaintext UDP 53 ──> [ ISP / Public Wi-Fi Hotspot ] ──> [ Authoritative DNS ]
                       ▲
                       │ Vulnerable to:
                       ├─ ISP Traffic Profiling & Metadata Harvesting
                       ├─ Rogue Wi-Fi MITM Spoofing & Phishing Redirection
                       ├─ State/Carrier DNS Censorship & Filtering
                       └─ Cache Poisoning & Kaminsky Attacks
```

* **Surveillance**: Anyone on the local network (coffee shop, airport, university) or upstream ISP can see every website, service, and API your device contacts, even if the subsequent HTTP connection uses HTTPS.
* **Tampering**: Malicious actors can spoof DNS responses to point you to phishing clones of banking, email, or social media login pages.

By using **DNS-over-HTTPS (DoH)** or **DNSCrypt**, queries are cryptographically encrypted before leaving your phone, preventing any intermediary from viewing or forging domain lookups.

---

## 2. DoH vs DNSCrypt: Architectural Comparison

| Security Dimension | Plaintext DNS (Default) | DNS-over-HTTPS (DoH - RFC 8484) | DNSCrypt (v2) |
| :--- | :---: | :---: | :---: |
| **Transport Port** | Port 53 (UDP/TCP) | Port 443 (HTTPS over TCP/HTTP/2/HTTP/3) | Custom / Port 443 (UDP/TCP) |
| **Encryption Standard**| None (Cleartext) | TLS 1.3 / ChaCha20 / AES-GCM | Elliptic Curve (Curve25519) + XSalsa20-Poly1305 |
| **ISP / Firewall Camouflage** | ❌ Blockable instantly | ✅ Looks identical to regular HTTPS traffic | ⚠️ Detectable signature on non-HTTPS ports |
| **Authentication** | None (unless DNSSEC) | X.509 PKI Certificates + DNSSEC | DNSCrypt Public Key Certificate + DNSSEC |
| **KotSafe Integration** | Native | **Built-in Native Engine** | Supported via Local Listener / Gateway Proxy |

---

## 3. KotSafe Built-In DoH Engine & Preset Benchmark

KotSafe features a **zero-configuration high-speed DNS engine** with an interactive **DNS Speed Benchmark** and hardened preset resolvers.

### Built-In Trusted Resolvers

| Provider | Primary IPv4 | Primary IPv6 | DoH Endpoint URL | Features / Threat Filtering |
| :--- | :--- | :--- | :--- | :--- |
| **Cloudflare** | `1.1.1.1` | `2606:4700:4700::1111` | `https://cloudflare-dns.com/dns-query` | Ultra-low latency, strict zero-logging |
| **Quad9 Security**| `9.9.9.9` | `2620:fe::fe` | `https://dns.quad9.net/dns-query` | Blocks malware, ransomware & phishing domains |
| **AdGuard DNS** | `94.140.14.14` | `2a10:50c0::ad1:ff` | `https://dns.adguard-dns.com/dns-query` | Blocks ads, telemetry, trackers & malicious sites |
| **Google Public** | `8.8.8.8` | `2001:4860:4860::8888` | `https://dns.google/dns-query` | Worldwide anycast redundancy, DNSSEC validated |
| **Mullvad Privacy**| `194.242.2.2`| `2a07:e340::2` | `https://dns.mullvad.net/dns-query` | Non-logging privacy, tracker blocking |

---

## 4. Step-by-Step: Enabling DoH in KotSafe

### Method A: One-Tap Preset & Live Speed Test (Recommended)

1. Launch **KotSafe** on your Android device.
2. Tap the **Settings** tab (or gear icon in the toolbar).
3. Under **Capture Engine & Interfaces**, tap **DNS servers**.
4. Tap **DNS Preset Picker & Benchmark**.
5. Tap **Run Speed Test**: KotSafe measures the exact round-trip ping time (latency in milliseconds) to each global resolver from your current network connection.
6. Select your preferred provider (e.g., **Cloudflare** for pure speed or **Quad9** for threat intelligence blocking).
7. Tap **Apply**: KotSafe instantly applies both IPv4 and IPv6 addresses and secures traffic through the chosen resolver!

### Method B: Native DoH (RFC 8484) Direct Encryption

1. Open **Settings** ➔ **Capture Engine & Interfaces** ➔ **DNS servers**.
2. Scroll to the **Encrypted DNS (RFC 8484 DoH)** section.
3. Toggle **Enable DNS-over-HTTPS (DoH)** to **ON**.
4. In **DoH Provider**, choose your desired service (`Cloudflare`, `Quad9`, `AdGuard`, or `Google`).
5. Return to the **Status** tab and tap **Start** (or restart the capture session). All DNS requests are now tunneled over encrypted TLS on port 443!

---

## 5. Using DNSCrypt with KotSafe (dnscrypt-proxy)

DNSCrypt provides cryptographic authentication and encryption using elliptic curve cryptography (`X25519-XSalsa20Poly1305`) and DNS stamps (`sdns://`).

Because DNSCrypt utilizes custom client-side key exchanges, it can be run via **`dnscrypt-proxy`** running locally on Android, a home Raspberry Pi/router, or a cloud server.

### Architecture with KotSafe

```
[ Android Apps ] ──> [ KotSafe Local TUN Engine ]
                            │
                            ├─ (Standard IP Traffic ──> Wi-Fi / LTE)
                            │
                            └─ (DNS Queries on Port 53)
                                      │
                                      ▼
                        [ dnscrypt-proxy listener ] (127.0.0.1:5353)
                                      │  (Encrypted DNSCrypt Channel)
                                      ▼
                        [ DNSCrypt Public Resolver ] (Port 443)
```

### Setup Steps:

1. **Deploy dnscrypt-proxy**:
   - Run `dnscrypt-proxy` on your local network (e.g., on `192.168.1.1` or `192.168.1.100`), or on-device via Termux/Magisk with a listener on `127.0.0.1:5353`.
   - In `dnscrypt-proxy.toml`, configure your chosen servers and set `listen_addresses = ['127.0.0.1:5353']`.
2. **Direct KotSafe to your DNSCrypt Listener**:
   - In KotSafe, go to **Settings** ➔ **DNS servers**.
   - Turn OFF **Use System DNS**.
   - In **IPv4 DNS Server**, enter the IP of your DNSCrypt listener (e.g., `192.168.1.1` or your loopback address).
3. **Start Capture**:
   - KotSafe routes all Android DNS queries to the DNSCrypt listener, which encrypts them and forwards them via DNSCrypt stamps to the upstream server.

---

## 6. Preventing Private DNS & System Fallback Leaks

Android 9+ includes a system feature called **Private DNS (DNS-over-TLS / DoT)**. If misconfigured, Android may attempt to bypass VPN DNS settings or leak queries to your cellular carrier.

### Best Configuration for Absolute Leak Prevention:

1. **Android System Settings**:
   - Go to Android **Settings** ➔ **Network & internet** ➔ **Private DNS**.
   - If using KotSafe's native DoH or custom DNS, set Private DNS to **Off** (or set it to your matching provider hostname, e.g., `one.one.one.one` or `dns.quad9.net`).
   - *Why?* If set to "Automatic", Android might fall back to unencrypted cellular DNS when switching networks.
2. **KotSafe DNS Settings**:
   - In KotSafe **Settings** ➔ **DNS servers**, make sure **Use System DNS** is **Disabled** whenever you want KotSafe to enforce encrypted custom resolvers.
   - KotSafe ensures all DNS requests arriving at the virtual TUN interface (`10.215.173.1`) are directed to your chosen secure resolver.

---

## 7. Verifying Encrypted DNS Operation

You can verify that DoH / DNSCrypt is active and leak-free:

### Step 1: In-App Verification via KotSafe DNS Tracker
1. In KotSafe, switch to the **Connections** or **DNS** tab.
2. Open your mobile browser and visit a few websites.
3. Look at the DNS log entries:
   - Destination address will show your configured secure DNS server.
   - For DoH, queries appear under **HTTPS / Port 443** rather than cleartext UDP Port 53.

### Step 2: Third-Party Forensic Tests
Navigate to any of the following independent leak-testing tools in your browser:
* **Cloudflare Help**: [1.1.1.1/help](https://1.1.1.1/help) — Should confirm `Using DNS over HTTPS (DoH): Yes`.
* **BrowserLeaks DNS Leak Test**: [browserleaks.com/dns](https://browserleaks.com/dns) — Verify only your chosen secure DNS servers appear, with 0 ISP leaks.
* **DNSLeakTest**: [dnsleaktest.com](https://www.dnsleaktest.com) — Run the Standard or Extended test.

---

## 8. Frequently Asked Questions (FAQ)

### Q: Does using DoH or DNSCrypt slow down my browsing?
**A:** No. In many cases, DoH with Cloudflare (`1.1.1.1`) or Google (`8.8.8.8`) is significantly faster than default mobile carrier DNS servers due to global Anycast routing and aggressive edge caching. Use KotSafe's built-in **DNS Speed Test** to find the lowest-latency resolver for your location.

### Q: Does KotSafe require Root to use DoH?
**A:** No root required! KotSafe uses Android's standard `VpnService` interface to intercept outbound DNS requests on loopback `10.215.173.1` and encrypts them locally before sending.

### Q: Can DoH block advertisements and trackers?
**A:** Yes! When you select **AdGuard DNS** or **Quad9** in KotSafe's DNS settings, queries for known advertising and tracker domains are blocked at the DNS resolver level.
