# Chapter 9: Troubleshooting, Performance Tuning & Backup

[⬅️ Chapter 8: Alerts Center & Remediation](08_ALERTS_CENTER_AND_REMEDIATION.md) | [🏠 Table of Contents](README.md)

---

This chapter covers troubleshooting strategies, OEM battery management tuning, storage retention controls, configuration backup/restore procedures, and solutions to common Android networking edge cases.

---

## 1. Battery Optimization & Background Persistence

Because KotSafe operates a continuous local network proxy, aggressive OEM background task killers may terminate the monitoring service during extended device sleep.

### OEM-Specific Battery Settings

| OEM Manufacturer | System Skin | Required Configuration Steps |
| :--- | :--- | :--- |
| **Samsung** | One UI | **Settings** $\rightarrow$ **Apps** $\rightarrow$ **KotSafe** $\rightarrow$ **Battery** $\rightarrow$ Select **Unrestricted**.<br>Also ensure KotSafe is NOT listed in **Sleeping apps** or **Deep sleeping apps**. |
| **Xiaomi / Poco / Redmi** | MIUI / HyperOS | **Settings** $\rightarrow$ **Apps** $\rightarrow$ **Manage Apps** $\rightarrow$ **KotSafe**:<br>1. Enable **Autostart**.<br>2. Set **Battery saver** to **No restrictions**.<br>3. In the Recent Apps carousel, long-press KotSafe and tap the **Padlock icon**. |
| **OnePlus / Oppo / Realme** | OxygenOS / ColorOS | **Settings** $\rightarrow$ **Battery** $\rightarrow$ **More Settings** $\rightarrow$ **App battery management** $\rightarrow$ **KotSafe** $\rightarrow$ Enable **Allow background activity** & **Allow auto-launch**. |
| **Google Pixel / Motorola** | Stock Android | **Settings** $\rightarrow$ **Apps** $\rightarrow$ **KotSafe** $\rightarrow$ **App battery usage** $\rightarrow$ Select **Unrestricted**. |

### Enterprise / ADB Automation
To exempt KotSafe from battery optimization via command line:
```bash
adb shell dumpsys deviceidle whitelist +com.kotsafe.security
```

---

## 2. Storage & Retention Management (`StorageManagementActivity.java`)

Continuous network packet logging and payload inspection can accumulate gigabytes of storage over time. KotSafe incorporates an automated retention engine:

```
┌──────────────────────────────────────────────────────────────┐
│  Storage & Retention Management                              │
├──────────────────────────────────────────────────────────────┤
│  Total KotSafe Storage Footprint: 214 MB                     │
│  • PCAP Captures:        142 MB   [Clear PCAPs]              │
│  • Connection Logs:       48 MB   [Prune Logs]               │
│  • Threat Intelligence:   24 MB   [Flush Cache]              │
├──────────────────────────────────────────────────────────────┤
│  Automatic Retention Policies:                               │
│  Maximum PCAP Buffer Size:       [ 500 MB ▼ ]                │
│  Connection Log Retention:       [ 14 Days ▼ ]               │
│  Automatic Circular Overwrite:   [ Enabled  ]                │
└──────────────────────────────────────────────────────────────┘
```

### Best Practices:
* **Circular Buffer**: When capturing live traffic for extended periods, set the **Maximum Buffer Size** to `250 MB` or `500 MB`. Once reached, KotSafe automatically drops the oldest frames (FIFO).
* **Payload Pruning**: If you do not require raw TCP payloads for Wireshark inspection, toggle **Headers Only Capture** in **Settings $\rightarrow$ PCAP Capture**. This reduces storage consumption by over 90%.

---

## 3. Configuration Backup & Disaster Recovery (`SettingsBackupHandler.java`)

KotSafe allows you to export your entire security configuration to a single encrypted JSON file. This includes:
* Custom Per-App Network Access Control (NAC) rules
* Custom Blacklists, Whitelists, and CIDR subnet blocks
* Threat Intelligence API keys and rate-limit settings
* TLS Decryption app lists and custom port mappings
* Screen-Off exemption lists

### How to Backup Settings:
1. Open **KotSafe** $\rightarrow$ Open drawer $\rightarrow$ **Settings** $\rightarrow$ **Backup & Restore**.
2. Tap **Export Settings**.
3. Android opens the system file picker. Choose your preferred destination (e.g., `/Documents` or Google Drive) and save `kotsafe_backup_<date>.json`.

### How to Restore Settings:
1. On your new or wiped device, install KotSafe.
2. Navigate to **Settings** $\rightarrow$ **Backup & Restore** $\rightarrow$ Tap **Import Settings**.
3. Select your saved backup JSON file.
4. KotSafe validates the schema, applies your rules, and displays a confirmation dialog. All firewall rules and API keys are immediately restored!

---

## 4. Android VPN Coexistence & Limitations

A fundamental architectural constraint of Android OS is that **only one application can hold the active `VpnService` interface at any given time**.

```
┌─────────────────────────────────────────────────────────────┐
│                    THE SINGLE-VPN LIMITATION                │
├─────────────────────────────────────────────────────────────┤
│  If you activate a commercial VPN (e.g., Mullvad, Express,  │
│  Proton, WireGuard), Android automatically terminates       │
│  KotSafe's local VPN interface.                             │
└─────────────────────────────────────────────────────────────┘
```

### Recommended Workarounds:

#### Solution A: Upstream DNS-over-HTTPS (DoH)
If your primary goal with a commercial VPN is encrypted DNS or tracker blocking:
* In KotSafe, go to **Settings** $\rightarrow$ **DNS & Protocols** $\rightarrow$ Set **DNS Mode** to **DNS-over-HTTPS (DoH)**.
* Select **Cloudflare (`1.1.1.1`)**, **Quad9 (`9.9.9.9`)**, or **AdGuard DNS**.
* KotSafe will encrypt all outgoing DNS queries, preventing ISP snooping while maintaining full local firewall and antivirus defense.

#### Solution B: SOCKS5 Upstream Proxy
If you need to mask your external IP address through a proxy or Tor:
* In KotSafe, go to **Settings** $\rightarrow$ **Upstream Proxy**.
* Enter your SOCKS5 proxy details (e.g., Orbot / Tor on `127.0.0.1:9050` or an SSH dynamic tunnel).
* KotSafe will inspect packets locally on `tun0` and forward all allowed traffic through your upstream proxy.

---

## 5. Frequently Asked Questions & Diagnostics

### Q1: Wi-Fi shows "Connected, no internet" after starting KotSafe.
* **Cause**: KotSafe was configured with an unreachable DNS server, or the local upstream gateway dropped DNS packets.
* **Resolution**: Go to **Settings** $\rightarrow$ **DNS Settings** $\rightarrow$ Toggle **Use System Default DNS** or select **Cloudflare (1.1.1.1)**.

### Q2: A banking app refuses to open or crashes.
* **Cause**: Some high-security banking applications check for active VPN connections or detect user CA certificates.
* **Resolution**:
  1. Go to **Settings** $\rightarrow$ **VPN Exemptions**.
  2. Add the banking app to the **Exemptions List**.
  3. KotSafe will bypass the app from the VPN interface entirely.

### Q3: TLS Decryption shows SSL Handshake errors in Chrome.
* **Cause**: The KotSafe root CA certificate is not installed in the Android Credential Store.
* **Resolution**: Follow the step-by-step installation instructions in [Chapter 5](05_TLS_DECRYPTION_AND_INSPECTION.md#2-decryption-setup-wizard--ca-certificate-installation).

---

[⬅️ Chapter 8: Alerts Center & Remediation](08_ALERTS_CENTER_AND_REMEDIATION.md) | [🏠 Table of Contents](README.md)
