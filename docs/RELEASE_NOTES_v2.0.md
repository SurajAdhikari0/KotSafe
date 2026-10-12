# Release Notes — KotSafe v2.0 Enterprise

**Version:** 2.0 (Build fullPowerRelease)  
**Distribution Target:** GitHub Releases / F-Droid / Direct APK / Google Play  

---

### 🚀 Highlights & Major Upgrades

#### 1. KotEngine NextGen C11 Architecture (Enabled by Default)
* Clean-room C11 core engine featuring zero-copy memory ring buffers and asynchronous rule lookup.
* **JA4 TLS Client Fingerprinting:** Identifies malicious encrypted C2 communication, cobalt strike beacons, and spoofed user agents even through full TLS 1.3 encryption.
* **Shannon Entropy Engine:** Computes character and byte randomness across DNS queries to immediately flag and drop high-entropy DNS tunneling exfiltration payloads and DGA (Domain Generation Algorithm) malware domains.

#### 2. Instant VPN Startup (<300ms)
* Background asynchronous threat worker thread reloads 1,116,000+ domain and IP rules without stalling the Android main thread or delaying virtual interface activation.
* Reduced startup latency from >5.0 seconds to **0.27 seconds**.

#### 3. Zero-Lag High-Frequency Connections Monitor
* SQLite database writes and log pruning moved to a dedicated single-threaded asynchronous queue (`DnsDbWriter`).
* $O(1)$ UID index in `AppNetworkRulesManager` eliminates SharedPreferences disk I/O while scrolling through active network connections.

#### 4. Hardened Security & Anti-Adversarial Posture
* **PBKDF2 with 120,000 Iterations + SHA-256 Salt:** Exceeds NIST SP 800-132 standards with constant-time verification (`MessageDigest.isEqual`) to eliminate timing side-channel attacks.
* **Proximity Sensor & Siren Alarm:** Physical anti-theft and pocket pickpocketing prevention with emergency `DevicePolicyManager.lockNow()`.
* **Zero Cleartext Network Policy:** `cleartextTrafficPermitted="false"` enforced globally; all outbound control channels strictly encrypted via TLS/HTTPS.
* **Curated System Allowlist:** 99+ critical banking, government, and communication applications protected from false positives.

---

### 📦 Checksums & Verification
Run `sha256sum KotSafe-fullPower-release.apk` to verify binary authenticity:
* **Package Name:** `com.kotsafe.security`
* **Target SDK:** 34 (Android 14) / Min SDK: 21 (Android 5.0+)
