# KotSafe: Master System Design & Project Architecture Repository

![KotSafe Full Project Architecture](images/full_project_architecture.jpg)

Welcome to the unified **`design`** folder for **KotSafe**.

This directory serves as the master repository for the entire project's multi-tier system architecture, frontend UI/UX design specifications, color tokens, and authentic Android device screenshots.

---

## 📑 Core Documentation Index

1. [**`PROJECT_ARCHITECTURE.md`**](PROJECT_ARCHITECTURE.md) – **Complete End-to-End System Architecture Specification**:
   * Multi-tier architectural blueprint spanning Linux kernel interception, native C/C++ engine, background daemons, Dalvik malware analysis, threat intelligence, and user workbenches.
   * `zdtun` user-space TCP/IP stack & `nDPI` deep packet inspection engine.
   * 5-way Network Access Control (NAC) evaluation hierarchy.
   * `DexStructuralParser` and Shannon string entropy mathematics ($H = -\sum p \log_2 p$).
   * Cloud Threat Intelligence APIs (VirusTotal, AlienVault OTX, MalwareBazaar) with SQLite `TiCacheDb`.
   * End-to-end packet processing sequence diagrams and data flow mechanics.

2. [**`FRONTEND_ARCHITECTURE.md`**](FRONTEND_ARCHITECTURE.md) – **Frontend Architecture & Reactive Streaming Pipeline**:
   * Android Activity & Fragment lifecycle and ViewPager2 navigation.
   * High-throughput `ConnectionsAdapter` utilizing `DiffUtil` payload updates (10,000+ packets/sec without UI stutter).
   * Visual components: Speedometers, 360° laser sweep radar (`laser_sweep.xml`), HTTP Repeater, and native/browser interception.
   * Navigation Drawer routing matrix and Jetpack Preferences hierarchy.

3. [**`DESIGN_SPECIFICATION.md`**](DESIGN_SPECIFICATION.md) – **Visual Identity & UI Design System**:
   * Material Design 3 design tokens and dark cyberpunk palette (`#0D1117`, `#00E5FF`, `#00E676`, `#FF1744`, `#FFC107`, `#0D47A1`).
   * Monospaced tabular typography (`Roboto Mono`) for jitter-free telemetry.
   * Custom inspector dialogs (DNS-over-HTTPS wire format, JWT token decoder, Protobuf payload inspector).

4. [**`redesign/index.html`**](redesign/index.html) – **KotSafe Fresh Classic Home Redesign**:
   * Interactive multi-theme mobile UI showcase with device frame preview.
   * **Tactical Guardian (Dark)**: High-contrast defense dashboard (`#070D1A`, `#3DDC84` emerald accents, `#0E1729` card surface).
   * **Fresh Classic (Light)**: Warm editorial defense aesthetic (`#F6F3EC`, `#0E9F83` classic pine/teal, `#DDD6C6` soft cards).
   * States included: Idle, Running (VPN Active), and Traffic/Telemetry switch.
   * Master bundle: [**`KotSafe – Fresh Classic Redesign.html`**](KotSafe%20%E2%80%93%20Fresh%20Classic%20Redesign.html).

---

## 📸 Complete Visual Asset Inventory ([`images/`](images/))

### 1. Architectural Blueprint Graphics
* [**`images/full_project_architecture.jpg`**](images/full_project_architecture.jpg) – **Master 6-tier end-to-end project architecture diagram**.
* [`images/frontend_architecture.jpg`](images/frontend_architecture.jpg) – Multi-tier frontend presentation, state, and native IPC diagram.
* [`images/hero_banner.jpg`](images/hero_banner.jpg) – Cyber defense hero graphic with KotSafe shield.
* [`images/firewall_nac.jpg`](images/firewall_nac.jpg) – 5-way Network Access Control architecture diagram.
* [`images/threat_intel.jpg`](images/threat_intel.jpg) – Threat Intelligence SOC feeds diagram.

### 2. Seamless Panoramic Device Screenshots (Stitched from `CPH2061`)
* [**`images/real_settings_full_scroll.png`**](images/real_settings_full_scroll.png) – **Complete Panoramic Settings Screen (1080×6415)** capturing every preference section from HTTP Server to Backup & Restore.
* [**`images/real_navbar_full_scroll.png`**](images/real_navbar_full_scroll.png) – **Complete Panoramic Slide-out Navigation Drawer (880×3123)** showing all 12 operational modules and switches.

### 3. Authentic Device Screenshots (Live 1080×2400 ADB Captures)
* [**`images/screen_fresh_tactical_v3.png`**](images/screen_fresh_tactical_v3.png) – **KotSafe Redesign with tactical status dots live on OPPO CPH2061** (Tactical dots for Firewall, Antivirus, SOC, Ask AI pill, shield icon in status circle, and seamless app bar).
* [`images/real_dashboard.png`](images/real_dashboard.png) – Real-time capture dashboard with speedometers.
* [`images/real_firewall.png`](images/real_firewall.png) – 5-way per-app firewall controls.
* [`images/real_antivirus.png`](images/real_antivirus.png) – Real-time scanning radar and Dalvik DEX analysis.
* [`images/real_action_center.png`](images/real_action_center.png) – Security rule manager and preset filters.
* [`images/real_alerts_center.png`](images/real_alerts_center.png) – Incident console with threat severity tags.
* [`images/real_repeater.png`](images/real_repeater.png) – Mobile HTTP request tampering and replay workbench.
* [`images/real_permissions.png`](images/real_permissions.png) – Dangerous runtime permission audit console.
* [`images/real_stats.png`](images/real_stats.png) – Network protocol statistics and top-talkers.

---

[⬅️ Back to Project Root](../README.md)
