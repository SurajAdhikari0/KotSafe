# Current State
Last updated: 2026-11-15 20:21 IST by Antigravity

## Goal right now
Tasks T001–T011 completed. Added Per-App Strict VPN-Only Lockdown mode and Home Screen P2P Gateway status card/pill.

## Stopped at
- Implemented and verified Per-App VPN-Only Lockdown Mode:
  1. `GatewayPreferenceKeys.VPN_ONLY_LOCKDOWN_ENABLED`: Added preference constant for per-app strict lockdown.
  2. `activity_p2p_app_routing.xml` & `P2PAppRoutingActivity.java`: Added dedicated "Strict VPN-Only Lockdown" switch card with real-time toggle handling.
  3. `CaptureService.java`: Enforced dynamic firewall rule dropping packets (`ld.apps.add(uid)`) for all selected apps whenever the secure VPN/P2P tunnel is inactive/disconnected, guaranteeing selected apps pretend as "No Internet Connection" without cutting off other device apps.
  4. Real-time Telemetry Observer: Registered listener in `CaptureService` to automatically trigger `reloadBlocklist()` the instant P2P status transitions between connected and disconnected.
- Home Screen P2P Gateway & VPN-Only Cards:
  1. Executive Posture Bar (Row 3): Added `status_posture_p2p` and `status_posture_vpn_only` interactive status pills with dynamic dot indicators.
  2. Security Workbench (Row 4): Added `card_btn_p2p_mesh` and `card_btn_vpn_only_mode` cards providing 1-tap quick access to P2P Hub and App Lockdown Routing.
- Verification:
  1. Compiled clean with Gradle (0 errors, 0 warnings).
  2. Passed all 542 Android unit tests (including new `VpnOnlyLockdownTest`).
  3. Re-assembled signed production release APKs (`KotSafe-standard-release.apk`, `KotSafe-fullPower-release.apk`) and Play Store bundle (`KotSafe-standard-release.aab`).
  4. Updated `downloads/SHA256SUMS.txt` and synced to `kotsafe-site`.

## Next steps
1. Upload `KotSafe-standard-release.aab` to Google Play Console when ready to publish update.

## Decisions made
- Adopted Amnesty International MVT capability model for mobile forensics:
  - iOS `shutdown.log` analysis focuses on client paths outside `/System/Library/` and abnormal process terminations (`SIGKILL`/`SIGTERM`) indicative of Pegasus/Predator memory-resident exploits.
  - Chrome history parsing safely deserializes in `:memory:` with `PRAGMA trusted_schema=OFF` and `PRAGMA query_only=ON`, converting microsecond timestamps (`(visit_time - 11644473600000000) / 1000`) into standardized epoch milliseconds.
  - Android stalkerware detection combines active `AccessibilityServiceInfo` capability bitmasks (`CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT`, `CAPABILITY_CAN_REQUEST_FILTER_KEY_EVENTS`, `CAPABILITY_CAN_PERFORM_GESTURES`), overlay permissions (`SYSTEM_ALERT_WINDOW`), stealth profile (no launcher activity), and known commercial stalkerware signatures (Cerberus, SpyHide, TrackView, mSpy, FlexiSPY, KidsGuard, Pegasus Chrysaor).
- Enhanced `/opt/kotsafe-monitor/resource_monitor.py` on Oracle VPS to track separated Whole-VM, P2P, and Threat Intelligence metrics, peak RAM with sliding window, directories covered, persistent monthly traffic, and Android publisher alert transitions.
- Labeled Oracle tenancy outbound allowance (10 TB) as Unverified.
- Maintained exact schema compatibility with Hostinger Laravel ingest controller.
- Executed isolated staging tests with disposable keys: STIX 2.1 import rejections, exact URL/domain/IP matching without whole-host blocking, package+signer certificate verification, separate audience distribution, and publisher expiry/withdrawal/replay rejection.
- Deployed tested engine wheel into `/opt/kotsafe-intelligence/.venv` and updated `publish_android_feed.py`.
- Preserved production signing keys and key ID (`android-public-2026-11`) trusted by installed APKs.
- Maintained absolute priority and continuous uptime for P2P mesh (0 restarts, active signaling and relay).
- Created a persistent 2 GB swap file (`/swapfile`) with `vm.swappiness=20` to protect P2P headroom against memory pressure and OOM crashes.
- Added Swap memory tracking to `resource_monitor.py` on Oracle VPS, backend controller validation, and the React frontend Infrastructure monitor in `ResourceMonitor.jsx`. Built and committed to `kotsafe-site` (commit `0d3b75f`).
- Configured systemd `ReadWritePaths=/var/lib/kotsafe-android-publisher` and dual-source verification in `resource_monitor.py` (systemd + JSON log), successfully confirming alert transition from overdue to recovered.
