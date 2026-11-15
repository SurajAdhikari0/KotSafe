# Current State
Last updated: 2026-11-15 10:10 IST by Antigravity

## Goal right now
Inherit advanced MVT capabilities (Live Android accessibility stalkerware watcher, iOS shutdown.log Pegasus parser, and Chrome history SQLite parser), verify test suites, assemble and sync production APKs, and prepare for GitHub push.

## Stopped at
- Task T007 completed:
  1. Live Android Accessibility & Stalkerware Watcher: Implemented `AccessibilityStalkerwareDetector.java` with commercial stalkerware signature catalog, screen-scraping/keylogging/overlay/stealth capability heuristics, and integrated into Phase 5b of `AntivirusScanEngine.java`. 541 Android unit tests passing (100%).
  2. iOS `shutdown.log` Pegasus Parser: Added `shutdown_records` in `mobile_forensics.py` detecting reboot anomalies, non-system execution from `/private/var/` or staging paths, and correlated terminations.
  3. Chromium / Chrome `History` SQLite Parser: Added `chrome_records` in `mobile_forensics.py` with epoch microsecond conversion, redirect chain analysis, and STIX indicator matching.
  4. Engine Verification: 215 unit tests passing in `kotsafe-intelligence`. Fresh wheel package built (`kotsafe_intelligence-0.1.0-py3-none-any.whl`, 93 KB).
  5. Assembled debug and signed production release APKs (`KotSafe-standard-release.apk`, `KotSafe-fullPower-release.apk`) with updated checksums synced to `https://kotsafe.com/downloads/` (verified HTTP 200).
- Option C ready: Local commits prepared in `KotSafe` (commit `6c97de9b`) and `kotsafe-site` (commit `8dd56b6`). Ready to push once GitHub Personal Access Token (PAT) or SSH key is provided.

## Next steps
1. Push `KotSafe` and `kotsafe-site` commits to GitHub upon receiving PAT/SSH key.
2. Verify physical phone testing if test device is plugged in via USB.
3. Keep `INTELLIGENCE_WORKSPACE_DISTRIBUTION` disabled until website release and both distribution paths have been tested together.

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
