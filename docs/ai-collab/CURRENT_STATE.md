# Current State
Last updated: 2026-11-15 18:30 IST by Antigravity

## Goal right now
Production deployment of Abuse.ch URLhaus threat intelligence, exact multi-tier URL defense, and fresh release APKs across Oracle VPS and Hostinger.

## Stopped at
- Task T008 fully implemented, tested, and deployed live to production:
  1. Oracle VPS Deployment:
     - Built fresh Python distribution wheel `kotsafe_intelligence-0.1.0-py3-none-any.whl` (94,479 bytes) with URLhaus provider.
     - Installed into `/opt/kotsafe-intelligence/.venv` and restarted `kotsafe-intelligence.service` (verified active HTTP 200).
     - Preserved 100% uptime for all P2P containers (`netpdroid-signaling`, `netpdroid-coturn`, `kotsafe-p2p-relay-1`).
  2. Hostinger Production Deployment:
     - Deployed updated multi-tier URL lookup in `ThreatIntelController.php`, `ThreatIndicator.php`, `TrustedDomain.php`, `ThreatDeltaService.php`, and `api.php`.
     - Uploaded fresh release APKs (`KotSafe.apk`, `KotSafe-standard-release.apk`, `KotSafe-fullPower-release.apk`) and `SHA256SUMS.txt`. Checksum verification on host returned `OK`.
     - Cleared and re-warmed Laravel config and route caches (`php artisan optimize:clear && php artisan config:cache && php artisan route:cache`).
     - Verified live public endpoints: `https://kotsafe.com/downloads/SHA256SUMS.txt` (HTTP 200), `https://kotsafe.com/downloads/KotSafe.apk` (HTTP/2 200), and `https://kotsafe.com/api/v1/threat-intel/lookup` (HTTP 200).
  3. Git Repositories:
     - `KotSafe`, `kotsafe-intelligence`, `backend`, and `kotsafe-site` working trees are completely clean with changes committed.

## Next steps
1. Push git commits across repositories to remote when GitHub credentials (PAT or SSH) are provided.
2. Install updated APK via ADB when physical Android phone is connected.
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
