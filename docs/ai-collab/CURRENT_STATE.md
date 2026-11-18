# Current State
Last updated: 2026-11-18 11:18 IST by Antigravity

## Goal right now
Threat Intelligence verification and hardening completed. All cloud and edge intelligence components are verified operational.

## Stopped at
- Hostinger Cloud Gateway (`193.203.185.182` / `kotsafe.com`):
  1. Resolved Composer relative path autoload conflict by configuring Hostinger's Git auto-deploy pipeline (`package.json`) to automatically run `composer install --no-dev --optimize-autoloader` in `backend/` upon push.
  2. Implemented resilient fallback in `backend/public/index.php` that copies from persistent `backup_vendor` if vendor dependencies are missing.
  3. Configured `ANDROID_INTELLIGENCE_PUBLISHER_TOKEN` in `.env` and `kotsafe_backend.env` for secure feed ingestion.
  4. Enabled `public_lookup = 1` for reviewed threat indicators in MySQL database.
  5. Verified live endpoints:
     - `https://kotsafe.com/api/v1/threat-intel/lookup`: HTTP/2 200 OK (verified Hash, Domain, IP, and URL lookup accuracy).
     - `https://kotsafe.com/api/v1/threat-intel/coverage`: HTTP/2 200 OK (`published_count: 5`).
- Oracle VPS Engine (`130.210.16.110`):
  - `kotsafe-intelligence.service`: Active (running).
  - `kotsafe-android-publisher.timer`: Active (waiting).
  - `kotsafe-android-publisher.service`: Verified executing with status 0 (SUCCESS), successfully signing and publishing 5 indicators to Hostinger.
  - P2P Docker Mesh (`netpdroid-signaling`, `netpdroid-coturn`, `kotsafe-p2p-relay-1`): 100% uptime with 0 restarts.
- Android Client:
  - Quarantine Vault reconciliation and live score calculation verified on physical device.
  - Client-side threat queries seamlessly utilize `https://kotsafe.com/api/v1/threat-intel/lookup`.

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
