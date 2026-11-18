# Current State
Last updated: 2026-11-15 20:21 IST by Antigravity

## Goal right now
Task T013 completed. Restored and hardened Hostinger Threat Intelligence backend and composer runtime. Verified live HTTP 200 responses.

## Stopped at
- Diagnosed and resolved Threat Intelligence Cloud Gateway downtime on Hostinger (`193.203.185.182`):
  1. Identified that Hostinger's automated Git deployment (`hbuilds`) had replaced `~/domains/kotsafe.com/public_html/backend/` without `.env` and `vendor/` (due to standard `.gitignore` rules), causing `index.php` to return 503 (`Backend temporarily unavailable`).
  2. Restored `.env` from secure backup (`~/domains/kotsafe.com/private-android-feed.puOvJ24j/backup/.env`) to `public_html/backend/.env` and created a protected copy in `~/domains/kotsafe.com/kotsafe_backend.env`.
  3. Ran `composer install --no-dev --optimize-autoloader` in `backend/` and copied the full runtime to `~/domains/kotsafe.com/persistent_vendor/`.
  4. Updated `backend/public/index.php` with self-healing fallback logic: if `.env` or `vendor/` are ever wiped by a Git auto-deploy webhook, `index.php` automatically restores `.env` from `kotsafe_backend.env` and falls back to `persistent_vendor/autoload.php` with zero downtime.
  5. Cleared and cached Laravel configuration and routes: `php artisan config:cache && php artisan route:cache`.
  6. Verified live: `https://kotsafe.com/api/v1/threat-intel/lookup` and `https://kotsafe.com/api/v1/threat-intel/coverage` returned immediate HTTP/2 200 responses.
- Verified Oracle VPS Threat Intelligence Engine (`130.210.16.110`):
  - `kotsafe-intelligence.service`: Active.
  - `kotsafe-android-publisher.timer`: Active.
  - P2P Docker containers (`netpdroid-signaling`, `netpdroid-coturn`, `kotsafe-p2p-relay-1`): 100% uptime with 0 restarts.

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
