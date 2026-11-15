# Current State
Last updated: 2026-11-15 20:21 IST by Antigravity

## Goal right now
Task T010: Sanitize public KotSafe repository and configure proprietary P2P feature segregation for KotSafe-Private.

## Stopped at
- Sanitized Oracle VPS IP literals (`130.210.16.110`) across all Java files and docs:
  1. `P2PExitNodeSettings.java`: Migrated IP regex check to auto-upgrade legacy IP endpoints to Cloudflare tunnel.
  2. `BackendProviderFactory.java`: Migrated IP regex check to auto-upgrade legacy custom IP configurations.
  3. `SecurePairingBundle.java`: Replaced raw IP check with generic regex migrating to `https://relay.kotsafe.com`.
  4. `PROGRESS.md`: Sanitized VPS reference to `relay.kotsafe.com`.
  5. `licenseBackend.js`: Removed enterprise keys, enabled dynamic `process.env.LICENSE_REGISTRY_JSON` injection, and verified strict `LICENSE_SALT` requirement in production.
  6. `google-services.json.example`: Created template with sanitized mock credentials.
- All 541 Android unit tests and 65 web vitest unit tests passing.

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
