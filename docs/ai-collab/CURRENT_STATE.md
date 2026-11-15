# Current State
Last updated: 2026-11-15 18:25 IST by Antigravity

## Goal right now
Expand KotSafe Threat Intelligence with Abuse.ch URLhaus live threat provider, unified multi-tier full URL/domain lookup, eliminate shared hosting blind spots, verify all test suites, and assemble production APKs.

## Stopped at
- Task T008 completed:
  1. Abuse.ch URLhaus Live Threat Provider: Implemented `kotsafe_intelligence/providers/urlhaus.py` with caching and async HTTP queries against URLhaus API (`/v1/url/` and `/v1/host/`).
  2. Threat Intelligence Server & Service: Exposed `@app.post("/v1/lookup/url")` in `server.py` and enabled `ObservableType.URL` in `public_lookup` in `service.py`. Python unit tests passing (12/12 in `test_intelligence.py` and 215/215 in full test suite).
  3. Backend Multi-Tier Lookup: Enhanced `deviceLookup` in `ThreatIntelController.php` on Hostinger backend with Tier 1 (exact URL query against URL indicators) and Tier 2 (fallback to parsed host domain/IP reputation). Backend test suite fully passing (150/150 tests, 627 assertions).
  4. Android Client Exact URL Defense: Updated `ThreatIntelApiClient.java` and `KotSafeCloudProvider.java` to preserve full URLs without prematurely stripping to domain names, closing the blind spot on shared hosting (e.g., Discord, Firebase, Google Drive). 541/541 Android unit tests passing (100%).
  5. Distribution & Assembly: Built `kotsafe_intelligence-0.1.0-py3-none-any.whl` (94 KB). Built `assembleStandardDebug`, `assembleStandardRelease`, and `assembleFullPowerRelease`. Updated `downloads/` and `SHA256SUMS.txt` across `KotSafe` and `kotsafe-website`.

## Next steps
1. Deploy wheel `dist/kotsafe_intelligence-0.1.0-py3-none-any.whl` to `/opt/kotsafe-intelligence/.venv` on Oracle VPS and restart `kotsafe-intelligence.service`.
2. Push git commits across repositories once GitHub authentication credentials (PAT or SSH) are provided.
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
