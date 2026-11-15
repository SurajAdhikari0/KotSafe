# Current State
Last updated: 2026-11-15 18:40 IST by Antigravity

## Goal right now
All project tasks T001–T008 completed, tested, and deployed. Frontend admin portal packaged with STIX source import review.

## Stopped at
- All collaboration tasks in `TASKS.json` (T001 through T008) are complete and verified:
  1. T001 [done]: Centralize APK threat intelligence to KotSafe Admin/Backend API.
  2. T002 [done]: Connect opt-in Android signed updates to authenticated device enrollment.
  3. T003 [done]: Activate signed Android consumer feed and match reviewed indicators in observe-only mode.
  4. T004 [done]: Preserve inconclusive cloud verdicts in antivirus scans.
  5. T005 [done]: Harden Autopilot evidence, response status and repeated alerts.
  6. T006 [done]: Update KotSafe monitoring and deploy tested MVT threat intelligence on Oracle VPS.
  7. T007 [done]: Inherit advanced MVT capabilities (Live accessibility watcher, iOS shutdown.log, Chrome SQLite).
  8. T008 [done]: Expand threat intelligence with Abuse.ch URLhaus, multi-tier URL defense, and live production deployment.
- Frontend Admin Portal: Packaged admin bundle with STIX source import review (`ImportReview.jsx`). 10/10 admin tests passed.
- All 4 repositories clean and committed locally. Ready for remote push when GitHub credentials are provided.

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
