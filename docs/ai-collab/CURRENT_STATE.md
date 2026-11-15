# Current State
Last updated: 2026-11-15 20:21 IST by Antigravity

## Goal right now
Task T012 completed. Synchronized Quarantine Vault state with antivirus scan cache and live score recalculation, verified live on physical device.

## Stopped at
- Fixed quarantine score persistence and live reconciliation across all quarantine channels:
  1. `QuarantineVaultManager.java`:
     - Added `isFileOrHashQuarantined(String filePath, String sha256)`: checks active records in vault.
     - Added `reconcileScanResultWithQuarantine(String originalPath, String sha256)`: immediately marks evidence items in `AntivirusScanService.getLastResult()` as `SEVERITY_RESOLVED` and recalculates `securityScore` dynamically.
     - On quarantine, immediately clears the threat from `FileHashDbHelper` and updates `ScanReportDbHelper`.
     - Broadcasts `ACTION_THREAT_QUARANTINED` to notify active UI listeners.
  2. `AntivirusScanActivity.java`:
     - Added broadcast listener `mQuarantineReceiver` and `reconcileWithQuarantineVault()` in `onResume()` and `syncScanServiceState()`.
     - Automatically reconciles cached scan report against Quarantine Vault so any background or notification-quarantined file immediately updates the UI score to 100 / Protected.
     - In `executeBatchQuarantine()`, handles files that were already shredded/quarantined in the vault.
  3. `AntivirusScanEngine.java`:
     - Checks `isFileOrHashQuarantined()` during storage evaluation, ensuring already quarantined artifacts are deleted from `hashDb` and never penalize the score in subsequent scans.
  4. `ThreatRemediationDialog.java`:
     - Detects if an item is already quarantined and applies green `QUARANTINED` badge.
     - Properly unwraps `ContextWrapper` to ensure `reanalyzeAndDisplayScore()` triggers correctly from dialog actions.
  5. `FileHashDbHelper.java`:
     - Added `deleteBySha256(String sha256)`.
- Verification:
  1. Unit test `QuarantineScoreReanalysisTest.testQuarantineVaultManager_ReconcilesScanResultAndScore` passed (100% of 543 unit tests passing).
  2. Assembled signed release APKs and Play Store bundle; updated `downloads/SHA256SUMS.txt` and synced to `kotsafe-site`.
  3. Installed on physical device (`7f55c189` OPPO CPH2061) and verified live:
     - Antivirus score updated to **100 / COMPLETE** (Device Fully Protected).
     - Scanned: 1471, Safe: 1471, Threats: 0.
     - Sandboxed Quarantine Vault displays: "1 isolated threat artifact in vault".

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
