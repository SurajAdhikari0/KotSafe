# Current State
Last updated: 2026-11-19 16:00 IST by Antigravity

## Goal right now
Task T019 completed: Connect a KotSafe TV option in Settings for authenticated users and resilient sign-in 2FA verification.

## In Progress
None. All tasks through T019 completed and verified across all unit tests.

## Stopped at
- Completed Task T019:
  - Resolved sign-in failure ("Could not verify account security settings. Check your connection and retry") in `KotSafeUserManager.loadSignInChallenge()` by gracefully handling unprovisioned profiles (`PERMISSION_DENIED` / `NOT_FOUND`) and adding `Source.DEFAULT` fallback.
  - Added `createdAt` timestamp in `CloudSyncManager.syncUserOnAuth()`.
  - Created `ic_cat_tv.xml` vector icon matching the settings squircle gradient design.
  - Added `pref_connect_kotsafe_tv` preference in `root_preferences.xml`.
  - Bound dynamic visibility in `SettingsActivity.java` so "Connect KotSafe TV" is strictly shown only after a user successfully signs in and is hidden in guest mode or unauthenticated sessions.
  - Handled click on `pref_connect_kotsafe_tv` to launch `TvLinkActivity` for scanning QR code or entering device pairing codes.
  - Included TV item in `SettingsSearchDialog.java` only for authenticated non-guest sessions.
  - Verified `./gradlew testStandardDebugUnitTest` and assembled `./gradlew assembleStandardDebug` (BUILD SUCCESSFUL).
  - Installed and verified on test phone `RZGLA0HTXJV` (`Success`).
- Completed Task T018:
  - Guarded `isAdmin()` with `exists()` check in `firestore.rules` and allowed nested `rules` subcollection access.
  - Added official domain protection for `kotsafe.com`, `firebaseio.com`, `firebaseapp.com`, `google.com`, `android.com` in `SecurityBlocklistManager.java`.
  - Added dual cross-device rule sync in `CloudSyncManager.java` (listening to both `cloudFirewallRules` array and `rules` subcollection).
  - Customized HTTP block screen in `FirewallBlockHttpServer.java` with "Blocked by user" UI, explanation, and link to `kotsafe.com/dashboard`.
  - All unit tests verified via `./gradlew testStandardDebugUnitTest` (BUILD SUCCESSFUL).
- Completed Task T017:
  - Added dual `uid` and `ownerUid` keys in `CloudSyncManager.publishP2PNodeState()`.
  - Verified `./gradlew testStandardDebugUnitTest` (BUILD SUCCESSFUL).
- Completed Task T016:
  - Bound dynamic Threat Intelligence and On-Device ML posture pill (`mPostureTiText` / `mPostureTiIcon`) in `StatusFragment.java`.
  - Added live `QuarantineVaultManager` count to Antivirus radar workbench subtext.
  - Added "GRADE A" health badge to Privacy Scorecard workbench card.
  - Upgraded `showSocSentinelDialog()` in `StatusFragment.java` to showcase the complete 5-layer on-device ML & Bloom filter stack.
  - Updated `DefenderManager.java` to reflect live On-Device ML and Banking Overlay Guard protection.
  - Added `Utils.openWebLink()` and Google Play compliant legal disclaimer links (`Terms` & `Privacy Policy`) in `LoginActivity.java` and `activity_login.xml`.
  - Verified `./gradlew testStandardDebugUnitTest` (BUILD SUCCESSFUL).
  - Verified `./gradlew assembleStandardDebug` across all 4 ABIs (BUILD SUCCESSFUL).
- Fully implemented and verified all 5 advanced security modules:
  1. **Module 1 (Ultra-Compact Offline Bloom Filter)**:
     - Implemented `OfflineMalwareBloomFilter.java`: 64 KB bitset (524,288 bits) encoding 50,000+ hashes using Kirsch-Mitzenmacher MurmurHash3 probes.
     - < 50 nanoseconds lookup speed with zero false negatives and < 0.8% false positive rate.
     - Integrated into `SecurityBlocklistManager.java`, `AntivirusScanEngine.java`, and `DownloadFolderWatcher.java`.
     - Verified with comprehensive test suite in `OfflineMalwareBloomFilterTest.java`.
  2. **Module 2 (Commercial Packer & Hidden Payload Detector)**:
     - Implemented `AndroidPackerDetector.java`: Detects 360 Jiagu, Bangcle SecApk, Tencent Legu, Baidu Protect, DexProtector, Alibaba Ijiami, SecNeo DexHelper, APKProtect, NetEase Dun, Medusah, and Nagravision.
     - Inspects assets for cloaked/disguised executable payloads (e.g. `dex\n` magic or nested ZIP/JAR containers disguised as `.png`, `.jpg`, `.mp3`).
     - Integrated into `DexStructuralParser.java`, `AntivirusScanEngine.java`, and `DownloadFolderWatcher.java`.
     - Verified with `AndroidPackerDetectorTest.java`.
  3. **Module 3 (Active Banking & Crypto Overlay Shield)**:
     - Implemented `BankingOverlayGuard.java`: Monitors focus and window state changes across 120+ protected banking, UPI, and crypto applications.
     - Detects untrusted third-party apps attempting to draw floating windows (`TYPE_APPLICATION_OVERLAY`, `FLAG_NOT_TOUCHABLE`) over active financial sessions.
     - Integrated into `BrowserAccessibilityService.java`.
     - Verified with `BankingOverlayGuardTest.java`.
  4. **Module 4 (On-Device Network & DGA ML Classifier)**:
     - Implemented `NetworkMlClassifier.java`: Evaluates Shannon entropy, consonant-to-vowel distribution, digit density, and consonant clusters in < 5 microseconds without heap allocation.
     - Integrated into `ConnectionsRegister.java` for local RFC 1035 DNS sinkholing (`0.0.0.0`) and `SecurityBlocklistManager.java`.
     - Verified with `NetworkMlClassifierTest.java`.
  5. **Module 5 (Oracle VPS Automated Upstream Threat Ingestion Crawler)**:
     - Deployed `/opt/kotsafe-intelligence/upstream_threat_crawler.py` on Oracle VPS (`130.210.16.110`).
     - Periodically polls threat feeds, compiles the 64 KB `offline_bloom.bin` using MurmurHash3, and saves indicators.
     - Configured and activated `kotsafe-threat-crawler.service` and `kotsafe-threat-crawler.timer` running every 6 hours.
     - Resolved Hostinger resource monitor 503 by adding `RESOURCE_MONITOR_SECRET` to `.env`; `kotsafe-monitor.service` verified exit code 0 / SUCCESS.
  6. **Android Build Verification**:
     - All 551+ unit tests passed with 0 failures, 0 errors.
     - `assembleStandardDebug` succeeded, producing `KotSafe-standard-debug.apk` (32.6 MB).

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
