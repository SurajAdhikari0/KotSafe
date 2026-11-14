# Current State
Last updated: 2026-11-14 17:55 IST by Antigravity

## Goal right now
Deploy STIX review gateway and routes to Hostinger, assemble fresh Android builds, verify test suites, and push commits to GitHub.

## Stopped at
- Option A completed: Deployed matching STIX review gateway, controller endpoints, models, and test suite to Hostinger production. All 13 intelligence routes registered and cached; 150 backend tests passing (627 assertions).
- Option B completed: 537 Android unit tests passed. Assembled debug and signed release APKs (`KotSafe-standard-release.apk`, `KotSafe-fullPower-release.apk`) with Autopilot safety, link scanner, and inconclusive scan preservation. Uploaded to Hostinger downloads with updated `SHA256SUMS.txt`.
- Option C ready: Local commits prepared in `KotSafe` (commit `dbb8a044`) and `kotsafe-site` (commit `8dd56b6`). Ready to push once GitHub Personal Access Token (PAT) or SSH key is provided.

## Next steps
1. Push `KotSafe` and `kotsafe-site` commits to GitHub upon receiving PAT/SSH key.
2. Verify physical phone testing if test device is plugged in via USB.
3. Keep `INTELLIGENCE_WORKSPACE_DISTRIBUTION` disabled until website release and both distribution paths have been tested together.

## Decisions made
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
