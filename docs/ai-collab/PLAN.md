# KotSafe shared project plan

## Collaboration setup — done

- [x] Add Aiteam CLI and shared memory in `docs/ai-collab/`.
- [x] Add root `AGENTS.md` instructions for assistants that can read the checkout.
- [x] Record the initial project map and handoff expectations.

## Next

- [ ] User identifies the current feature or bug and acceptance criteria.
- [ ] Assign one assistant to implement; use the other for review or a separate task.
- [ ] Record focused build/test results and hand off the checkpoint.

## 2026-11-15 19:05 IST | Antigravity | Task T009: Microsoft Defender-Grade Immediate Threat Detection & Remediation

### Objective
Upgrade KotSafe's real-time threat response and notification architecture to match Microsoft Defender:
1. In-notification 1-click remediation actions: `[ ⚡ Uninstall ]`, `[ 🛡️ Quarantine ]`, `[ 🚫 Block ]`.
2. Connect `ActionReceiver.java` to handle direct package uninstallation via Android system intent, direct quarantine via `QuarantineVaultManager`, and direct firewall blocking via `SecurityRulesDb`.
3. In-flight network alert integration in `ConnectionsRegister.java` when malicious IOCs or URLhaus indicators are blocked.
4. On-access download sentinel connection in `DownloadFolderWatcher.java` dispatching direct quarantine notifications.
5. Verify with `./gradlew testStandardDebugUnitTest` and assemble updated APKs.

## 2026-11-15 18:05 IST | Antigravity | Task T008: Expand Threat Intelligence Engine with Abuse.ch URLhaus & Exact URL Defense

### Objective
Enhance KotSafe threat intelligence across the Python intelligence engine and Android client to support full, exact URL threat detection, integrating Abuse.ch URLhaus live queries and eliminating the blind spot where malicious URLs on shared/benign hosting (GitHub, Firebase, Google Drive, Discord) were stripped to domains and missed.

### Implementation Steps
1. **Engine Provider (`kotsafe_intelligence/providers/urlhaus.py`)**:
   - Implement asynchronous URLhaus client querying `https://urlhaus-api.abuse.ch/v1/url/` (and `/host/` fallback).
   - In-memory bounded cache with TTL.
   - Extracts payload signatures (Android APK trojans, droppers), tags, threat types, and online status.
2. **Engine Endpoint & Observables (`server.py` & `service.py`)**:
   - Expose `/v1/lookup/url` in FastAPI server.
   - Add `url` observable support in `public_lookup` (`service.py`), utilizing `ObservableType.URL` and existing RFC-compliant normalization.
3. **Android Client Multi-Tier Scanner (`ThreatIntelApiClient.java` & `ThreatIntelManager.java`)**:
   - Retain full URL when `type` is `URL` rather than stripping to domain prematurely.
   - Tier 1: Query exact URL against KotSafe intelligence gateway.
   - Tier 2: If URL is unknown/clean, fallback to checking host domain.
4. **Testing & Verification**:
   - Unit tests in `test_intelligence.py` for URLhaus provider and `/v1/lookup/url` endpoint.
   - Unit tests in Android test suite (`./gradlew testStandardDebugUnitTest`).
   - Run full Python engine test suite (`pytest`).

## 2026-11-11 08:50 IST | Codex | KotSafe professional cleanup audit

Initial read-only audit across Android, desktop, website and Intelligence: establish canonical source ownership; retire alternate PHP authentication/mock-data fallback; trace and remove unreachable legacy admin component dependencies; keep AdminThreatIntel/AI/content currently imported by active routes; preserve admin.html redirect; generate deployment backend and admin from source rather than manually maintaining copies; remove workstation vendor symlink from release packaging; distinguish Chromium web desktop launcher from native Python desktop; clean only generated Android app/build, Gradle caches, frontend dist and desktop generated build outputs while preserving build scripts; move standalone Intelligence source from temporary dated workspace into a versioned repository after inventory. Neon PHP settings and Python persistence are separate and need explicit ownership. No removals authorized by this audit alone; review concrete patch before code changes under AGENTS.md.
