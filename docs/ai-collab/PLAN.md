# KotSafe shared project plan

## Collaboration setup — done

- [x] Add Aiteam CLI and shared memory in `docs/ai-collab/`.
- [x] Add root `AGENTS.md` instructions for assistants that can read the checkout.
- [x] Record the initial project map and handoff expectations.

## Next

- [ ] User identifies the current feature or bug and acceptance criteria.
- [ ] Assign one assistant to implement; use the other for review or a separate task.
- [ ] Record focused build/test results and hand off the checkpoint.

## 2026-11-11 08:50 IST | Codex | KotSafe professional cleanup audit

Initial read-only audit across Android, desktop, website and Intelligence: establish canonical source ownership; retire alternate PHP authentication/mock-data fallback; trace and remove unreachable legacy admin component dependencies; keep AdminThreatIntel/AI/content currently imported by active routes; preserve admin.html redirect; generate deployment backend and admin from source rather than manually maintaining copies; remove workstation vendor symlink from release packaging; distinguish Chromium web desktop launcher from native Python desktop; clean only generated Android app/build, Gradle caches, frontend dist and desktop generated build outputs while preserving build scripts; move standalone Intelligence source from temporary dated workspace into a versioned repository after inventory. Neon PHP settings and Python persistence are separate and need explicit ownership. No removals authorized by this audit alone; review concrete patch before code changes under AGENTS.md.
