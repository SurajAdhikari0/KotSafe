# KotSafe project

- **Purpose:** Android mobile security suite with firewall and VPN features, encrypted peer-to-peer mesh networking, threat protection, and an offline AI assistant. The repository also contains a web licensing/settings app.
- **Tech stack:** Android app built with Gradle, Java 17, Android Gradle Plugin, Kotlin/native C++ through JNI and CMake; web app uses TypeScript, React, Vite, Firebase, and Vitest.
- **Build Android:** `./gradlew assembleStandardDebug` or `./gradlew assembleFullPowerDebug` (Android SDK/NDK and CMake required; see root README).
- **Web app:** `cd web && npm run dev`; build with `npm run build`; tests with `npm test`.
- **Structure:** `app/` Android application and variants; `app/src/main/jni/` native code; `submodules/` dependencies; `web/` React/TypeScript portal; `tests/` and `app/src/test/` tests; `docs/ai-collab/` shared AI project memory.
- **Rules:** Treat this project as security-sensitive. Do not weaken security controls or change permissions, cryptography, network policy, signing, or release behavior without an explicit task. Never expose credentials or signing keys. Read root `README.md` and relevant module docs before making scoped changes. Run focused checks for changes and record exactly what passed or was not run. Preserve unrelated working-tree edits.
