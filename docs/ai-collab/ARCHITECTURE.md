# KotSafe architecture notes

## Repository structure

- Android application: root Gradle project includes `:app`; Android configuration and product flavors live in `app/build.gradle`.
- Android app flavors: `standard`, `fullPower`, `corporate`, and `withoutUshark`; `standard` is configured as the default flavor.
- Native components: `app/src/main/jni/` builds through CMake and JNI; Java sources include the MaxMind DB reader submodule.
- Web portal: `web/` is a separate React/TypeScript/Vite application with Firebase dependencies and a Node license backend.

## Constraints

- Android build configuration currently uses Java 17, compile SDK 36, target SDK 34, and CMake 3.22.1 (see `app/build.gradle`).
- The README describes privacy-sensitive, on-device security behavior. Verify data flows and security boundaries before changing network, cryptographic, permission, or telemetry behavior.
- Details here are an initial map from repository configuration; update this file when verified architectural decisions are made.
