# Signed advisory intelligence integration

The new `IntelligenceManifestV2Verifier`, `IntelligenceSnapshotStore` and
`IntelligenceV2SyncCoordinator` classes provide an opt-in v2 integration seam.
They do not register a worker or modify legacy firewall, malicious hash, or
threat-cache databases. A signed snapshot is source evidence, not a malware verdict.

The application must provision a key-ID map of raw 32-byte Ed25519 public keys and
an authenticated tenant scope outside downloaded content. Key rotation requires
overlapping explicitly trusted keys; a response cannot introduce a signing key.
Construct the store beneath an app-private, tenant-specific `getFilesDir()`
directory. AtomicFile retains the prior complete envelope during interrupted writes.
An expired cached envelope retains its signed version as a replay watermark and
returns no active indicators. Protect app data: an attacker able to delete all
local state can reset a local version counter.

Run coordinator `sync(...)` on an executor after explicit opt-in. Configure an
approved HTTPS hostname and inject `DeviceCredential` obtained from a trusted
device enrollment, never from a hardcoded service/admin token. The default
`HttpsFetcher` validates platform TLS, refuses redirects, limits bytes/timeouts and
never logs token contents. It accepts either an envelope or the API's `data` wrapper.
Requests include the injected device ID; the account gateway must independently
validate role, tenant, expiry, revocation and device binding. The localhost pilot
service's credentials do not directly replace Firebase account authentication.

No production gateway URL, key, token or default opt-in is enabled in these files.
Existing `ThreatFeedSyncManager` continues to handle its separate legacy signed
delta format. Never route v2 snapshots into that legacy auto-blocking path.

Targeted checks (JDK 17 and the configured Android SDK):

```
./gradlew :app:testStandardDebugUnitTest --tests 'com.kotsafe.security.model.IntelligenceManifestV2Test'
./gradlew :app:compileStandardDebugJavaWithJavac
```

Tests use a synthetic Python-signed envelope and an explicitly test-only private
seed. They cover signature interoperability, tampering, audience/tenant/expiry,
replay, strict JSON, unsupported types, preserved URL paths, interrupted writes
and opt-in/origin gates. Those fixture keys must never be provisioned in a release.
