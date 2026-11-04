# KotSafe Release APKs (v2.1.0)

Official signed release binaries for KotSafe v2.1.0 (Build 98).

## Available Binaries

| Variant | Package | Description | SHA-256 Checksum |
| :--- | :--- | :--- | :--- |
| **Standard Release** | [`KotSafe-standard-release.apk`](KotSafe-standard-release.apk) | Core firewall, privacy controls, and residential defense with minimal permissions. | `826d61e4209a46244853bd5eed1c302ac464752e9a8cde1f9a4ec323bb42b5aa` |
| **Full-Power Release** | [`KotSafe-fullPower-release.apk`](KotSafe-fullPower-release.apk) | Unrestricted suite with live APK malware inspector, phishing guard, and P2P residential mesh. | `9dd2de5642f4577aa4ec0ee8bb2f956cf5d728f46c851fdf65a4d8b9be3a5f57` |

## Integrity & Signature Verification

You can verify the official KotSafe release signature using `apksigner`:
```bash
apksigner verify --print-certs KotSafe-standard-release.apk
```
Expected SHA-256 Certificate Fingerprint:
`6a806ce6f4a426e997c3c3c29f6d1f9739e6ea3689768c5c546d0bc501f7c31f`
