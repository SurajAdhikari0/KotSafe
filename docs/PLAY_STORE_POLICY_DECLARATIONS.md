# Google Play Store Compliance & Policy Declarations
**Application Name:** KotSafe / NETPdroid  
**Target Category:** Security & Anti-Malware / Personal Firewall  

This document contains the exact declaration texts, policy justifications, and video demonstration instructions required for Google Play Console submission.

---

## 1. High-Risk Permission: `QUERY_ALL_PACKAGES`

### Google Play Console Declaration Form

**1. What is the core functionality that requires this permission?**
> **Selected Category:** Device security / Antivirus / Personal Firewall

**2. Detailed Description & Justification:**
```
KotSafe is an open-source, on-device personal firewall and endpoint security suite. 
The QUERY_ALL_PACKAGES permission is essential for its core functionality:

1. Per-App Firewall Enforcement: KotSafe captures local network packets via a local VpnService and maps each TCP/UDP socket directly to the transmitting Linux UID. To present the user with human-readable application names and icons, and to enforce user-configured firewall allow/block network rules, the application must query the installed package inventory for that UID.
2. Real-Time Antivirus & Malware Defense: The built-in 15-phase AntivirusScanEngine and AppTrustEvaluator inspect installed applications on the device, extracting APK hashes (SHA-256) and verifying cryptographic signatures against curated threat databases, YARA rules, and known malware signatures.

Without this permission, the firewall cannot identify which app is communicating, cannot enforce per-app network rules, and the antivirus engine cannot scan installed packages to protect the device.
```

**3. Why can't you use standard `<queries>` declaration?**
```
Because KotSafe acts as a general-purpose local firewall and system-wide antivirus engine, it must monitor and protect against network traffic and malicious binaries originating from *any* arbitrary application installed by the user now or in the future. It is technically impossible to anticipate or enumerate third-party package names ahead of time in AndroidManifest.xml.
```

---

## 2. High-Risk Permission: `MANAGE_EXTERNAL_STORAGE` (All Files Access)

### Google Play Console Declaration Form

**1. What is the primary purpose of requesting All Files Access?**
> **Selected Category:** Anti-virus / Security

**2. Detailed Description & Justification:**
```
KotSafe contains an on-device real-time anti-ransomware and file protection watcher (FileProtectionWatcher / DownloadFolderWatcher). 

This engine continuously monitors the Download directory and external storage volumes for newly downloaded files, suspicious executable payloads, trojanized APK droppers, and sudden mass-encryption behavior characteristic of mobile ransomware.

Real-time protection operates autonomously in the background to alert the user before a downloaded malicious payload can be opened or executed. Using the Storage Access Framework (SAF) interactive document picker is technically infeasible for automated, uninterrupted background filesystem protection.
```

---

## 3. Video Walkthrough Demonstration Script (For Google Reviewers)

Google requires a publicly accessible video link (e.g., unlisted YouTube link) demonstrating the user-facing necessity of these permissions.

### Recommended 45-Second Recording Sequence:
1. **[0:00 - 0:15] Per-App Firewall Demonstration:**
   - Open KotSafe.
   - Navigate to the **"Firewall"** / **"Apps"** tab.
   - Show the complete list of installed applications with their respective icons, network permissions, and data usage.
   - Toggle one app to "Blocked" (red shield).
   - Open that app and show that network access is blocked, demonstrating direct reliance on `QUERY_ALL_PACKAGES`.
2. **[0:15 - 0:30] Antivirus Scan Demonstration:**
   - Navigate to the **"Antivirus"** tab.
   - Tap **"Full Security Scan"**.
   - Show the scanning phases inspecting installed APKs, calculating cryptographic hashes, and matching YARA rules.
3. **[0:30 - 0:45] File & Download Real-Time Protection:**
   - In Settings, show **"File & Download Protection"** enabled.
   - Download a test file / APK to the Downloads folder; show KotSafe instant notification inspecting the hash, demonstrating the need for `MANAGE_EXTERNAL_STORAGE`.

---

## 4. Google Play "Data Safety" Form Responses

| Question | Answer | Rationale |
|:---|:---:|:---|
| **Does your app collect or share user data?** | **No** | All packet capture, malware hashing, and firewall rules are processed 100% locally on the device. |
| **Is data transferred over an encrypted connection?** | **N/A** | No user data leaves the device. |
| **Can users request data deletion?** | **Yes** | Users can wipe logs, flush databases, or clear app data directly within App Settings. |
| **Is this app designed for children?** | **No** | Targeted at general users and security professionals. |
