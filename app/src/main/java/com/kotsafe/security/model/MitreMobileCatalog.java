/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 *
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Authoritative registry of MITRE ATT&CK for Mobile (Android v15) techniques,
 * tactics, sub-techniques, and paired MITRE D3FEND countermeasures.
 */
public final class MitreMobileCatalog {

    public enum MobileTactic {
        INITIAL_ACCESS("Initial Access", "#DC2626", 1),
        EXECUTION("Execution", "#D97706", 2),
        PERSISTENCE("Persistence", "#059669", 3),
        PRIVILEGE_ESCALATION("Privilege Escalation", "#B45309", 4),
        DEFENSE_EVASION("Defense Evasion", "#6D28D9", 5),
        CREDENTIAL_ACCESS("Credential Access", "#BE123C", 6),
        DISCOVERY("Discovery", "#0369A1", 7),
        LATERAL_MOVEMENT("Lateral Movement", "#0F766E", 8),
        COLLECTION("Collection", "#1D4ED8", 9),
        COMMAND_AND_CONTROL("Command & Control", "#9333EA", 10),
        EXFILTRATION("Exfiltration", "#E11D48", 11),
        IMPACT("Impact", "#B91C1C", 12),
        NETWORK_EFFECTS("Network Effects", "#0284C7", 13);

        public final String label;
        public final String color;
        public final int order;

        MobileTactic(String label, String color, int order) {
            this.label = label;
            this.color = color;
            this.order = order;
        }
    }

    public static class MobileTechniqueDef {
        public final String id;
        public final String name;
        public final MobileTactic tactic;
        public final String description;
        public final String d3fendId;
        public final String d3fendName;
        public final String recommendedMitigation;
        public final boolean isSubtechnique;
        public final String parentId;

        public MobileTechniqueDef(String id, String name, MobileTactic tactic,
                                  String description, String d3fendId, String d3fendName,
                                  String mitigation, boolean isSubtechnique, String parentId) {
            this.id = id;
            this.name = name;
            this.tactic = tactic;
            this.description = description;
            this.d3fendId = d3fendId;
            this.d3fendName = d3fendName;
            this.recommendedMitigation = mitigation;
            this.isSubtechnique = isSubtechnique;
            this.parentId = parentId;
        }

        public MobileTechniqueDef(String id, String name, MobileTactic tactic,
                                  String description, String d3fendId, String d3fendName,
                                  String mitigation) {
            this(id, name, tactic, description, d3fendId, d3fendName, mitigation, false, null);
        }
    }

    private static final Map<String, MobileTechniqueDef> S_TECHNIQUES = new LinkedHashMap<>();

    static {
        // ── 1. Initial Access ───────────────────────────────────────────────
        add(new MobileTechniqueDef("T1475", "Deliver Malicious App via Sideloading", MobileTactic.INITIAL_ACCESS,
                "Adversaries trick users into installing malicious APKs outside official app stores.",
                "D3-APPV", "Application Package Verification",
                "Audit unknown package install permissions and inspect APK binaries before staging."));

        add(new MobileTechniqueDef("T1189", "Drive-by Compromise", MobileTactic.INITIAL_ACCESS,
                "Exploitation of web browser components or embedded web views during normal internet browsing.",
                "D3-URLF", "URL Reputation & Content Filtering",
                "Enable KotSafe SmartScreen domain filtering and block known malicious redirection chains."));

        add(new MobileTechniqueDef("T1610", "Rogue Cellular / Fake Base Station / Wi-Fi AP", MobileTactic.INITIAL_ACCESS,
                "Adversaries spoof wireless base stations or Wi-Fi APs (Evil Twin) to intercept traffic.",
                "D3-WND", "Wireless Network Anomaly Detection",
                "Verify BSSID duplicate fingerprints, encryption standards, and gateway ARP integrity."));

        // ── 2. Execution ────────────────────────────────────────────────────
        add(new MobileTechniqueDef("T1407", "Download New Code at Runtime (DEX Dropper)", MobileTactic.EXECUTION,
                "Applications download secondary encrypted DEX payloads and execute them via dynamic classloaders.",
                "D3-DPA", "Dynamic Package Analysis",
                "Scan filesystem for dynamically written DEX/JAR binaries and isolate offending packages."));

        add(new MobileTechniqueDef("T1204", "User Execution", MobileTactic.EXECUTION,
                "Adversaries rely on social engineering to trick the user into executing a malicious payload.",
                "D3-SEA", "Social Engineering Analysis",
                "Present high-contrast security warnings prior to granting device administrative or notification rights."));

        add(new MobileTechniqueDef("T1404", "Exploit OS Vulnerability", MobileTactic.EXECUTION,
                "Leveraging Android kernel (Dirty Pipe) or GPU (Mali sandbox escape) bugs to break runtime isolation.",
                "D3-KH", "Kernel Hardening & Patch Verification",
                "Keep device firmware updated and enforce strict SELinux policy checks."));

        // ── 3. Persistence ──────────────────────────────────────────────────
        add(new MobileTechniqueDef("T1437", "Abuse Accessibility Features", MobileTactic.PERSISTENCE,
                "Malware uses Android Accessibility Services to persist, monitor user activity, and bypass controls.",
                "D3-SVE", "Screen Verification & Accessibility Watchdog",
                "Continuously audit active accessibility bindings and alert on unauthorized background services."));

        add(new MobileTechniqueDef("T1624", "Event-Triggered Execution: Broadcast Receivers", MobileTactic.PERSISTENCE,
                "Malicious apps register BOOT_COMPLETED or network connectivity intents to restart automatically.",
                "D3-MFA", "Manifest Filter Audit",
                "Inspect manifest receivers and disable automatic startup for unverified background apps."));

        add(new MobileTechniqueDef("T1402", "Device Administrator Rights Abuse", MobileTactic.PERSISTENCE,
                "Adversaries request Device Admin permissions to prevent the user from uninstalling the application.",
                "D3-DPA", "Device Policy Administration Audit",
                "Enforce strict policy approval before any third-party app receives device admin privileges."));

        // ── 4. Privilege Escalation ─────────────────────────────────────────
        add(new MobileTechniqueDef("T1626", "Abuse Elevation Control (Root Abuse)", MobileTactic.PRIVILEGE_ESCALATION,
                "Adversaries exploit local vulnerabilities or leverage Magisk/KernelSU to gain root permissions.",
                "D3-RI", "Root Integrity Validation",
                "Verify system partition mounting status, su binary paths, and SafetyNet/Play Integrity status."));

        add(new MobileTechniqueDef("T1458", "Exploitation for Privilege Escalation", MobileTactic.PRIVILEGE_ESCALATION,
                "Exploiting local system services or IPC binders to gain permissions beyond the application sandbox.",
                "D3-IPC", "Inter-Process Communication Sandboxing",
                "Audit exported components and restrict unauthenticated AIDL/Binder calls."));

        // ── 5. Defense Evasion ──────────────────────────────────────────────
        add(new MobileTechniqueDef("T1406", "Obfuscated Files or Information", MobileTactic.DEFENSE_EVASION,
                "Adversaries pack, encrypt, or obfuscate code and strings to prevent static reverse engineering.",
                "D3-BEA", "Bytecode Entropy Analysis",
                "Analyze DEX class entropy, string encryption routines, and native JNI obfuscation signatures."));

        add(new MobileTechniqueDef("T1036", "Masquerading (App & Domain Spoofing)", MobileTactic.DEFENSE_EVASION,
                "Using deceptive app titles, icons, or typosquatted domains to mimic trusted services.",
                "D3-SIA", "Software Identity & Signature Authentication",
                "Verify signing certificate fingerprints (SHA-256) and UID ownership against official stores."));

        add(new MobileTechniqueDef("T1562.001", "Impair Defenses: Disable / Bypass VPN", MobileTactic.DEFENSE_EVASION,
                "Malicious apps attempt to terminate KotSafe VPN service or bypass local routing controls.",
                "D3-LKV", "Lockdown VPN Enforcement",
                "Enable system-level Always-on VPN and Block connections without VPN in Android settings."));

        add(new MobileTechniqueDef("T1444", "Double Extension Masquerading", MobileTactic.DEFENSE_EVASION,
                "Cloaking executable APK files under fake document or media extensions (.pdf.apk, .mp4.apk).",
                "D3-MIME", "MIME Type & Header Verification",
                "Inspect file magic bytes (ZIP/PK headers) rather than relying on filesystem file extensions."));

        // ── 6. Credential Access ────────────────────────────────────────────
        add(new MobileTechniqueDef("T1411", "Input Prompt / Overlay Attack", MobileTactic.CREDENTIAL_ACCESS,
                "Displaying fake overlay windows above banking or crypto apps to steal credentials and 2FA codes.",
                "D3-OVD", "Overlay & System Alert Window Defense",
                "Detect background SYSTEM_ALERT_WINDOW usage and block touches to obscured activities."));

        add(new MobileTechniqueDef("T1417", "Input Capture (Keylogging)", MobileTactic.CREDENTIAL_ACCESS,
                "Logging touchscreen taps or leveraging custom soft keyboards to steal entered credentials.",
                "D3-IKP", "Input Key Protection",
                "Flag third-party input method editors (IME) and screen-reading background services."));

        add(new MobileTechniqueDef("T1516", "Input Capture: SIM Swapping & 2FA Hijack", MobileTactic.CREDENTIAL_ACCESS,
                "Intercepting SMS verification codes or detecting unexpected physical SIM card removal.",
                "D3-SIMM", "SIM State & Telephony Monitor",
                "Monitor telephony manager subscriber IDs and alert upon sudden SIM state transitions."));

        // ── 7. Discovery ────────────────────────────────────────────────────
        add(new MobileTechniqueDef("T1418", "Application Discovery (Package Enumeration)", MobileTactic.DISCOVERY,
                "Apps query the package manager to inventory banking, cryptocurrency, or security software.",
                "D3-PMA", "Package Query Anomaly Detection",
                "Monitor excessive getInstalledPackages() API invocations from untrusted applications."));

        add(new MobileTechniqueDef("T1590", "Gather Victim Network Information", MobileTactic.DISCOVERY,
                "Querying external IP lookup services or STUN endpoints to map ISP, country, and public IP.",
                "D3-NDI", "Network Discovery Inspection",
                "Log and throttle requests to public IP lookup services (ipinfo.io, ifconfig.me)."));

        add(new MobileTechniqueDef("T1595", "Active Scanning (Subnet Sweep)", MobileTactic.DISCOVERY,
                "Scanning the local Wi-Fi subnet for open ports, routers, or vulnerable smart home devices.",
                "D3-PSB", "Port Sweep & SYN Flood Blocker",
                "Detect rapid sequential socket connections to private RFC-1918 subnets and block the sweep."));

        // ── 8. Collection ───────────────────────────────────────────────────
        add(new MobileTechniqueDef("T1430", "Location Tracking & Audio Surveillance", MobileTactic.COLLECTION,
                "Spyware records microphone audio, camera frames, or continuous GPS coordinates in the background.",
                "D3-PAM", "Privacy & Sensor Access Monitoring",
                "Track background sensor access frequency and alert when audio/location is captured without UI."));

        add(new MobileTechniqueDef("T1412", "Capture SMS & Call Logs", MobileTactic.COLLECTION,
                "Exfiltrating sensitive SMS messages containing one-time passwords and personal communications.",
                "D3-PPD", "Personal Privacy Data Protection",
                "Strictly restrict READ_SMS and READ_CALL_LOG permissions to default dialer/SMS apps only."));

        add(new MobileTechniqueDef("T1432", "Access Contact List", MobileTactic.COLLECTION,
                "Harvester apps harvest contact phone numbers and emails for phishing or extortion campaigns.",
                "D3-PPD", "Personal Privacy Data Protection",
                "Audit contact reading frequency and restrict full-addressbook exports."));

        // ── 9. Command & Control ────────────────────────────────────────────
        add(new MobileTechniqueDef("T1071.001", "Application Layer Protocol: Web Protocols", MobileTactic.COMMAND_AND_CONTROL,
                "Adversaries use standard HTTP/HTTPS channels to blend in with legitimate user traffic.",
                "D3-OFC", "Outbound Flow & TLS SNI Inspection",
                "Inspect TLS server names, detect non-browser User-Agents, and enforce domain blocklists.",
                true, "T1071"));

        add(new MobileTechniqueDef("T1071.004", "Application Layer Protocol: DNS Tunneling", MobileTactic.COMMAND_AND_CONTROL,
                "Encoding commands or payloads inside DNS query subdomains and TXT/NULL record responses.",
                "D3-DDA", "DNS Tunnel & High-Entropy Analysis",
                "Calculate Shannon entropy on DNS labels and drop excessive DNS query frequencies.",
                true, "T1071"));

        add(new MobileTechniqueDef("T1090.003", "Multi-hop Proxy / Tor Anonymization", MobileTactic.COMMAND_AND_CONTROL,
                "Routing command traffic through Tor or proxy chains to conceal the C2 destination IP.",
                "D3-TOR", "Anonymizer & Tor Node Blocking",
                "Drop socket handshakes destined to known Tor relays, proxies, and suspicious VPN endpoints.",
                true, "T1090"));

        add(new MobileTechniqueDef("T1573", "Encrypted Channel (Non-Standard Crypto)", MobileTactic.COMMAND_AND_CONTROL,
                "Using custom TLS implementations or raw TCP sockets on obscure ports to hide C2 messages.",
                "D3-PIA", "Protocol Identification & Validation",
                "Classify packet streams using DPI and alert on unrecognized encrypted binary handshakes."));

        // ── 10. Exfiltration ────────────────────────────────────────────────
        add(new MobileTechniqueDef("T1048.001", "Exfiltration Over Alternative Protocol: HTTPS", MobileTactic.EXFILTRATION,
                "Silently uploading exfiltrated files or database records over encrypted cloud endpoints.",
                "D3-UQ", "Upload Quota & Volume Monitoring",
                "Enforce upload volume limits on background apps and alert on high outbound data surges.",
                true, "T1048"));

        add(new MobileTechniqueDef("T1567", "Exfiltration Over Web Service (Cloud APIs)", MobileTactic.EXFILTRATION,
                "Adversaries exfiltrate stolen data to Telegram bots, Discord webhooks, or cloud paste sites.",
                "D3-CDA", "Cloud Data API Auditing",
                "Block unapproved background socket sessions to webhook services and paste APIs."));

        // ── 11. Impact ──────────────────────────────────────────────────────
        add(new MobileTechniqueDef("T1471", "Data Encrypted for Impact (Ransomware)", MobileTactic.IMPACT,
                "Mobile ransomware encrypts device photos, documents, and media, demanding ransom payment.",
                "D3-RSC", "Ransomware Canary & Mass File Modification Detector",
                "Detect rapid batch file renames or high filesystem write frequency and freeze the process."));

        add(new MobileTechniqueDef("T1447", "Device Lockout / Extortion Screen", MobileTactic.IMPACT,
                "Malware locks the phone screen with unclosable full-screen windows or changes device PIN.",
                "D3-LOD", "Lockout Protection & Emergency Mode",
                "Enforce window flag restrictions and provide safe boot recovery mechanisms."));

        add(new MobileTechniqueDef("T1469", "Denial of Service / Battery Exhaustion", MobileTactic.IMPACT,
                "Malware performs unauthorized cryptocurrency mining or background DDoS packet floods.",
                "D3-RFC", "Rate Limiting & Socket Throttling",
                "Throttle socket creation rates and detect thermal/battery spikes from background apps."));
    }

    private static void add(MobileTechniqueDef def) {
        S_TECHNIQUES.put(def.id, def);
    }

    public static MobileTechniqueDef get(String techniqueId) {
        if (techniqueId == null) return null;
        return S_TECHNIQUES.get(techniqueId.trim());
    }

    public static List<MobileTechniqueDef> getAllTechniques() {
        return Collections.unmodifiableList(new ArrayList<>(S_TECHNIQUES.values()));
    }

    public static List<MobileTechniqueDef> getTechniquesForTactic(MobileTactic tactic) {
        List<MobileTechniqueDef> list = new ArrayList<>();
        for (MobileTechniqueDef def : S_TECHNIQUES.values()) {
            if (def.tactic == tactic) {
                list.add(def);
            }
        }
        return list;
    }

    public static List<MobileTactic> getOrderedTactics() {
        List<MobileTactic> tactics = new ArrayList<>();
        Collections.addAll(tactics, MobileTactic.values());
        tactics.sort((a, b) -> Integer.compare(a.order, b.order));
        return tactics;
    }

    private MitreMobileCatalog() {}
}
