/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * MitreCorrelator
 * ===============
 * Correlates Antivirus detections, behavioral signals, network telemetry,
 * and malicious artifacts with the MITRE ATT&CK Mobile Framework (Tactics, Techniques & Procedures).
 */

package com.kotsafe.security.model;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

public class MitreCorrelator {

    public static class MitreTtp implements Serializable {
        public String techniqueId;    // e.g. "T1437"
        public String tacticName;     // e.g. "Persistence"
        public String techniqueName;   // e.g. "Abuse Accessibility Features"
        public String badgeColor;     // e.g. "#DC2626"
        public String explanation;    // e.g. "Banking Trojan accessibility overlay hijack detected"
        public String mitreUrl;       // e.g. "https://attack.mitre.org/techniques/T1437/"

        public MitreTtp(String techniqueId, String tacticName, String techniqueName, String badgeColor, String explanation) {
            this.techniqueId = techniqueId;
            this.tacticName = tacticName;
            this.techniqueName = techniqueName;
            this.badgeColor = badgeColor != null ? badgeColor : "#E91E63";
            this.explanation = explanation;
            this.mitreUrl = "https://attack.mitre.org/techniques/" + techniqueId.replace(".", "/");
        }

        public String getSummaryBadge() {
            return "[" + techniqueId + " " + techniqueName + "]";
        }
    }

    /**
     * Correlates an AlertRecord directly with MITRE ATT&CK Mobile matrix TTPs.
     */
    public static List<MitreTtp> correlate(AlertRecord alert) {
        if (alert == null) return Collections.emptyList();
        List<MitreTtp> ttps = new ArrayList<>();
        if (alert.mitreTechniqueId != null && !alert.mitreTechniqueId.isEmpty()) {
            MitreMobileCatalog.MobileTechniqueDef def = MitreMobileCatalog.get(alert.mitreTechniqueId);
            if (def != null) {
                ttps.add(new MitreTtp(def.id, def.tactic.label, def.name, def.tactic.color, def.description));
                return ttps;
            }
        }
        AntivirusEvidenceItem dummy = new AntivirusEvidenceItem(
                alert.type.name(),
                alert.title != null ? alert.title : "",
                alert.sourceApp != null ? alert.sourceApp : "",
                alert.sourceApp != null ? alert.sourceApp : "",
                alert.severity == AlertRecord.Severity.HIGH ? AntivirusEvidenceItem.SEVERITY_MALICIOUS : AntivirusEvidenceItem.SEVERITY_SUSPICIOUS,
                alert.message != null ? alert.message : ""
        );
        return correlate(dummy);
    }

    /**
     * Correlates an AntivirusEvidenceItem with MITRE ATT&CK Mobile matrix TTPs.
     */
    public static List<MitreTtp> correlate(AntivirusEvidenceItem item) {
        if (item == null) return Collections.emptyList();
        List<MitreTtp> ttps = new ArrayList<>();

        String type = item.type != null ? item.type : "";
        String details = item.details != null ? item.details.toLowerCase(Locale.ROOT) : "";
        String title = item.title != null ? item.title.toLowerCase(Locale.ROOT) : "";
        String subtitle = item.subtitle != null ? item.subtitle.toLowerCase(Locale.ROOT) : "";
        String fullText = (type + " " + title + " " + subtitle + " " + details).toLowerCase(Locale.ROOT);

        // 1. Accessibility Service Abuse & Screenjacking / Keylogging
        if (fullText.contains("accessibility") || fullText.contains("screenjack") || fullText.contains("keylog") || fullText.contains("overlay")) {
            ttps.add(new MitreTtp("T1437", "Persistence & Privilege Escalation", "Abuse Accessibility Features", "#DC2626",
                    "Adversaries leverage Android Accessibility Services to read screen contents, capture user input, and intercept credentials."));
            ttps.add(new MitreTtp("T1411", "Credential Access", "Overlay Attack", "#BE123C",
                    "Malicious application generates deceptive overlay windows above targeted apps to phish banking or login credentials."));
            ttps.add(new MitreTtp("T1417", "Collection", "Input Capture (Keylogging)", "#1D4ED8",
                    "Intercepting keystrokes and sensitive text inputs across operating system user interfaces."));
        }

        // 2. Dynamic Code Loading & Obfuscated DEX Bytecode
        if (fullText.contains("dex") || fullText.contains("obfuscat") || fullText.contains("dynamic loading") || fullText.contains("structural")) {
            ttps.add(new MitreTtp("T1406", "Defense Evasion", "Obfuscated Files or Dynamic Code Loading", "#6D28D9",
                    "Malware conceals payloads using encrypted DEX bytecode, packing wrappers, or runtime reflective class invocation."));
            ttps.add(new MitreTtp("T1407", "Execution", "Malicious APK / Bytecode Execution", "#D97706",
                    "Executing compiled Dalvik/ART executable structures containing malicious capability routines."));
        }

        // 3. Ransomware Canary / Encrypted Artifact / Device Locker
        if (fullText.contains("ransomware") || fullText.contains("canary") || fullText.contains(".lock") || fullText.contains("crypt")) {
            ttps.add(new MitreTtp("T1471", "Impact", "Data Encrypted for Impact (Mobile Ransomware)", "#B91C1C",
                    "Adversaries encrypt documents, photos, or device storage to extort ransom payments from users."));
            ttps.add(new MitreTtp("T1447", "Impact", "Device Lockout / Extortion", "#B91C1C",
                    "Attempting to lock the user out of the mobile device or display permanent blocking splash screens."));
        }

        // 4. Double Extension Masquerading & Dropper Evasion
        if (fullText.contains("double extension") || fullText.contains("cloaked") || fullText.contains("masquerad")) {
            ttps.add(new MitreTtp("T1444", "Defense Evasion", "Masquerading (Double Extension Evasion)", "#6D28D9",
                    "Using misleading double file extensions (e.g. .pdf.apk) to trick users and security scanners into mistaking malicious binaries for harmless media."));
        }

        // 5. YARA Signature Threat Hit
        if (AntivirusEvidenceItem.TYPE_YARA_MATCH.equals(item.type) || fullText.contains("yara")) {
            if (ttps.stream().noneMatch(t -> "T1407".equals(t.techniqueId))) {
                ttps.add(new MitreTtp("T1407", "Execution", "Malicious Payload / YARA Signature Hit", "#D97706",
                        "Matched known malware signature patterns or threat family byte sequences."));
            }
        }

        // 6. Command & Control (C2) Communication & High-Risk Ports / DGA
        if (fullText.contains("c2") || fullText.contains("beacon") || fullText.contains("suspicious port") || AntivirusEvidenceItem.TYPE_SUSPICIOUS_PORT.equals(item.type)) {
            ttps.add(new MitreTtp("T1071.001", "Command and Control", "Application Layer Protocol: C2 Web Protocols", "#9333EA",
                    "Communicating with external command-and-control servers using recurring beaconing cadences or unverified HTTP/TCP channels."));
            ttps.add(new MitreTtp("T1436", "Command and Control", "Non-Standard Port Communication", "#9333EA",
                    "Establishing raw socket sessions over suspicious non-standard or backdoor ports."));
        }

        // 7. Dynamic Resolution / Dynamic DNS / Malicious Domain
        if (fullText.contains("dynamic dns") || fullText.contains("high-risk domain") || AntivirusEvidenceItem.TYPE_URL.equals(item.type)) {
            ttps.add(new MitreTtp("T1568", "Command and Control", "Dynamic Resolution (Fast Flux / DynDNS)", "#9333EA",
                    "Routing network traffic through volatile Dynamic DNS domains to evade fixed domain reputation blocklists."));
        }

        // 8. Sideloaded / Untrusted Installation
        if (fullText.contains("sideload") || fullText.contains("untrusted source") || fullText.contains("unknown source")) {
            ttps.add(new MitreTtp("T1475", "Initial Access", "Deliver Malicious App via Sideloading", "#DC2626",
                    "Application installed from third-party or untrusted sideload source bypassing Google Play Protect validation."));
        }

        // 9. Inbound Network Port Scanning / Honeypot
        if (fullText.contains("port scan") || fullText.contains("honeypot") || fullText.contains("inbound probe")) {
            ttps.add(new MitreTtp("T1595", "Reconnaissance", "Active Scanning / Port Sweep", "#7C3AED",
                    "Adversary probing local host or network interface for open listeners and vulnerable service daemons."));
        }

        // 10. Default Fallback for generic threats
        if (ttps.isEmpty()) {
            if (AntivirusEvidenceItem.SEVERITY_MALICIOUS.equals(item.severity)) {
                ttps.add(new MitreTtp("T1407", "Execution", "Malicious Binary / Artifact", "#DC2626",
                        "Identified malicious behavior or confirmed signature match within device telemetry."));
                ttps.add(new MitreTtp("T1041", "Exfiltration", "Exfiltration Over C2 Channel", "#E11D48",
                        "Potential unauthorized transmission of device telemetry to external infrastructure."));
            } else if (AntivirusEvidenceItem.SEVERITY_SUSPICIOUS.equals(item.severity)) {
                ttps.add(new MitreTtp("T1418", "Discovery", "Software & Environmental Discovery", "#0369A1",
                        "Heuristic anomaly identified during system and network behavioral auditing."));
            }
        }

        return ttps;
    }

    /**
     * Formats MITRE ATT&CK TTPs into a clean Markdown / text breakdown.
     */
    public static String formatTtpBreakdown(List<MitreTtp> ttps) {
        if (ttps == null || ttps.isEmpty()) return "No mapped MITRE ATT&CK TTPs.";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < ttps.size(); i++) {
            MitreTtp t = ttps.get(i);
            sb.append("• [").append(t.techniqueId).append("] ").append(t.tacticName).append(": ").append(t.techniqueName).append("\n");
            sb.append("  ↳ ").append(t.explanation);
            if (i < ttps.size() - 1) sb.append("\n\n");
        }
        return sb.toString();
    }

    /**
     * Formats MITRE ATT&CK TTPs into concise badge tags (e.g., "[T1437 Accessibility] [T1411 Overlay]").
     */
    public static String formatShortBadges(List<MitreTtp> ttps) {
        if (ttps == null || ttps.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (MitreTtp t : ttps) {
            sb.append("[").append(t.techniqueId).append(" ").append(t.techniqueName.split(" ")[0]).append("] ");
        }
        return sb.toString().trim();
    }
}
