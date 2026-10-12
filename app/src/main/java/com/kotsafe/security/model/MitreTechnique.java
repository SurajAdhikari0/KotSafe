/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 *
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.model;

import android.content.Context;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Represents a MITRE ATT&CK technique with detection and dynamic mapping state,
 * enriched with MITRE Mobile v15 and MITRE D3FEND countermeasure metadata.
 */
public class MitreTechnique {

    public enum Tactic {
        INITIAL_ACCESS("Initial Access", "#DC2626", 1),
        EXECUTION("Execution",          "#D97706", 2),
        PERSISTENCE("Persistence",      "#059669", 3),
        PRIVILEGE_ESC("Privilege Esc.", "#B45309", 4),
        DEFENSE_EVADE("Defense Evasion","#6D28D9", 5),
        CREDENTIAL("Credential Access","#BE123C", 6),
        DISCOVERY("Discovery",          "#0369A1", 7),
        LATERAL("Lateral Movement",     "#0F766E", 8),
        COLLECTION("Collection",        "#1D4ED8", 9),
        C2("Command & Control",         "#9333EA", 10),
        EXFIL("Exfiltration",           "#E11D48", 11),
        IMPACT("Impact",                "#B91C1C", 12),
        NETWORK_EFFECTS("Network Effects", "#0284C7", 13),
        RECONNAISSANCE("Reconnaissance", "#7C3AED", 14),
        RESOURCE_DEV("Resource Dev.",   "#0891B2", 15);

        public final String label;
        public final String color;
        public final int order;

        Tactic(String label, String color, int order) {
            this.label = label;
            this.color = color;
            this.order = order;
        }

        Tactic(String label, String color) {
            this(label, color, 99);
        }
    }

    public static final int STATUS_MONITORED     = 0; // Clean, sensor listening
    public static final int STATUS_DEFENDED      = 1; // Protected by firewall/YARA rule
    public static final int STATUS_SUSPICIOUS    = 2; // Heuristic anomaly observed
    public static final int STATUS_ACTIVE_THREAT = 3; // Active malware / C2 detected

    public final String  id;           // e.g. "T1071.001"
    public final String  name;         // e.g. "Application Layer Protocol: Web Protocols"
    public final Tactic  tactic;
    public final String  description;
    public final String  mitreUrl;
    public final String  mitigation;   // Recommended defense action
    public final String  d3fendId;     // e.g. "D3-OFC"
    public final String  d3fendName;   // e.g. "Outbound Flow Control"
    public boolean       isDetected;   // true if mapped to alerts or traffic
    public int           statusLevel;  // STATUS_*
    public String        evidence;     // detection explanation or mapped alert summary
    public final List<AlertRecord> mappedAlerts; // alerts specifically mapped to this technique

    public MitreTechnique(String id, String name, Tactic tactic,
                          String description, String mitigation,
                          String d3fendId, String d3fendName,
                          boolean isDetected, String evidence) {
        this.id           = id;
        this.name         = name;
        this.tactic       = tactic;
        this.description  = description;
        this.mitreUrl     = "https://attack.mitre.org/techniques/" + id.replace(".", "/");
        this.mitigation   = mitigation;
        this.d3fendId     = (d3fendId != null && !d3fendId.isEmpty()) ? d3fendId : "D3-APPV";
        this.d3fendName   = (d3fendName != null && !d3fendName.isEmpty()) ? d3fendName : "Application Security Inspection";
        this.isDetected   = isDetected;
        this.statusLevel  = isDetected ? STATUS_ACTIVE_THREAT : STATUS_MONITORED;
        this.evidence     = evidence;
        this.mappedAlerts = new ArrayList<>();
    }

    public MitreTechnique(String id, String name, Tactic tactic,
                          String description, String mitigation,
                          boolean isDetected, String evidence) {
        this(id, name, tactic, description, mitigation, "D3-APPV", "Application Security Inspection", isDetected, evidence);
    }

    public void addMappedAlert(AlertRecord alert) {
        if (alert == null) return;
        this.mappedAlerts.add(alert);
        this.isDetected = true;

        if (alert.isResolved()) {
            if (this.statusLevel < STATUS_DEFENDED) {
                this.statusLevel = STATUS_DEFENDED;
            }
        } else if (alert.severity == AlertRecord.Severity.HIGH) {
            this.statusLevel = STATUS_ACTIVE_THREAT;
        } else if (this.statusLevel < STATUS_SUSPICIOUS) {
            this.statusLevel = STATUS_SUSPICIOUS;
        }
    }

    public int getMappedAlertCount() {
        return mappedAlerts.size();
    }

    public String getStatusBadgeLabel() {
        switch (statusLevel) {
            case STATUS_ACTIVE_THREAT: return "🔴 THREAT DETECTED";
            case STATUS_SUSPICIOUS:    return "🟡 ANOMALY OBSERVED";
            case STATUS_DEFENDED:      return "🟢 DEFENDED & CONTAINED";
            case STATUS_MONITORED:
            default:                   return "🛡️ SENSOR ACTIVE";
        }
    }

    public int getStatusColor() {
        switch (statusLevel) {
            case STATUS_ACTIVE_THREAT: return 0xFFEF4444; // Red
            case STATUS_SUSPICIOUS:    return 0xFFF59E0B; // Amber
            case STATUS_DEFENDED:      return 0xFF10B981; // Emerald Green
            case STATUS_MONITORED:
            default:                   return 0xFF64748B; // Slate Gray
        }
    }

    /**
     * Checks if this technique matches user-specified query and filters.
     */
    public boolean matchesFilter(String query, String tacticName, Boolean detectedOnly) {
        if (detectedOnly != null && this.isDetected != detectedOnly) {
            return false;
        }

        if (tacticName != null && !tacticName.isEmpty() && !tacticName.equalsIgnoreCase("ALL")) {
            if (!this.tactic.name().equalsIgnoreCase(tacticName) &&
                !this.tactic.label.equalsIgnoreCase(tacticName)) {
                return false;
            }
        }

        if (query == null || query.trim().isEmpty()) {
            return true;
        }

        String q = query.trim().toLowerCase(Locale.ROOT);
        if (id.toLowerCase(Locale.ROOT).contains(q)) return true;
        if (name.toLowerCase(Locale.ROOT).contains(q)) return true;
        if (tactic.label.toLowerCase(Locale.ROOT).contains(q)) return true;
        if (description.toLowerCase(Locale.ROOT).contains(q)) return true;
        if (d3fendId.toLowerCase(Locale.ROOT).contains(q)) return true;
        if (d3fendName.toLowerCase(Locale.ROOT).contains(q)) return true;

        for (AlertRecord alert : mappedAlerts) {
            if (alert.title != null && alert.title.toLowerCase(Locale.ROOT).contains(q)) return true;
            if (alert.sourceApp != null && alert.sourceApp.toLowerCase(Locale.ROOT).contains(q)) return true;
        }

        return false;
    }

    // ── Built-in technique catalog with dynamic alert mapping ──────────────────

    public static List<MitreTechnique> getBuiltinTechniques() {
        return getTechniquesWithMappedAlerts(null);
    }

    private static Tactic mapMobileTactic(MitreMobileCatalog.MobileTactic mt) {
        switch (mt) {
            case INITIAL_ACCESS:       return Tactic.INITIAL_ACCESS;
            case EXECUTION:            return Tactic.EXECUTION;
            case PERSISTENCE:          return Tactic.PERSISTENCE;
            case PRIVILEGE_ESCALATION: return Tactic.PRIVILEGE_ESC;
            case DEFENSE_EVASION:      return Tactic.DEFENSE_EVADE;
            case CREDENTIAL_ACCESS:    return Tactic.CREDENTIAL;
            case DISCOVERY:            return Tactic.DISCOVERY;
            case LATERAL_MOVEMENT:     return Tactic.LATERAL;
            case COLLECTION:           return Tactic.COLLECTION;
            case COMMAND_AND_CONTROL:  return Tactic.C2;
            case EXFILTRATION:         return Tactic.EXFIL;
            case IMPACT:               return Tactic.IMPACT;
            case NETWORK_EFFECTS:      return Tactic.NETWORK_EFFECTS;
            default:                   return Tactic.DEFENSE_EVADE;
        }
    }

    /**
     * Returns the MITRE ATT&CK technique catalog mapped against active device alerts.
     */
    public static List<MitreTechnique> getTechniquesWithMappedAlerts(Context context) {
        List<MitreTechnique> list = new ArrayList<>();

        // 1. Ingest all authoritative Android ATT&CK techniques from MitreMobileCatalog
        for (MitreMobileCatalog.MobileTechniqueDef def : MitreMobileCatalog.getAllTechniques()) {
            list.add(new MitreTechnique(
                    def.id,
                    def.name,
                    mapMobileTactic(def.tactic),
                    def.description,
                    def.recommendedMitigation,
                    def.d3fendId,
                    def.d3fendName,
                    false,
                    "Sensor active • No anomalous activity observed"
            ));
        }

        // 2. Query AlertStore for live device incidents
        if (context != null) {
            try {
                AlertStore store = AlertStore.getInstance(context);
                List<AlertRecord> alerts = store.getAll();

                for (AlertRecord alert : alerts) {
                    mapAlertToTechniques(alert, list);
                }
            } catch (Exception ignored) {}
        }

        // 3. Final pass: update evidence strings and status levels
        for (MitreTechnique t : list) {
            if (!t.mappedAlerts.isEmpty()) {
                t.isDetected = true;
                int count = t.mappedAlerts.size();
                AlertRecord latest = t.mappedAlerts.get(0);
                String source = (latest.sourceApp != null && !latest.sourceApp.isEmpty()) ?
                        " (" + latest.sourceApp + ")" : "";
                t.evidence = "Observed in " + count + " active alert" + (count > 1 ? "s" : "") + ": \"" +
                        latest.title + "\"" + source;
            } else {
                t.isDetected = false;
                t.statusLevel = STATUS_MONITORED;
                t.evidence = "Sensor active • No anomalous activity observed";
            }
        }

        return list;
    }

    private static void mapAlertToTechniques(AlertRecord alert, List<MitreTechnique> techniques) {
        if (alert == null || techniques == null) return;

        // A. Direct Sensor Tagging Check (Strongest fidelity)
        if (alert.mitreTechniqueId != null && !alert.mitreTechniqueId.isEmpty()) {
            for (MitreTechnique t : techniques) {
                if (t.id.equalsIgnoreCase(alert.mitreTechniqueId)) {
                    t.addMappedAlert(alert);
                    return;
                }
            }
        }

        // B. Heuristic Pattern & Alert Type Mapping
        String title = alert.title != null ? alert.title.toLowerCase(Locale.ROOT) : "";
        String msg = alert.message != null ? alert.message.toLowerCase(Locale.ROOT) : "";
        String fullText = title + " " + msg;

        for (MitreTechnique t : techniques) {
            boolean mapped = false;

            if (alert.type == AlertRecord.AlertType.DNS_ANOMALY) {
                if (t.id.equals("T1071.004")) mapped = true;
                if (t.id.equals("T1036") && (fullText.contains("dga") || fullText.contains("masquerade"))) mapped = true;
            } else if (alert.type == AlertRecord.AlertType.MALWARE) {
                if (t.id.equals("T1071.001") && (fullText.contains("c2") || fullText.contains("beacon"))) mapped = true;
                if (t.id.equals("T1048.001") && (fullText.contains("exfil") || fullText.contains("upload"))) mapped = true;
                if (t.id.equals("T1475") && (fullText.contains("apk") || fullText.contains("sideload"))) mapped = true;
                if (t.id.equals("T1204")) mapped = true;
                if (t.id.equals("T1406") && (fullText.contains("dex") || fullText.contains("obfus"))) mapped = true;
                if (t.id.equals("T1407") && fullText.contains("runtime")) mapped = true;
            } else if (alert.type == AlertRecord.AlertType.FIREWALL_BLOCK) {
                if (t.id.equals("T1595") && (fullText.contains("port") || fullText.contains("scan") || fullText.contains("sweep"))) mapped = true;
                if (t.id.equals("T1090.003") && (fullText.contains("tor") || fullText.contains("proxy"))) mapped = true;
                if (t.id.equals("T1562.001")) mapped = true;
            } else if (alert.type == AlertRecord.AlertType.SMARTSCREEN) {
                if (t.id.equals("T1189")) mapped = true;
                if (t.id.equals("T1562.001")) mapped = true;
            } else if (alert.type == AlertRecord.AlertType.TLS_ERROR) {
                if (t.id.equals("T1573")) mapped = true;
            } else if (alert.type == AlertRecord.AlertType.ATTACK_PATTERN) {
                if (fullText.contains(t.id.toLowerCase(Locale.ROOT)) ||
                    fullText.contains(t.name.toLowerCase(Locale.ROOT))) {
                    mapped = true;
                }
            }

            // Keyword fallback mapping
            if (!mapped) {
                if (t.id.equals("T1437") && (fullText.contains("accessibility") || fullText.contains("screenjack"))) mapped = true;
                if (t.id.equals("T1411") && (fullText.contains("overlay") || fullText.contains("phish"))) mapped = true;
                if (t.id.equals("T1471") && (fullText.contains("ransomware") || fullText.contains("canary"))) mapped = true;
                if (t.id.equals("T1610") && (fullText.contains("rogue ap") || fullText.contains("evil twin") || fullText.contains("wifi"))) mapped = true;
                if (t.id.equals("T1626") && (fullText.contains("root") || fullText.contains("magisk") || fullText.contains("su binary"))) mapped = true;
                if (t.id.equals("T1430") && fullText.contains("surveillance")) mapped = true;
                if (t.id.equals("T1516") && fullText.contains("sim")) mapped = true;
            }

            if (mapped) {
                t.addMappedAlert(alert);
            }
        }
    }
}
