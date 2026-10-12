/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import org.json.JSONException;
import org.json.JSONObject;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/** Represents a single security alert event stored in the app's alert log. */
public class AlertRecord {

    public enum Severity { HIGH, MEDIUM, LOW, INFO }

    public enum AlertType {
        MALWARE("Malware Detected"),
        QUARANTINE("Quarantine Isolation"),
        FIREWALL_BLOCK("Firewall Block"),
        SMARTSCREEN("SmartScreen Alert"),
        TLS_ERROR("TLS / Certificate"),
        DNS_ANOMALY("DNS Anomaly"),
        ATTACK_PATTERN("ATT\u0026CK Pattern"),
        GENERAL("General");

        public final String label;
        AlertType(String label) { this.label = label; }
    }

    public final String     id;
    public final long       timestampMs;
    public final Severity   severity;
    public final AlertType  type;
    public final String     title;
    public String           message;
    public final String     sourceApp;   // package name or IP
    public boolean          dismissed;

    // Quarantine Specific Metadata & KotSafe Risk Acceptance
    public long    quarantineRecordId = -1L;
    public String  quarantineSha256   = null;
    public String  quarantinePath     = null;
    public boolean isReleased         = false;
    public boolean isResolved         = false;

    // Automatic Alert Aggregation & Similarity Merging
    public int  occurrenceCount = 1;
    public long firstSeenMs;
    public long lastSeenMs;
    public String mitreTechniqueId = null;

    // AI SOAR Pre-Triage Assessment & Autonomous Threat Scoring
    public String aiAssessment = null;
    public int    aiMaliciousProbability = -1; // -1 = un-triaged, 0-100 = score

    public void setQuarantineMetadata(long recordId, String sha256, String originalPath) {
        this.quarantineRecordId = recordId;
        this.quarantineSha256 = sha256;
        this.quarantinePath = originalPath;
    }

    public AlertRecord(String id, long timestampMs, Severity severity,
                       AlertType type, String title, String message, String sourceApp) {
        this.id              = id;
        this.timestampMs     = timestampMs;
        this.severity        = resolveRiskPriority(severity, type, title, message);
        this.type            = type;
        this.title           = title;
        this.message         = message;
        this.sourceApp       = sourceApp;
        this.dismissed       = false;
        this.firstSeenMs     = timestampMs;
        this.lastSeenMs      = timestampMs;
        this.occurrenceCount = 1;

        String t = (title != null ? title : "").toUpperCase(Locale.ROOT);
        String m = (message != null ? message : "").toUpperCase(Locale.ROOT);
        this.isResolved      = t.contains("RESOLVED") || t.contains("CONTAINED")
                || t.contains("NEUTRALIZED") || m.contains("NEUTRALIZED")
                || m.contains("AUTOMATICALLY NEUTRALIZED") || m.contains("BLOCKED AT FIREWALL LEVEL");
    }

    /**
     * Checks if this alert has been remediated, auto-contained, or released.
     */
    public boolean isResolved() {
        if (isResolved) return true;
        if (isReleased) return true;
        String t = title != null ? title.toUpperCase(Locale.ROOT) : "";
        String m = message != null ? message.toUpperCase(Locale.ROOT) : "";
        return t.contains("RESOLVED") || t.contains("CONTAINED") || t.contains("NEUTRALIZED")
                || m.contains("NEUTRALIZED") || m.contains("AUTOMATICALLY NEUTRALIZED")
                || m.contains("BLOCKED AT FIREWALL LEVEL");
    }

    public void markResolved(boolean resolved) {
        this.isResolved = resolved;
    }

    /**
     * Intelligent Risk Priority Classification Engine.
     * Guarantees that:
     * - HIGH: Confirmed Malware, Trojans, Spyware, Ransomware, RAT, C2 Beacons, Exploit hits, Quarantine events.
     * - MEDIUM: ATT&amp;CK Patterns, Reconnaissance/Port scans, Lateral Movement, TLS Certificate Errors, Heuristic anomalies.
     * - LOW: Policy firewall blocks, ad/tracker shield blocks, rate limiting, minor DNS anomalies.
     * - INFO: General informational/audit notices.
     */
    public static Severity resolveRiskPriority(Severity explicitSeverity, AlertType type, String title, String message) {
        String t = (title != null ? title : "").toLowerCase(Locale.ROOT);
        String m = (message != null ? message : "").toLowerCase(Locale.ROOT);

        // 1. Highest Priority (HIGH): Confirmed Malware, Trojans, Spyware, C2, Quarantine
        if (type == AlertType.MALWARE || type == AlertType.QUARANTINE
                || t.contains("malware") || m.contains("malware")
                || t.contains("trojan") || m.contains("trojan")
                || t.contains("spyware") || m.contains("spyware")
                || t.contains("pegasus") || m.contains("pegasus")
                || t.contains("predator") || m.contains("predator")
                || t.contains("ransomware") || m.contains("ransomware")
                || t.contains("backdoor") || m.contains("backdoor")
                || t.contains("rootkit") || m.contains("rootkit")
                || t.contains("c2 beacon") || m.contains("c2 beacon")
                || t.contains("c2 command") || m.contains("c2 command")
                || t.contains("exfiltration") || m.contains("exfiltration")
                || t.contains("exploit") || m.contains("exploit")
                || t.contains("quarantine") || m.contains("quarantine")) {
            return Severity.HIGH;
        }

        // 2. Medium Priority (MEDIUM): Attack Patterns, Reconnaissance, Port Scans, TLS Tampering, Phishing
        if (type == AlertType.ATTACK_PATTERN || type == AlertType.TLS_ERROR || type == AlertType.SMARTSCREEN
                || t.contains("port scan") || m.contains("port scan")
                || t.contains("reconnaissance") || m.contains("reconnaissance")
                || t.contains("lateral movement") || m.contains("lateral movement")
                || t.contains("brute force") || m.contains("brute force")
                || t.contains("attack pattern") || m.contains("attack pattern")
                || t.contains("certificate") || m.contains("certificate")
                || t.contains("ssl strip") || m.contains("ssl strip")
                || t.contains("phishing") || m.contains("phishing")
                || t.contains("dns tunnel") || m.contains("dns tunnel")) {
            return Severity.MEDIUM;
        }

        // 3. Low Priority (LOW): Routine Firewall Blocks, Rate Limits, Ad/Tracker Shield Blocks
        if (type == AlertType.FIREWALL_BLOCK || type == AlertType.DNS_ANOMALY
                || t.contains("firewall block") || m.contains("firewall block")
                || t.contains("rate limit") || m.contains("rate limit")
                || t.contains("flood guard") || m.contains("flood guard")
                || t.contains("adblock") || m.contains("adblock")
                || t.contains("tracker") || m.contains("tracker")) {
            return Severity.LOW;
        }

        // 4. Default to explicit severity if non-null, else LOW
        return explicitSeverity != null ? explicitSeverity : Severity.LOW;
    }

    /**
     * Priority weight score for sorting alerts (High/Malware first, then Medium, Low, Info).
     */
    public int getPriorityWeight() {
        switch (severity) {
            case HIGH:
                return (type == AlertType.MALWARE || type == AlertType.QUARANTINE) ? 100 : 90;
            case MEDIUM:
                return 60;
            case LOW:
                return 30;
            case INFO:
            default:
                return 10;
        }
    }

    /** Friendly relative timestamp string. */
    public String getFormattedTime() {
        long now = System.currentTimeMillis();
        long diff = now - timestampMs;
        if (diff < 60_000)   return "Just now";
        if (diff < 3_600_000) return (diff / 60_000) + "m ago";
        if (diff < 86_400_000) return (diff / 3_600_000) + "h ago";
        return new SimpleDateFormat("MMM d, HH:mm", Locale.getDefault()).format(new Date(timestampMs));
    }

    /**
     * Checks if another alert is similar enough to be automatically merged.
     * Criteria: same sourceApp, same AlertType, and matching title / core anomaly signature.
     */
    public boolean isSimilarTo(AlertRecord other) {
        if (other == null) return false;
        if (this.type != other.type) return false;

        // Match sourceApp (e.g. UID 1000 or com.package)
        String s1 = this.sourceApp != null ? this.sourceApp.trim() : "";
        String s2 = other.sourceApp != null ? other.sourceApp.trim() : "";
        if (!s1.equalsIgnoreCase(s2)) return false;

        // Match normalized title
        String t1 = this.title != null ? this.title.trim().toLowerCase(Locale.ROOT) : "";
        String t2 = other.title != null ? other.title.trim().toLowerCase(Locale.ROOT) : "";
        if (t1.equals(t2)) return true;

        // Check if both are KotEngine Anomaly alerts or DNS Tunneling alerts
        if (t1.contains("kotengine") && t2.contains("kotengine")) return true;
        if (t1.contains("dns tunneling") && t2.contains("dns tunneling")) return true;
        if (t1.contains("firewall block") && t2.contains("firewall block")) return true;

        return false;
    }

    /**
     * Merges a similar alert into this record, updating counts and time bounds.
     */
    public void mergeWith(AlertRecord other) {
        if (other == null) return;
        this.occurrenceCount += Math.max(1, other.occurrenceCount);
        if (other.timestampMs < this.firstSeenMs || this.firstSeenMs == 0) {
            this.firstSeenMs = other.timestampMs;
        }
        if (other.timestampMs > this.lastSeenMs) {
            this.lastSeenMs = other.timestampMs;
        }
        if (other.getPriorityWeight() > this.getPriorityWeight()) {
            // Upgrade severity if newer occurrence is more severe
            try {
                java.lang.reflect.Field f = AlertRecord.class.getDeclaredField("severity");
                f.setAccessible(true);
                f.set(this, other.severity);
            } catch (Exception ignored) {}
        }
    }

    // ── JSON serialization ───────────────────────────────────────────────────

    public JSONObject toJson() throws JSONException {
        JSONObject o = new JSONObject();
        o.put("id",          id);
        o.put("ts",          timestampMs);
        o.put("sev",         severity.name());
        o.put("type",        type.name());
        o.put("title",       title);
        o.put("message",     message);
        o.put("sourceApp",   sourceApp);
        o.put("dismissed",   dismissed);
        o.put("qRecId",      quarantineRecordId);
        if (quarantineSha256 != null) o.put("qSha", quarantineSha256);
        if (quarantinePath != null)   o.put("qPath", quarantinePath);
        o.put("isReleased",  isReleased);
        o.put("isResolved",  isResolved());
        o.put("count",       occurrenceCount);
        o.put("firstSeen",   firstSeenMs);
        o.put("lastSeen",    lastSeenMs);
        if (mitreTechniqueId != null) o.put("mitreId", mitreTechniqueId);
        if (aiAssessment != null) o.put("aiAssess", aiAssessment);
        if (aiMaliciousProbability >= 0) o.put("aiProb", aiMaliciousProbability);
        return o;
    }

    public static AlertRecord fromJson(JSONObject o) throws JSONException {
        AlertRecord r = new AlertRecord(
                o.getString("id"),
                o.getLong("ts"),
                Severity.valueOf(o.getString("sev")),
                AlertType.valueOf(o.getString("type")),
                o.getString("title"),
                o.getString("message"),
                o.optString("sourceApp", "")
        );
        r.dismissed = o.optBoolean("dismissed", false);
        r.quarantineRecordId = o.optLong("qRecId", -1L);
        r.quarantineSha256 = o.optString("qSha", null);
        r.quarantinePath = o.optString("qPath", null);
        r.isReleased = o.optBoolean("isReleased", false);
        r.isResolved = o.optBoolean("isResolved", r.isResolved());
        r.occurrenceCount = o.optInt("count", 1);
        r.firstSeenMs = o.optLong("firstSeen", r.timestampMs);
        r.lastSeenMs = o.optLong("lastSeen", r.timestampMs);
        r.mitreTechniqueId = o.optString("mitreId", null);
        r.aiAssessment = o.has("aiAssess") ? o.optString("aiAssess", null) : null;
        r.aiMaliciousProbability = o.optInt("aiProb", -1);
        return r;
    }
}
