/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 *
 * UnifiedIncidentTimeline — Phase 4 Forensic Incident Timeline
 *
 * Aggregates ALL security events from every subsystem into a single
 * chronological event stream optimised for forensic analysis:
 *
 *   Source subsystems:
 *     - IPS Exploit Signature hits          (IpsEngine)
 *     - DNS Sinkhole / tunnel detections    (DnsSinkholeResponder / DohDecoder)
 *     - Port Scan / lateral movement        (ReconnaissanceDetector)
 *     - TLS JA3 fingerprint matches         (Ja3Fingerprinter)
 *     - Web Category policy blocks/warns    (WebCategoryEngine)
 *     - Firewall block rule triggers        (NetworkSecurityMonitor)
 *     - Rate-limit / flood-guard events     (TokenBucketRateLimiter)
 *     - General security alerts             (AlertStore)
 *
 * Storage:
 *   - Kept in a bounded in-memory ring buffer (last MAX_EVENTS events)
 *   - Persisted to SQLite via IncidentTimelineDb for cross-session forensics
 *   - Listeners are notified on the background thread that inserted the event
 *
 * Thread safety: all public methods are thread-safe.
 */

package com.kotsafe.security.model;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

import com.kotsafe.security.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

public class UnifiedIncidentTimeline {

    private static final String TAG = "UnifiedIncidentTimeline";
    private static final int MAX_EVENTS = 500;  // ring-buffer capacity

    // ── Event Type ────────────────────────────────────────────────────────────

    public enum EventType {
        IPS_HIT("IPS Exploit Hit"),
        DNS_SINKHOLE("DNS Sinkhole"),
        DNS_TUNNEL("DNS Tunnel Detected"),
        PORT_SCAN("Port Scan / Recon"),
        LATERAL_MOVEMENT("Lateral Movement"),
        JA3_MALICIOUS("Malicious TLS JA3"),
        WEB_CATEGORY_BLOCK("Web Category Block"),
        WEB_CATEGORY_WARN("Web Category Warning"),
        FIREWALL_BLOCK("Firewall Block"),
        RATE_LIMIT("Rate Limit / Flood Guard"),
        THREAT_INTEL("Threat Intelligence Alert"),
        HEURISTIC_ANOMALY("Heuristic Anomaly"),
        MALWARE_DETECTED("Malware Detected"),
        APP_INSTALL("App Installed/Updated"),
        APP_PERMISSION_CHANGE("App Permission Change"),
        SENSITIVE_CAPABILITY("High-Risk Permission Invoked"),
        CERTIFICATE_ANOMALY("Certificate Anomaly"),
        BEHAVIORAL_CORRELATION("EDR Behavioral Correlation"),
        DEVICE_POSTURE_CHANGE("Device Posture Alert"),
        GENERAL_ALERT("Security Alert");

        public final String label;
        EventType(String label) { this.label = label; }
    }

    // ── Severity ──────────────────────────────────────────────────────────────

    public enum Severity { CRITICAL, HIGH, MEDIUM, LOW, INFO }

    // ── IncidentEvent ─────────────────────────────────────────────────────────

    public static class IncidentEvent {
        public final String    id;
        public final long      timestampMs;
        public final EventType type;
        public final Severity  severity;
        public final String    title;
        public final String    detail;
        public final String    sourceApp;       // package name or IP
        public final String    target;          // domain / IP / hash that triggered event
        public final String    mitreTechnique;  // e.g. "T1046", "T1071.001"
        public final int       riskScore;       // 0-100

        // For correlation: links to other events in the same incident cluster
        public String          correlationId;

        public IncidentEvent(Builder b) {
            this.id             = b.id;
            this.timestampMs    = b.timestampMs;
            this.type           = b.type;
            this.severity       = b.severity;
            this.title          = b.title;
            this.detail         = b.detail;
            this.sourceApp      = b.sourceApp;
            this.target         = b.target;
            this.mitreTechnique = b.mitreTechnique;
            this.riskScore      = b.riskScore;
            this.correlationId  = b.correlationId;
        }

        public JSONObject toJson() {
            JSONObject o = new JSONObject();
            try {
                o.put("id",          id);
                o.put("ts",          timestampMs);
                o.put("type",        type.name());
                o.put("severity",    severity.name());
                o.put("title",       title);
                o.put("detail",      detail != null ? detail : "");
                o.put("sourceApp",   sourceApp != null ? sourceApp : "");
                o.put("target",      target != null ? target : "");
                o.put("mitre",       mitreTechnique != null ? mitreTechnique : "");
                o.put("risk",        riskScore);
                o.put("corrId",      correlationId != null ? correlationId : "");
            } catch (JSONException ignored) {}
            return o;
        }

        /** Human-readable timestamp for UI display. */
        public String getFormattedTime() {
            long diff = System.currentTimeMillis() - timestampMs;
            if (diff < 60_000)    return "Just now";
            if (diff < 3_600_000) return (diff / 60_000) + "m ago";
            if (diff < 86_400_000)return (diff / 3_600_000) + "h ago";
            return new java.text.SimpleDateFormat("MMM d, HH:mm",
                    java.util.Locale.getDefault()).format(new java.util.Date(timestampMs));
        }

        // ── Builder ───────────────────────────────────────────────────────────

        public static class Builder {
            final String    id          = UUID.randomUUID().toString();
            long            timestampMs = System.currentTimeMillis();
            EventType       type        = EventType.GENERAL_ALERT;
            Severity        severity    = Severity.MEDIUM;
            String          title       = "";
            String          detail;
            String          sourceApp;
            String          target;
            String          mitreTechnique;
            int             riskScore   = 50;
            String          correlationId;

            public Builder type(EventType t)         { this.type          = t;  return this; }
            public Builder severity(Severity s)      { this.severity      = s;  return this; }
            public Builder title(String t)           { this.title         = t;  return this; }
            public Builder detail(String d)          { this.detail        = d;  return this; }
            public Builder sourceApp(String a)       { this.sourceApp     = a;  return this; }
            public Builder target(String t)          { this.target        = t;  return this; }
            public Builder mitre(String m)           { this.mitreTechnique= m;  return this; }
            public Builder risk(int r)               { this.riskScore     = r;  return this; }
            public Builder correlationId(String c)   { this.correlationId = c;  return this; }
            public Builder timestamp(long ts)        { this.timestampMs   = ts; return this; }
            public IncidentEvent build()             { return new IncidentEvent(this); }
        }
    }

    // ── Listener interface ────────────────────────────────────────────────────

    public interface TimelineListener {
        void onEventAdded(IncidentEvent event);
    }

    // ── Singleton ─────────────────────────────────────────────────────────────

    private static volatile UnifiedIncidentTimeline sInstance;

    public static UnifiedIncidentTimeline getInstance(Context context) {
        if (sInstance == null) {
            synchronized (UnifiedIncidentTimeline.class) {
                if (sInstance == null) {
                    sInstance = new UnifiedIncidentTimeline(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    // ── State ─────────────────────────────────────────────────────────────────

    private final Context mContext;
    private final Deque<IncidentEvent>              mRingBuffer  = new ArrayDeque<>(MAX_EVENTS + 1);
    private final CopyOnWriteArrayList<TimelineListener> mListeners = new CopyOnWriteArrayList<>();
    private final TimelineDbHelper                  mDb;

    private UnifiedIncidentTimeline(Context ctx) {
        mContext = ctx;
        mDb = new TimelineDbHelper(ctx);
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /** Add an event to the timeline. Thread-safe. */
    public void record(IncidentEvent event) {
        if (event == null) return;

        synchronized (mRingBuffer) {
            mRingBuffer.addFirst(event);
            if (mRingBuffer.size() > MAX_EVENTS) mRingBuffer.removeLast();
        }

        // Persist asynchronously
        try {
            mDb.insert(event);
        } catch (Exception e) {
            Log.w(TAG, "DB insert error: " + e.getMessage());
        }

        // Forward to Enterprise SIEM telemetry spool if configured
        try {
            SiemTelemetryForwarder.getInstance(mContext).spoolIncident(event);
        } catch (Exception ignored) {}

        // Notify listeners
        for (TimelineListener l : mListeners) {
            try { l.onEventAdded(event); } catch (Exception ignored) {}
        }

        Log.d(TAG, "[TIMELINE] " + event.type.name() + " | " + event.title
                + " | risk=" + event.riskScore);
    }

    /** Convenience builder shortcut. */
    public void record(IncidentEvent.Builder builder) {
        record(builder.build());
    }

    /** Get a snapshot of the in-memory ring buffer (newest first). */
    public List<IncidentEvent> getRecentEvents() {
        synchronized (mRingBuffer) {
            return new ArrayList<>(mRingBuffer);
        }
    }

    /**
     * Get events filtered by type (newest first).
     */
    public List<IncidentEvent> getEventsByType(EventType type) {
        List<IncidentEvent> result = new ArrayList<>();
        synchronized (mRingBuffer) {
            for (IncidentEvent e : mRingBuffer) {
                if (e.type == type) result.add(e);
            }
        }
        return result;
    }

    /**
     * Get events for a specific source app or target (newest first).
     */
    public List<IncidentEvent> getEventsForTarget(String target) {
        List<IncidentEvent> result = new ArrayList<>();
        if (target == null) return result;
        synchronized (mRingBuffer) {
            for (IncidentEvent e : mRingBuffer) {
                if (target.equals(e.target) || target.equals(e.sourceApp)) result.add(e);
            }
        }
        return result;
    }

    /** Get events from DB for a specific time range (for forensic export). */
    public List<IncidentEvent> getHistoricalEvents(long fromMs, long toMs, int limit) {
        return mDb.query(fromMs, toMs, limit);
    }

    /** Persisted permission history for one package, newest first. */
    public List<IncidentEvent> getPermissionEventsForApp(String packageName, int limit) {
        if (packageName == null || packageName.isEmpty() || limit <= 0) return Collections.emptyList();
        return mDb.queryForSourceApp(packageName, EventType.APP_PERMISSION_CHANGE, limit);
    }

    /** Count total events in the ring buffer. */
    public int getEventCount() {
        synchronized (mRingBuffer) { return mRingBuffer.size(); }
    }

    /** Clear the in-memory ring buffer (does NOT touch SQLite). */
    public void clearMemory() {
        synchronized (mRingBuffer) { mRingBuffer.clear(); }
    }

    public void addListener(TimelineListener l)    { if (l != null) mListeners.add(l); }
    public void removeListener(TimelineListener l) { mListeners.remove(l); }

    // ── Static convenience factory methods ────────────────────────────────────

    /** Record an IPS exploit signature hit. */
    public void recordIpsHit(String packageName, String target, String ruleName, int riskScore) {
        record(new IncidentEvent.Builder()
                .type(EventType.IPS_HIT)
                .severity(riskScore >= 80 ? Severity.CRITICAL : Severity.HIGH)
                .title("IPS: " + ruleName)
                .detail("Exploit signature matched for " + target)
                .sourceApp(packageName)
                .target(target)
                .mitre("T1190")
                .risk(riskScore));
    }

    /** Record a DNS sinkhole event. */
    public void recordDnsSinkhole(String domain, String packageName) {
        record(new IncidentEvent.Builder()
                .type(EventType.DNS_SINKHOLE)
                .severity(Severity.HIGH)
                .title("DNS Sinkhole: " + domain)
                .detail("Malicious domain blocked at DNS resolution — sinkholed to 0.0.0.0")
                .sourceApp(packageName)
                .target(domain)
                .mitre("T1071.004")
                .risk(90));
    }

    /** Record a DNS tunnel detection. */
    public void recordDnsTunnel(String domain, String packageName) {
        record(new IncidentEvent.Builder()
                .type(EventType.DNS_TUNNEL)
                .severity(Severity.HIGH)
                .title("DNS Tunnel: " + domain)
                .detail("High-entropy DNS query indicative of data exfiltration via DNS")
                .sourceApp(packageName)
                .target(domain)
                .mitre("T1048.003")
                .risk(85));
    }

    /** Record a port scan detection. */
    public void recordPortScan(String sourceIp, int portCount, String packageName) {
        record(new IncidentEvent.Builder()
                .type(EventType.PORT_SCAN)
                .severity(Severity.MEDIUM)
                .title("Port Scan from " + sourceIp)
                .detail("Port probe velocity exceeded threshold: " + portCount + " distinct ports")
                .sourceApp(packageName)
                .target(sourceIp)
                .mitre("T1046")
                .risk(65));
    }

    /** Record lateral movement detection. */
    public void recordLateralMovement(String sourceIp, int hostCount) {
        record(new IncidentEvent.Builder()
                .type(EventType.LATERAL_MOVEMENT)
                .severity(Severity.HIGH)
                .title("Lateral Movement: " + sourceIp)
                .detail("LAN sweep detected: " + hostCount + " distinct hosts probed (MITRE T1021)")
                .target(sourceIp)
                .mitre("T1021")
                .risk(80));
    }

    /** Record a malicious JA3 fingerprint match. */
    public void recordJa3Match(String ja3, String toolName, String category, String packageName) {
        record(new IncidentEvent.Builder()
                .type(EventType.JA3_MALICIOUS)
                .severity(Severity.HIGH)
                .title("C2 Client Fingerprint: " + toolName)
                .detail("JA3=" + ja3 + " matches known " + category + " C2 toolkit")
                .sourceApp(packageName)
                .target(ja3)
                .mitre("T1071.001")
                .risk(95));
    }

    /** Record a web category policy block. */
    public void recordWebCategoryBlock(String domain, WebCategoryEngine.Category category,
                                       String packageName) {
        record(new IncidentEvent.Builder()
                .type(EventType.WEB_CATEGORY_BLOCK)
                .severity(Severity.MEDIUM)
                .title("Web Block: " + category.label + " — " + domain)
                .detail("Domain blocked by web category policy: " + category.label)
                .sourceApp(packageName)
                .target(domain)
                .mitre("T1071.001")
                .risk(category.defaultRisk));
    }

    /** Record a web category policy warning. */
    public void recordWebCategoryWarn(String domain, WebCategoryEngine.Category category,
                                      String packageName) {
        record(new IncidentEvent.Builder()
                .type(EventType.WEB_CATEGORY_WARN)
                .severity(Severity.LOW)
                .title("Web Warning: " + category.label + " — " + domain)
                .detail("Domain flagged by web category policy: " + category.label)
                .sourceApp(packageName)
                .target(domain)
                .risk(category.defaultRisk / 2));
    }

    /** Record a firewall rule block. */
    public void recordFirewallBlock(String target, String reason, String packageName, int riskScore) {
        record(new IncidentEvent.Builder()
                .type(EventType.FIREWALL_BLOCK)
                .severity(riskScore >= 75 ? Severity.HIGH : Severity.MEDIUM)
                .title("Firewall Block: " + target)
                .detail(reason != null ? reason : "Blocked by firewall rule")
                .sourceApp(packageName)
                .target(target)
                .risk(riskScore));
    }

    /** Record a rate-limit / flood-guard event. */
    public void recordRateLimit(String key, boolean quarantined, String packageName) {
        record(new IncidentEvent.Builder()
                .type(EventType.RATE_LIMIT)
                .severity(quarantined ? Severity.HIGH : Severity.MEDIUM)
                .title(quarantined ? "Flood Guard Quarantine: " + key : "Rate Limit: " + key)
                .detail(quarantined
                        ? "Connection rate exceeded flood-guard threshold; app/IP quarantined"
                        : "Token bucket exhausted — connection throttled")
                .sourceApp(packageName)
                .target(key)
                .mitre("T1498")
                .risk(quarantined ? 70 : 40));
    }

    // ── SQLite Persistence ────────────────────────────────────────────────────

    private static final class TimelineDbHelper extends SQLiteOpenHelper {
        private static final String DB_NAME    = "incident_timeline.db";
        private static final int    DB_VERSION = 1;
        private static final String TABLE      = "timeline";

        private static final String COL_ID        = "event_id";
        private static final String COL_TS        = "ts";
        private static final String COL_TYPE      = "type";
        private static final String COL_SEVERITY  = "severity";
        private static final String COL_TITLE     = "title";
        private static final String COL_DETAIL    = "detail";
        private static final String COL_SRC_APP   = "src_app";
        private static final String COL_TARGET    = "target";
        private static final String COL_MITRE     = "mitre";
        private static final String COL_RISK      = "risk";
        private static final String COL_CORR_ID   = "corr_id";

        private static final String CREATE_SQL =
                "CREATE TABLE IF NOT EXISTS " + TABLE + " ("
                + COL_ID       + " TEXT PRIMARY KEY, "
                + COL_TS       + " INTEGER NOT NULL, "
                + COL_TYPE     + " TEXT NOT NULL, "
                + COL_SEVERITY + " TEXT NOT NULL, "
                + COL_TITLE    + " TEXT NOT NULL, "
                + COL_DETAIL   + " TEXT, "
                + COL_SRC_APP  + " TEXT, "
                + COL_TARGET   + " TEXT, "
                + COL_MITRE    + " TEXT, "
                + COL_RISK     + " INTEGER DEFAULT 0, "
                + COL_CORR_ID  + " TEXT"
                + ");";

        private static final String IDX_TS_SQL =
                "CREATE INDEX IF NOT EXISTS idx_tl_ts ON " + TABLE + "(" + COL_TS + " DESC);";

        TimelineDbHelper(Context ctx) {
            super(ctx, DB_NAME, null, DB_VERSION);
        }

        @Override
        public void onCreate(SQLiteDatabase db) {
            db.execSQL(CREATE_SQL);
            db.execSQL(IDX_TS_SQL);
        }

        @Override
        public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
            db.execSQL("DROP TABLE IF EXISTS " + TABLE);
            onCreate(db);
        }

        void insert(IncidentEvent event) {
            ContentValues cv = new ContentValues();
            cv.put(COL_ID,       event.id);
            cv.put(COL_TS,       event.timestampMs);
            cv.put(COL_TYPE,     event.type.name());
            cv.put(COL_SEVERITY, event.severity.name());
            cv.put(COL_TITLE,    event.title);
            cv.put(COL_DETAIL,   event.detail != null ? event.detail : "");
            cv.put(COL_SRC_APP,  event.sourceApp != null ? event.sourceApp : "");
            cv.put(COL_TARGET,   event.target != null ? event.target : "");
            cv.put(COL_MITRE,    event.mitreTechnique != null ? event.mitreTechnique : "");
            cv.put(COL_RISK,     event.riskScore);
            cv.put(COL_CORR_ID,  event.correlationId != null ? event.correlationId : "");
            getWritableDatabase().insertOrThrow(TABLE, null, cv);

            // Retention: keep at most 10 000 rows, delete oldest
            getWritableDatabase().execSQL(
                    "DELETE FROM " + TABLE + " WHERE " + COL_TS +
                    " <= (SELECT " + COL_TS + " FROM " + TABLE +
                    " ORDER BY " + COL_TS + " DESC LIMIT 1 OFFSET 10000)");
        }

        List<IncidentEvent> query(long fromMs, long toMs, int limit) {
            List<IncidentEvent> list = new ArrayList<>();
            String sel = COL_TS + " BETWEEN ? AND ?";
            String[] args = { String.valueOf(fromMs), String.valueOf(toMs) };
            try (Cursor c = getReadableDatabase().query(
                    TABLE, null, sel, args, null, null,
                    COL_TS + " DESC", String.valueOf(limit))) {
                while (c != null && c.moveToNext()) {
                    try {
                        IncidentEvent.Builder b = new IncidentEvent.Builder()
                                .type(EventType.valueOf(c.getString(c.getColumnIndexOrThrow(COL_TYPE))))
                                .severity(Severity.valueOf(c.getString(c.getColumnIndexOrThrow(COL_SEVERITY))))
                                .title(c.getString(c.getColumnIndexOrThrow(COL_TITLE)))
                                .detail(c.getString(c.getColumnIndexOrThrow(COL_DETAIL)))
                                .sourceApp(c.getString(c.getColumnIndexOrThrow(COL_SRC_APP)))
                                .target(c.getString(c.getColumnIndexOrThrow(COL_TARGET)))
                                .mitre(c.getString(c.getColumnIndexOrThrow(COL_MITRE)))
                                .risk(c.getInt(c.getColumnIndexOrThrow(COL_RISK)))
                                .correlationId(c.getString(c.getColumnIndexOrThrow(COL_CORR_ID)))
                                .timestamp(c.getLong(c.getColumnIndexOrThrow(COL_TS)));
                        list.add(b.build());
                    } catch (Exception ignored) {}
                }
            } catch (Exception e) {
                Log.w("TimelineDb", "query error: " + e.getMessage());
            }
            return list;
        }

        List<IncidentEvent> queryForSourceApp(String packageName, EventType type, int limit) {
            List<IncidentEvent> list = new ArrayList<>();
            String selection = COL_SRC_APP + "=? AND " + COL_TYPE + "=?";
            String[] args = { packageName, type.name() };
            try (Cursor c = getReadableDatabase().query(
                    TABLE, null, selection, args, null, null,
                    COL_TS + " DESC", String.valueOf(limit))) {
                while (c != null && c.moveToNext()) {
                    try {
                        IncidentEvent.Builder builder = new IncidentEvent.Builder()
                                .type(EventType.valueOf(c.getString(c.getColumnIndexOrThrow(COL_TYPE))))
                                .severity(Severity.valueOf(c.getString(c.getColumnIndexOrThrow(COL_SEVERITY))))
                                .title(c.getString(c.getColumnIndexOrThrow(COL_TITLE)))
                                .detail(c.getString(c.getColumnIndexOrThrow(COL_DETAIL)))
                                .sourceApp(c.getString(c.getColumnIndexOrThrow(COL_SRC_APP)))
                                .target(c.getString(c.getColumnIndexOrThrow(COL_TARGET)))
                                .mitre(c.getString(c.getColumnIndexOrThrow(COL_MITRE)))
                                .risk(c.getInt(c.getColumnIndexOrThrow(COL_RISK)))
                                .correlationId(c.getString(c.getColumnIndexOrThrow(COL_CORR_ID)))
                                .timestamp(c.getLong(c.getColumnIndexOrThrow(COL_TS)));
                        list.add(builder.build());
                    } catch (Exception ignored) {}
                }
            } catch (Exception e) {
                Log.w("TimelineDb", "permission history query error: " + e.getMessage());
            }
            return list;
        }
    }
}
