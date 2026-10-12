/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;

import com.kotsafe.security.Log;
import com.kotsafe.security.Utils;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Unified AI Database Access Layer & Activity Bridge.
 *
 * Provides a standardized query and export interface across all security databases:
 *   - firewall_logs.db (Network flows, protocols, port activities)
 *   - url_visits.db (Domains, URLs, HTTP methods, visited destinations)
 *   - file_hashes.db (App binaries, storage files, SHA-256 hashes)
 *   - evidence.db (Forensic evidence, YARA matches, TI responses)
 *
 * Built for future on-device AI / ML models (sequence anomaly detectors, LLM telemetry summarizers,
 * and True-Positive classifiers) to analyze logs and correlate true positives.
 */
public class AiTelemetryBridge {
    private static final String TAG = "AiTelemetryBridge";
    private static final int MAX_MEMORY_LEDGER = 500;

    public static class AiActivityRecord {
        public long timestamp;
        public String category; // "NETWORK", "BROWSER", "FILE", "EVIDENCE"
        public String entity;   // IP, URL, Hash, Package
        public String packageName;
        public String details;
        public int riskScore;
        public String verdict;
        public boolean isSystemApp;
        public Map<String, Object> features = new HashMap<>();

        public JSONObject toJson() {
            JSONObject obj = new JSONObject();
            try {
                obj.put("timestamp", timestamp);
                obj.put("category", category);
                obj.put("entity", entity);
                obj.put("packageName", packageName != null ? packageName : "");
                obj.put("details", details != null ? details : "");
                obj.put("riskScore", riskScore);
                obj.put("verdict", verdict != null ? verdict : "SAFE");
                obj.put("isSystemApp", isSystemApp);
                JSONObject feat = new JSONObject();
                for (Map.Entry<String, Object> e : features.entrySet()) {
                    feat.put(e.getKey(), e.getValue());
                }
                obj.put("features", feat);
            } catch (Exception ignored) {}
            return obj;
        }
    }

    private static AiTelemetryBridge sInstance;
    private final Context mContext;
    private final List<AiActivityRecord> mRecentLedger;

    public static synchronized AiTelemetryBridge getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new AiTelemetryBridge(context.getApplicationContext());
        }
        return sInstance;
    }

    private AiTelemetryBridge(Context context) {
        mContext = context;
        mRecentLedger = Collections.synchronizedList(new ArrayList<>());
    }

    /**
     * Records parsed telemetry records into the real-time AI ledger.
     */
    public void recordBatch(List<TelemetryDataParser.TelemetryRecord> batch) {
        if (batch == null || batch.isEmpty()) return;
        synchronized (mRecentLedger) {
            for (TelemetryDataParser.TelemetryRecord tr : batch) {
                AiActivityRecord ar = new AiActivityRecord();
                ar.timestamp = tr.timestamp;
                ar.category = tr.source;
                ar.entity = tr.domain != null ? tr.domain : (tr.ip != null ? tr.ip : tr.packageName);
                ar.packageName = tr.packageName;
                ar.isSystemApp = tr.isSystemApp;
                ar.riskScore = tr.riskScore;
                ar.verdict = tr.verdict;
                ar.details = tr.method != null ? (tr.method + " " + (tr.url != null ? tr.url : "")) : "";
                ar.features.put("port", tr.port);
                ar.features.put("protocol", tr.protocol);
                ar.features.put("payloadBytes", tr.payloadBytes);
                ar.features.put("entropy", tr.entropy);
                ar.features.put("isBackground", tr.isBackground);

                mRecentLedger.add(ar);
                if (mRecentLedger.size() > MAX_MEMORY_LEDGER) {
                    mRecentLedger.remove(0);
                }
            }
        }
    }

    /**
     * Unified Query: pulls correlated events from all databases within a time window.
     */
    public List<AiActivityRecord> queryUnifiedActivity(long startTime, long endTime, String packageFilter, int limit) {
        List<AiActivityRecord> list = new ArrayList<>();

        // 1. In-memory recent events
        synchronized (mRecentLedger) {
            for (AiActivityRecord r : mRecentLedger) {
                if (r.timestamp >= startTime && r.timestamp <= endTime) {
                    if (packageFilter == null || packageFilter.isEmpty() || packageFilter.equals(r.packageName)) {
                        list.add(r);
                    }
                }
            }
        }

        // 2. Query URL Visits database
        try {
            UrlVisitDbHelper urlDb = UrlVisitDbHelper.getInstance(mContext);
            List<UrlVisitLog> visits = urlDb.getRecentVisits(limit);
            for (UrlVisitLog v : visits) {
                if (v.timestamp >= startTime && v.timestamp <= endTime) {
                    if (packageFilter == null || packageFilter.isEmpty() || packageFilter.equals(v.packageName)) {
                        AiActivityRecord rec = new AiActivityRecord();
                        rec.timestamp = v.timestamp;
                        rec.category = "BROWSER";
                        rec.entity = v.domain != null ? v.domain : v.url;
                        rec.packageName = v.packageName;
                        rec.isSystemApp = Utils.isSystemApp(mContext, v.packageName);
                        rec.riskScore = v.riskScore;
                        rec.verdict = v.verdict;
                        rec.details = v.method + " " + v.url;
                        list.add(rec);
                    }
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "URL visits query error: " + e.getMessage());
        }

        // 3. Query Evidence database
        try {
            EvidenceDbHelper eviDb = EvidenceDbHelper.getInstance(mContext);
            List<EvidenceDbHelper.EvidenceRecord> evidences = eviDb.getRecentEvidence(limit);
            for (EvidenceDbHelper.EvidenceRecord ev : evidences) {
                if (ev.timestamp >= startTime && ev.timestamp <= endTime) {
                    if (packageFilter == null || packageFilter.isEmpty() || packageFilter.equals(ev.packageName)) {
                        AiActivityRecord rec = new AiActivityRecord();
                        rec.timestamp = ev.timestamp;
                        rec.category = "EVIDENCE";
                        rec.entity = ev.iocValue;
                        rec.packageName = ev.packageName;
                        rec.isSystemApp = Utils.isSystemApp(mContext, ev.packageName);
                        rec.riskScore = ev.riskScore;
                        rec.verdict = ev.verdict;
                        rec.details = ev.title + " | " + ev.description;
                        rec.features.put("source", ev.source);
                        rec.features.put("type", ev.type);
                        list.add(rec);
                    }
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "Evidence query error: " + e.getMessage());
        }

        // Sort by timestamp descending and limit
        Collections.sort(list, (a, b) -> Long.compare(b.timestamp, a.timestamp));
        if (list.size() > limit) {
            return new ArrayList<>(list.subList(0, limit));
        }
        return list;
    }

    /**
     * Builds a System Baseline Profile of benign OS services and legitimate background activities.
     * Future AI models will compare new events against this baseline to eliminate false positives.
     */
    public JSONObject getSystemBaselineProfile() {
        JSONObject baseline = new JSONObject();
        try {
            Set<String> systemPackages = new HashSet<>();
            Set<String> systemWhitelistedDomains = new HashSet<>();
            SecurityBlocklistManager blMgr = SecurityBlocklistManager.getInstance(mContext);

            // Pull active file hashes of system apps
            FileHashDbHelper hashDb = FileHashDbHelper.getInstance(mContext);
            List<FileHashEntry> hashes = hashDb.queryHashes(null, "ALL", 500, 0);
            for (FileHashEntry h : hashes) {
                if (h.isSystemApp) {
                    systemPackages.add(h.packageName);
                }
            }

            baseline.put("systemPackagesCount", systemPackages.size());
            baseline.put("knownOfficialDomainsSupported", true);
            baseline.put("profileGeneratedAt", System.currentTimeMillis());
            baseline.put("baselineStatus", "ACTIVE_TRUSTED");
        } catch (Exception e) {
            Log.e(TAG, "getSystemBaselineProfile error: " + e.getMessage());
        }
        return baseline;
    }

    /**
     * Exports a structured JSON dataset covering the specified time window for AI model training or offline inference.
     */
    public boolean exportAiTrainingDataset(long timeWindowMs, File targetJsonFile) {
        long startTime = System.currentTimeMillis() - timeWindowMs;
        long endTime = System.currentTimeMillis();
        List<AiActivityRecord> records = queryUnifiedActivity(startTime, endTime, null, 1000);

        try (FileWriter writer = new FileWriter(targetJsonFile)) {
            JSONObject root = new JSONObject();
            root.put("schemaVersion", 1);
            root.put("exportedAt", System.currentTimeMillis());
            root.put("timeWindowMs", timeWindowMs);
            root.put("baseline", getSystemBaselineProfile());

            JSONArray eventsArr = new JSONArray();
            for (AiActivityRecord r : records) {
                eventsArr.put(r.toJson());
            }
            root.put("events", eventsArr);

            writer.write(root.toString(2));
            writer.flush();
            Log.i(TAG, "AI training dataset exported successfully: " + targetJsonFile.getAbsolutePath() + " (" + records.size() + " events)");
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Failed to export AI dataset: " + e.getMessage());
            return false;
        }
    }

    /**
     * Generates a structured multi-domain forensic investigation dossier for AI security analysis.
     */
    public JSONObject generateForensicDossier(String packageName) {
        JSONObject dossier = new JSONObject();
        try {
            dossier.put("package", packageName != null ? packageName : "Unknown");
            dossier.put("timestamp", System.currentTimeMillis());

            // 1. App Identity
            com.kotsafe.security.security.identity.AppIdentityEngine.AppIdentity identity =
                    com.kotsafe.security.security.identity.AppIdentityEngine.getInstance(mContext).resolvePackage(packageName);
            if (identity != null) {
                JSONObject idObj = new JSONObject();
                idObj.put("appName", identity.appLabel);
                idObj.put("uid", identity.uid);
                idObj.put("installer", identity.installer);
                idObj.put("isSideloaded", identity.isSideloaded);
                idObj.put("isSystemApp", identity.isSystemApp);
                idObj.put("certSha256", identity.certSha256);
                idObj.put("riskScore", identity.currentRiskScore);
                idObj.put("verdict", identity.verdict);
                dossier.put("identity", idObj);
            }

            // 2. Evidence Graph Causal Storyline
            String storyline = com.kotsafe.security.security.graph.EvidenceGraph.getInstance().buildForensicStoryline(packageName);
            dossier.put("evidenceStoryline", storyline);

            // 3. App Behavior Lifecycle Chain
            List<com.kotsafe.security.security.graph.AppBehaviorGraph.BehaviorNode> lifecycle =
                    com.kotsafe.security.security.graph.AppBehaviorGraph.getInstance().getLifecycleChain(packageName);
            JSONArray lifecycleArr = new JSONArray();
            for (com.kotsafe.security.security.graph.AppBehaviorGraph.BehaviorNode node : lifecycle) {
                JSONObject n = new JSONObject();
                n.put("timestamp", node.timestamp);
                n.put("eventType", node.eventType);
                n.put("description", node.description);
                n.put("severity", node.severity.name());
                lifecycleArr.put(n);
            }
            dossier.put("behaviorLifecycleChain", lifecycleArr);

            // 4. Device Posture Context
            DeviceSecurityEngine.DevicePosture posture = DeviceSecurityEngine.evaluate(mContext);
            JSONObject postObj = new JSONObject();
            postObj.put("postureScore", posture.overallScore);
            postObj.put("patchDate", posture.securityPatchDate);
            postObj.put("isEncrypted", posture.isEncrypted);
            postObj.put("isAdbEnabled", posture.isAdbEnabled);
            dossier.put("devicePosture", postObj);

        } catch (Exception e) {
            Log.e(TAG, "generateForensicDossier error: " + e.getMessage());
        }
        return dossier;
    }
}
