/*
 * This file is part of KotSafe.
 * KotSafe Autonomous AI Security Operations Center (SOAR) Engine.
 */

package com.kotsafe.security.ai;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import com.kotsafe.security.Log;
import com.kotsafe.security.model.AlertRecord;
import com.kotsafe.security.model.AlertStore;
import com.kotsafe.security.model.SecurityNotificationHub;
import com.kotsafe.security.model.SecurityRulesDb;
import com.kotsafe.security.model.SiemTelemetryForwarder;

import java.util.Locale;
import java.util.UUID;
import java.util.LinkedHashMap;
import android.os.SystemClock;
import com.kotsafe.security.CaptureService;
import com.kotsafe.security.model.KotSafeCloudProvider;
import com.kotsafe.security.model.ThreatIntelProvider;
import java.util.concurrent.ExecutorService;

/**
 * Autonomous AI SOC Incident Analyst & SOAR Engine (Security Orchestration, Automation, and Response).
 * Continuously audits threat signals (Mercenary Spyware, C2 beacons, high-entropy exfiltration,
 * zero-click bursts, and malicious flow anomalies), generates threat assessments,
 * and saves firewall rules for network indicators confirmed by KotSafe intelligence.
 */
public class AutonomousSocAnalyst {

    private static final String TAG = "AutonomousSocAnalyst";
    private static volatile AutonomousSocAnalyst sInstance;

    private final Context mContext;
    private final AiConfig mAiConfig;
    private final SecurityRulesDb mRulesDb;
    private final AlertStore mAlertStore;
    private final SecurityNotificationHub mNotificationHub;
    private final ExecutorService mExecutor = new java.util.concurrent.ThreadPoolExecutor(
            1, 1, 0L, java.util.concurrent.TimeUnit.MILLISECONDS,
            new java.util.concurrent.ArrayBlockingQueue<>(64));
    private final Handler mMainHandler = new Handler(Looper.getMainLooper());
    private final LinkedHashMap<String, Long> mRecentIncidents = new LinkedHashMap<>();
    private static final long INCIDENT_COOLDOWN_MS = 5 * 60 * 1000L;

    public static class ThreatIncident {
        public final String ioc;                // Domain, IP, Package Name, or Hash
        public final String iocType;            // DOMAIN | IP | APP | HASH
        public final String threatCategory;     // MERCENARY_SPYWARE | C2_BEACON | ZERO_CLICK | DATA_EXFILTRATION | MALICIOUS_FLOW
        public final String headline;           // Short title
        public final String technicalDetails;   // Forensic narrative
        public final String sourceApp;          // Originating app (e.g. WhatsApp, Browser)
        public final int maliciousProbability;  // 0 - 100
        public final String mitreTechnique;     // e.g. T1071.001, T1048

        public ThreatIncident(String ioc, String iocType, String threatCategory,
                              String headline, String technicalDetails, String sourceApp,
                              int maliciousProbability, String mitreTechnique) {
            this.ioc = ioc;
            this.iocType = iocType != null ? iocType.toUpperCase(Locale.ROOT) : "DOMAIN";
            this.threatCategory = threatCategory;
            this.headline = headline;
            this.technicalDetails = technicalDetails;
            this.sourceApp = sourceApp != null ? sourceApp : "System";
            this.maliciousProbability = maliciousProbability;
            this.mitreTechnique = mitreTechnique != null ? mitreTechnique : "T1071";
        }
    }

    public static class RemediationVerdict {
        public final boolean autoResolved;
        public final String actionTaken;        // BLOCK_LOADED | RULE_SAVED | NOTIFIED_USER | MONITORED
        public final String summaryMessage;

        public RemediationVerdict(boolean autoResolved, String actionTaken, String summaryMessage) {
            this.autoResolved = autoResolved;
            this.actionTaken = actionTaken;
            this.summaryMessage = summaryMessage;
        }
    }

    public interface RemediationCallback {
        void onRemediationCompleted(RemediationVerdict verdict);
    }

    public static AutonomousSocAnalyst getInstance(Context context) {
        if (sInstance == null) {
            synchronized (AutonomousSocAnalyst.class) {
                if (sInstance == null) {
                    sInstance = new AutonomousSocAnalyst(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    private AutonomousSocAnalyst(Context context) {
        mContext = context;
        mAiConfig = new AiConfig(context);
        mRulesDb = SecurityRulesDb.getInstance(context);
        mAlertStore = AlertStore.getInstance(context);
        mNotificationHub = SecurityNotificationHub.getInstance(context);
    }

    /**
     * Triages a detected threat and autonomously applies remediation if confidence threshold is met.
     */
    public void triageAndRemediate(ThreatIncident incident, RemediationCallback callback) {
        if (incident == null || incident.ioc == null || incident.ioc.trim().isEmpty()) {
            if (callback != null) {
                callback.onRemediationCompleted(new RemediationVerdict(false, "NONE", "Invalid incident data."));
            }
            return;
        }

        try {
            mExecutor.execute(() -> {
                String key = incident.iocType + ":" + incident.ioc.trim().toLowerCase(Locale.ROOT)
                        + ":" + (incident.maliciousProbability >= 90) + ":" + mAiConfig.isAutopilotEnabled();
                RemediationVerdict verdict;
                try {
                    long now = SystemClock.elapsedRealtime();
                    Long previous = mRecentIncidents.get(key);
                    if (previous != null && now - previous < INCIDENT_COOLDOWN_MS) {
                        if (callback != null) mMainHandler.post(() -> callback.onRemediationCompleted(
                                new RemediationVerdict(false, "DUPLICATE", "This incident was recently reviewed. Check alert history.")));
                        return;
                    }
                    boolean isAutopilot = mAiConfig.isAutopilotEnabled();
                    boolean isHighConfidence = incident.maliciousProbability >= 90 && incident.maliciousProbability <= 100;

                    Log.i(TAG, String.format(Locale.ROOT,
                            "[AI SOC] Triaging %s (%s) from %s - Score: %d%% - Autopilot: %b",
                            incident.ioc, incident.threatCategory, incident.sourceApp,
                            incident.maliciousProbability, isAutopilot));

                    if (isAutopilot && isHighConfidence && hasConfirmedNetworkEvidence(incident)) {
                        // Autonomous Resolution (SOAR Autopilot Action)
                        verdict = executeAutoRemediation(incident);
                    } else if (incident.maliciousProbability >= 50) {
                        // Suspicious (Interactive Human-in-the-Loop Alert)
                        verdict = executeInteractiveAlert(incident);
                    } else {
                        // Low risk / Informational
                        verdict = new RemediationVerdict(false, "MONITORED", "Low-confidence signal reviewed without a blocking action.");
                    }

                    // Always forward incident telemetry to SIEM if enabled
                    forwardToSiem(incident, verdict);
                    if (mRecentIncidents.size() >= 256) mRecentIncidents.remove(mRecentIncidents.keySet().iterator().next());
                    mRecentIncidents.put(key, now);
                } catch (RuntimeException failure) {
                    Log.e(TAG, "Autopilot response failed: " + failure.getClass().getSimpleName());
                    verdict = new RemediationVerdict(false, "FAILED", "Autopilot could not complete this action. Review the incident and retry.");
                }

                if (callback != null) {
                    RemediationVerdict completed = verdict;
                    mMainHandler.post(() -> callback.onRemediationCompleted(completed));
                }
            });
        } catch (java.util.concurrent.RejectedExecutionException busy) {
            if (callback != null) mMainHandler.post(() -> callback.onRemediationCompleted(
                    new RemediationVerdict(false, "BUSY", "Autopilot is processing other incidents. Please retry.")));
        }
    }

    private boolean hasConfirmedNetworkEvidence(ThreatIncident incident) {
        if (!isNetworkTarget(incident.iocType, incident.ioc)) return false;
        KotSafeCloudProvider provider = new KotSafeCloudProvider(mContext);
        if (!provider.isAvailable()) return false;
        ThreatIntelProvider.ThreatReport report;
        switch (incident.iocType) {
            case "IP": report = provider.queryIp(incident.ioc); break;
            case "DOMAIN": report = provider.queryDomain(incident.ioc); break;
            default: return false;
        }
        return confirmsMalicious(report);
    }

    static boolean confirmsMalicious(ThreatIntelProvider.ThreatReport report) {
        return report != null && report.isMalicious && !report.isSuspicious
                && report.confidence >= 0.9f && report.confidence <= 1.0f
                && report.riskScore >= 90 && report.riskScore <= 100;
    }

    static boolean isNetworkTarget(String type, String value) {
        if (value == null || !value.equals(value.trim())) return false;
        if ("IP".equals(type)) return android.util.Patterns.IP_ADDRESS.matcher(value).matches();
        return "DOMAIN".equals(type) && value.length() <= 253 && value.contains(".")
                && !android.util.Patterns.IP_ADDRESS.matcher(value).matches()
                && value.matches("(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?");
    }

    /**
     * Executes automatic mitigation: Enforces firewall block rule, logs forensic record,
     * and notifies user of successful autonomous defense.
     */
    private RemediationVerdict executeAutoRemediation(ThreatIncident incident) {
        String blockReason = "Autopilot: confirmed malware indicator (" + incident.mitreTechnique + ")";

        com.kotsafe.security.model.SecurityBlocklistManager secMgr =
                com.kotsafe.security.model.SecurityBlocklistManager.getInstance(mContext);
        if (secMgr.isSystemWhitelisted(incident.ioc)
                || com.kotsafe.security.model.SecurityBlocklistManager.isOfficialDomain(incident.ioc)
                || com.kotsafe.security.model.SecurityBlocklistManager.isLocalOrConnectedDeviceIp(incident.ioc)) {
            Log.w(TAG, "Prevented auto-remediation against trusted service/IP: " + incident.ioc);
            return new RemediationVerdict(false, "EXEMPT", "Target belongs to trusted infrastructure or system whitelist.");
        }

        // 1. Enforce Firewall Block Rule via SecurityBlocklistManager
        long ruleId;
        if ("IP".equals(incident.iocType)) {
            ruleId = secMgr.blockIp(incident.ioc, blockReason, SecurityRulesDb.SOURCE_HEURISTIC);
        } else if ("DOMAIN".equals(incident.iocType)) {
            ruleId = secMgr.blockDomain(incident.ioc, blockReason, SecurityRulesDb.SOURCE_HEURISTIC);
        } else {
            return executeInteractiveAlert(incident);
        }
        if (ruleId < 0 || mRulesDb.getRule(ruleId) == null) return executeInteractiveAlert(incident);

        // Instantly reload in-memory firewall fast blocklist to halt traffic on active threads
        secMgr.reloadCache();
        boolean loaded = false;
        com.kotsafe.security.model.Blocklist blocklist = com.kotsafe.security.KotSafe.getInstance().getBlocklist();
        if (blocklist != null) loaded = "DOMAIN".equals(incident.iocType)
                ? blocklist.matchesHost(incident.ioc) : blocklist.matchesExactIP(incident.ioc);
        boolean active = CaptureService.isFirewallRunning() && loaded;
        String status = active ? "BLOCK_LOADED" : "RULE_SAVED";
        String description = active ? "Block rule loaded into the active firewall." : "Block rule saved. Firewall activation or rule loading is pending.";

        // 2. Persist Incident in AlertStore
        mAlertStore.add(
                AlertRecord.Severity.HIGH,
                AlertRecord.AlertType.MALWARE,
                "Autopilot: " + incident.headline,
                description + " Target: " + incident.ioc + ". "
                        + incident.technicalDetails,
                incident.sourceApp
        );

        // 3. Post High-Priority Notification via SecurityNotificationHub
        mNotificationHub.postThreatAlert(
                "Autopilot: " + status + " · " + incident.headline,
                incident.ioc,
                incident.threatCategory,
                "MALICIOUS"
        );

        String summary = description + " Target: " + incident.ioc;

        Log.w(TAG, "[AUTO-REMEDIATION EXECUTED] " + summary);
        return new RemediationVerdict(active, status, summary);
    }

    /**
     * Posts an interactive alert when confidence is medium or autopilot is paused.
     */
    private RemediationVerdict executeInteractiveAlert(ThreatIncident incident) {
        mAlertStore.add(
                AlertRecord.Severity.MEDIUM,
                AlertRecord.AlertType.MALWARE,
                "⚠️ " + incident.headline,
                incident.technicalDetails + " Target: " + incident.ioc + ". Pending user confirmation.",
                incident.sourceApp
        );

        mNotificationHub.postThreatAlert(
                "Action Required: " + incident.headline,
                incident.ioc,
                incident.threatCategory,
                "SUSPICIOUS"
        );

        String summary = "Threat flagged for user review (" + incident.ioc + ").";
        return new RemediationVerdict(false, "NOTIFIED_USER", summary);
    }

    private void forwardToSiem(ThreatIncident incident, RemediationVerdict verdict) {
        try {
            SiemTelemetryForwarder forwarder = SiemTelemetryForwarder.getInstance(mContext);
            if (forwarder != null) {
                forwarder.spoolRawEvent(
                        UUID.randomUUID().toString(),
                        System.currentTimeMillis(),
                        incident.threatCategory,
                        incident.maliciousProbability >= 75 ? "CRITICAL" : "HIGH",
                        incident.headline + " [" + verdict.actionTaken + "]",
                        incident.technicalDetails + " | Target: " + incident.ioc,
                        incident.sourceApp,
                        incident.mitreTechnique
                );
            }
        } catch (Exception e) {
            Log.w(TAG, "SIEM spooling notice: " + e.getMessage());
        }
    }

    /**
     * Proactively pre-triages incoming alerts synchronously, computes autonomous threat scoring,
     * and updates the AlertRecord in AlertStore with verified SOC assessment badges.
     */
    public void preTriageAlert(AlertRecord alert) {
        if (alert == null || alert.isResolved()) return;
        try {
            AiClientEngine.AlertTriageResult triage = AiClientEngine.computeLocalAlertTriage(alert);
            alert.aiMaliciousProbability = triage.maliciousProbability;
            alert.aiAssessment = "[" + triage.verdict + "] " + triage.reasoning;
            mAlertStore.updateAlert(alert);
            Log.d(TAG, "[PRE-TRIAGE] Alert " + alert.id + " scored: " + alert.aiMaliciousProbability + "% (" + triage.verdict + ")");
        } catch (Exception e) {
            Log.e(TAG, "Pre-triage error: " + e.getMessage());
        }
    }

    /**
     * Proactively pre-triages incoming alerts in background thread.
     */
    public void preTriageAlertAsync(AlertRecord alert) {
        if (alert == null || alert.isResolved()) return;
        try {
            mExecutor.execute(() -> preTriageAlert(alert));
        } catch (java.util.concurrent.RejectedExecutionException busy) {
            Log.w(TAG, "Autopilot queue is full; the original alert remains available for review.");
        }
    }
}
