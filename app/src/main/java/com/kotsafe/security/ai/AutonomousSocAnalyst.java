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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Autonomous AI SOC Incident Analyst & SOAR Engine (Security Orchestration, Automation, and Response).
 * Continuously audits threat signals (Mercenary Spyware, C2 beacons, high-entropy exfiltration,
 * zero-click bursts, and malicious flow anomalies), generates threat assessments,
 * and automatically executes kernel-level remediation when confidence is high.
 */
public class AutonomousSocAnalyst {

    private static final String TAG = "AutonomousSocAnalyst";
    private static volatile AutonomousSocAnalyst sInstance;

    private final Context mContext;
    private final AiConfig mAiConfig;
    private final SecurityRulesDb mRulesDb;
    private final AlertStore mAlertStore;
    private final SecurityNotificationHub mNotificationHub;
    private final ExecutorService mExecutor = Executors.newSingleThreadExecutor();
    private final Handler mMainHandler = new Handler(Looper.getMainLooper());

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
        public final String actionTaken;        // BLOCKED_FIREWALL | QUARANTINED | NOTIFIED_USER | MONITORED
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

        mExecutor.execute(() -> {
            boolean isAutopilot = mAiConfig.isAutopilotEnabled();
            boolean isHighConfidence = incident.maliciousProbability >= 75;

            Log.i(TAG, String.format(Locale.ROOT,
                    "[AI SOC] Triaging %s (%s) from %s - Score: %d%% - Autopilot: %b",
                    incident.ioc, incident.threatCategory, incident.sourceApp,
                    incident.maliciousProbability, isAutopilot));

            RemediationVerdict verdict;

            if (isAutopilot && isHighConfidence) {
                // Autonomous Resolution (SOAR Autopilot Action)
                verdict = executeAutoRemediation(incident);
            } else if (incident.maliciousProbability >= 50) {
                // Suspicious (Interactive Human-in-the-Loop Alert)
                verdict = executeInteractiveAlert(incident);
            } else {
                // Low risk / Informational
                verdict = new RemediationVerdict(false, "MONITORED", "Threat logged for background surveillance.");
            }

            // Always forward incident telemetry to SIEM if enabled
            forwardToSiem(incident, verdict);

            if (callback != null) {
                mMainHandler.post(() -> callback.onRemediationCompleted(verdict));
            }
        });
    }

    /**
     * Executes automatic mitigation: Enforces firewall block rule, logs forensic record,
     * and notifies user of successful autonomous defense.
     */
    private RemediationVerdict executeAutoRemediation(ThreatIncident incident) {
        String blockReason = "Autonomous AI SOC: Neutralized " + incident.threatCategory + " (" + incident.mitreTechnique + ")";

        com.kotsafe.security.model.SecurityBlocklistManager secMgr =
                com.kotsafe.security.model.SecurityBlocklistManager.getInstance(mContext);
        if (secMgr.isSystemWhitelisted(incident.ioc)
                || com.kotsafe.security.model.SecurityBlocklistManager.isOfficialDomain(incident.ioc)
                || com.kotsafe.security.model.SecurityBlocklistManager.isLocalOrConnectedDeviceIp(incident.ioc)) {
            Log.w(TAG, "Prevented auto-remediation against trusted service/IP: " + incident.ioc);
            return new RemediationVerdict(false, "EXEMPT", "Target belongs to trusted infrastructure or system whitelist.");
        }

        // 1. Enforce Firewall Block Rule via SecurityBlocklistManager
        if ("IP".equalsIgnoreCase(incident.iocType)) {
            secMgr.blockIp(incident.ioc, blockReason, SecurityRulesDb.SOURCE_HEURISTIC);
        } else if ("APP".equalsIgnoreCase(incident.iocType)) {
            secMgr.blockApp(incident.ioc, blockReason, SecurityRulesDb.SOURCE_HEURISTIC);
        } else {
            // Default to DOMAIN
            secMgr.blockDomain(incident.ioc, blockReason, SecurityRulesDb.SOURCE_HEURISTIC);
        }

        // Instantly reload in-memory firewall fast blocklist to halt traffic on active threads
        try {
            secMgr.reloadCache();
        } catch (Exception ignored) {}

        // 2. Persist Incident in AlertStore
        mAlertStore.add(
                AlertRecord.Severity.HIGH,
                AlertRecord.AlertType.MALWARE,
                "🛡️ [AUTO-RESOLVED] " + incident.headline,
                "Threat automatically neutralized by KotSafe AI SOC Analyst. "
                        + "Outbound connection to " + incident.ioc + " blocked at firewall level. "
                        + incident.technicalDetails,
                incident.sourceApp
        );

        // 3. Post High-Priority Notification via SecurityNotificationHub
        mNotificationHub.postThreatAlert(
                "🛡️ Auto-Resolved: " + incident.headline,
                incident.ioc,
                incident.threatCategory,
                "MALICIOUS"
        );

        String summary = String.format(Locale.ROOT,
                "Autonomous AI SOC blocked %s (%s). Egress traffic halted immediately.",
                incident.ioc, incident.threatCategory);

        Log.w(TAG, "[AUTO-REMEDIATION EXECUTED] " + summary);
        return new RemediationVerdict(true, "BLOCKED_FIREWALL", summary);
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
        mExecutor.execute(() -> preTriageAlert(alert));
    }
}
