/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * CorrelationEngine
 * =================
 * The core bridge between the Network Firewall Engine and the Antivirus Engine.
 * Correlates live outbound socket flows (IP, port, domain, JA3) with endpoint
 * application intelligence (provenance, permissions, certificate trust, install time).
 * Synthesizes multi-signal evidence into unified, high-confidence EDR incidents.
 */

package com.kotsafe.security.model;

import android.content.Context;

import com.kotsafe.security.Log;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

public class CorrelationEngine {
    private static final String TAG = "CorrelationEngine";
    private static final int MAX_CORRELATED_INCIDENTS = 50;

    public static class CorrelatedIncident {
        public String id;
        public long timestampMs;
        public String packageName;
        public String appName;
        public String destinationIp;
        public int destinationPort;
        public String domain;
        public String ruleTriggered;
        public int confidenceScore; // 0-100
        public String severity; // INFO, LOW, MEDIUM, HIGH, CRITICAL
        public String summary;
        public List<String> contributingSignals = new ArrayList<>();
    }

    private static volatile CorrelationEngine sInstance;
    private final Context mContext;
    private final Deque<CorrelatedIncident> mIncidentHistory = new ArrayDeque<>(MAX_CORRELATED_INCIDENTS + 1);

    public static CorrelationEngine getInstance(Context context) {
        if (sInstance == null) {
            synchronized (CorrelationEngine.class) {
                if (sInstance == null) {
                    sInstance = new CorrelationEngine(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    private CorrelationEngine(Context context) {
        mContext = context;
    }

    /**
     * Called whenever NetworkSecurityMonitor observes an outbound socket connection.
     */
    public void onNetworkFlowObserved(String appName, String packageName,
                                     String ip, int port, String domain, String url) {
        if (packageName == null || packageName.isEmpty()) return;

        // Skip self & system apps from suspicious correlation
        AppIntelligenceEngine intel = AppIntelligenceEngine.getInstance(mContext);
        AppIntelligenceEngine.AppSecurityProfile profile = intel.getProfile(packageName);
        if (profile != null && (profile.isSystemApp || profile.isSelfKotSafe)) {
            return;
        }

        // Record network event in behavior engine
        AndroidBehaviorEngine.getInstance().recordEvent(
                packageName,
                "NETWORK",
                "Connected to " + (domain != null && !domain.isEmpty() ? domain : ip) + ":" + port,
                ip
        );

        if (profile == null) return;

        boolean isSuspiciousDestination = isSuspiciousNetworkTarget(domain, port);
        boolean isHighRiskPerms = profile.permissionAnalysis != null && profile.permissionAnalysis.riskScore >= 40;
        boolean isSideloaded = profile.isSideloaded;
        boolean hasDebugCert = profile.certificateProfile != null && profile.certificateProfile.isDebugKeystore;

        // Rule 1: Sideloaded + High-Risk Permissions + Suspicious Egress Port/Domain
        if (isSideloaded && isHighRiskPerms && isSuspiciousDestination) {
            createIncident(
                    packageName, profile.appName, ip, port, domain,
                    "CORR-01: Untrusted Sideload with Sensitive Permissions Contacting High-Risk Network Destination",
                    "CRITICAL", 92,
                    new String[] {
                            "Sideloaded application origin (outside Google Play)",
                            "Declares dangerous capability cluster: " + String.join(", ", profile.permissionAnalysis.flaggedClusters),
                            "Outbound connection to suspect destination: " + (domain != null ? domain : ip) + ":" + port
                    }
            );
        }
        // Rule 2: Debug Certificate + Outbound Network Activity on Non-Standard Port
        else if (hasDebugCert && (port == 4444 || port == 5555 || port == 1337 || port == 31337)) {
            createIncident(
                    packageName, profile.appName, ip, port, domain,
                    "CORR-02: Test/Debug Signed APK Connecting to Reverse-Shell Port",
                    "CRITICAL", 95,
                    new String[] {
                            "Signed with public Android Debug Certificate",
                            "Attempted communication on known backdoor/shell port: " + port,
                            "Destination host: " + ip
                    }
            );
        }
    }

    private boolean isSuspiciousNetworkTarget(String domain, int port) {
        if (port == 23 || port == 1337 || port == 31337 || port == 4444 || port == 5555 || port == 6667) {
            return true;
        }
        if (domain != null) {
            String lower = domain.toLowerCase();
            return lower.endsWith(".top") || lower.endsWith(".xyz") || lower.endsWith(".click")
                    || lower.endsWith(".buzz") || lower.contains(".duckdns.org") || lower.contains(".hopto.org");
        }
        return false;
    }

    private void createIncident(String pkg, String appName, String ip, int port, String domain,
                                String rule, String severity, int confidence, String[] signals) {
        CorrelatedIncident incident = new CorrelatedIncident();
        incident.id = java.util.UUID.randomUUID().toString();
        incident.timestampMs = System.currentTimeMillis();
        incident.packageName = pkg;
        incident.appName = (appName != null && !appName.isEmpty()) ? appName : pkg;
        incident.destinationIp = ip;
        incident.destinationPort = port;
        incident.domain = domain != null ? domain : "";
        incident.ruleTriggered = rule;
        incident.severity = severity;
        incident.confidenceScore = confidence;
        incident.summary = incident.appName + " triggered correlation alert: " + rule;
        for (String s : signals) incident.contributingSignals.add(s);

        synchronized (mIncidentHistory) {
            mIncidentHistory.addFirst(incident);
            if (mIncidentHistory.size() > MAX_CORRELATED_INCIDENTS) {
                mIncidentHistory.removeLast();
            }
        }

        // Record to UnifiedIncidentTimeline
        UnifiedIncidentTimeline timeline = UnifiedIncidentTimeline.getInstance(mContext);
        timeline.record(new UnifiedIncidentTimeline.IncidentEvent.Builder()
                .type(UnifiedIncidentTimeline.EventType.GENERAL_ALERT)
                .severity(UnifiedIncidentTimeline.Severity.valueOf(severity))
                .title("App ↔ Network Correlated Incident")
                .detail(incident.summary + " | Evidence: " + String.join(" | ", signals))
                .sourceApp(pkg)
                .target((domain != null && !domain.isEmpty() ? domain : ip) + ":" + port)
                .risk(confidence)
                .build());

        Log.w(TAG, "[CORRELATION INCIDENT] " + incident.summary);
    }

    public List<CorrelatedIncident> getRecentIncidents() {
        synchronized (mIncidentHistory) {
            return new ArrayList<>(mIncidentHistory);
        }
    }

    public int getIncidentCount() {
        synchronized (mIncidentHistory) {
            return mIncidentHistory.size();
        }
    }
}
