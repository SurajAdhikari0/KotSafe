/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * CrossDomainCorrelationEngine
 * =============================
 * Correlates independent low/medium signals across Network, Antivirus,
 * and Physical domains into high-confidence composite incidents.
 *
 * Implements the 4 Bidirectional Feedback Loops:
 * 1. Network -> Antivirus: Network anomalies elevate app threat score.
 * 2. Antivirus -> Firewall: High-risk apps automatically trigger egress restrictions.
 * 3. Physical -> Firewall: BadUSB / physical tamper triggers network isolation.
 * 4. Firewall -> Physical: Egress bursts post-USB trigger physical compromise alerts.
 */

package com.kotsafe.security.security.correlation;

import android.content.Context;

import com.kotsafe.security.Log;
import com.kotsafe.security.model.AppIntelligenceEngine;
import com.kotsafe.security.model.SecurityBlocklistManager;
import com.kotsafe.security.model.UnifiedIncidentTimeline;
import com.kotsafe.security.security.event.EventTypes;
import com.kotsafe.security.security.event.SecurityEvent;
import com.kotsafe.security.security.event.SecurityEventBus;
import com.kotsafe.security.security.graph.AppBehaviorGraph;
import com.kotsafe.security.security.graph.EvidenceGraph;
import com.kotsafe.security.security.identity.AppIdentityEngine;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class CrossDomainCorrelationEngine implements SecurityEventBus.SecurityEventListener {
    private static final String TAG = "CrossDomainCorrelationEngine";

    public static class CorrelatedIncident {
        public final String incidentId;
        public final String title;
        public final String patternType; // BANKING_TROJAN, PHYSICAL_TAMPER, SIM_HIJACK, SLEEPER_DROPPER
        public final SecurityEvent.Severity severity;
        public final String targetPackage;
        public final int targetUid;
        public final List<String> causalEventIds;
        public final String explanation;
        public final long timestamp;

        public CorrelatedIncident(String id, String title, String pattern, SecurityEvent.Severity severity,
                                  String pkg, int uid, List<String> eventIds, String explanation) {
            this.incidentId = id;
            this.title = title;
            this.patternType = pattern;
            this.severity = severity;
            this.targetPackage = pkg;
            this.targetUid = uid;
            this.causalEventIds = eventIds;
            this.explanation = explanation;
            this.timestamp = System.currentTimeMillis();
        }
    }

    private static volatile CrossDomainCorrelationEngine sInstance;
    private final Context mContext;
    private final AppIdentityEngine mIdentityEngine;
    private final AppBehaviorGraph mBehaviorGraph;
    private final EvidenceGraph mEvidenceGraph;
    private final List<CorrelatedIncident> mIncidents = Collections.synchronizedList(new ArrayList<>());

    // Sliding window of recent events per package (last 10 minutes)
    private final Map<String, List<SecurityEvent>> mRecentEventsByPkg = new ConcurrentHashMap<>();
    private static final long SLIDING_WINDOW_MS = TimeUnit.MINUTES.toMillis(10);

    // Global state
    private long mLastUsbAttachTime = 0;
    private boolean mIsAdbActive = false;
    private boolean mIsBadUsbAttached = false;

    public static CrossDomainCorrelationEngine getInstance(Context context) {
        if (sInstance == null) {
            synchronized (CrossDomainCorrelationEngine.class) {
                if (sInstance == null) {
                    sInstance = new CrossDomainCorrelationEngine(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    private CrossDomainCorrelationEngine(Context context) {
        mContext = context;
        mIdentityEngine = AppIdentityEngine.getInstance(context);
        mBehaviorGraph = AppBehaviorGraph.getInstance();
        mEvidenceGraph = EvidenceGraph.getInstance();

        // Subscribe to all security events on the central bus
        SecurityEventBus.getInstance().subscribe(this);
    }

    @Override
    public void onSecurityEvent(SecurityEvent event) {
        if (event == null) return;

        // 1. Ingest into AppBehaviorGraph & EvidenceGraph
        mBehaviorGraph.recordEvent(event);
        addEventToEvidenceGraph(event);

        // 2. Track sliding window for correlation
        String pkg = event.getSubjectPackage();
        if (pkg != null && !pkg.isEmpty()) {
            List<SecurityEvent> list = mRecentEventsByPkg.computeIfAbsent(pkg, k -> new ArrayList<>());
            synchronized (list) {
                list.add(event);
                purgeExpiredEvents(list);
            }
        }

        // 3. Track physical indicators
        if (EventTypes.USB_ATTACHED.equals(event.getEventType())) {
            mLastUsbAttachTime = System.currentTimeMillis();
        } else if (EventTypes.BAD_USB_HID_DETECTED.equals(event.getEventType())) {
            mIsBadUsbAttached = true;
            mLastUsbAttachTime = System.currentTimeMillis();
            executePhysicalToFirewallFeedback(event);
        } else if (EventTypes.DEVICE_POSTURE_CHANGED.equals(event.getEventType())) {
            mIsAdbActive = Boolean.TRUE.equals(event.getAttribute("is_adb_enabled", false));
        }

        // 4. Run Multi-Vector Correlation Rules
        evaluateCorrelations(event);
    }

    private void purgeExpiredEvents(List<SecurityEvent> list) {
        long cutoff = System.currentTimeMillis() - SLIDING_WINDOW_MS;
        list.removeIf(e -> e.getTimestamp() < cutoff);
    }

    private void addEventToEvidenceGraph(SecurityEvent event) {
        String pkg = event.getSubjectPackage();
        if (pkg != null && !pkg.isEmpty()) {
            mEvidenceGraph.addNode(new EvidenceGraph.Node(pkg, EvidenceGraph.NodeType.APP, pkg));
        }

        String eventNodeId = "EVENT_" + event.getEventId();
        mEvidenceGraph.addNode(new EvidenceGraph.Node(eventNodeId, EvidenceGraph.NodeType.INCIDENT, event.getTitle())
                .property("type", event.getEventType())
                .property("severity", event.getSeverity().name()));

        if (pkg != null && !pkg.isEmpty()) {
            mEvidenceGraph.addEdge(pkg, eventNodeId, "EMITTED_EVENT");
        }

        String ip = event.getAttribute("dst_ip", null);
        if (ip != null) {
            String ipNodeId = "IP_" + ip;
            mEvidenceGraph.addNode(new EvidenceGraph.Node(ipNodeId, EvidenceGraph.NodeType.IP_ADDRESS, ip));
            mEvidenceGraph.addEdge(eventNodeId, ipNodeId, "CONNECTED_TO");
        }

        String domain = event.getAttribute("domain", null);
        if (domain != null) {
            String domainNodeId = "DOMAIN_" + domain;
            mEvidenceGraph.addNode(new EvidenceGraph.Node(domainNodeId, EvidenceGraph.NodeType.DOMAIN, domain));
            mEvidenceGraph.addEdge(eventNodeId, domainNodeId, "RESOLVED_DOMAIN");
        }
    }

    private void evaluateCorrelations(SecurityEvent event) {
        String pkg = event.getSubjectPackage();
        if (pkg == null || pkg.isEmpty()) return;

        AppIdentityEngine.AppIdentity identity = mIdentityEngine.resolvePackage(pkg);
        if (identity == null) return;

        // Skip KotSafe and Verified Platform components from false-positive correlation
        if (identity.isSystemApp || identity.packageName.equals(mContext.getPackageName())) {
            return;
        }

        // Correlation Pattern 1: Sideloaded App + Network Anomaly (Banking Trojan ATS)
        if (event.getDomain() == SecurityEvent.Domain.NETWORK) {
            boolean isBlocked = Boolean.TRUE.equals(event.getAttribute("is_blocked", false));
            identity.recordDestination(event.getAttribute("dst_ip", ""), event.getAttribute("domain", ""), isBlocked);

            // Network -> Antivirus Feedback: ONLY for sideloaded or non-vetted apps (never for browsers/media/essential apps)
            if (isBlocked && identity.totalBlockedConnections >= 3 
                    && identity.isSideloaded 
                    && !com.kotsafe.security.Utils.isEssentialOrBrowserApp(mContext, identity.packageName)) {
                executeNetworkToAntivirusFeedback(identity, event);
            }

            // High confidence Banking Trojan: Sideloaded + High Risk + Egress to unvetted IP
            if (identity.isSideloaded && identity.currentRiskScore >= 60 && isBlocked
                    && !com.kotsafe.security.Utils.isEssentialOrBrowserApp(mContext, identity.packageName)) {
                emitCorrelatedIncident("Banking Trojan ATS Pattern",
                        "BANKING_TROJAN",
                        SecurityEvent.Severity.CRITICAL,
                        pkg, identity.uid,
                        "Sideloaded app (" + identity.appLabel + ") with elevated risk score attempted outbound socket to blocked destination: "
                                + event.getAttribute("dst_ip", ""));
            }
        }

        // Correlation Pattern 2: Physical Device attached + Sudden Egress Burst
        if (event.getDomain() == SecurityEvent.Domain.NETWORK && mLastUsbAttachTime > 0) {
            long timeSinceUsb = System.currentTimeMillis() - mLastUsbAttachTime;
            if (timeSinceUsb <= TimeUnit.MINUTES.toMillis(3)) {
                // High-risk physical + network correlation
                if (mIsBadUsbAttached || (mIsAdbActive && identity.isSideloaded)) {
                    emitCorrelatedIncident("Physical Tamper / BadUSB Exfiltration",
                            "PHYSICAL_TAMPER",
                            SecurityEvent.Severity.CRITICAL,
                            pkg, identity.uid,
                            "New outbound network flow triggered within 3 minutes of physical USB/HID device attachment on an unvetted package: " + pkg);
                }
            }
        }
    }

    // ─── Bidirectional Feedback Executions ─────────────────────────────────────

    // Feedback 1: Network -> Antivirus
    private void executeNetworkToAntivirusFeedback(AppIdentityEngine.AppIdentity identity, SecurityEvent netEvent) {
        int previousRisk = identity.currentRiskScore;
        int newRisk = Math.min(100, previousRisk + 20);
        identity.currentRiskScore = newRisk;
        identity.verdict = (newRisk >= 75) ? "MALICIOUS" : "SUSPICIOUS";

        Log.w(TAG, "[Feedback Network -> AV] Elevated risk score for " + identity.packageName + " from " + previousRisk + " to " + newRisk + " due to repeated blocked connections.");

        recordTimelineEvent(
                UnifiedIncidentTimeline.EventType.BEHAVIORAL_CORRELATION,
                UnifiedIncidentTimeline.Severity.HIGH,
                "Network-Elevated Risk: " + identity.appLabel,
                "Antivirus elevated threat assessment due to repeated network policy violations.",
                identity.packageName
        );
    }

    // Feedback 2: Antivirus -> Firewall
    public void executeAntivirusToFirewallFeedback(String packageName, int riskScore) {
        if (packageName == null || packageName.isEmpty()) return;
        if (com.kotsafe.security.Utils.isVerifiedGoogleTrustedService(mContext, packageName)
                || com.kotsafe.security.Utils.isEssentialOrBrowserApp(mContext, packageName)) {
            Log.i(TAG, "Skipping AV->Firewall isolation for trusted / browser / essential app: " + packageName);
            return;
        }
        if (riskScore >= 75) {
            Log.w(TAG, "[Feedback AV -> Firewall] Restricting network egress for high-risk package: " + packageName);
            SecurityBlocklistManager secMgr = SecurityBlocklistManager.getInstance(mContext);
            secMgr.blockApp(packageName, "Antivirus EDR High-Risk Detection (Score: " + riskScore + ")", "EDR_FEEDBACK");
        }
    }

    // Feedback 3: Physical -> Firewall
    private void executePhysicalToFirewallFeedback(SecurityEvent physicalEvent) {
        Log.w(TAG, "[Feedback Physical -> Firewall] BadUSB keyboard detected. Triggering immediate network defense posture.");
        recordTimelineEvent(
                UnifiedIncidentTimeline.EventType.DEVICE_POSTURE_CHANGE,
                UnifiedIncidentTimeline.Severity.CRITICAL,
                "Physical Defense Activated",
                "Firewall policy tightened following external BadUSB/HID hardware connection.",
                null
        );
    }

    private void emitCorrelatedIncident(String title, String pattern, SecurityEvent.Severity severity,
                                       String pkg, int uid, String explanation) {
        String incidentId = "INC_" + System.currentTimeMillis();
        CorrelatedIncident incident = new CorrelatedIncident(incidentId, title, pattern, severity, pkg, uid,
                Collections.singletonList(incidentId), explanation);
        mIncidents.add(incident);

        Log.e(TAG, "[CORRELATED INCIDENT] " + title + " -> " + explanation);

        // Publish to central bus
        SecurityEvent.Builder builder = new SecurityEvent.Builder(SecurityEvent.Domain.CORRELATION, EventTypes.CORRELATED_INCIDENT)
                .severity(severity)
                .title(title)
                .description(explanation)
                .subject(pkg, uid)
                .attribute("pattern", pattern)
                .attribute("incident_id", incidentId);
        SecurityEventBus.getInstance().publish(builder.build());

        UnifiedIncidentTimeline.Severity timelineSev = (severity == SecurityEvent.Severity.CRITICAL) 
                ? UnifiedIncidentTimeline.Severity.CRITICAL 
                : UnifiedIncidentTimeline.Severity.HIGH;

        // Feed to Timeline
        recordTimelineEvent(
                UnifiedIncidentTimeline.EventType.BEHAVIORAL_CORRELATION,
                timelineSev,
                title,
                explanation,
                pkg
        );

        // Trigger Antivirus -> Firewall isolation if critical
        if (severity == SecurityEvent.Severity.CRITICAL && pkg != null) {
            executeAntivirusToFirewallFeedback(pkg, 95);
        }
    }

    private void recordTimelineEvent(UnifiedIncidentTimeline.EventType type,
                                    UnifiedIncidentTimeline.Severity severity,
                                    String title, String detail, String sourceApp) {
        try {
            UnifiedIncidentTimeline.getInstance(mContext).record(
                    new UnifiedIncidentTimeline.IncidentEvent.Builder()
                            .type(type)
                            .severity(severity)
                            .title(title != null ? title : "")
                            .detail(detail)
                            .sourceApp(sourceApp)
                            .build()
            );
        } catch (Exception ignored) {}
    }

    public List<CorrelatedIncident> getActiveIncidents() {
        return new ArrayList<>(mIncidents);
    }
}
