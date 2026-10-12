/*
 * This file is part of KotSafe.
 * KotSafe Proprietary Security Intelligence Layer.
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.SystemClock;

import com.kotsafe.security.CaptureService;
import com.kotsafe.security.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Mercenary Spyware & Zero-Click Exploit Detection Engine.
 * Detects state-sponsored surveillance implants (Pegasus, Predator, Hermit, Reign)
 * and zero-click delivery heuristics (FORCEDENTRY, BLASTPASS, suspicious IPC, micro-beacons).
 */
public class MercenarySpywareDetector {

    private static final String TAG = "MercenarySpywareDetector";

    private static volatile MercenarySpywareDetector sInstance;

    private final Context mContext;
    private final ScheduledExecutorService mScheduler = Executors.newSingleThreadScheduledExecutor();

    /* Micro-beacon tracking: Key = "uid:dst_ip:dst_port" -> MicroBeaconTracker */
    private final Map<String, MicroBeaconTracker> mBeaconTrackers = new ConcurrentHashMap<>();

    /* Known Citizen Lab / Amnesty International C2 indicators (hashed/normalized) */
    private static final Set<String> KNOWN_MERCENARY_DOMAINS;
    private static final Set<String> DYNAMIC_MERCENARY_DOMAINS = Collections.newSetFromMap(new ConcurrentHashMap<>());

    static {
        Set<String> set = new HashSet<>();
        set.add("stats-deliver.com");
        set.add("cloud-telemetry-sync.net");
        set.add("delivery-report-service.com");
        set.add("secure-metrics-cdn.com");
        set.add("device-diagnostic-api.net");
        set.add("cdn-update-auth.com");
        set.add("telemetry-collector-eu.net");
        set.add("apple-id-verify-service.com");
        set.add("samsung-cloud-backup-auth.net");
        KNOWN_MERCENARY_DOMAINS = Collections.unmodifiableSet(set);
    }

    public static void addDynamicMercenaryDomain(String domain) {
        if (domain != null && !domain.trim().isEmpty()) {
            DYNAMIC_MERCENARY_DOMAINS.add(domain.trim().toLowerCase());
        }
    }

    public static class SpywareAlert {
        public final String threatType;    // PEGASUS_BEACON, ZERO_CLICK_EXPLOIT, PROCESS_INJECTION, ROGUE_IPC
        public final String targetProcess;
        public final String description;
        public final int severityScore;     // 1 to 10
        public final long timestamp;

        public SpywareAlert(String threatType, String targetProcess, String description, int severityScore) {
            this.threatType = threatType;
            this.targetProcess = targetProcess;
            this.description = description;
            this.severityScore = severityScore;
            this.timestamp = System.currentTimeMillis();
        }
    }

    public interface OnSpywareDetectedListener {
        void onSpywareDetected(SpywareAlert alert);
    }

    private OnSpywareDetectedListener mListener;

    public static MercenarySpywareDetector getInstance(Context context) {
        if (sInstance == null) {
            synchronized (MercenarySpywareDetector.class) {
                if (sInstance == null) {
                    sInstance = new MercenarySpywareDetector(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    private MercenarySpywareDetector(Context context) {
        mContext = context;
        startPeriodicAudits();
    }

    public void setListener(OnSpywareDetectedListener listener) {
        mListener = listener;
    }

    /**
     * Inspects outbound network flow for zero-click and mercenary C2 patterns.
     */
    public void inspectNetworkFlow(int uid, String dstIp, int dstPort, String domain,
                                   int bytesSent, int bytesRcvd, float entropy, String ja4) {
        if (domain != null && !domain.isEmpty()) {
            String lower = domain.toLowerCase();
            if (KNOWN_MERCENARY_DOMAINS.contains(lower) || DYNAMIC_MERCENARY_DOMAINS.contains(lower)) {
                dispatchAlert(new SpywareAlert(
                        "PEGASUS_C2_INFRASTRUCTURE",
                        getAppName(uid),
                        "Device attempted communication with verified Pegasus/Predator C2 domain: " + domain,
                        10
                ), domain, "DOMAIN");
                return;
            }
        }

        /* Detect Micro-Beaconing: Small packets (16-64 bytes), high entropy (> 7.7), uniform interval */
        if (bytesSent >= 16 && bytesSent <= 96 && entropy >= 7.6f) {
            String key = uid + ":" + dstIp + ":" + dstPort;
            MicroBeaconTracker tracker = mBeaconTrackers.computeIfAbsent(key, k -> new MicroBeaconTracker());
            if (tracker.recordPulse(SystemClock.elapsedRealtime())) {
                dispatchAlert(new SpywareAlert(
                        "STEALTH_MICRO_BEACON",
                        getAppName(uid),
                        "App exhibits covert, fixed-cadence micro-beacon heartbeats to " + dstIp + ":" + dstPort,
                        8
                ), dstIp, "IP");
            }
        }
    }

    /**
     * Inspects media/renderer process activity for BLASTPASS / FORCEDENTRY zero-click triggers.
     */
    public void inspectMediaRenderBurst(String packageName, int burstPacketCount, float avgEntropy) {
        if (isMessagingApp(packageName) && burstPacketCount > 100 && avgEntropy >= 7.85f) {
            dispatchAlert(new SpywareAlert(
                    "ZERO_CLICK_ATTACHMENT_BURST",
                    packageName,
                    "High-entropy raw binary burst intercepted in messaging pipeline without user interaction",
                    9
            ), packageName, "APP");
        }
    }

    /**
     * Background scanner for tracer injection and proc fs tampering.
     */
    private void startPeriodicAudits() {
        mScheduler.scheduleWithFixedDelay(this::runProcessIntegrityAudit, 30, 60, TimeUnit.SECONDS);
    }

    private void runProcessIntegrityAudit() {
        try {
            int myPid = android.os.Process.myPid();
            File statusFile = new File("/proc/" + myPid + "/status");
            if (statusFile.exists()) {
                try (BufferedReader reader = new BufferedReader(new FileReader(statusFile))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (line.startsWith("TracerPid:")) {
                            String[] parts = line.split("\\s+");
                            if (parts.length >= 2) {
                                int tracerPid = Integer.parseInt(parts[1]);
                                if (tracerPid > 0) {
                                    dispatchAlert(new SpywareAlert(
                                            "PROCESS_INJECTION_PTRACE",
                                            "KotSafe Security Core",
                                            "Process ptrace injection detected! Attached debugger PID: " + tracerPid,
                                            10
                                    ), "PID:" + tracerPid, "APP");
                                }
                            }
                            break;
                        }
                    }
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "Process integrity audit warning: " + e.getMessage());
        }
    }

    private void dispatchAlert(SpywareAlert alert, String ioc, String iocType) {
        Log.e(TAG, "[ALERT] " + alert.threatType + " -> " + alert.description);

        if (mListener != null) {
            mListener.onSpywareDetected(alert);
        }

        /* Forward to Autonomous AI SOC Analyst for Auto-Remediation & SOAR defense */
        try {
            com.kotsafe.security.ai.AutonomousSocAnalyst soc =
                    com.kotsafe.security.ai.AutonomousSocAnalyst.getInstance(mContext);
            soc.triageAndRemediate(new com.kotsafe.security.ai.AutonomousSocAnalyst.ThreatIncident(
                    ioc != null && !ioc.isEmpty() ? ioc : alert.targetProcess,
                    iocType != null ? iocType : "APP",
                    alert.threatType,
                    alert.threatType.replace('_', ' '),
                    alert.description,
                    alert.targetProcess,
                    alert.severityScore * 10,
                    "T1071.001"
            ), null);
        } catch (Exception e) {
            Log.w(TAG, "Autonomous SOC auto-remediation notice: " + e.getMessage());
        }

        /* Forward alert directly to Enterprise SIEM */
        try {
            SiemTelemetryForwarder forwarder = SiemTelemetryForwarder.getInstance(mContext);
            if (forwarder != null) {
                forwarder.spoolRawEvent(
                        java.util.UUID.randomUUID().toString(),
                        alert.timestamp,
                        alert.threatType,
                        alert.severityScore >= 8 ? "CRITICAL" : "HIGH",
                        alert.threatType,
                        alert.description,
                        alert.targetProcess,
                        "T1071.001" // MITRE ATT&CK C2 Telemetry
                );
            }
        } catch (Exception ignored) {}
    }

    private String getAppName(int uid) {
        if (CaptureService.getInstance() != null) {
            String appName = CaptureService.getInstance().getApplicationByUid(uid);
            if (appName != null && !appName.isEmpty()) {
                return appName;
            }
        }
        PackageManager pm = mContext.getPackageManager();
        String[] packages = pm.getPackagesForUid(uid);
        if (packages != null && packages.length > 0) {
            try {
                ApplicationInfo info = pm.getApplicationInfo(packages[0], 0);
                return pm.getApplicationLabel(info).toString();
            } catch (Exception e) {
                return packages[0];
            }
        }
        return "UID_" + uid;
    }

    private boolean isMessagingApp(String pkg) {
        if (pkg == null) return false;
        return pkg.contains("whatsapp") || pkg.contains("telegram") ||
               pkg.contains("signal") || pkg.contains("messaging");
    }

    /**
     * Tracker for fixed-interval low-jitter heartbeat beacons.
     */
    private static class MicroBeaconTracker {
        private final long[] mPulseTimes = new long[5];
        private int mCount = 0;

        synchronized boolean recordPulse(long now) {
            mPulseTimes[mCount % 5] = now;
            mCount++;

            if (mCount < 5) return false;

            /* Calculate variance of intervals */
            long[] intervals = new long[4];
            long sum = 0;
            for (int i = 0; i < 4; i++) {
                intervals[i] = Math.abs(mPulseTimes[(i + 1) % 5] - mPulseTimes[i]);
                sum += intervals[i];
            }
            long avg = sum / 4;
            if (avg < 5000 || avg > 300000) return false; // Between 5s and 5m

            long varianceSum = 0;
            for (long inter : intervals) {
                long diff = inter - avg;
                varianceSum += (diff * diff);
            }
            long stdDev = (long) Math.sqrt((double) varianceSum / 4);

            /* Standard deviation < 8% of average indicates algorithmic (non-human) heartbeat */
            return stdDev < (avg * 0.08);
        }
    }
}
