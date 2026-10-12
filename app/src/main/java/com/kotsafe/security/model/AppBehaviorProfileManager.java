/*
 * This file is part of KotSafe.
 *
 * KotSafe is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * KotSafe is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with KotSafe.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2026 KotSafe Cyber Security Project
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.os.PowerManager;

import com.kotsafe.security.Log;
import com.kotsafe.security.Utils;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Pillar 1: Per-App Network Behavioral Profiling & Zero-Trust Anomaly Engine.
 *
 * Maintains automated baselines of standard ports and domains for each installed application.
 * Identifies stealthy outbound C2 beaconing, Metasploit/Meterpreter ports, DGA domains,
 * and covert exfiltration while screen is locked.
 */
public class AppBehaviorProfileManager {
    private static final String TAG = "AppBehaviorProfile";
    private static final int LEARNING_FLOW_THRESHOLD = 25; // flows needed before enforcing anomaly alerts

    // Known adversary / backdoor / mining ports
    private static final Set<Integer> SUSPICIOUS_C2_PORTS = new HashSet<>(Arrays.asList(
            4444, 1337, 31337, 5555, 6667, 3333, 8888, 9999, 1080, 7777, 8443, 9001
    ));

    private static volatile AppBehaviorProfileManager sInstance;
    private final Context mContext;
    private final AppBaselineDb mDb;
    private final PowerManager mPowerManager;
    private final ExecutorService mAsyncExecutor = Executors.newSingleThreadExecutor();

    // In-memory cache of active app profiles for sub-millisecond lookups
    private final Map<String, AppBaselineDb.AppProfile> mProfileCache = new ConcurrentHashMap<>();

    // Tracks recent connection timestamps for beaconing jitter analysis: key = "pkg:ip:port"
    private final Map<String, Deque<Long>> mConnectionHistory = new ConcurrentHashMap<>();

    public interface AnomalyListener {
        void onAnomalyDetected(AppBaselineDb.AnomalyEvent event);
    }

    public static boolean isQuarantineEligible(String severity, String anomalyType) {
        if (severity == null || anomalyType == null) return false;
        String normalizedSeverity = severity.trim().toUpperCase(Locale.ROOT);
        String normalizedType = anomalyType.trim().toUpperCase(Locale.ROOT);
        if ("CRITICAL".equals(normalizedSeverity)) return true;
        if (!"HIGH".equals(normalizedSeverity)) return false;

        // DGA entropy and generic behavioral noise are statistical telemetry indicators
        // and must never be quarantine-eligible. Only severe covert anomalies qualify.
        return "UNEXPECTED_PORT".equals(normalizedType)
                || "COVERT_BEACONING".equals(normalizedType)
                || "SCREEN_OFF_EXFILTRATION".equals(normalizedType)
                || "CONFIRMED_MALWARE_C2".equals(normalizedType)
                || "EXPLOIT_PAYLOAD".equals(normalizedType);
    }

    private final Set<AnomalyListener> mListeners = new HashSet<>();

    public static synchronized AppBehaviorProfileManager getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new AppBehaviorProfileManager(context.getApplicationContext());
        }
        return sInstance;
    }

    private AppBehaviorProfileManager(Context context) {
        mContext = context;
        mDb = AppBaselineDb.getInstance(context);
        mPowerManager = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
    }

    public synchronized void registerListener(AnomalyListener listener) {
        if (listener != null) mListeners.add(listener);
    }

    public synchronized void unregisterListener(AnomalyListener listener) {
        mListeners.remove(listener);
    }

    /**
     * Non-blocking entry point called for every observed network flow in the VPN tunnel.
     */
    public void processFlow(String appName, String packageName, String ip, int port, String domain, String url) {
        if (packageName == null || packageName.isEmpty() || "android".equals(packageName) || port <= 0) {
            return;
        }

        // Fast path: exempt self & p2p tunnel components
        if (packageName.startsWith("com.kotsafe.security") || packageName.startsWith("com.kotsafe.security")) {
            return;
        }

        final boolean isScreenOff = (mPowerManager != null) && !mPowerManager.isInteractive();
        final long now = System.currentTimeMillis();

        mAsyncExecutor.execute(() -> {
            try {
                analyzeFlowAsync(appName, packageName, ip, port, domain, url, isScreenOff, now);
            } catch (Exception e) {
                Log.w(TAG, "Error analyzing flow: " + e.getMessage());
            }
        });
    }

    private void analyzeFlowAsync(String appName, String packageName, String ip, int port,
                                  String domain, String url, boolean isScreenOff, long timestamp) {
        AppBaselineDb.AppProfile profile = mProfileCache.get(packageName);
        if (profile == null) {
            profile = mDb.getProfile(packageName);
            if (profile == null) {
                profile = new AppBaselineDb.AppProfile();
                profile.packageName = packageName;
                profile.appName = (appName != null && !appName.isEmpty()) ? appName : packageName;
                profile.firstSeen = timestamp;
            }
            mProfileCache.put(packageName, profile);
        }

        profile.lastSeen = timestamp;
        profile.totalFlows++;

        // 1. Learning Phase vs Active Protection
        if (!profile.isLearningComplete) {
            profile.knownPorts.add(port);
            if (domain != null && !domain.isEmpty()) {
                profile.knownDomains.add(domain.toLowerCase(Locale.ROOT));
            }

            if (profile.totalFlows >= LEARNING_FLOW_THRESHOLD) {
                profile.isLearningComplete = true;
                Log.i(TAG, "Baseline established for " + packageName + " (" + profile.knownPorts.size() + " ports)");
            }
            mDb.saveProfile(profile);
            return;
        }

        // 2. Active Protection Checks (Anomaly Detection)
        AppBaselineDb.AnomalyEvent anomaly = null;

        // Check A: Unexpected Port Anomaly
        if (!profile.isKnownPort(port)) {
            if (SUSPICIOUS_C2_PORTS.contains(port)) {
                anomaly = createAnomaly(profile, ip, port, domain, timestamp,
                        "UNEXPECTED_PORT", "CRITICAL",
                        "App initiated out-of-baseline connection to known offensive C2 port: " + port,
                        "BLOCKED");
            } else if (port < 1024 && port != 80 && port != 443 && port != 53 && port != 123) {
                anomaly = createAnomaly(profile, ip, port, domain, timestamp,
                        "UNEXPECTED_PORT", "HIGH",
                        "App attempted out-of-baseline privileged service connection to port " + port,
                        "ALERTED");
            }
        }

        // Check B: DGA (Domain Generation Algorithm) Entropy Anomaly
        if (anomaly == null && domain != null && !domain.isEmpty() && !profile.isKnownDomain(domain)) {
            String d = domain.trim().toLowerCase(Locale.ROOT);
            // Ignore package names, Android system identifiers, IPs, and known trusted domains/CDNs
            boolean isPackage = d.equals(packageName) || d.equals(profile.packageName)
                    || d.startsWith(packageName) || d.contains(".mshop.") || d.contains(".shopping")
                    || d.contains(".android.") || d.contains(".app.");
            boolean isKnownTrusted = SecurityBlocklistManager.isOfficialDomain(d)
                    || SecurityBlocklistManager.isTrustedAdOrAnalyticsDomain(d)
                    || d.contains("amazon")
                    || d.contains("whatsapp")
                    || d.contains("google")
                    || d.contains("apple")
                    || d.contains("microsoft")
                    || d.contains("heytap")
                    || d.contains("oppo")
                    || d.contains("realme")
                    || d.contains("oneplus")
                    || d.contains("xiaomi")
                    || d.contains("samsung")
                    || d.contains("cloudflare")
                    || d.contains("akamaized")
                    || d.contains("cloudfront");

            if (!isPackage && !isKnownTrusted && d.contains(".")) {
                // Compute entropy on the specific domain label (SLD), avoiding dots and TLD bias
                String[] parts = d.split("\\.");
                String label = parts.length >= 2 ? parts[parts.length - 2] : d;
                if (label.length() >= 16) {
                    double entropy = calculateShannonEntropy(label);
                    if (entropy > 4.60) {
                        anomaly = createAnomaly(profile, ip, port, domain, timestamp,
                                "DGA_ENTROPY", "MEDIUM",
                                String.format(Locale.ROOT, "High-entropy algorithmic domain label detected: %s (Entropy: %.2f)", label, entropy),
                                "ALERTED");
                    }
                }
            }
        }

        // Check C: Automated Periodic Beaconing (Low Jitter)
        if (anomaly == null) {
            boolean isExemptPushOrWeb = port == 443 || port == 80 || port == 5228 || port == 5229 || port == 5230
                    || (domain != null && (SecurityBlocklistManager.isOfficialDomain(domain) || domain.contains("whatsapp") || domain.contains("google")))
                    || Utils.isEssentialOrBrowserApp(mContext, packageName);

            if (!isExemptPushOrWeb) {
                String flowKey = packageName + ":" + ip + ":" + port;
                Deque<Long> history = mConnectionHistory.computeIfAbsent(flowKey, k -> new ArrayDeque<>());
                synchronized (history) {
                    history.addLast(timestamp);
                    while (history.size() > 8) {
                        history.removeFirst();
                    }

                    if (history.size() >= 5) {
                        if (detectPeriodicBeaconing(history)) {
                            anomaly = createAnomaly(profile, ip, port, domain, timestamp,
                                    "COVERT_BEACONING", "MEDIUM",
                                    "Detected fixed-interval covert beaconing heartbeat to " + ip + ":" + port,
                                    "ALERTED");
                            history.clear(); // Reset to avoid re-triggering immediately
                        }
                    }
                }
            }
        }

        // Check D: Covert Screen-Off Background Exfiltration
        if (anomaly == null && isScreenOff && !profile.isKnownPort(port)) {
            anomaly = createAnomaly(profile, ip, port, domain, timestamp,
                    "SCREEN_OFF_EXFILTRATION", "HIGH",
                    "Suspicious background socket opened to unseen port " + port + " while device screen is locked",
                    "ALERTED");
        }

        // If anomaly found, record and notify
        if (anomaly != null) {
            mDb.recordAnomaly(anomaly);
            profile.anomalyCount++;

            // If critical or harmful, quarantine the offending app and sever the active C2 path.
            if (isQuarantineEligible(anomaly.severity, anomaly.anomalyType)) {
                try {
                    String appPackage = profile.packageName;
                    if (appPackage != null && !appPackage.isEmpty()
                            && !"android".equals(appPackage)
                            && !appPackage.startsWith("com.kotsafe.security")
                            && !Utils.isEssentialOrBrowserApp(mContext, appPackage)
                            && !Utils.isVerifiedGoogleTrustedService(mContext, appPackage)) {
                        String reason = "Behavioral quarantine: " + anomaly.anomalyType + " (" + anomaly.severity + ")";
                        SecurityBlocklistManager secMgr = SecurityBlocklistManager.getInstance(mContext);
                        secMgr.quarantineApp(appPackage, reason, SecurityRulesDb.SOURCE_HEURISTIC);
                        if (ip != null && !ip.isEmpty()) {
                            secMgr.blockIp(ip, reason, SecurityRulesDb.SOURCE_HEURISTIC);
                        }
                        Log.w(TAG, "Behavioral quarantine enforced for " + appPackage + " via " + anomaly.anomalyType);
                    }
                } catch (Exception be) {
                    Log.w(TAG, "Failed to apply behavioral quarantine: " + be.getMessage());
                }
            }

            // If critical and confirmed malicious C2, automatically add to blocklist to sever connection
            if ("BLOCKED".equalsIgnoreCase(anomaly.actionTaken) || "CRITICAL".equalsIgnoreCase(anomaly.severity)) {
                try {
                    SecurityBlocklistManager secMgr = SecurityBlocklistManager.getInstance(mContext);
                    if (SecurityBlocklistManager.isKnownMalwareC2(ip) || (anomaly.anomalyType != null && anomaly.anomalyType.contains("C2"))) {
                        secMgr.blockIp(
                                ip, "Zero-Trust Behavioral Engine: " + anomaly.anomalyType, SecurityRulesDb.SOURCE_HEURISTIC
                        );
                        Log.w(TAG, "Zero-Trust auto-block enforced on confirmed malicious C2 IP: " + ip + " for " + packageName);
                    } else {
                        Log.i(TAG, "Zero-Trust anomaly recorded without blocking IP (not confirmed malicious): " + ip);
                    }
                } catch (Exception be) {
                    Log.w(TAG, "Failed to apply auto-block: " + be.getMessage());
                }
            }

            final AppBaselineDb.AnomalyEvent finalAnomaly = anomaly;
            try {
                UnifiedIncidentTimeline.getInstance(mContext).record(
                        new UnifiedIncidentTimeline.IncidentEvent.Builder()
                                .type(UnifiedIncidentTimeline.EventType.BEHAVIORAL_CORRELATION)
                                .severity("CRITICAL".equalsIgnoreCase(anomaly.severity)
                                        ? UnifiedIncidentTimeline.Severity.CRITICAL
                                        : UnifiedIncidentTimeline.Severity.HIGH)
                                .title("Behavioral Anomaly: " + anomaly.anomalyType)
                                .detail(anomaly.details)
                                .sourceApp(anomaly.packageName)
                                .target(anomaly.destIp + (anomaly.destPort > 0 ? ":" + anomaly.destPort : ""))
                                .mitre("T1071")
                                .risk(85)
                                .timestamp(anomaly.timestamp)
                );
            } catch (Exception ignored) {}

            for (AnomalyListener l : mListeners) {
                try {
                    l.onAnomalyDetected(finalAnomaly);
                } catch (Exception ignored) {}
            }
        } else {
            // Gradually expand legitimate baseline if safe
            profile.knownPorts.add(port);
            if (domain != null && !domain.isEmpty()) {
                profile.knownDomains.add(domain.toLowerCase(Locale.ROOT));
            }
        }

        mDb.saveProfile(profile);
    }

    private AppBaselineDb.AnomalyEvent createAnomaly(AppBaselineDb.AppProfile profile, String ip, int port,
                                                     String domain, long time, String type, String severity,
                                                     String details, String action) {
        AppBaselineDb.AnomalyEvent e = new AppBaselineDb.AnomalyEvent();
        e.timestamp = time;
        e.packageName = profile.packageName;
        e.appName = profile.appName;
        e.destIp = ip;
        e.destPort = port;
        e.domain = domain;
        e.anomalyType = type;
        e.severity = severity;
        e.details = details;
        e.actionTaken = action;
        Log.w(TAG, "🚨 [EDR ANOMALY] " + type + " (" + severity + ") in " + profile.appName + " -> " + details);
        return e;
    }

    /**
     * Calculates Shannon entropy for detecting algorithmic DGA domains.
     */
    public static double calculateShannonEntropy(String s) {
        if (s == null || s.isEmpty()) return 0.0;
        Map<Character, Integer> freq = new HashMap<>();
        for (char c : s.toCharArray()) {
            freq.put(c, freq.getOrDefault(c, 0) + 1);
        }
        double entropy = 0.0;
        int len = s.length();
        for (int count : freq.values()) {
            double p = (double) count / len;
            entropy -= p * (Math.log(p) / Math.log(2.0));
        }
        return entropy;
    }

    /**
     * Detects low-jitter periodic beaconing intervals (e.g. heartbeats occurring every N seconds with < 8% variance).
     */
    private boolean detectPeriodicBeaconing(Deque<Long> history) {
        Long[] times = history.toArray(new Long[0]);
        if (times.length < 5) return false;

        long[] deltas = new long[times.length - 1];
        long sum = 0;
        for (int i = 0; i < deltas.length; i++) {
            deltas[i] = times[i + 1] - times[i];
            sum += deltas[i];
        }

        double mean = (double) sum / deltas.length;
        // Periodic C2 beaconing typically happens between 5s and 300s
        if (mean < 5000 || mean > 300000) {
            return false;
        }

        double variance = 0.0;
        for (long d : deltas) {
            variance += Math.pow(d - mean, 2);
        }
        variance /= deltas.length;
        double stdDev = Math.sqrt(variance);

        // Coefficient of variation (jitter)
        double cv = stdDev / mean;
        return cv < 0.08; // Less than 8% jitter is typical of automated C2 beaconing
    }

    public List<AppBaselineDb.AnomalyEvent> getRecentAnomalies(int limit) {
        return mDb.getRecentAnomalies(limit);
    }
}
