/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Port Scan and Internal Lateral Movement Guard (MITRE ATT&CK T1046 & T1021).
 *
 * Tracks per-application connection patterns in a sliding 10-second window to detect:
 * 1. Rapid sequential port scanning (T1046: Network Service Discovery)
 * 2. Internal private LAN subnet sweeping (T1021: Remote Services / Lateral Movement)
 */
public class ReconnaissanceDetector {

    public static final long SLIDING_WINDOW_MS = 10_000L;
    public static final int PORT_SCAN_THRESHOLD = 12; // > 12 distinct ports in 10s
    public static final int LAN_SWEEP_THRESHOLD = 5;  // > 5 distinct private LAN IPs in 10s

    public static class ReconResult {
        public final boolean hasThreat;
        public final String mitreId;
        public final String threatName;
        public final String category;
        public final String severity;
        public final int uniquePorts;
        public final int uniqueLanIps;
        public final String details;

        public ReconResult(boolean hasThreat, String mitreId, String threatName,
                           String category, String severity, int uniquePorts,
                           int uniqueLanIps, String details) {
            this.hasThreat = hasThreat;
            this.mitreId = mitreId != null ? mitreId : "";
            this.threatName = threatName != null ? threatName : "";
            this.category = category != null ? category : "";
            this.severity = severity != null ? severity : "LOW";
            this.uniquePorts = uniquePorts;
            this.uniqueLanIps = uniqueLanIps;
            this.details = details != null ? details : "";
        }

        public static ReconResult clean(int ports, int lanIps) {
            return new ReconResult(false, "", "Normal Traffic", "NONE", "LOW", ports, lanIps, "");
        }
    }

    private static class ConnectionAttempt {
        final String dstIp;
        final int dstPort;
        final long timestamp;
        final boolean isLan;

        ConnectionAttempt(String dstIp, int dstPort, long timestamp, boolean isLan) {
            this.dstIp = dstIp;
            this.dstPort = dstPort;
            this.timestamp = timestamp;
            this.isLan = isLan;
        }
    }

    private static class AppTracker {
        private final List<ConnectionAttempt> attempts = new ArrayList<>();
        private long lastAlertMs = 0L;

        synchronized ReconResult record(String dstIp, int dstPort, long nowMs, boolean isLan) {
            long windowStart = nowMs - SLIDING_WINDOW_MS;

            // Prune attempts older than sliding window
            attempts.removeIf(a -> a.timestamp < windowStart);
            attempts.add(new ConnectionAttempt(dstIp, dstPort, nowMs, isLan));

            Set<Integer> ports = new HashSet<>();
            Set<String> lanIps = new HashSet<>();

            for (ConnectionAttempt a : attempts) {
                if (a.dstPort > 0) ports.add(a.dstPort);
                if (a.isLan && a.dstIp != null) lanIps.add(a.dstIp);
            }

            int pCount = ports.size();
            int lanCount = lanIps.size();

            // Suppress duplicate alert floods within 15 seconds
            if (nowMs - lastAlertMs < 15_000L) {
                return ReconResult.clean(pCount, lanCount);
            }

            // 1. LAN Subnet Sweep / Lateral Movement check (CRITICAL)
            if (lanCount >= LAN_SWEEP_THRESHOLD) {
                lastAlertMs = nowMs;
                return new ReconResult(true, "T1021", "LAN Subnet Sweep / Lateral Movement",
                        "LATERAL_MOVEMENT", "CRITICAL", pCount, lanCount,
                        "App probed " + lanCount + " distinct internal LAN devices within 10s");
            }

            // 2. Multi-Port Scanner check (HIGH)
            if (pCount >= PORT_SCAN_THRESHOLD) {
                lastAlertMs = nowMs;
                return new ReconResult(true, "T1046", "Network Service Discovery / Port Scan",
                        "RECONNAISSANCE", "HIGH", pCount, lanCount,
                        "App probed " + pCount + " distinct ports within 10s");
            }

            return ReconResult.clean(pCount, lanCount);
        }

        synchronized boolean isIdle(long nowMs, long maxIdleMs) {
            return attempts.isEmpty() || (nowMs - attempts.get(attempts.size() - 1).timestamp > maxIdleMs);
        }
    }

    private final ConcurrentHashMap<String, AppTracker> mTrackers = new ConcurrentHashMap<>();
    private long mLastPruneMs = System.currentTimeMillis();

    /**
     * Records an outbound connection attempt and evaluates for reconnaissance anomalies.
     */
    public ReconResult recordConnection(String packageName, String dstIp, int dstPort) {
        return recordConnection(packageName, dstIp, dstPort, System.currentTimeMillis());
    }

    public ReconResult recordConnection(String packageName, String dstIp, int dstPort, long nowMs) {
        if (packageName == null || packageName.isEmpty() || dstIp == null) {
            return ReconResult.clean(0, 0);
        }

        boolean isLan = isPrivateLanIp(dstIp);
        AppTracker tracker = mTrackers.computeIfAbsent(packageName, k -> new AppTracker());
        ReconResult result = tracker.record(dstIp, dstPort, nowMs, isLan);

        if (nowMs - mLastPruneMs > 60_000L) {
            pruneIdleTrackers(nowMs);
        }

        return result;
    }

    /**
     * Identifies private RFC 1918 IPv4 and link-local addresses:
     * - 10.0.0.0/8
     * - 172.16.0.0/12
     * - 192.168.0.0/16
     * - 169.254.0.0/16
     */
    public static boolean isPrivateLanIp(String ip) {
        if (ip == null || ip.isEmpty() || ip.contains(":")) {
            return false; // Skip IPv6 / hostname
        }
        try {
            if (ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("169.254.")) {
                return true;
            }
            if (ip.startsWith("172.")) {
                int secondDot = ip.indexOf('.', 4);
                if (secondDot > 4) {
                    int octet = Integer.parseInt(ip.substring(4, secondDot));
                    return octet >= 16 && octet <= 31;
                }
            }
        } catch (Exception ignored) {}
        return false;
    }

    public synchronized void pruneIdleTrackers(long nowMs) {
        mLastPruneMs = nowMs;
        long maxIdleMs = 60_000L;
        Iterator<Map.Entry<String, AppTracker>> it = mTrackers.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, AppTracker> entry = it.next();
            if (entry.getValue().isIdle(nowMs, maxIdleMs)) {
                it.remove();
            }
        }
    }

    public void clear() {
        mTrackers.clear();
    }
}
