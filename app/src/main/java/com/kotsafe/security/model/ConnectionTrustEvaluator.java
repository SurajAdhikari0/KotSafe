/*
 * This file is part of KotSafe / KotSafe Cyber Security Project.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import androidx.annotation.NonNull;

/**
 * On-device connection trust scorer.
 *
 * Produces a {@link RiskLevel} for any {@link ConnectionDescriptor} using:
 * <ul>
 *   <li>Threat-intelligence blacklist status (fastest signal, highest weight)</li>
 *   <li>Sensitive / non-standard port heuristics</li>
 *   <li>Cleartext protocol detection (HTTP over public internet)</li>
 *   <li>Heavy outbound data asymmetry (exfiltration indicator)</li>
 *   <li>Periodic connection cadence (C2 beaconing detector)</li>
 * </ul>
 *
 * All computations are synchronous and allocation-light for use inside a
 * {@link androidx.recyclerview.widget.RecyclerView} adapter's {@code onBindViewHolder}.
 */
public final class ConnectionTrustEvaluator {

    // -----------------------------------------------------------------------
    // Risk level enum
    // -----------------------------------------------------------------------

    public enum RiskLevel {
        /** No threat signals detected. */
        CLEAN,
        /** One or more low-severity anomalies. Monitor but do not block. */
        SUSPICIOUS,
        /** Multiple strong threat signals. User action recommended. */
        HIGH_RISK,
        /** Matched confirmed blacklist. Block immediately. */
        MALICIOUS;

        /** Human-readable short label for badge display. */
        @NonNull
        public String label() {
            switch (this) {
                case MALICIOUS:  return "MALICIOUS";
                case HIGH_RISK:  return "HIGH RISK";
                case SUSPICIOUS: return "SUSPICIOUS";
                default:         return "CLEAN";
            }
        }

        /** Returns true if this level warrants a visible badge in the UI. */
        public boolean isBadgeVisible() {
            return this != CLEAN;
        }
    }

    // -----------------------------------------------------------------------
    // Ports
    // -----------------------------------------------------------------------

    /** Ports that are suspicious when used as *outbound* destinations. */
    private static final int[] SUSPICIOUS_PORTS = {
            23,    // Telnet — cleartext remote shell
            4444,  // Meterpreter / common malware shell
            4445,  // Alternate shell / botnet
            6667, 6668, 6669, // IRC — C2 channel
            1080,  // SOCKS proxy (may be tunnelled traffic)
            8888,  // Alternate HTTP, malware loaders
            31337, // "Elite" port, historic malware
            12345, 54321 // Common RAT back-connect ports
    };

    /** Standard ports that strongly suggest legitimate traffic when used. */
    private static final int[] TRUSTED_PORTS = {
            80, 443, 8080, 8443, 53, 853, 25, 465, 587, 993, 995, 21, 22
    };

    // -----------------------------------------------------------------------
    // Beaconing detector state — stored per evaluator instance.
    // -----------------------------------------------------------------------

    /**
     * Minimum number of repeat connections to the same endpoint before the
     * interval regularity check fires.
     */
    private static final int BEACON_MIN_OBSERVATIONS = 3;

    /**
     * Maximum acceptable jitter (fraction of mean interval) for a connection
     * series to be flagged as regular C2 beaconing.
     */
    private static final double BEACON_JITTER_THRESHOLD = 0.08; // 8%

    /**
     * Minimum interval (ms) between connections to count as periodic
     * (ignore rapid retries).
     */
    private static final long BEACON_MIN_INTERVAL_MS = 20_000; // 20 s

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /**
     * Evaluate the risk level of a single connection.
     *
     * @param conn the connection descriptor to evaluate.
     * @return a {@link RiskLevel} — never null.
     */
    @NonNull
    public RiskLevel evaluate(@NonNull ConnectionDescriptor conn) {
        int score = 0;

        // --- Signal 1: Blacklist (highest weight, instant MALICIOUS) ---
        if (conn.isBlacklisted()) {
            return RiskLevel.MALICIOUS;
        }

        // --- Signal 2: Port heuristics ---
        int portScore = scorePort(conn.dst_port);
        score += portScore;

        // --- Signal 3: Cleartext protocol over non-local destination ---
        if (isCleartextSuspicious(conn)) {
            score += 20;
        }

        // --- Signal 4: Heavy upload asymmetry (exfiltration) ---
        if (isExfiltrationSuspicious(conn)) {
            score += 30;
        }

        // --- Signal 5: Reduce score for well-known cloud destinations ---
        if (isTrustedHost(conn)) {
            score = Math.max(0, score - 30);
        }

        return scoreToLevel(score);
    }

    /**
     * Evaluate beaconing risk across a list of recent connection timestamps
     * (epoch ms) to the same endpoint.
     *
     * @param timestampsMs sorted list of {@code first_seen} timestamps.
     * @return {@code true} if the cadence matches periodic C2 beaconing.
     */
    public boolean isBeaconing(@NonNull long[] timestampsMs) {
        if (timestampsMs.length < BEACON_MIN_OBSERVATIONS) return false;

        // Compute inter-arrival intervals
        int n = timestampsMs.length - 1;
        double[] intervals = new double[n];
        double sum = 0;
        for (int i = 0; i < n; i++) {
            intervals[i] = timestampsMs[i + 1] - timestampsMs[i];
            sum += intervals[i];
        }

        double mean = sum / n;
        if (mean < BEACON_MIN_INTERVAL_MS) return false; // Ignore rapid retries

        // Compute coefficient of variation (std/mean)
        double varianceSum = 0;
        for (double iv : intervals) {
            double diff = iv - mean;
            varianceSum += diff * diff;
        }
        double stdDev = Math.sqrt(varianceSum / n);
        double cv = stdDev / mean;

        return cv <= BEACON_JITTER_THRESHOLD;
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    private int scorePort(int port) {
        for (int tp : TRUSTED_PORTS) {
            if (port == tp) return -10; // Well-known, reduce score
        }
        for (int sp : SUSPICIOUS_PORTS) {
            if (port == sp) return 45; // Strong signal
        }
        if (port > 0 && port < 1024) return 5;   // Other privileged port
        if (port > 49151) return 10;              // Ephemeral range outbound
        return 0;                                  // Registered range — neutral
    }

    private boolean isCleartextSuspicious(@NonNull ConnectionDescriptor conn) {
        // HTTP on port 80 or custom HTTP port going to a non-LAN address
        if (conn.dst_port == 80 || conn.dst_port == 8080) {
            String dst = conn.dst_ip;
            if (dst != null && !isPrivateAddress(dst)) {
                return true;
            }
        }
        return false;
    }

    private boolean isExfiltrationSuspicious(@NonNull ConnectionDescriptor conn) {
        long sent = conn.sent_bytes;
        long rcvd = conn.rcvd_bytes;
        // Heavy upload with minimal server response
        return sent > 100_000 && rcvd > 0 && (double) sent / rcvd > 20.0;
    }

    private boolean isTrustedHost(@NonNull ConnectionDescriptor conn) {
        String info = conn.info;
        if (info == null || info.isEmpty()) return false;
        String h = info.toLowerCase(java.util.Locale.ROOT);
        return h.contains("google") || h.contains("gstatic") || h.contains("apple") ||
               h.contains("microsoft") || h.contains("cloudflare") || h.contains("akamai") ||
               h.contains("amazonaws") || h.contains("azure") || h.contains("fastly");
    }

    private boolean isPrivateAddress(@NonNull String ip) {
        return ip.startsWith("10.") ||
               ip.startsWith("192.168.") ||
               ip.startsWith("172.") ||   // 172.16–31.x.x (good-enough heuristic)
               ip.startsWith("127.") ||
               ip.equals("::1");
    }

    @NonNull
    private RiskLevel scoreToLevel(int score) {
        if (score >= 55) return RiskLevel.HIGH_RISK;
        if (score >= 25) return RiskLevel.SUSPICIOUS;
        return RiskLevel.CLEAN;
    }
}
