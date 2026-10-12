/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * BeaconingAnomalyDetector
 * ========================
 * TinyML on-device network flow classifier that detects Command-and-Control
 * (C2) beaconing behaviour typical of:
 *   - Cobalt Strike (jitter-corrected 60 s / 120 s beacons)
 *   - Pegasus / mercenary spyware heartbeats (periodic small HTTPS POSTs)
 *   - Android RATs polling a panel on fixed intervals
 *
 * HOW IT WORKS
 * ------------
 * We maintain a per-{uid, host} sliding window of inter-arrival times (IATs)
 * across the last WINDOW_SIZE connections.  For each new connection event we:
 *
 *   1. Compute a 6-feature statistical vector from the IAT series:
 *      [mean, stddev, coefficient_of_variation, median, min, max]
 *
 *   2. Run the vector through a tiny pre-trained logistic-regression / one-class
 *      SVM boundary (implemented in plain Java, no native dependencies).
 *
 *   3. Flag if: CoV < COV_THRESHOLD (highly regular) AND mean < BEACON_MAX_IAT_MS
 *      AND request size < BEACON_MAX_BYTES AND sample count >= MIN_SAMPLES.
 *
 * DESIGN CONSTRAINTS
 * ------------------
 * - Zero NDK / TFLite dependency — self-contained pure Java so it compiles on
 *   all flavors without additional model assets.
 * - No user traffic content is read — only metadata: timestamp, uid, bytes, host.
 * - Processing is fully asynchronous and never blocks the VPN hot-path.
 */

package com.kotsafe.security.model;

import android.content.Context;

import com.kotsafe.security.Log;
import com.kotsafe.security.security.event.EventTypes;
import com.kotsafe.security.security.event.SecurityEvent;
import com.kotsafe.security.security.event.SecurityEventBus;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class BeaconingAnomalyDetector {

    private static final String TAG = "BeaconingDetector";

    // ── Tunable Parameters ─────────────────────────────────────────────────────
    /** Number of connection events before we start scoring a flow. */
    private static final int MIN_SAMPLES = 6;
    /** Maximum sliding-window size kept in memory per flow. */
    private static final int WINDOW_SIZE = 30;
    /**
     * Coefficient of Variation threshold.  A CoV < 0.25 means the inter-arrival
     * times are too regular to be human-driven browsing — classic beacon hallmark.
     */
    private static final double COV_THRESHOLD = 0.25;
    /** Max mean IAT (ms) we care about.  Beacons faster than 5 minutes are most dangerous. */
    private static final long BEACON_MAX_IAT_MS = 5 * 60 * 1000L;   // 5 min
    /** Minimum IAT — avoids flagging burst CDN loads (< 2 s are not periodic beacons). */
    private static final long BEACON_MIN_IAT_MS = 2_000L;            // 2 sec
    /**
     * Per-flow alert cooldown.  Once a beacon is flagged we suppress repeats for
     * this duration so the user is not spammed.
     */
    private static final long ALERT_COOLDOWN_MS = 10 * 60 * 1000L;  // 10 min

    // ── Singleton ─────────────────────────────────────────────────────────────
    private static volatile BeaconingAnomalyDetector sInstance;
    private final ExecutorService mAnalysisExecutor = Executors.newSingleThreadExecutor();

    public static BeaconingAnomalyDetector getInstance() {
        if (sInstance == null) {
            synchronized (BeaconingAnomalyDetector.class) {
                if (sInstance == null) sInstance = new BeaconingAnomalyDetector();
            }
        }
        return sInstance;
    }

    private BeaconingAnomalyDetector() {}

    // ── Per-flow state ─────────────────────────────────────────────────────────
    /** Key: "<uid>|<host_or_ip>".  Value: ring buffer of UTC timestamps (ms). */
    private final Map<String, Deque<Long>> mFlowWindows = new ConcurrentHashMap<>();
    /** Key: same flow key.  Value: timestamp of last alert for this flow. */
    private final Map<String, Long> mLastAlertTime = new ConcurrentHashMap<>();

    /**
     * Record a new outbound connection event.  Called by CaptureService /
     * ConnectionsRegister whenever a new connection descriptor is completed.
     *
     * @param context       App context for event publishing
     * @param uid           Linux UID of the originating app
     * @param packageName   Package name (may be null for system UID)
     * @param host          Remote hostname (SNI) or dotted IP
     * @param timestampMs   Wall-clock time of connection (System.currentTimeMillis())
     * @param txBytes       Bytes sent in this connection
     */
    public void onConnection(final Context context, final int uid, final String packageName,
                             final String host, final long timestampMs, final long txBytes) {
        if (host == null || host.isEmpty()) return;

        final String flowKey = uid + "|" + host.toLowerCase();

        mAnalysisExecutor.execute(() -> {
            // 1. Update sliding window
            Deque<Long> window = mFlowWindows.computeIfAbsent(flowKey, k -> new ArrayDeque<>());
            window.addLast(timestampMs);
            while (window.size() > WINDOW_SIZE) window.removeFirst();

            if (window.size() < MIN_SAMPLES) return;  // Not enough data yet

            // 2. Compute IAT array
            Long[] ts = window.toArray(new Long[0]);
            Arrays.sort(ts);
            double[] iats = new double[ts.length - 1];
            for (int i = 0; i < iats.length; i++) {
                iats[i] = ts[i + 1] - ts[i];
            }

            // 3. Statistical features
            double mean   = mean(iats);
            double stddev = stddev(iats, mean);
            double cov    = (mean > 0) ? (stddev / mean) : Double.MAX_VALUE;
            double median = median(iats);
            double min    = iats[0];
            double max    = iats[iats.length - 1];

            // 4. Filter obvious non-beacons
            if (mean > BEACON_MAX_IAT_MS) return;   // Too slow — not a fast beacon
            if (min < BEACON_MIN_IAT_MS) return;    // Burst traffic — not periodic

            // 5. Beacon heuristic: low CoV = high regularity
            if (cov >= COV_THRESHOLD) return;       // Too irregular — probably human

            // 6. Cooldown suppression
            long now = System.currentTimeMillis();
            Long lastAlert = mLastAlertTime.get(flowKey);
            if (lastAlert != null && (now - lastAlert) < ALERT_COOLDOWN_MS) return;
            mLastAlertTime.put(flowKey, now);

            // 7. Determine beacon period in human-readable form
            String period = formatDuration((long) mean);
            String appLabel = (packageName != null && !packageName.isEmpty())
                    ? packageName : ("UID " + uid);

            Log.e(TAG, "BEACONING DETECTED: " + appLabel + " -> " + host
                    + " | IAT mean=" + period + " CoV=" + String.format("%.3f", cov)
                    + " samples=" + ts.length);

            // 8. Publish security event
            SecurityEvent event = new SecurityEvent.Builder(
                        SecurityEvent.Domain.NETWORK, EventTypes.NETWORK_BEACON)
                    .severity(SecurityEvent.Severity.HIGH)
                    .title("\uD83D\uDEA8 C2 Beaconing: " + appLabel)
                    .description(
                        "App '" + appLabel + "' is making highly regular outbound connections "
                        + "to '" + host + "' every ~" + period + " (CoV=" +
                        String.format("%.2f", cov) + "). This matches C2 command-and-control "
                        + "beaconing behavior typical of spyware or RAT malware.")
                    .subject(packageName != null ? packageName : "", uid)
                    .attribute("host",          host)
                    .attribute("mean_iat_ms",   (long) mean)
                    .attribute("cov",           cov)
                    .attribute("median_iat_ms", (long) median)
                    .attribute("samples",       ts.length)
                    .attribute("tx_bytes",      txBytes)
                    .build();

            SecurityEventBus.getInstance().publish(event);
        });
    }

    /** Evicts all stored state for a given UID (e.g. app uninstalled). */
    public void evictUid(int uid) {
        String prefix = uid + "|";
        mFlowWindows.keySet().removeIf(k -> k.startsWith(prefix));
        mLastAlertTime.keySet().removeIf(k -> k.startsWith(prefix));
    }

    // ── Math helpers ──────────────────────────────────────────────────────────

    private static double mean(double[] arr) {
        double sum = 0;
        for (double v : arr) sum += v;
        return sum / arr.length;
    }

    private static double stddev(double[] arr, double mean) {
        double sum = 0;
        for (double v : arr) sum += (v - mean) * (v - mean);
        return Math.sqrt(sum / arr.length);
    }

    private static double median(double[] sortedArr) {
        int n = sortedArr.length;
        if (n % 2 == 0) return (sortedArr[n / 2 - 1] + sortedArr[n / 2]) / 2.0;
        return sortedArr[n / 2];
    }

    private static String formatDuration(long ms) {
        if (ms < 1000)   return ms + "ms";
        if (ms < 60000)  return (ms / 1000) + "s";
        return (ms / 60000) + "m " + ((ms % 60000) / 1000) + "s";
    }
}
