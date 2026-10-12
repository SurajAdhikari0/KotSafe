/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import android.content.Context;

import com.kotsafe.security.Log;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * High-Volume Telemetry Parser & Stream Buffer.
 *
 * Manages high-throughput ingestion of network flows, packet headers, DNS records,
 * and browser visits without stalling the VPN tunnel or causing UI frame drops.
 *
 * Architecture:
 *   1. Non-blocking enqueue into a bounded ConcurrentLinkedQueue.
 *   2. Scheduled background worker flushes batches to SQLite databases (every 500ms or 50 items).
 *   3. Feature extraction & normalization (entropy, protocols, ports, payload sizes, TLDs).
 *   4. Feed stream to RiskCorrelationEngine and AiTelemetryBridge for real-time analysis.
 */
public class TelemetryDataParser {
    private static final String TAG = "TelemetryDataParser";
    private static final int MAX_QUEUE_CAPACITY = 2000;
    private static final int BATCH_SIZE = 50;
    private static final long FLUSH_INTERVAL_MS = 500;

    public static class TelemetryRecord {
        public long timestamp;
        public String source; // "NETWORK" | "BROWSER" | "FILE" | "APP"
        public String packageName;
        public String appName;
        public String ip;
        public int port;
        public String protocol;
        public String domain;
        public String url;
        public String method;
        public long payloadBytes;
        public double entropy;
        public boolean isSystemApp;
        public boolean isBackground;
        public boolean wasBlocked;
        public String verdict; // "SAFE" | "LOW" | "SUSPICIOUS" | "MALICIOUS"
        public int riskScore;

        public TelemetryRecord() {
            this.timestamp = System.currentTimeMillis();
            this.verdict = "SAFE";
            this.riskScore = 0;
        }
    }

    private static TelemetryDataParser sInstance;
    private final Context mContext;
    private final ConcurrentLinkedQueue<TelemetryRecord> mQueue;
    private final ScheduledExecutorService mFlushExecutor;
    private final AtomicBoolean mIsFlushing = new AtomicBoolean(false);

    public static synchronized TelemetryDataParser getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new TelemetryDataParser(context.getApplicationContext());
        }
        return sInstance;
    }

    private TelemetryDataParser(Context context) {
        mContext = context;
        mQueue = new ConcurrentLinkedQueue<>();
        mFlushExecutor = Executors.newSingleThreadScheduledExecutor();
        mFlushExecutor.scheduleWithFixedDelay(this::flushBatch, FLUSH_INTERVAL_MS, FLUSH_INTERVAL_MS, TimeUnit.MILLISECONDS);
    }

    /**
     * Non-blocking ingestion: enqueues a telemetry record. If queue is saturated, drops oldest.
     */
    public void enqueue(TelemetryRecord record) {
        if (record == null) return;
        if (mQueue.size() >= MAX_QUEUE_CAPACITY) {
            mQueue.poll(); // Discard oldest to preserve memory
        }
        mQueue.offer(record);
        if (mQueue.size() >= BATCH_SIZE && !mIsFlushing.get()) {
            mFlushExecutor.execute(this::flushBatch);
        }
    }

    /**
     * Extracts Shannon entropy for payload analysis (detects encrypted C2 payloads or high-entropy stagers).
     */
    public static double computeEntropy(byte[] data) {
        if (data == null || data.length == 0) return 0.0;
        int[] freq = new int[256];
        for (byte b : data) {
            freq[b & 0xFF]++;
        }
        double entropy = 0.0;
        int len = data.length;
        for (int count : freq) {
            if (count > 0) {
                double p = (double) count / len;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }
        return entropy;
    }

    /**
     * Flushes a batch of queued records to storage and the AI telemetry stream.
     */
    private void flushBatch() {
        if (!mIsFlushing.compareAndSet(false, true)) return;
        try {
            List<TelemetryRecord> batch = new ArrayList<>();
            TelemetryRecord r;
            while ((r = mQueue.poll()) != null && batch.size() < BATCH_SIZE) {
                batch.add(r);
            }
            if (batch.isEmpty()) return;

            // Batch write URL visits to UrlVisitDbHelper if appropriate
            UrlVisitDbHelper urlDb = UrlVisitDbHelper.getInstance(mContext);
            for (TelemetryRecord item : batch) {
                if ("BROWSER".equals(item.source) || ("NETWORK".equals(item.source) && item.domain != null && !item.domain.isEmpty())) {
                    UrlVisitLog visit = new UrlVisitLog();
                    visit.timestamp = item.timestamp;
                    visit.appName = item.appName;
                    visit.packageName = item.packageName;
                    visit.ip = item.ip;
                    visit.domain = item.domain;
                    visit.url = item.url != null ? item.url : item.domain;
                    visit.method = item.method != null ? item.method : "TCP";
                    visit.riskScore = item.riskScore;
                    visit.verdict = item.verdict;
                    visit.wasBlocked = item.wasBlocked;
                    urlDb.logUrlVisit(visit);
                }
            }

            // Feed to unified AI activity ledger
            AiTelemetryBridge.getInstance(mContext).recordBatch(batch);
        } catch (Exception e) {
            Log.e(TAG, "flushBatch error: " + e.getMessage());
        } finally {
            mIsFlushing.set(false);
        }
    }

    public void shutdown() {
        try {
            mFlushExecutor.shutdown();
        } catch (Exception ignored) {}
    }
}
