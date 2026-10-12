/*
 * This file is part of KotSafe.
 * Copyright (c) 2026 KotSafe Cyber Security Project. All Rights Reserved.
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;

import com.kotsafe.security.Log;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * TrafficTimeSeriesCollector
 * ==========================
 * Manages both real-time (last 60 seconds rolling buffer) and historical time-series
 * data streams for GlassWire-style traffic wave graphs.
 */
public class TrafficTimeSeriesCollector {
    private static final String TAG = "TrafficTimeSeriesCol";
    private static final int ROLLING_BUFFER_CAPACITY = 60; // 60 seconds of live rolling data

    public static class DataPoint {
        public long timestamp;
        public float downloadKbps;
        public float uploadKbps;
        public boolean isNewAppEvent;
        public int alertCount;
        public String eventLabel;

        public DataPoint(long timestamp, float downloadKbps, float uploadKbps) {
            this.timestamp = timestamp;
            this.downloadKbps = downloadKbps;
            this.uploadKbps = uploadKbps;
            this.isNewAppEvent = false;
            this.alertCount = 0;
            this.eventLabel = null;
        }
    }

    public interface OnLiveTrafficListener {
        void onPointAdded(DataPoint point, List<DataPoint> rollingWindow);
    }

    private static volatile TrafficTimeSeriesCollector sInstance;
    private final List<DataPoint> mRollingBuffer = new LinkedList<>();
    private final List<OnLiveTrafficListener> mListeners = new ArrayList<>();

    private long mLastTimestamp = 0;
    private long mLastBytesRcvd = 0;
    private long mLastBytesSent = 0;

    public static TrafficTimeSeriesCollector getInstance() {
        if (sInstance == null) {
            synchronized (TrafficTimeSeriesCollector.class) {
                if (sInstance == null) {
                    sInstance = new TrafficTimeSeriesCollector();
                }
            }
        }
        return sInstance;
    }

    private TrafficTimeSeriesCollector() {
        // Initialize rolling buffer with 60 flat zero points
        long now = System.currentTimeMillis();
        for (int i = ROLLING_BUFFER_CAPACITY - 1; i >= 0; i--) {
            mRollingBuffer.add(new DataPoint(now - (i * 1000L), 0f, 0f));
        }
    }

    public synchronized void addListener(OnLiveTrafficListener listener) {
        if (listener != null && !mListeners.contains(listener)) {
            mListeners.add(listener);
        }
    }

    public synchronized void removeListener(OnLiveTrafficListener listener) {
        mListeners.remove(listener);
    }

    /**
     * Ingests a live tick (called roughly once per second from CaptureService stats observer).
     */
    public synchronized void recordLiveTick(long totalBytesRcvd, long totalBytesSent, boolean hasNewApp, int alertCount) {
        long now = System.currentTimeMillis();
        float downKbps = 0f;
        float upKbps = 0f;

        if (mLastTimestamp > 0 && now > mLastTimestamp) {
            float deltaSec = (now - mLastTimestamp) / 1000f;
            if (deltaSec > 0) {
                long deltaDown = Math.max(0, totalBytesRcvd - mLastBytesRcvd);
                long deltaUp = Math.max(0, totalBytesSent - mLastBytesSent);

                downKbps = (deltaDown / 1024f) / deltaSec;
                upKbps = (deltaUp / 1024f) / deltaSec;
            }
        }

        mLastTimestamp = now;
        mLastBytesRcvd = totalBytesRcvd;
        mLastBytesSent = totalBytesSent;

        DataPoint point = new DataPoint(now, downKbps, upKbps);
        point.isNewAppEvent = hasNewApp;
        point.alertCount = alertCount;
        if (hasNewApp) point.eventLabel = "NEW";
        else if (alertCount > 0) point.eventLabel = String.valueOf(alertCount);

        // Maintain 60-second fixed window
        mRollingBuffer.add(point);
        while (mRollingBuffer.size() > ROLLING_BUFFER_CAPACITY) {
            mRollingBuffer.remove(0);
        }

        List<DataPoint> snapshot = new ArrayList<>(mRollingBuffer);
        for (OnLiveTrafficListener l : mListeners) {
            try {
                l.onPointAdded(point, snapshot);
            } catch (Exception e) {
                Log.w(TAG, "Listener error: " + e.getMessage());
            }
        }
    }

    public synchronized List<DataPoint> getRollingSnapshot() {
        return new ArrayList<>(mRollingBuffer);
    }

    public synchronized void clearLiveWindow() {
        mRollingBuffer.clear();
        mLastTimestamp = 0;
        mLastBytesRcvd = 0;
        mLastBytesSent = 0;
        long now = System.currentTimeMillis();
        for (int i = ROLLING_BUFFER_CAPACITY - 1; i >= 0; i--) {
            mRollingBuffer.add(new DataPoint(now - (i * 1000L), 0f, 0f));
        }
    }

    /**
     * Queries historical time-series buckets from firewall_logs.db for the Stats screen.
     */
    public static List<DataPoint> queryHistoricalData(Context context, long sinceMs, long bucketIntervalMs, int filterUid) {
        List<DataPoint> result = new ArrayList<>();
        if (context == null || bucketIntervalMs <= 0) return result;

        try {
            FirewallLogDbHelper dbHelper = FirewallLogDbHelper.getInstance(context);
            SQLiteDatabase db = dbHelper.getReadableDatabase();

            String selection = "timestamp >= ?";
            List<String> argsList = new ArrayList<>();
            argsList.add(String.valueOf(sinceMs));

            if (filterUid > 0) {
                selection += " AND uid = ?";
                argsList.add(String.valueOf(filterUid));
            }

            String sql = "SELECT (timestamp / " + bucketIntervalMs + ") * " + bucketIntervalMs + " AS bucket, " +
                    "SUM(bytes_rcvd) AS down_total, " +
                    "SUM(bytes_sent) AS up_total " +
                    "FROM " + FirewallLogDbHelper.TABLE_LOGS + " " +
                    "WHERE " + selection + " " +
                    "GROUP BY bucket " +
                    "ORDER BY bucket ASC";

            String[] args = argsList.toArray(new String[0]);
            try (Cursor cursor = db.rawQuery(sql, args)) {
                while (cursor.moveToNext()) {
                    long bucket = cursor.getLong(0);
                    long downBytes = cursor.getLong(1);
                    long upBytes = cursor.getLong(2);

                    float downKbps = (downBytes / 1024f) / (bucketIntervalMs / 1000f);
                    float upKbps = (upBytes / 1024f) / (bucketIntervalMs / 1000f);

                    DataPoint pt = new DataPoint(bucket, downKbps, upKbps);
                    result.add(pt);
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "queryHistoricalData error: " + e.getMessage());
        }

        return result;
    }
}
