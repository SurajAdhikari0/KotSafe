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
 * Copyright 2026 - KotSafe
 */

package com.kotsafe.security.model;

import android.content.Context;

import com.kotsafe.security.AppsResolver;
import com.kotsafe.security.Log;
import com.kotsafe.security.ScreenStateMonitor;
import com.kotsafe.security.Utils;

import java.util.HashMap;
import java.util.Map;

/**
 * Background Data Exfiltration Sentinel.
 * Correlates per-app NetworkStats data transmission specifically while the screen is locked/sleeping.
 * Triggers high-severity alerts when untrusted background applications upload abnormal byte volumes.
 */
public class BackgroundExfiltrationSentinel implements ScreenStateMonitor.ScreenStateListener {
    private static final String TAG = "BgExfiltrationSentinel";
    private static volatile BackgroundExfiltrationSentinel sInstance;

    // Threshold: 15 MB uploaded while screen was continuously off
    private static final long EXFILTRATION_ALERT_THRESHOLD_BYTES = 15 * 1024 * 1024L;

    private final Context mContext;
    private final AppsResolver mAppsResolver;
    private final ScreenStateMonitor mScreenMonitor;
    private final Map<Integer, Long> mScreenOffStartBytes;
    private boolean mIsScreenOn = true;

    public static BackgroundExfiltrationSentinel getInstance(Context context) {
        if (sInstance == null) {
            synchronized (BackgroundExfiltrationSentinel.class) {
                if (sInstance == null) {
                    sInstance = new BackgroundExfiltrationSentinel(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    private BackgroundExfiltrationSentinel(Context context) {
        mContext = context;
        mAppsResolver = new AppsResolver(context);
        mScreenOffStartBytes = new HashMap<>();
        mScreenMonitor = new ScreenStateMonitor(context, this);
    }

    public synchronized void start() {
        mScreenMonitor.startMonitoring();
        Log.i(TAG, "Background Data Exfiltration Sentinel started");
    }

    public synchronized void stop() {
        mScreenMonitor.stopMonitoring();
        mScreenOffStartBytes.clear();
        Log.i(TAG, "Background Data Exfiltration Sentinel stopped");
    }

    @Override
    public synchronized void onScreenStateChanged(boolean isScreenOn) {
        mIsScreenOn = isScreenOn;
        if (!isScreenOn) {
            // Screen went off -> reset screen-off baseline
            mScreenOffStartBytes.clear();
            Log.d(TAG, "Screen OFF -> Arming Background Exfiltration Sentinel");
        } else {
            Log.d(TAG, "Screen ON -> Disarming Screen-Off counters");
            mScreenOffStartBytes.clear();
        }
    }

    /**
     * Called by NetworkStatsUsageMonitor when a byte delta is detected for a given app.
     */
    public synchronized void recordAppBytes(int uid, String packageName, long bytesDelta) {
        if (mIsScreenOn || uid < 10000 || bytesDelta <= 0) {
            return; // Ignore if screen is ON or core system UID
        }

        long cumulative = mScreenOffStartBytes.getOrDefault(uid, 0L) + bytesDelta;
        mScreenOffStartBytes.put(uid, cumulative);

        if (cumulative >= EXFILTRATION_ALERT_THRESHOLD_BYTES) {
            triggerExfiltrationAlert(uid, packageName, cumulative);
            // Reset counter after alert so we don't spam repeatedly
            mScreenOffStartBytes.put(uid, 0L);
        }
    }

    private void triggerExfiltrationAlert(int uid, String packageName, long exfiltratedBytes) {
        AppDescriptor app = mAppsResolver.getAppByPackage(packageName, 0);
        String appName = app != null ? app.getName() : packageName;

        String formattedBytes = Utils.formatBytes(exfiltratedBytes);
        String alertTitle = "Background Exfiltration: " + appName;
        String alertMsg = "Uploaded " + formattedBytes + " silently while the device screen was off. Possible background spyware or data leak.";

        Log.w(TAG, "EXFILTRATION ALERT: " + packageName + " uploaded " + formattedBytes + " in background!");

        try {
            AlertStore.getInstance(mContext).add(
                    AlertRecord.Severity.HIGH,
                    AlertRecord.AlertType.MALWARE,
                    alertTitle,
                    alertMsg,
                    packageName
            );

            SmartScreenManager.getInstance(mContext).showSuspiciousWarning(
                    appName,
                    "Silent Background Upload (" + formattedBytes + ")",
                    "EXFILTRATION",
                    85,
                    "KotSafe Sentinel"
            );
        } catch (Exception e) {
            Log.e(TAG, "Error raising exfiltration alert: " + e.getMessage());
        }
    }

    public boolean isScreenOn() {
        return mIsScreenOn;
    }
}
