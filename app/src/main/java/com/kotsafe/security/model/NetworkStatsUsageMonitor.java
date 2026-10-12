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

import android.app.AppOpsManager;
import android.app.usage.NetworkStats;
import android.app.usage.NetworkStatsManager;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.os.Build;
import android.os.Process;

import androidx.annotation.RequiresApi;

import com.kotsafe.security.Log;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Passive API-mode network monitor using Android NetworkStatsManager.
 * Runs when VPN is inactive (or in parallel) to track per-app byte deltas and detect exfiltration anomalies.
 */
public class NetworkStatsUsageMonitor {
    private static final String TAG = "NetworkStatsUsageMon";
    private static volatile NetworkStatsUsageMonitor sInstance;

    private final Context mContext;
    private final ScheduledExecutorService mScheduler;
    private final Map<Integer, Long> mLastUidBytes;
    private boolean mIsRunning = false;

    public static NetworkStatsUsageMonitor getInstance(Context context) {
        if (sInstance == null) {
            synchronized (NetworkStatsUsageMonitor.class) {
                if (sInstance == null) {
                    sInstance = new NetworkStatsUsageMonitor(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    private NetworkStatsUsageMonitor(Context context) {
        mContext = context;
        mScheduler = Executors.newSingleThreadScheduledExecutor();
        mLastUidBytes = new HashMap<>();
    }

    public static boolean hasUsageStatsPermission(Context context) {
        try {
            AppOpsManager appOps = (AppOpsManager) context.getSystemService(Context.APP_OPS_SERVICE);
            if (appOps == null) return false;
            int mode = appOps.checkOpNoThrow(
                    AppOpsManager.OPSTR_GET_USAGE_STATS,
                    Process.myUid(),
                    context.getPackageName()
            );
            return mode == AppOpsManager.MODE_ALLOWED;
        } catch (Exception e) {
            return false;
        }
    }

    public synchronized void startMonitoring() {
        if (mIsRunning) return;
        mIsRunning = true;
        Log.i(TAG, "Starting passive NetworkStats usage polling worker (API Mode)");
        mScheduler.scheduleWithFixedDelay(this::pollUsageStats, 5, 30, TimeUnit.SECONDS);
    }

    public synchronized void stopMonitoring() {
        mIsRunning = false;
        Log.i(TAG, "Stopping passive NetworkStats usage polling worker");
    }

    private void pollUsageStats() {
        if (!hasUsageStatsPermission(mContext) || Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return;
        }

        try {
            NetworkStatsManager nsm = (NetworkStatsManager) mContext.getSystemService(Context.NETWORK_STATS_SERVICE);
            if (nsm == null) return;

            long now = System.currentTimeMillis();
            long startTime = now - (60 * 1000L); // 1 minute window

            PackageManager pm = mContext.getPackageManager();
            List<ApplicationInfo> installedApps = pm.getInstalledApplications(0);

            for (ApplicationInfo appInfo : installedApps) {
                // Skip core OS daemon UIDs and KotSafe VPN itself (as Android attributes all forwarded VPN tunnel packets to KotSafe UID)
                if (appInfo.uid < 10000 || appInfo.uid == Process.myUid()) continue;

                long currentBytes = queryUidTotalBytes(nsm, appInfo.uid, startTime, now);
                Long prevBytes = mLastUidBytes.get(appInfo.uid);

                if (prevBytes != null && currentBytes > prevBytes) {
                    long delta = currentBytes - prevBytes;
                    if (delta > 50 * 1024) { // Report meaningful activity (> 50 KB)
                        TrafficDeduplicationParser.getInstance(mContext).onApiUsageDelta(
                                appInfo.uid,
                                appInfo.packageName,
                                delta,
                                now
                        );
                        BackgroundExfiltrationSentinel.getInstance(mContext).recordAppBytes(
                                appInfo.uid,
                                appInfo.packageName,
                                delta
                        );
                    }
                }
                mLastUidBytes.put(appInfo.uid, currentBytes);
            }
        } catch (Exception e) {
            Log.d(TAG, "pollUsageStats notice: " + e.getMessage());
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private long queryUidTotalBytes(NetworkStatsManager nsm, int uid, long start, long end) {
        long total = 0;
        try {
            NetworkStats statsWifi = nsm.queryDetailsForUid(ConnectivityManager.TYPE_WIFI, null, start, end, uid);
            total += extractBucketBytes(statsWifi);
        } catch (Exception ignored) {}

        try {
            NetworkStats statsMobile = nsm.queryDetailsForUid(ConnectivityManager.TYPE_MOBILE, null, start, end, uid);
            total += extractBucketBytes(statsMobile);
        } catch (Exception ignored) {}

        return total;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private long extractBucketBytes(NetworkStats stats) {
        if (stats == null) return 0;
        long bytes = 0;
        NetworkStats.Bucket bucket = new NetworkStats.Bucket();
        while (stats.hasNextBucket()) {
            stats.getNextBucket(bucket);
            bytes += bucket.getRxBytes() + bucket.getTxBytes();
        }
        stats.close();
        return bytes;
    }
}
