/*
 * This file is part of KotSafe.
 * KotSafe Automated Threat Intelligence Sync Engine.
 */

package com.kotsafe.security.model;

import android.content.Context;

import androidx.annotation.NonNull;
import androidx.work.Constraints;
import androidx.work.ExistingPeriodicWorkPolicy;
import androidx.work.NetworkType;
import androidx.work.PeriodicWorkRequest;
import androidx.work.WorkManager;
import androidx.work.Worker;
import androidx.work.WorkerParameters;

import com.kotsafe.security.Log;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Background WorkManager worker that synchronizes threat feeds (URLhaus, ThreatFox, C2 IOCs)
 * once every 24 hours when the device is connected to an unmetered network (Wi-Fi).
 */
public class ThreatFeedSyncWorker extends Worker {

    private static final String TAG = "ThreatFeedSyncWorker";
    public static final String WORK_NAME = "KotSafeThreatIntelDailySync";

    public ThreatFeedSyncWorker(@NonNull Context context, @NonNull WorkerParameters params) {
        super(context, params);
    }

    @NonNull
    @Override
    public Result doWork() {
        Log.i(TAG, "Starting automated background threat intel delta sync");
        final CountDownLatch latch = new CountDownLatch(1);
        final boolean[] success = new boolean[]{false};

        ThreatFeedSyncManager.getInstance(getApplicationContext()).syncNow(new ThreatFeedSyncManager.SyncCallback() {
            @Override
            public void onProgress(String status) {
                Log.d(TAG, "Sync progress: " + status);
            }

            @Override
            public void onSuccess(int totalRulesAdded) {
                Log.i(TAG, "Automated threat sync succeeded. Added " + totalRulesAdded + " rules.");
                success[0] = true;
                latch.countDown();
            }

            @Override
            public void onError(String errorMessage) {
                Log.w(TAG, "Automated threat sync error: " + errorMessage);
                latch.countDown();
            }
        });

        try {
            latch.await(60, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Log.w(TAG, "Threat sync timed out");
        }

        return success[0] ? Result.success() : Result.retry();
    }

    /**
     * Enqueues a periodic sync work request to execute every 24 hours.
     */
    public static void schedulePeriodicSync(@NonNull Context context) {
        try {
            Constraints constraints = new Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .setRequiresBatteryNotLow(true)
                    .build();

            PeriodicWorkRequest request = new PeriodicWorkRequest.Builder(
                    ThreatFeedSyncWorker.class,
                    24, TimeUnit.HOURS,
                    6, TimeUnit.HOURS // 6-hour flex interval
            )
                    .setConstraints(constraints)
                    .build();

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                    WORK_NAME,
                    ExistingPeriodicWorkPolicy.KEEP,
                    request
            );
            Log.i(TAG, "Automated 24-hour threat intelligence sync worker scheduled successfully");
        } catch (Throwable t) {
            Log.e(TAG, "Failed to schedule ThreatFeedSyncWorker: " + t.getMessage());
        }
    }
}
