/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.annotation.NonNull;
import androidx.preference.PreferenceManager;
import androidx.work.Constraints;
import androidx.work.ExistingPeriodicWorkPolicy;
import androidx.work.OneTimeWorkRequest;
import androidx.work.PeriodicWorkRequest;
import androidx.work.WorkManager;
import androidx.work.Worker;
import androidx.work.WorkerParameters;

import com.kotsafe.security.Log;

import java.util.concurrent.TimeUnit;

/**
 * Background worker for automatic storage maintenance and data retention.
 *
 * Rules:
 *  - Evidence older than threshold (default: 30 days) is purged
 *  - Visit logs older than threshold (default: 14 days) are purged
 *  - Expired TI cache items are purged
 *  - SECURITY RULES (Blocklist / Whitelist / YARA) ARE NEVER TOUCHED OR AUTO-DELETED.
 */
public class RetentionWorker extends Worker {
    private static final String TAG = "RetentionWorker";

    public static final String WORK_NAME = "kotsafe_retention_cleanup";
    public static final String PREF_RETENTION_EVIDENCE_DAYS = "pref_retention_evidence_days";
    public static final String PREF_RETENTION_LOGS_DAYS = "pref_retention_logs_days";

    public static final int DEFAULT_EVIDENCE_DAYS = 30;
    public static final int DEFAULT_LOGS_DAYS = 14;

    public RetentionWorker(@NonNull Context context, @NonNull WorkerParameters workerParams) {
        super(context, workerParams);
    }

    @NonNull
    @Override
    public Result doWork() {
        Context context = getApplicationContext();
        Log.i(TAG, "Starting automatic storage retention cleanup...");

        try {
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
            int evidenceDays = getIntPref(prefs, PREF_RETENTION_EVIDENCE_DAYS, DEFAULT_EVIDENCE_DAYS);
            int logsDays = getIntPref(prefs, PREF_RETENTION_LOGS_DAYS, DEFAULT_LOGS_DAYS);

            long evidenceCutoff = System.currentTimeMillis() - ((long) evidenceDays * 24L * 60L * 60L * 1000L);

            SecurityDatabase secDb = SecurityDatabase.getInstance(context);

            // 1. Purge evidence older than retention window
            int purgedEvidence = secDb.purgeEvidenceOlderThan(evidenceCutoff);

            // 2. Purge URL visits older than retention window
            int purgedLogs = secDb.purgeLogsOlderThan(logsDays);

            // 3. Purge expired TI cache entries
            int purgedCache = secDb.purgeExpiredCache();

            // Note: Rules are intentionally NEVER touched by retention policies
            Log.i(TAG, String.format("Retention cleanup finished: %d evidence rows, %d logs, %d cache entries removed. (Rules preserved untouched)",
                    purgedEvidence, purgedLogs, purgedCache));

            return Result.success();
        } catch (Exception e) {
            Log.e(TAG, "Retention cleanup failed: " + e.getMessage());
            return Result.retry();
        }
    }

    private int getIntPref(SharedPreferences prefs, String key, int defaultValue) {
        try {
            String val = prefs.getString(key, null);
            if (val != null) return Integer.parseInt(val);
        } catch (Exception ignored) {}
        return prefs.getInt(key, defaultValue);
    }

    /**
     * Schedules periodic daily retention cleanup.
     */
    public static void schedulePeriodic(Context context) {
        try {
            Constraints constraints = new Constraints.Builder()
                    .setRequiresBatteryNotLow(true)
                    .build();

            PeriodicWorkRequest request = new PeriodicWorkRequest.Builder(
                    RetentionWorker.class,
                    24, TimeUnit.HOURS,
                    2, TimeUnit.HOURS
            ).setConstraints(constraints).build();

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                    WORK_NAME,
                    ExistingPeriodicWorkPolicy.KEEP,
                    request
            );
            Log.i(TAG, "Scheduled daily retention cleanup task");
        } catch (Exception e) {
            Log.e(TAG, "Failed to schedule periodic retention work: " + e.getMessage());
        }
    }

    /**
     * Triggers one-time immediate retention cleanup on demand.
     */
    public static void runOnceNow(Context context) {
        try {
            OneTimeWorkRequest request = new OneTimeWorkRequest.Builder(RetentionWorker.class).build();
            WorkManager.getInstance(context).enqueue(request);
            Log.i(TAG, "Queued immediate retention cleanup task");
        } catch (Exception e) {
            Log.e(TAG, "Failed to run immediate retention work: " + e.getMessage());
        }
    }
}
