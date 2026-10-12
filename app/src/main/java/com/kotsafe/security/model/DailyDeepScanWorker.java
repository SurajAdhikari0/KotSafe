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
 * Background worker for automatic daily deep antivirus & vulnerability audits.
 *
 * Runs once every 24 hours in the background:
 *  1. Performs full deep scan across installed apps, split APKs, DEX structures, storage files & traffic telemetry.
 *  2. Records structured scan audit report into ScanReportDbHelper.
 *  3. Dispatches Defender-grade summary notification via SecurityNotificationHub.
 */
public class DailyDeepScanWorker extends Worker {
    private static final String TAG = "DailyDeepScanWorker";

    public static final String WORK_NAME = "kot_daily_deep_scan";
    public static final String PREF_AUTO_DAILY_DEEP_SCAN = "pref_auto_daily_deep_scan";
    public static final String PREF_LAST_AUTO_SCAN_TIME = "pref_last_auto_scan_time";

    public DailyDeepScanWorker(@NonNull Context context, @NonNull WorkerParameters workerParams) {
        super(context, workerParams);
    }

    @NonNull
    @Override
    public Result doWork() {
        Context context = getApplicationContext();
        Log.i(TAG, "Starting automatic daily background deep scan...");

        try {
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
            boolean enabled = prefs.getBoolean(PREF_AUTO_DAILY_DEEP_SCAN, true);
            if (!enabled) {
                Log.i(TAG, "Automatic daily deep scan disabled in preferences. Skipping.");
                return Result.success();
            }

            long startTime = System.currentTimeMillis();

            // Run Deep Scan in background thread
            AntivirusScanEngine.ScanResult result = AntivirusScanEngine.runScan(
                    context,
                    ScanModeConfig.ScanMode.DEEP,
                    null
            );

            long durationMs = System.currentTimeMillis() - startTime;

            // 1. Save structured report to database
            ScanReportEntry report = ScanReportEntry.fromScanResult(result, true, durationMs);
            ScanReportDbHelper.getInstance(context).insertReport(report);

            // 2. Update last scan timestamp
            prefs.edit().putLong(PREF_LAST_AUTO_SCAN_TIME, System.currentTimeMillis()).apply();

            // 3. Dispatch completion / threat notification
            SecurityNotificationHub.getInstance(context).postScanCompleteNotification(result);

            Log.i(TAG, String.format("Daily deep scan finished in %dms. Score: %d/100, Threats: %d, Scanned: %d apps, %d files.",
                    durationMs, result.securityScore, result.threatsDetected, result.totalPackagesScanned, result.totalStorageScanned));

            return Result.success();
        } catch (Exception e) {
            Log.e(TAG, "Daily deep scan failed: " + e.getMessage());
            return Result.retry();
        }
    }

    /**
     * Schedules periodic daily deep scan (every 24 hours).
     */
    public static void schedulePeriodic(Context context) {
        try {
            Constraints constraints = new Constraints.Builder()
                    .setRequiresBatteryNotLow(true)
                    .build();

            PeriodicWorkRequest request = new PeriodicWorkRequest.Builder(
                    DailyDeepScanWorker.class,
                    24, TimeUnit.HOURS,
                    2, TimeUnit.HOURS
            ).setConstraints(constraints).build();

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                    WORK_NAME,
                    ExistingPeriodicWorkPolicy.KEEP,
                    request
            );
            Log.i(TAG, "Scheduled automatic daily deep scan worker (24h period)");
        } catch (Exception e) {
            Log.e(TAG, "Failed to schedule daily deep scan worker: " + e.getMessage());
        }
    }

    /**
     * Triggers one-time background deep scan execution immediately.
     */
    public static void runOnceNow(Context context) {
        try {
            OneTimeWorkRequest request = new OneTimeWorkRequest.Builder(DailyDeepScanWorker.class).build();
            WorkManager.getInstance(context).enqueue(request);
            Log.i(TAG, "Queued immediate one-time background deep scan task");
        } catch (Exception e) {
            Log.e(TAG, "Failed to queue immediate background deep scan: " + e.getMessage());
        }
    }
}
