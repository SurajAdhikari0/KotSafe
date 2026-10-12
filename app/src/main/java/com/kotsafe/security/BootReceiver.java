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
 * * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security;

import android.annotation.SuppressLint;
import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Build;

import androidx.core.content.ContextCompat;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.model.CaptureSettings;
import com.kotsafe.security.model.DefenderManager;
import com.kotsafe.security.model.FirewallPolicy;
import com.kotsafe.security.model.Prefs;

public class BootReceiver extends BroadcastReceiver {
    private static final String TAG = "BootReceiver";
    public static final String ACTION_BOOT_RESTORE_RETRY = "com.kotsafe.security.action.BOOT_RESTORE_RETRY";
    private static final String EXTRA_RETRY_COUNT = "com.kotsafe.security.extra.RETRY_COUNT";
    private static final int MAX_RETRIES = 3;

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null) {
            return;
        }

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        String action = intent.getAction();
        Log.d(TAG, "onReceive: " + action);

        if (!FirewallPolicy.isSupportedBootAction(action) && !ACTION_BOOT_RESTORE_RETRY.equals(action)) {
            Log.w(TAG, "Unexpected action: " + action);
            return;
        }

        if (!FirewallPolicy.shouldRestoreFirewallOnBoot(context, prefs)) {
            Log.i(TAG, "Boot restore skipped: start-at-boot or firewall preference disabled");
            return;
        }

        if (CaptureService.isServiceActive()) {
            Log.i(TAG, "Service already active, nothing to do");
            return;
        }

        int retryCount = intent.getIntExtra(EXTRA_RETRY_COUNT, 0);
        if (retryCount < MAX_RETRIES) {
            scheduleRetry(context, retryCount + 1);
        }

        if (DefenderManager.restoreProtectionIfNeeded(context)) {
            Log.i(TAG, "Defender service start requested from " + action + " (retry=" + retryCount + "); delayed retry will verify runtime activation.");
            return;
        }

        Log.i(TAG, "Defender restore not active from " + action + " (retry=" + retryCount + "); service remains degraded or consent-blocked.");
    }

    @SuppressLint("MissingPermission")
    private void scheduleRetry(Context context, int nextRetryCount) {
        try {
            AlarmManager alarmManager = (AlarmManager) context.getSystemService(Context.ALARM_SERVICE);
            if (alarmManager == null) {
                return;
            }

            Intent retryIntent = new Intent(context, BootReceiver.class);
            retryIntent.setAction(ACTION_BOOT_RESTORE_RETRY);
            retryIntent.putExtra(EXTRA_RETRY_COUNT, nextRetryCount);

            PendingIntent pendingIntent = PendingIntent.getBroadcast(
                    context,
                    1001,
                    retryIntent,
                    PendingIntent.FLAG_CANCEL_CURRENT | (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M ? PendingIntent.FLAG_IMMUTABLE : 0)
            );

            long delayMs = 30_000L * nextRetryCount;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
                    && !alarmManager.canScheduleExactAlarms()) {
                // Exact alarms are special app access on Android 12+. Do not
                // make boot recovery depend on that user-granted permission.
                alarmManager.setAndAllowWhileIdle(
                        AlarmManager.RTC_WAKEUP,
                        System.currentTimeMillis() + delayMs,
                        pendingIntent
                );
                Log.i(TAG, "Exact alarms unavailable; scheduled an inexact boot restore retry");
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                alarmManager.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, System.currentTimeMillis() + delayMs, pendingIntent);
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
                alarmManager.setExact(AlarmManager.RTC_WAKEUP, System.currentTimeMillis() + delayMs, pendingIntent);
            } else {
                alarmManager.set(AlarmManager.RTC_WAKEUP, System.currentTimeMillis() + delayMs, pendingIntent);
            }
            Log.i(TAG, "Scheduled boot restore retry in " + delayMs + "ms (attempt " + nextRetryCount + ")");
        } catch (SecurityException e) {
            // OEM builds can reject an exact alarm even when the platform
            // capability check says it is allowed. Fall back to a non-exact
            // alarm so retries remain best-effort instead of being lost.
            try {
                AlarmManager alarmManager = (AlarmManager) context.getSystemService(Context.ALARM_SERVICE);
                if (alarmManager == null) return;

                Intent retryIntent = new Intent(context, BootReceiver.class);
                retryIntent.setAction(ACTION_BOOT_RESTORE_RETRY);
                retryIntent.putExtra(EXTRA_RETRY_COUNT, nextRetryCount);
                PendingIntent pendingIntent = PendingIntent.getBroadcast(
                        context,
                        1001,
                        retryIntent,
                        PendingIntent.FLAG_CANCEL_CURRENT | (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M ? PendingIntent.FLAG_IMMUTABLE : 0)
                );
                long delayMs = 30_000L * nextRetryCount;
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    alarmManager.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, System.currentTimeMillis() + delayMs, pendingIntent);
                } else {
                    alarmManager.set(AlarmManager.RTC_WAKEUP, System.currentTimeMillis() + delayMs, pendingIntent);
                }
                Log.w(TAG, "Exact retry alarm denied; scheduled inexact fallback: " + e.getMessage());
            } catch (Exception fallbackException) {
                Log.w(TAG, "Could not schedule boot restore retry fallback: " + fallbackException.getMessage());
            }
        } catch (Exception e) {
            Log.w(TAG, "Could not schedule boot restore retry: " + e.getMessage());
        }
    }
}
