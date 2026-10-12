/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * AntivirusResponseEngine
 * =======================
 * Executes Android sandbox-compliant remediation actions.
 * Respects consumer Android security boundaries without requiring root:
 *   - Instant firewall app network isolation
 *   - Official system uninstallation intent dispatch
 *   - Sandboxed quarantine vault storage
 *   - System security / permissions settings navigation
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.provider.Settings;

import com.kotsafe.security.Log;

public class AntivirusResponseEngine {
    private static final String TAG = "AntivirusResponseEngine";

    public enum ResponseAction {
        MONITOR,
        BLOCK_NETWORK,
        REQUEST_UNINSTALL,
        OPEN_SETTINGS,
        QUARANTINE
    }

    public static void isolateNetworkAccess(Context context, String packageName, String reason) {
        if (context == null || packageName == null || packageName.isEmpty()) return;
        String lower = packageName.trim().toLowerCase(java.util.Locale.US);
        if (lower.equals("com.kotsafe.security") || lower.equals(context.getPackageName().toLowerCase(java.util.Locale.US)) || lower.contains("kotsafe")) {
            Log.w(TAG, "Self-Protection: Prevented network isolation of KotSafe");
            return;
        }
        try {
            SecurityBlocklistManager secMgr = SecurityBlocklistManager.getInstance(context);
            secMgr.blockApp(packageName, reason != null ? reason : "EDR Network Isolation", "EDR");
            Log.i(TAG, "Isolated network access for " + packageName);
        } catch (Exception e) {
            Log.w(TAG, "Failed to isolate network for " + packageName + ": " + e.getMessage());
        }
    }

    public static void requestUninstall(Context context, String packageName) {
        if (context == null || packageName == null || packageName.isEmpty()) return;
        String lower = packageName.trim().toLowerCase(java.util.Locale.US);
        if (lower.equals("com.kotsafe.security") || lower.equals(context.getPackageName().toLowerCase(java.util.Locale.US)) || lower.contains("kotsafe")) {
            Log.w(TAG, "Self-Protection: Prevented uninstall request for KotSafe");
            return;
        }
        try {
            Intent intent = new Intent(Intent.ACTION_DELETE);
            intent.setData(Uri.parse("package:" + packageName));
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            context.startActivity(intent);
        } catch (Exception e) {
            Log.w(TAG, "Failed to launch uninstall for " + packageName + ": " + e.getMessage());
        }
    }

    public static void openAppSettings(Context context, String packageName) {
        if (context == null || packageName == null || packageName.isEmpty()) return;
        try {
            Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
            intent.setData(Uri.parse("package:" + packageName));
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            context.startActivity(intent);
        } catch (Exception e) {
            Log.w(TAG, "Failed to open settings for " + packageName + ": " + e.getMessage());
        }
    }
}
