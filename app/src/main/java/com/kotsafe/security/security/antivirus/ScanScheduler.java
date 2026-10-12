/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * ScanScheduler
 * =============
 * Coordinates event-driven and automated background scans:
 * - On-install scan of newly added/updated packages
 * - Threat-triggered scans when firewall detects anomalous traffic spikes
 * - Hardware-triggered scans when USB peripherals attach
 */

package com.kotsafe.security.security.antivirus;

import android.content.Context;
import android.content.Intent;

import com.kotsafe.security.Log;
import com.kotsafe.security.model.AppIntelligenceEngine;
import com.kotsafe.security.model.ScanModeConfig;
import com.kotsafe.security.model.SecurityTaskScheduler;
import com.kotsafe.security.services.AntivirusScanService;

public class ScanScheduler {
    private static final String TAG = "ScanScheduler";

    private static volatile ScanScheduler sInstance;
    private final Context mContext;

    public static ScanScheduler getInstance(Context context) {
        if (sInstance == null) {
            synchronized (ScanScheduler.class) {
                if (sInstance == null) {
                    sInstance = new ScanScheduler(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    private ScanScheduler(Context context) {
        mContext = context;
    }

    public void triggerPackageScan(String packageName, String reason) {
        if (packageName == null || packageName.isEmpty()) return;
        Log.i(TAG, "Triggering event-driven scan for " + packageName + " (" + reason + ")");

        SecurityTaskScheduler.getInstance(mContext).submitCritical("PackageScan:" + packageName, () -> {
            try {
                AppIntelligenceEngine.getInstance(mContext).getProfile(packageName);
            } catch (Exception e) {
                Log.w(TAG, "Package scan error: " + e.getMessage());
            }
        });
    }

    public void triggerFullScan() {
        Log.i(TAG, "Triggering background full scan via AntivirusScanService");
        try {
            Intent intent = new Intent(mContext, AntivirusScanService.class);
            intent.setAction(AntivirusScanService.ACTION_START_SCAN);
            intent.putExtra(AntivirusScanService.EXTRA_SCAN_MODE, ScanModeConfig.ScanMode.FULL.name());
            mContext.startService(intent);
        } catch (Exception e) {
            Log.e(TAG, "Failed to start scan service: " + e.getMessage());
        }
    }
}
