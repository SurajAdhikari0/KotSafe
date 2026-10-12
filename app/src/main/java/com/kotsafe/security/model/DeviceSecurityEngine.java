/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * DeviceSecurityEngine
 * ====================
 * Evaluates host device security posture as an objective 0-100 score.
 * Tracks OS patch currency, hardware encryption, developer options,
 * lock screen security, ADB state, and KotSafe defense layers.
 */

package com.kotsafe.security.model;

import android.app.KeyguardManager;
import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.os.Build;
import android.provider.Settings;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.io.File;

public class DeviceSecurityEngine {
    private static final String TAG = "DeviceSecurityEngine";

    public static class DevicePosture {
        public int overallScore = 100; // 0-100
        public String postureGrade = "GOOD"; // EXCELLENT, GOOD, FAIR, AT_RISK
        public String securityPatchDate = "Unknown";
        public int patchAgeMonths = 0;
        public boolean isPatchCurrent = true;
        public boolean isEncrypted = true;
        public boolean isLockScreenSecured = true;
        public boolean isAdbEnabled = false;
        public boolean isDeveloperOptionsEnabled = false;
        public boolean isVpnActive = false;
        public List<String> positiveFactors = new ArrayList<>();
        public List<String> riskWarnings = new ArrayList<>();
        public List<String> actionableRecommendations = new ArrayList<>();
    }

    public static DevicePosture evaluate(Context context) {
        DevicePosture posture = new DevicePosture();
        if (context == null) return posture;

        int score = 100;

        // 1. Security Patch Level
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            String patch = Build.VERSION.SECURITY_PATCH;
            if (patch != null && !patch.isEmpty()) {
                posture.securityPatchDate = patch;
                try {
                    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd", Locale.US);
                    Date patchDate = sdf.parse(patch);
                    if (patchDate != null) {
                        long diffMs = System.currentTimeMillis() - patchDate.getTime();
                        long days = TimeUnit.MILLISECONDS.toDays(diffMs);
                        posture.patchAgeMonths = (int) (days / 30);
                        if (posture.patchAgeMonths > 6) {
                            posture.isPatchCurrent = false;
                            score -= 15;
                            posture.riskWarnings.add("Security patch is over 6 months old (" + patch + ")");
                            posture.actionableRecommendations.add("Check System Updates for the latest security patch.");
                        } else if (posture.patchAgeMonths > 3) {
                            score -= 5;
                            posture.positiveFactors.add("Recent Security Patch (" + patch + ")");
                        } else {
                            posture.positiveFactors.add("Up-to-date Security Patch (" + patch + ")");
                        }
                    }
                } catch (Exception ignored) {}
            }
        }

        // 2. Encryption State
        try {
            DevicePolicyManager dpm = (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
            if (dpm != null) {
                int status = dpm.getStorageEncryptionStatus();
                posture.isEncrypted = (status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE
                        || (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N && status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER));
                if (!posture.isEncrypted) {
                    score -= 20;
                    posture.riskWarnings.add("Device storage is not fully encrypted");
                    posture.actionableRecommendations.add("Enable full-disk device encryption in Settings.");
                } else {
                    posture.positiveFactors.add("Storage hardware encryption active");
                }
            }
        } catch (Exception ignored) {}

        // 3. Screen Lock Security
        try {
            KeyguardManager km = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
            if (km != null) {
                posture.isLockScreenSecured = km.isDeviceSecure();
                if (!posture.isLockScreenSecured) {
                    score -= 15;
                    posture.riskWarnings.add("Screen lock (PIN/Password/Biometrics) is disabled");
                    posture.actionableRecommendations.add("Set a PIN, password, or fingerprint lock.");
                } else {
                    posture.positiveFactors.add("Screen lock protection active");
                }
            }
        } catch (Exception ignored) {}

        // 4. ADB & Developer Options
        try {
            int adb = Settings.Global.getInt(context.getContentResolver(), Settings.Global.ADB_ENABLED, 0);
            posture.isAdbEnabled = (adb == 1);
            if (posture.isAdbEnabled) {
                score -= 10;
                posture.riskWarnings.add("USB Debugging (ADB) is enabled");
                posture.actionableRecommendations.add("Disable USB Debugging in Developer Options when not in use.");
            }

            int dev = Settings.Global.getInt(context.getContentResolver(), Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0);
            posture.isDeveloperOptionsEnabled = (dev == 1);
            if (posture.isDeveloperOptionsEnabled && !posture.isAdbEnabled) {
                posture.positiveFactors.add("Developer mode active (ADB closed)");
            }
        } catch (Exception ignored) {}

        // 5. Root / Magisk / Superuser Detection (ADV-004)
        boolean isRooted = false;
        try {
            // 5a. Check well-known su binary locations
            final String[] ROOT_PATHS = {
                    "/sbin/su", "/system/bin/su", "/system/xbin/su",
                    "/su/bin/su", "/data/local/su", "/data/local/xbin/su",
                    "/system/app/Superuser.apk", "/system/app/SuperSU.apk",
                    "/system/xbin/busybox", "/data/local/tmp/busybox"
            };
            for (String path : ROOT_PATHS) {
                if (new File(path).exists()) { isRooted = true; break; }
            }

            // 5b. Known root-management package names
            if (!isRooted) {
                final String[] ROOT_PKGS = {
                        "com.topjohnwu.magisk", "eu.chainfire.supersu",
                        "com.noshufou.android.su", "com.koushikdutta.superuser",
                        "com.thirdparty.superuser", "com.zachspong.temprootremovejb",
                        "com.ramdroid.appquarantine"
                };
                android.content.pm.PackageManager pm = context.getPackageManager();
                for (String pkg : ROOT_PKGS) {
                    try { pm.getPackageInfo(pkg, 0); isRooted = true; break; }
                    catch (android.content.pm.PackageManager.NameNotFoundException ignored) {}
                }
            }

            // 5c. Build tag check (test-keys indicates unofficial / rooted ROM)
            if (!isRooted) {
                String tags = android.os.Build.TAGS;
                if (tags != null && (tags.contains("test-keys") || tags.contains("dev-keys"))) {
                    isRooted = true;
                }
            }

            // 5d. Writeable /system partition (strong root indicator)
            if (!isRooted) {
                File systemDir = new File("/system");
                if (systemDir.canWrite()) { isRooted = true; }
            }
        } catch (Exception ignored) {}

        if (isRooted) {
            score -= 25;
            posture.riskWarnings.add("Device appears to be rooted (su/Magisk/test-keys detected)");
            posture.actionableRecommendations.add(
                    "Root access severely undermines OS sandboxing. Remove root or use a non-rooted device for sensitive operations.");
        } else {
            posture.positiveFactors.add("No root indicators detected");
        }

        // 6. Pillar 3: Runtime Dynamic Instrumentation & Process Tamper Guard
        ProcessSecurityInspector.InspectionReport procReport = ProcessSecurityInspector.inspect(context);
        if (procReport.isTampered) {
            score -= 30;
            posture.riskWarnings.add("Runtime Dynamic Tampering Detected (" + android.text.TextUtils.join(", ", procReport.detectedThreats) + ")");
            posture.actionableRecommendations.add("Remove dynamic instrumentation tools (Frida/Xposed) and terminate any attached debuggers to protect application memory integrity.");
            try {
                UnifiedIncidentTimeline.getInstance(context).record(
                        new UnifiedIncidentTimeline.IncidentEvent.Builder()
                                .type(UnifiedIncidentTimeline.EventType.DEVICE_POSTURE_CHANGE)
                                .severity(UnifiedIncidentTimeline.Severity.CRITICAL)
                                .title("Process Tampering Detected: " + android.text.TextUtils.join(", ", procReport.detectedThreats))
                                .detail(android.text.TextUtils.join("\n", procReport.details))
                                .sourceApp(context.getPackageName())
                                .mitre("T1055")
                                .risk(90)
                );
            } catch (Exception ignored) {}
        } else {
            posture.positiveFactors.add("Process & memory integrity verified (No Frida/tampering)");
        }

        posture.overallScore = Math.max(10, Math.min(100, score));

        if (posture.overallScore >= 90) {
            posture.postureGrade = "EXCELLENT";
        } else if (posture.overallScore >= 75) {
            posture.postureGrade = "GOOD";
        } else if (posture.overallScore >= 50) {
            posture.postureGrade = "FAIR";
        } else {
            posture.postureGrade = "AT_RISK";
        }

        return posture;
    }
}
