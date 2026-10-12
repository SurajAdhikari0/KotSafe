/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * AppIntelligenceEngine
 * =====================
 * Central application inventory and security profiler.
 * Caches detailed application profiles, signing identities, install provenance,
 * capability clusters, and security baselines across the device.
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.InstallSourceInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;

import com.kotsafe.security.Log;
import com.kotsafe.security.Utils;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class AppIntelligenceEngine {
    private static final String TAG = "AppIntelligenceEngine";

    public static final Set<String> VETTED_STORE_INSTALLERS = new HashSet<>(Arrays.asList(
            "com.android.vending",
            "com.google.android.packageinstaller.apex",
            "com.amazon.venezia",
            "com.sec.android.app.samsungapps",
            "com.huawei.appmarket",
            "com.xiaomi.mipicks",
            "com.heytap.market",
            "com.oppo.market",
            "com.vivo.appstore",
            "org.fdroid.fdroid"
    ));

    public static class AppSecurityProfile {
        public String packageName = "";
        public String appName = "";
        public String versionName = "";
        public long versionCode = 0;
        public int uid = 0;
        public String installerPackage = "";
        public boolean isVettedStoreInstall = false;
        public boolean isSideloaded = false;
        public boolean isSystemApp = false;
        public boolean isSelfKotSafe = false;
        public long firstInstallTime = 0;
        public long lastUpdateTime = 0;
        public String apkPath = "";
        public long apkSize = 0;
        public String sha256 = "";
        public int targetSdk = 0;
        public int minSdk = 0;
        public boolean hasLauncherActivity = false;

        public CertificateEngine.CertificateProfile certificateProfile = new CertificateEngine.CertificateProfile();
        public PermissionRiskEngine.PermissionAnalysis permissionAnalysis = new PermissionRiskEngine.PermissionAnalysis();

        public int overallRiskScore = 0;
        public String verdict = "UNKNOWN"; // TRUSTED, CLEAN, MONITOR, SUSPICIOUS, MALICIOUS
        public String severity = "INFO"; // INFO, LOW, MEDIUM, HIGH, CRITICAL
        public String confidence = "HIGH"; // LOW, MEDIUM, HIGH
        public List<String> forensicReasons = new ArrayList<>();
    }

    private static volatile AppIntelligenceEngine sInstance;
    private final Context mContext;
    private final Map<String, AppSecurityProfile> mProfileCache = new ConcurrentHashMap<>();

    public static AppIntelligenceEngine getInstance(Context context) {
        if (sInstance == null) {
            synchronized (AppIntelligenceEngine.class) {
                if (sInstance == null) {
                    sInstance = new AppIntelligenceEngine(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    private AppIntelligenceEngine(Context context) {
        mContext = context;
    }

    public AppSecurityProfile getProfile(String packageName) {
        if (packageName == null || packageName.isEmpty()) return null;
        AppSecurityProfile profile = mProfileCache.get(packageName);
        if (profile == null) {
            profile = buildProfile(packageName);
            if (profile != null) {
                mProfileCache.put(packageName, profile);
            }
        }
        return profile;
    }

    public List<AppSecurityProfile> getAllProfiles() {
        return new ArrayList<>(mProfileCache.values());
    }

    public synchronized void refreshAllProfiles() {
        PackageManager pm = mContext.getPackageManager();
        List<PackageInfo> packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS | PackageManager.GET_SERVICES);
        for (PackageInfo pi : packages) {
            try {
                AppSecurityProfile p = buildProfileFromPackageInfo(pi);
                if (p != null) {
                    mProfileCache.put(p.packageName, p);
                }
            } catch (Exception e) {
                Log.w(TAG, "Error profiling " + pi.packageName + ": " + e.getMessage());
            }
        }
    }

    public AppSecurityProfile buildProfile(String packageName) {
        try {
            PackageManager pm = mContext.getPackageManager();
            PackageInfo pi = pm.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS | PackageManager.GET_SERVICES);
            return buildProfileFromPackageInfo(pi);
        } catch (Exception e) {
            Log.d(TAG, "Could not profile package " + packageName + ": " + e.getMessage());
            return null;
        }
    }

    private AppSecurityProfile buildProfileFromPackageInfo(PackageInfo pi) {
        if (pi == null) return null;
        AppSecurityProfile p = new AppSecurityProfile();
        p.packageName = pi.packageName;
        PackageManager pm = mContext.getPackageManager();
        ApplicationInfo ai = pi.applicationInfo;

        p.appName = ai != null ? pm.getApplicationLabel(ai).toString() : pi.packageName;
        p.versionName = pi.versionName != null ? pi.versionName : "";
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            p.versionCode = pi.getLongVersionCode();
        } else {
            p.versionCode = pi.versionCode;
        }

        p.uid = ai != null ? ai.uid : 0;
        p.firstInstallTime = pi.firstInstallTime;
        p.lastUpdateTime = pi.lastUpdateTime;
        p.targetSdk = ai != null ? ai.targetSdkVersion : 0;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N && ai != null) {
            p.minSdk = ai.minSdkVersion;
        }

        p.isSelfKotSafe = pi.packageName.equals(mContext.getPackageName()) || pi.packageName.startsWith("com.kotsafe.security") || pi.packageName.startsWith("com.kotsafe.security");
        p.isSystemApp = p.isSelfKotSafe
            || Utils.classifyAppInstall(ai) == Utils.AppInstallClass.SYSTEM;

        if (ai != null && ai.sourceDir != null) {
            p.apkPath = ai.sourceDir;
            File apkFile = new File(ai.sourceDir);
            if (apkFile.exists()) {
                p.apkSize = apkFile.length();
                p.sha256 = FileHashScanner.computeHash(apkFile, "SHA-256");
            }
        }

        p.hasLauncherActivity = pm.getLaunchIntentForPackage(pi.packageName) != null;

        // Installer Provenance
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                InstallSourceInfo isi = pm.getInstallSourceInfo(pi.packageName);
                p.installerPackage = isi.getInstallingPackageName();
            } else {
                p.installerPackage = pm.getInstallerPackageName(pi.packageName);
            }
        } catch (Exception ignored) {}

        if (p.installerPackage != null && !p.installerPackage.isEmpty()) {
            p.isVettedStoreInstall = VETTED_STORE_INSTALLERS.contains(p.installerPackage);
            p.isSideloaded = !p.isVettedStoreInstall && !p.isSystemApp;
        } else {
            p.isSideloaded = !p.isSystemApp;
        }

        // Certificate Inspection
        p.certificateProfile = CertificateEngine.analyze(mContext, pi.packageName);

        // Permission Combination Risk
        p.permissionAnalysis = PermissionRiskEngine.analyze(mContext, pi, p.isSideloaded);

        return p;
    }
}
