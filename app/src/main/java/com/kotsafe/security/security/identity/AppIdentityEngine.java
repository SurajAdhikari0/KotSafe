/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * AppIdentityEngine
 * =================
 * Binds network layer socket entities (UID, IP, port) to rich endpoint application
 * identity (package name, installer provenance, cryptographic signing fingerprint,
 * security risk score, and recent network egress destinations).
 */

package com.kotsafe.security.security.identity;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.InstallSourceInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;

import com.kotsafe.security.Log;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.AppIntelligenceEngine;
import com.kotsafe.security.model.CertificateEngine;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

public class AppIdentityEngine {
    private static final String TAG = "AppIdentityEngine";

    public static class AppIdentity {
        public String packageName = "";
        public String appLabel = "";
        public int uid = -1;
        public String versionName = "";
        public long versionCode = 0;
        public String installer = "";
        public boolean isVettedStore = false;
        public boolean isSideloaded = false;
        public boolean isSystemApp = false;
        public String certSha256 = "";
        public String certIssuer = "";
        public int currentRiskScore = 0; // 0-100
        public String verdict = "CLEAN";
        public long firstInstallTime = 0;
        public long lastUpdateTime = 0;

        // Recent Network destinations (capped sliding window)
        public final List<String> recentDestinations = new CopyOnWriteArrayList<>();
        public final List<String> recentDomains = new CopyOnWriteArrayList<>();
        public int totalBlockedConnections = 0;
        public int totalAllowedConnections = 0;

        public void recordDestination(String dstIp, String domain, boolean wasBlocked) {
            if (dstIp != null && !dstIp.isEmpty()) {
                if (!recentDestinations.contains(dstIp)) {
                    if (recentDestinations.size() >= 20) recentDestinations.remove(0);
                    recentDestinations.add(dstIp);
                }
            }
            if (domain != null && !domain.isEmpty()) {
                if (!recentDomains.contains(domain)) {
                    if (recentDomains.size() >= 20) recentDomains.remove(0);
                    recentDomains.add(domain);
                }
            }
            if (wasBlocked) totalBlockedConnections++;
            else totalAllowedConnections++;
        }
    }

    private static volatile AppIdentityEngine sInstance;
    private final Context mContext;
    private final Map<Integer, AppIdentity> mUidIdentityCache = new ConcurrentHashMap<>();
    private final Map<String, AppIdentity> mPkgIdentityCache = new ConcurrentHashMap<>();

    public static AppIdentityEngine getInstance(Context context) {
        if (sInstance == null) {
            synchronized (AppIdentityEngine.class) {
                if (sInstance == null) {
                    sInstance = new AppIdentityEngine(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    private AppIdentityEngine(Context context) {
        mContext = context;
    }

    public AppIdentity resolveUid(int uid) {
        if (uid < 0) return null;
        AppIdentity identity = mUidIdentityCache.get(uid);
        if (identity == null) {
            try {
                String[] pkgs = mContext.getPackageManager().getPackagesForUid(uid);
                if (pkgs != null && pkgs.length > 0) {
                    identity = resolvePackage(pkgs[0]);
                    if (identity != null) {
                        identity.uid = uid;
                        mUidIdentityCache.put(uid, identity);
                    }
                }
            } catch (Exception e) {
                Log.w(TAG, "Failed resolving UID " + uid + ": " + e.getMessage());
            }
        }
        return identity;
    }

    public AppIdentity resolvePackage(String packageName) {
        if (packageName == null || packageName.isEmpty()) return null;
        AppIdentity identity = mPkgIdentityCache.get(packageName);
        if (identity == null) {
            identity = buildIdentity(packageName);
            if (identity != null) {
                mPkgIdentityCache.put(packageName, identity);
                if (identity.uid > 0) {
                    mUidIdentityCache.put(identity.uid, identity);
                }
            }
        }
        return identity;
    }

    private AppIdentity buildIdentity(String packageName) {
        AppIdentity id = new AppIdentity();
        id.packageName = packageName;

        try {
            PackageManager pm = mContext.getPackageManager();
            PackageInfo pi = pm.getPackageInfo(packageName, 0);
            ApplicationInfo ai = pi.applicationInfo;

            id.appLabel = pm.getApplicationLabel(ai).toString();
            id.uid = ai.uid;
            id.versionName = pi.versionName != null ? pi.versionName : "";
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                id.versionCode = pi.getLongVersionCode();
            } else {
                //noinspection deprecation
                id.versionCode = pi.versionCode;
            }
            id.firstInstallTime = pi.firstInstallTime;
            id.lastUpdateTime = pi.lastUpdateTime;
            id.isSystemApp = Utils.classifyAppInstall(ai) == Utils.AppInstallClass.SYSTEM;

            // Installer provenance
            String installer = null;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                try {
                    InstallSourceInfo srcInfo = pm.getInstallSourceInfo(packageName);
                    installer = srcInfo.getInstallingPackageName();
                } catch (Exception ignored) {}
            } else {
                try {
                    //noinspection deprecation
                    installer = pm.getInstallerPackageName(packageName);
                } catch (Exception ignored) {}
            }
            id.installer = installer != null ? installer : "";
            id.isVettedStore = AppIntelligenceEngine.VETTED_STORE_INSTALLERS.contains(id.installer);
            id.isSideloaded = !id.isSystemApp && !id.isVettedStore;

            // Certificate Info
            CertificateEngine.CertificateProfile certProfile = CertificateEngine.analyze(mContext, packageName);
            if (certProfile != null) {
                id.certSha256 = certProfile.sha256Fingerprint;
                id.certIssuer = certProfile.issuerDn;
            }

            // Sync with existing profile risk
            AppIntelligenceEngine.AppSecurityProfile profile = AppIntelligenceEngine.getInstance(mContext).getProfile(packageName);
            if (profile != null) {
                id.currentRiskScore = profile.overallRiskScore;
                id.verdict = profile.verdict;
            }

        } catch (Exception e) {
            Log.w(TAG, "Error building identity for " + packageName + ": " + e.getMessage());
        }

        return id;
    }

    public void updateAppRisk(String packageName, int riskScore, String verdict) {
        AppIdentity id = resolvePackage(packageName);
        if (id != null) {
            id.currentRiskScore = Math.max(0, Math.min(100, riskScore));
            if (verdict != null) id.verdict = verdict;
        }
    }
}
