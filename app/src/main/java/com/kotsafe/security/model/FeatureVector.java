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
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;

import java.io.File;
import java.io.Serializable;
import java.util.Arrays;

/**
 * Lazy-loaded structural feature vector store for deep scan and ML threat scoring.
 * Encapsulates a standardized 32-dimensional normalized vector for on-device inference.
 */
public class FeatureVector implements Serializable {
    public static final int VECTOR_SIZE = 32;

    public String contentHash = "";
    public byte[] permissionBitmap;
    public String apiCallGraphHash = "";
    public float reflectionDensity;
    public float stringEntropy;
    public int nativeLibCount;
    public float assetToCodeRatio;
    public long extractedAt;

    // ── Structural & Entropy Features (0..5) ──
    public float hasPackerStub = 0f;
    public float dexSizeKb = 0f;

    // ── Dangerous API Sink Invocations (6..15) ──
    public float dynamicLoadingCount = 0f;
    public float processExecCount = 0f;
    public float cryptoOpsCount = 0f;
    public float smsAbuseCount = 0f;
    public float deviceIdAccessCount = 0f;
    public float audioCameraCount = 0f;
    public float locationCount = 0f;
    public float rawSocketCount = 0f;
    public float pmTamperingCount = 0f;
    public float windowOverlayCount = 0f;

    // ── High-Risk Permissions Matrix (16..27) ──
    public float permAccessibility = 0f;
    public float permOverlay = 0f;
    public float permBootCompleted = 0f;
    public float permSms = 0f;
    public float permContacts = 0f;
    public float permRequestInstall = 0f;
    public float permStorage = 0f;
    public float permMicCam = 0f;
    public float permLocation = 0f;
    public float permKillProcesses = 0f;
    public float permQueryAllPackages = 0f;
    public float permBiometric = 0f;

    // ── Provenance & Certificate Signals (28..31) ──
    public float isSideloaded = 0f;
    public float hasDebugCert = 0f;
    public float isSystemApp = 0f;
    public float targetSdkAntiquity = 0f;

    public FeatureVector() {
        extractedAt = System.currentTimeMillis();
    }

    /**
     * Packs and normalizes all 32 fields into a continuous float vector.
     */
    public float[] toArray() {
        float[] v = new float[VECTOR_SIZE];
        v[0] = Math.min(1.0f, assetToCodeRatio / 10.0f);
        v[1] = Math.min(1.0f, stringEntropy / 8.0f);
        v[2] = Math.min(1.0f, reflectionDensity * 5.0f);
        v[3] = Math.min(1.0f, nativeLibCount / 10.0f);
        v[4] = hasPackerStub > 0f ? 1.0f : 0.0f;
        v[5] = Math.min(1.0f, dexSizeKb / 10000.0f);

        v[6] = Math.min(1.0f, dynamicLoadingCount / 5.0f);
        v[7] = Math.min(1.0f, processExecCount / 5.0f);
        v[8] = Math.min(1.0f, cryptoOpsCount / 10.0f);
        v[9] = Math.min(1.0f, smsAbuseCount / 5.0f);
        v[10] = Math.min(1.0f, deviceIdAccessCount / 5.0f);
        v[11] = Math.min(1.0f, audioCameraCount / 5.0f);
        v[12] = Math.min(1.0f, locationCount / 5.0f);
        v[13] = Math.min(1.0f, rawSocketCount / 10.0f);
        v[14] = Math.min(1.0f, pmTamperingCount / 3.0f);
        v[15] = Math.min(1.0f, windowOverlayCount / 3.0f);

        v[16] = permAccessibility > 0f ? 1.0f : 0.0f;
        v[17] = permOverlay > 0f ? 1.0f : 0.0f;
        v[18] = permBootCompleted > 0f ? 1.0f : 0.0f;
        v[19] = permSms > 0f ? 1.0f : 0.0f;
        v[20] = permContacts > 0f ? 1.0f : 0.0f;
        v[21] = permRequestInstall > 0f ? 1.0f : 0.0f;
        v[22] = permStorage > 0f ? 1.0f : 0.0f;
        v[23] = permMicCam > 0f ? 1.0f : 0.0f;
        v[24] = permLocation > 0f ? 1.0f : 0.0f;
        v[25] = permKillProcesses > 0f ? 1.0f : 0.0f;
        v[26] = permQueryAllPackages > 0f ? 1.0f : 0.0f;
        v[27] = permBiometric > 0f ? 1.0f : 0.0f;

        v[28] = isSideloaded > 0f ? 1.0f : 0.0f;
        v[29] = hasDebugCert > 0f ? 1.0f : 0.0f;
        v[30] = isSystemApp > 0f ? 1.0f : 0.0f;
        v[31] = Math.min(1.0f, Math.max(0.0f, targetSdkAntiquity / 15.0f));

        return v;
    }

    /**
     * Extracts structural bytecode features from classes.dex and manifest permissions from an APK file.
     */
    public static FeatureVector extractFromApkFile(Context context, File apkFile) {
        if (apkFile == null || !apkFile.exists() || !apkFile.canRead()) {
            return new FeatureVector();
        }
        DexStructuralParser.DexAnalysisResult dexRes = DexStructuralParser.analyzeApk(apkFile);
        FeatureVector fv = (dexRes != null && dexRes.featureVector != null) ? dexRes.featureVector : new FeatureVector();

        if (context != null) {
            try {
                PackageManager pm = context.getPackageManager();
                PackageInfo archiveInfo = pm.getPackageArchiveInfo(apkFile.getAbsolutePath(),
                        PackageManager.GET_PERMISSIONS | PackageManager.GET_SERVICES);
                if (archiveInfo != null) {
                    fv.populateFromPackageInfo(archiveInfo, true);
                }
            } catch (Exception ignored) {}
        }
        return fv;
    }

    /**
     * Enriches this FeatureVector with declared permissions and manifest capabilities.
     */
    public void populateFromPackageInfo(PackageInfo pkgInfo, boolean isSideloadedApp) {
        if (pkgInfo == null) return;
        this.isSideloaded = isSideloadedApp ? 1.0f : 0.0f;
        if (pkgInfo.applicationInfo != null) {
            this.isSystemApp = (pkgInfo.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0 ? 1.0f : 0.0f;
            if (pkgInfo.applicationInfo.targetSdkVersion > 0 && pkgInfo.applicationInfo.targetSdkVersion < 29) {
                this.targetSdkAntiquity = (float) (29 - pkgInfo.applicationInfo.targetSdkVersion);
            }
        }
        if (pkgInfo.requestedPermissions != null) {
            for (String perm : pkgInfo.requestedPermissions) {
                if (perm == null) continue;
                switch (perm) {
                    case "android.permission.SYSTEM_ALERT_WINDOW":
                        this.permOverlay = 1.0f;
                        break;
                    case "android.permission.RECEIVE_BOOT_COMPLETED":
                        this.permBootCompleted = 1.0f;
                        break;
                    case "android.permission.SEND_SMS":
                    case "android.permission.READ_SMS":
                    case "android.permission.RECEIVE_SMS":
                        this.permSms = 1.0f;
                        break;
                    case "android.permission.READ_CONTACTS":
                    case "android.permission.WRITE_CONTACTS":
                        this.permContacts = 1.0f;
                        break;
                    case "android.permission.REQUEST_INSTALL_PACKAGES":
                        this.permRequestInstall = 1.0f;
                        break;
                    case "android.permission.READ_EXTERNAL_STORAGE":
                    case "android.permission.WRITE_EXTERNAL_STORAGE":
                    case "android.permission.MANAGE_EXTERNAL_STORAGE":
                        this.permStorage = 1.0f;
                        break;
                    case "android.permission.CAMERA":
                    case "android.permission.RECORD_AUDIO":
                        this.permMicCam = 1.0f;
                        break;
                    case "android.permission.ACCESS_FINE_LOCATION":
                    case "android.permission.ACCESS_COARSE_LOCATION":
                    case "android.permission.ACCESS_BACKGROUND_LOCATION":
                        this.permLocation = 1.0f;
                        break;
                    case "android.permission.KILL_BACKGROUND_PROCESSES":
                        this.permKillProcesses = 1.0f;
                        break;
                    case "android.permission.QUERY_ALL_PACKAGES":
                        this.permQueryAllPackages = 1.0f;
                        break;
                    case "android.permission.USE_BIOMETRIC":
                    case "android.permission.USE_FINGERPRINT":
                        this.permBiometric = 1.0f;
                        break;
                }
            }
        }
        if (pkgInfo.services != null) {
            for (ServiceInfo si : pkgInfo.services) {
                if (si != null && "android.permission.BIND_ACCESSIBILITY_SERVICE".equals(si.permission)) {
                    this.permAccessibility = 1.0f;
                    break;
                }
            }
        }
    }
}
