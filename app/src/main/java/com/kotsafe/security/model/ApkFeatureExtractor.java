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
 *
 * Copyright 2026 KotSafe Cyber Security Project
 */

package com.kotsafe.security.model;

import android.content.pm.PackageInfo;

import com.kotsafe.security.Log;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Pillar 2: Feature Extractor for On-Device Machine Learning Bytecode Classifier.
 *
 * Extracts a normalized 48-dimensional vector from APK files and PackageInfo metadata,
 * quantifying DEX entropy, dangerous permission clusters, sensitive API calls,
 * and manifest anomalies for neural inference.
 */
public class ApkFeatureExtractor {
    private static final String TAG = "ApkFeatureExtractor";
    public static final int VECTOR_SIZE = 48;

    // High-risk permissions mapped to feature vector slots [6..21]
    private static final String[] DANGEROUS_PERMS = {
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_SETTINGS",
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.INSTALL_PACKAGES",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.INTERNET"
    };

    // Sensitive API method indicators mapped to vector slots [22..37]
    private static final String[] SENSITIVE_APIS = {
            "Runtime;->exec",
            "ProcessBuilder;->start",
            "DexClassLoader",
            "InMemoryDexClassLoader",
            "PathClassLoader",
            "getAssets",
            "Cipher;->getInstance",
            "KeyGenerator",
            "AudioRecord;->startRecording",
            "Camera;->open",
            "SmsManager;->sendTextMessage",
            "TelephonyManager;->getDeviceId",
            "installPackage",
            "Process;->killProcess",
            "/system/bin/su",
            "System;->loadLibrary"
    };

    public static class ExtractedFeatures {
        public float[] vector = new float[VECTOR_SIZE];
        public double dexEntropy = 0.0;
        public int dangerousPermsCount = 0;
        public int sensitiveApiMatches = 0;
        public boolean hasDropperAssets = false;
        public boolean hasEmbeddedSo = false;
    }

    public static ExtractedFeatures extract(File apkFile, PackageInfo pkgInfo, boolean isSideloaded) {
        return extract(apkFile, pkgInfo, isSideloaded, false);
    }

    public static ExtractedFeatures extract(File apkFile, PackageInfo pkgInfo, boolean isSideloaded, boolean hasLauncher) {
        ExtractedFeatures result = new ExtractedFeatures();
        // Section 1: File Size & Structural DEX Metrics [Indices 0..5]
        if (apkFile != null && apkFile.exists()) {
            long fileSize = apkFile.length();
            result.vector[0] = (float) Math.min(1.0, Math.log10(Math.max(1, fileSize)) / 8.0); // Size normalized

            int dexCount = 0;
            int soCount = 0;
            int assetDexJarCount = 0;
            double totalDexEntropy = 0.0;
            Set<String> apkStrings = new HashSet<>();

            try (ZipInputStream zis = new ZipInputStream(new BufferedInputStream(new FileInputStream(apkFile)))) {
                ZipEntry entry;
                byte[] buffer = new byte[8192];
                while ((entry = zis.getNextEntry()) != null) {
                    String name = entry.getName().toLowerCase();
                    if (name.endsWith(".dex")) {
                        dexCount++;
                        // Read first 16KB of primary DEX to calculate header entropy
                        if (dexCount == 1) {
                            int read = zis.read(buffer, 0, Math.min(buffer.length, 16384));
                            if (read > 0) {
                                totalDexEntropy = calculateByteEntropy(buffer, read);
                            }
                        }
                    } else if (name.endsWith(".so")) {
                        soCount++;
                    } else if ((name.startsWith("assets/") || name.startsWith("res/")) &&
                            (name.endsWith(".dex") || name.endsWith(".jar") || name.endsWith(".apk"))) {
                        assetDexJarCount++;
                    }

                    // Sample string references inside dex files
                    if (name.endsWith(".dex") && apkStrings.size() < 200) {
                        byte[] sample = new byte[4096];
                        int r = zis.read(sample);
                        if (r > 0) {
                            String s = new String(sample, 0, r);
                            for (String api : SENSITIVE_APIS) {
                                if (s.contains(api)) apkStrings.add(api);
                            }
                        }
                    }
                    zis.closeEntry();
                }
            } catch (Exception e) {
                Log.w(TAG, "Error parsing APK structure: " + e.getMessage());
            }

            result.dexEntropy = totalDexEntropy;
            result.vector[1] = (float) Math.min(1.0, totalDexEntropy / 8.0); // DEX Entropy (0.0 to 1.0)
            result.vector[2] = (float) Math.min(1.0, dexCount / 5.0);       // Multidex ratio
            result.vector[3] = (float) Math.min(1.0, soCount / 10.0);       // Native SO presence
            result.vector[4] = (float) Math.min(1.0, assetDexJarCount);     // Hidden payload in assets

            result.hasDropperAssets = assetDexJarCount > 0;
            result.hasEmbeddedSo = soCount > 0;

            // Section 3: Sensitive API Invocations [Indices 22..37]
            for (int i = 0; i < SENSITIVE_APIS.length; i++) {
                if (apkStrings.contains(SENSITIVE_APIS[i])) {
                    result.vector[22 + i] = 1.0f;
                    result.sensitiveApiMatches++;
                } else {
                    result.vector[22 + i] = 0.0f;
                }
            }
        }

        result.vector[5] = isSideloaded ? 1.0f : 0.0f; // Sideloaded marker

        // Section 2: Dangerous Permissions [Indices 6..21]
        Set<String> grantedPerms = new HashSet<>();
        if (pkgInfo != null && pkgInfo.requestedPermissions != null) {
            grantedPerms.addAll(Arrays.asList(pkgInfo.requestedPermissions));
        }

        for (int i = 0; i < DANGEROUS_PERMS.length; i++) {
            if (grantedPerms.contains(DANGEROUS_PERMS[i])) {
                result.vector[6 + i] = 1.0f;
                result.dangerousPermsCount++;
            } else {
                result.vector[6 + i] = 0.0f;
            }
        }


        // Section 4: Manifest & Component Heuristic Features [Indices 38..47]
        if (pkgInfo != null) {
            // Target SDK downgrade marker
            int targetSdk = (pkgInfo.applicationInfo != null) ? pkgInfo.applicationInfo.targetSdkVersion : 30;
            result.vector[38] = targetSdk < 26 ? 1.0f : 0.0f;

            // Accessibility + Overlay dangerous pairing
            boolean hasOverlay = grantedPerms.contains("android.permission.SYSTEM_ALERT_WINDOW");
            boolean hasAccess = grantedPerms.contains("android.permission.BIND_ACCESSIBILITY_SERVICE");
            result.vector[39] = (hasOverlay && hasAccess) ? 1.0f : 0.0f;

            // Device Admin + Notification Listener pairing (Rafel / SpyNote marker)
            boolean hasAdmin = grantedPerms.contains("android.permission.BIND_DEVICE_ADMIN");
            boolean hasNotif = grantedPerms.contains("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE");
            result.vector[40] = (hasAdmin && hasNotif) ? 1.0f : 0.0f;

            // SMS + Boot Completed (Covert SMS Spyware marker)
            boolean hasSms = grantedPerms.contains("android.permission.READ_SMS") || grantedPerms.contains("android.permission.RECEIVE_SMS");
            boolean hasBoot = grantedPerms.contains("android.permission.RECEIVE_BOOT_COMPLETED");
            result.vector[41] = (hasSms && hasBoot) ? 1.0f : 0.0f;

            // Audio Record + Background Location (Stalkerware marker)
            boolean hasAudio = grantedPerms.contains("android.permission.RECORD_AUDIO");
            boolean hasGps = grantedPerms.contains("android.permission.ACCESS_FINE_LOCATION");
            result.vector[42] = (hasAudio && hasGps) ? 1.0f : 0.0f;

            // Install Packages request (Dropper marker)
            boolean hasInstall = grantedPerms.contains("android.permission.REQUEST_INSTALL_PACKAGES");
            result.vector[43] = (hasInstall && isSideloaded) ? 1.0f : 0.0f;

            // Receiver / Activity count ratios
            int activities = (pkgInfo.activities != null) ? pkgInfo.activities.length : 0;
            int receivers = (pkgInfo.receivers != null) ? pkgInfo.receivers.length : 0;
            int services = (pkgInfo.services != null) ? pkgInfo.services.length : 0;

            result.vector[44] = (float) Math.min(1.0, activities / 15.0);
            result.vector[45] = (float) Math.min(1.0, receivers / 10.0);
            result.vector[46] = (float) Math.min(1.0, services / 10.0);

            // Stealth app with zero launcher activities but active services:
            // High confidence risk indicator ONLY if the APK is sideloaded, has NO launcher intent/icon,
            // has 0 declared activities, and actively registers background services/receivers.
            result.vector[47] = (isSideloaded && !hasLauncher && activities == 0 && (receivers > 0 || services > 0)) ? 1.0f : 0.0f;
        }

        return result;
    }

    private static double calculateByteEntropy(byte[] data, int length) {
        if (data == null || length <= 0) return 0.0;
        int[] freq = new int[256];
        for (int i = 0; i < length; i++) {
            freq[data[i] & 0xFF]++;
        }
        double entropy = 0.0;
        for (int count : freq) {
            if (count > 0) {
                double p = (double) count / length;
                entropy -= p * (Math.log(p) / Math.log(2.0));
            }
        }
        return entropy;
    }
}
