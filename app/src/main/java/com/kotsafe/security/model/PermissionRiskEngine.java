/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * PermissionRiskEngine
 * ====================
 * Evaluates contextual permission combinations instead of raw counts.
 * Analyzes high-risk capability clusters (Banking Trojan, Spyware, Dropper, Ransomware)
 * cross-referenced against installer origin and application context.
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class PermissionRiskEngine {
    private static final String TAG = "PermissionRiskEngine";

    public static class PermissionAnalysis {
        public int riskScore = 0; // 0-100
        public String capabilityVerdict = "NORMAL"; // NORMAL, SENSITIVE, HIGH_RISK, DANGEROUS_COMBINATION
        public List<String> flaggedClusters = new ArrayList<>();
        public List<String> criticalCapabilities = new ArrayList<>();
        public boolean hasAccessibilityService = false;
        public boolean hasOverlayPermission = false;
        public boolean hasSmsCapabilities = false;
        public boolean hasInstallerCapability = false;
        public boolean hasBackgroundLocation = false;
        public boolean hasQueryAllPackages = false;
        public boolean hasDeviceAdmin = false;
        public boolean hasNotificationListener = false;
    }

    public static PermissionAnalysis analyze(Context context, PackageInfo pkgInfo, boolean isSideloaded) {
        PermissionAnalysis analysis = new PermissionAnalysis();
        if (pkgInfo == null) return analysis;

        Set<String> declaredPermissions = new HashSet<>();
        if (pkgInfo.requestedPermissions != null) {
            for (String perm : pkgInfo.requestedPermissions) {
                if (perm != null) declaredPermissions.add(perm);
            }
        }

        // Check dangerous permissions
        analysis.hasOverlayPermission = declaredPermissions.contains("android.permission.SYSTEM_ALERT_WINDOW");
        analysis.hasInstallerCapability = declaredPermissions.contains("android.permission.REQUEST_INSTALL_PACKAGES");
        analysis.hasQueryAllPackages = declaredPermissions.contains("android.permission.QUERY_ALL_PACKAGES");
        analysis.hasBackgroundLocation = declaredPermissions.contains("android.permission.ACCESS_BACKGROUND_LOCATION");

        boolean hasReadSms = declaredPermissions.contains("android.permission.READ_SMS");
        boolean hasSendSms = declaredPermissions.contains("android.permission.SEND_SMS");
        boolean hasReceiveSms = declaredPermissions.contains("android.permission.RECEIVE_SMS");
        analysis.hasSmsCapabilities = hasReadSms || hasSendSms || hasReceiveSms;

        boolean hasCamera = declaredPermissions.contains("android.permission.CAMERA");
        boolean hasRecordAudio = declaredPermissions.contains("android.permission.RECORD_AUDIO");
        boolean hasFineLocation = declaredPermissions.contains("android.permission.ACCESS_FINE_LOCATION");
        boolean hasInternet = declaredPermissions.contains("android.permission.INTERNET");

        // Inspect declared services for high-privilege bindings
        if (pkgInfo.services != null) {
            for (ServiceInfo si : pkgInfo.services) {
                if (si != null && si.permission != null) {
                    if ("android.permission.BIND_ACCESSIBILITY_SERVICE".equals(si.permission)) {
                        analysis.hasAccessibilityService = true;
                    } else if ("android.permission.BIND_DEVICE_ADMIN".equals(si.permission)) {
                        analysis.hasDeviceAdmin = true;
                    } else if ("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE".equals(si.permission)) {
                        analysis.hasNotificationListener = true;
                    }
                }
            }
        }

        int score = 0;

        // 1. BANKING TROJAN / ATS CLUSTER: Accessibility + Overlay + (SMS or Internet)
        if (analysis.hasAccessibilityService && analysis.hasOverlayPermission) {
            if (analysis.hasSmsCapabilities || hasInternet) {
                analysis.flaggedClusters.add("Banking Trojan ATS Pattern: Accessibility + Overlay + SMS/Network");
                score += isSideloaded ? 55 : 35;
            }
        }

        // 2. SPYWARE / SURVEILLANCE CLUSTER: Background Location + Audio/Camera + Query All Packages
        if ((hasCamera || hasRecordAudio) && (analysis.hasBackgroundLocation || hasFineLocation) && analysis.hasQueryAllPackages) {
            analysis.flaggedClusters.add("Surveillance/Spyware Pattern: Audio/Camera + Location + Installed App Enumeration");
            score += isSideloaded ? 45 : 25;
        }

        // 3. SILENT DROPPER CLUSTER: REQUEST_INSTALL_PACKAGES + Hidden / Sideloaded
        if (analysis.hasInstallerCapability && isSideloaded) {
            analysis.flaggedClusters.add("Untrusted Package Dropper: Sideloaded app with REQUEST_INSTALL_PACKAGES");
            score += 30;
        }

        // 4. SMS INTERCEPTION & 2FA THEFT: SMS + Notification Listener
        if (analysis.hasSmsCapabilities && analysis.hasNotificationListener) {
            analysis.flaggedClusters.add("2FA Interception Cluster: SMS + Notification Listener Service");
            score += isSideloaded ? 40 : 25;
        }

        // Add single capability points
        if (analysis.hasAccessibilityService) {
            analysis.criticalCapabilities.add("Accessibility Service (Can read screen & perform taps)");
            score += 15;
        }
        if (analysis.hasOverlayPermission) {
            analysis.criticalCapabilities.add("System Alert Window / Display Over Other Apps");
            score += 10;
        }
        if (analysis.hasSmsCapabilities) {
            analysis.criticalCapabilities.add("SMS Read/Send/Receive");
            score += 10;
        }
        if (analysis.hasInstallerCapability) {
            analysis.criticalCapabilities.add("Install Unknown Packages");
            score += 10;
        }
        if (analysis.hasDeviceAdmin) {
            analysis.criticalCapabilities.add("Device Administrator Binding");
            score += 15;
        }

        analysis.riskScore = Math.min(100, score);
        if (analysis.riskScore >= 70) {
            analysis.capabilityVerdict = "DANGEROUS_COMBINATION";
        } else if (analysis.riskScore >= 40) {
            analysis.capabilityVerdict = "HIGH_RISK";
        } else if (analysis.riskScore >= 20) {
            analysis.capabilityVerdict = "SENSITIVE";
        } else {
            analysis.capabilityVerdict = "NORMAL";
        }

        return analysis;
    }
}
