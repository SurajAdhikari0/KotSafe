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

import android.accessibilityservice.AccessibilityServiceInfo;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.provider.Settings;
import android.view.accessibility.AccessibilityManager;

import com.kotsafe.security.Log;
import com.kotsafe.security.Utils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Live Accessibility & Stalkerware Abuse Watcher.
 *
 * Inherited from Amnesty International MVT (Mobile Verification Toolkit) & Citizen Lab
 * forensic methodologies: inspects active accessibility services to detect stalkerware,
 * keystroke loggers, screen scrapers, and tapjacking overlays running on Android devices.
 */
public final class AccessibilityStalkerwareDetector {
    private static final String TAG = "StalkerwareWatcher";

    private static final Map<String, String> KNOWN_STALKERWARE_FAMILIES = new HashMap<>();
    static {
        KNOWN_STALKERWARE_FAMILIES.put("com.cerberus", "Cerberus");
        KNOWN_STALKERWARE_FAMILIES.put("com.fsp.android", "Cerberus");
        KNOWN_STALKERWARE_FAMILIES.put("com.spyhide", "SpyHide");
        KNOWN_STALKERWARE_FAMILIES.put("com.spyfone", "SpyFone");
        KNOWN_STALKERWARE_FAMILIES.put("com.mspy", "mSpy");
        KNOWN_STALKERWARE_FAMILIES.put("com.mspyservice", "mSpy");
        KNOWN_STALKERWARE_FAMILIES.put("com.trackview", "TrackView");
        KNOWN_STALKERWARE_FAMILIES.put("com.clevguard", "KidsGuard");
        KNOWN_STALKERWARE_FAMILIES.put("com.hoverwatch", "Hoverwatch");
        KNOWN_STALKERWARE_FAMILIES.put("com.flexispy", "FlexiSPY");
        KNOWN_STALKERWARE_FAMILIES.put("com.thetruthspy", "TheTruthSpy");
        KNOWN_STALKERWARE_FAMILIES.put("com.spappmonitoring", "Spapp Monitoring");
        KNOWN_STALKERWARE_FAMILIES.put("com.mobiletracker", "MobileTracker");
        KNOWN_STALKERWARE_FAMILIES.put("com.chrysaor", "Pegasus / Chrysaor");
        KNOWN_STALKERWARE_FAMILIES.put("com.cytrox", "Predator / Cytrox");
        KNOWN_STALKERWARE_FAMILIES.put("com.nso", "NSO Group Artifact");
        KNOWN_STALKERWARE_FAMILIES.put("com.spymasterpro", "SpyMaster Pro");
        KNOWN_STALKERWARE_FAMILIES.put("com.cocospy", "CocoSpy");
        KNOWN_STALKERWARE_FAMILIES.put("com.xprofile.tracker", "XProfile Tracker");
    }

    public static class StalkerwareThreat {
        public String packageName = "";
        public String serviceName = "";
        public String appLabel = "";
        public String filePath = "";
        public int riskScore = 0; // 0 - 100
        public String severity = AntivirusEvidenceItem.SEVERITY_CLEAN; // CLEAN, LOW, SUSPICIOUS, MALICIOUS
        public boolean isSystemApp = false;
        public boolean isWhitelisted = false;
        public boolean canRetrieveWindowContent = false;
        public boolean canFilterKeyEvents = false;
        public boolean canPerformGestures = false;
        public boolean hasOverlayPermission = false;
        public boolean isHiddenWithoutLauncher = false;
        public boolean isSideloaded = false;
        public boolean isKnownStalkerwareFamily = false;
        public String stalkerwareFamily = "";
        public List<String> forensicDetails = new ArrayList<>();
        public String recommendation = "";

        public boolean isThreat() {
            return AntivirusEvidenceItem.SEVERITY_MALICIOUS.equals(severity)
                    || AntivirusEvidenceItem.SEVERITY_SUSPICIOUS.equals(severity);
        }
    }

    private AccessibilityStalkerwareDetector() {}

    /**
     * Checks if a package matches known commercial stalkerware signatures.
     */
    public static boolean isKnownStalkerwarePackage(String packageName) {
        if (packageName == null) return false;
        String lower = packageName.toLowerCase(Locale.US);
        for (String prefix : KNOWN_STALKERWARE_FAMILIES.keySet()) {
            if (lower.startsWith(prefix) || lower.contains("." + prefix)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns the name of the known stalkerware family or null.
     */
    public static String getStalkerwareFamily(String packageName) {
        if (packageName == null) return null;
        String lower = packageName.toLowerCase(Locale.US);
        for (Map.Entry<String, String> entry : KNOWN_STALKERWARE_FAMILIES.entrySet()) {
            if (lower.startsWith(entry.getKey()) || lower.contains("." + entry.getKey())) {
                return entry.getValue();
            }
        }
        return null;
    }

    /**
     * Scans currently enabled and active Accessibility Services on the device.
     */
    public static List<StalkerwareThreat> scanActiveServices(Context context) {
        if (context == null) return Collections.emptyList();

        List<StalkerwareThreat> threats = new ArrayList<>();
        try {
            AccessibilityManager am = (AccessibilityManager) context.getSystemService(Context.ACCESSIBILITY_SERVICE);
            if (am == null) return threats;

            List<AccessibilityServiceInfo> enabledServices =
                    am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK);
            if (enabledServices == null) return threats;

            for (AccessibilityServiceInfo sInfo : enabledServices) {
                StalkerwareThreat threat = evaluateService(context, sInfo);
                if (threat != null) {
                    threats.add(threat);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error evaluating active accessibility services: " + e.getMessage());
        }
        return threats;
    }

    /**
     * Evaluates an individual AccessibilityServiceInfo against stalkerware indicators.
     */
    public static StalkerwareThreat evaluateService(Context context, AccessibilityServiceInfo sInfo) {
        if (context == null || sInfo == null || sInfo.getResolveInfo() == null || sInfo.getResolveInfo().serviceInfo == null) {
            return null;
        }

        StalkerwareThreat t = new StalkerwareThreat();
        String pkg = sInfo.getResolveInfo().serviceInfo.packageName;
        String name = sInfo.getResolveInfo().serviceInfo.name;
        t.packageName = pkg != null ? pkg : "";
        t.serviceName = name != null ? name : "";

        PackageManager pm = context.getPackageManager();
        CharSequence labelChar = sInfo.getResolveInfo().loadLabel(pm);
        t.appLabel = labelChar != null ? labelChar.toString() : t.packageName;

        // Retrieve APK file path
        try {
            ApplicationInfo ai = pm.getApplicationInfo(t.packageName, 0);
            if (ai != null && ai.sourceDir != null) {
                t.filePath = ai.sourceDir;
            }
        } catch (Exception ignored) {}

        // 1. KotSafe self-exemption
        boolean isSelf = context.getPackageName().equals(t.packageName)
                || t.packageName.startsWith("com.kotsafe.security");
        if (isSelf) {
            t.isWhitelisted = true;
            t.severity = AntivirusEvidenceItem.SEVERITY_CLEAN;
            t.riskScore = 0;
            t.forensicDetails.add("Authorized KotSafe Web Protection accessibility provider.");
            t.recommendation = "Active protection operational.";
            return t;
        }

        // 2. System and Google trusted apps
        t.isSystemApp = Utils.isSystemApp(context, t.packageName)
                || Utils.isVerifiedGoogleTrustedService(context, t.packageName);
        if (t.isSystemApp) {
            t.isWhitelisted = true;
            t.severity = AntivirusEvidenceItem.SEVERITY_CLEAN;
            t.riskScore = 0;
            t.forensicDetails.add("Verified Android OS or vendor platform accessibility component.");
            t.recommendation = "Standard platform component.";
            return t;
        }

        // 3. Inspect Service Capabilities
        int capabilities = sInfo.getCapabilities();
        t.canRetrieveWindowContent = (capabilities & AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT) != 0;
        t.canFilterKeyEvents = (capabilities & AccessibilityServiceInfo.CAPABILITY_CAN_REQUEST_FILTER_KEY_EVENTS) != 0;
        t.canPerformGestures = (capabilities & AccessibilityServiceInfo.CAPABILITY_CAN_PERFORM_GESTURES) != 0;

        // 4. Inspect Package Trust & Installation Metadata
        PackageInfo pi = null;
        try {
            pi = pm.getPackageInfo(t.packageName, PackageManager.GET_PERMISSIONS);
        } catch (Exception ignored) {}

        AppTrustEvaluator.TrustProfile profile = (pi != null) ? AppTrustEvaluator.profile(context, pi) : null;
        if (profile != null) {
            t.isSideloaded = profile.isSideloaded;
            t.hasOverlayPermission = profile.requestsOverlayPermission;
            t.isHiddenWithoutLauncher = !profile.hasLauncherIcon;
        } else {
            t.hasOverlayPermission = checkOverlayPermission(context, t.packageName);
            t.isHiddenWithoutLauncher = (pm.getLaunchIntentForPackage(t.packageName) == null);
        }

        // 5. Check known stalkerware family catalog
        String family = getStalkerwareFamily(t.packageName);
        if (family != null) {
            t.isKnownStalkerwareFamily = true;
            t.stalkerwareFamily = family;
        }

        // 6. Compute Stalkerware Risk Score
        int score = 10; // Baseline third-party accessibility service

        if (t.isKnownStalkerwareFamily) {
            score = 100;
            t.forensicDetails.add("Matches known commercial stalkerware signature: " + t.stalkerwareFamily);
        } else {
            if (t.canRetrieveWindowContent) {
                score += 30;
                t.forensicDetails.add("Active Screen Reader capability (CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT): Can scrape chats, credentials, and app views.");
            }
            if (t.canFilterKeyEvents) {
                score += 35;
                t.forensicDetails.add("Active Keystroke Filter capability (CAPABILITY_CAN_REQUEST_FILTER_KEY_EVENTS): Can log passwords and typed inputs.");
            }
            if (t.canPerformGestures) {
                score += 20;
                t.forensicDetails.add("Active Touch Injection capability (CAPABILITY_CAN_PERFORM_GESTURES): Can automate unauthorized taps and permission approvals.");
            }
            if (t.hasOverlayPermission) {
                score += 25;
                t.forensicDetails.add("Overlay / Window Tapjacking permission (SYSTEM_ALERT_WINDOW): Can draw invisible overlays over banking and sensitive apps.");
            }
            if (t.isHiddenWithoutLauncher) {
                score += 25;
                t.forensicDetails.add("Stealth application profile: No launcher icon present in app drawer.");
            }
            if (t.isSideloaded) {
                score += 15;
                t.forensicDetails.add("Sideloaded installation: Package was not installed from a vetted app marketplace.");
            }
            if (profile != null && (profile.isVettedInstall || profile.isPlatformSigned)) {
                score = Math.max(10, score - 25);
                t.forensicDetails.add("Mitigating factor: Installed from verified application store.");
            }
        }

        t.riskScore = Math.min(100, Math.max(0, score));

        // 7. Determine Final Severity & Recommendation
        if (t.riskScore >= 70 || t.isKnownStalkerwareFamily) {
            t.severity = AntivirusEvidenceItem.SEVERITY_MALICIOUS;
            t.recommendation = "CRITICAL: Disable accessibility permission and uninstall immediately in Android Settings -> Accessibility.";
        } else if (t.riskScore >= 40) {
            t.severity = AntivirusEvidenceItem.SEVERITY_SUSPICIOUS;
            t.recommendation = "WARNING: Suspicious accessibility behavior. Verify that you explicitly installed and trust this app.";
        } else if (t.riskScore >= 20) {
            t.severity = AntivirusEvidenceItem.SEVERITY_LOW;
            t.recommendation = "Monitored third-party accessibility service.";
        } else {
            t.severity = AntivirusEvidenceItem.SEVERITY_CLEAN;
            t.isWhitelisted = true;
            t.recommendation = "Normal accessibility service operation.";
        }

        return t;
    }

    private static boolean checkOverlayPermission(Context context, String packageName) {
        if (context == null || packageName == null) return false;
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                return Settings.canDrawOverlays(context);
            }
        } catch (Exception ignored) {}
        return false;
    }
}

