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
 * Copyright 2026 - KotSafe
 */

package com.kotsafe.security.services;

import android.accessibilityservice.AccessibilityService;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.provider.Settings;
import android.text.TextUtils;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;

import com.kotsafe.security.Log;
import com.kotsafe.security.activities.FirewallBlockPageActivity;
import com.kotsafe.security.model.AlertRecord;
import com.kotsafe.security.model.AlertStore;
import com.kotsafe.security.model.BrowserActivityManager;
import com.kotsafe.security.model.FirewallLogDbHelper;
import com.kotsafe.security.model.FirewallLogEntry;
import com.kotsafe.security.model.PhysicalSecurityManager;
import com.kotsafe.security.model.SecurityBlocklistManager;
import com.kotsafe.security.model.SecurityDatabase;
import com.kotsafe.security.model.SecurityRulesDb;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Accessibility Service replicating Microsoft Defender Web Protection on Android.
 * Reads the address bar in major web browsers directly from the UI hierarchy,
 * capturing the exact clean URL without requiring TLS decryption or root CA certificates.
 */
public class BrowserAccessibilityService extends AccessibilityService {
    private static final String TAG = "BrowserAccessibilityService";
    private static volatile boolean sIsRunning = false;

    /** Last package for which the screenshot-block overlay was shown (avoid redundant show/hide). */
    private String mLastScreenshotBlockedPkg = null;

    // Known URL bar resource IDs across mobile web browsers and modern Chromium variants.
    private static final List<String> URL_BAR_VIEW_IDS = Arrays.asList(
            "url_bar",                           // Chrome, Brave, Chromium, Edge
            "search_box_text",                   // Chrome tablet / custom tabs
            "search_src_text",                   // Android 12+ Chrome search bar
            "omnibox",                          // Chrome / Chromium omnibox
            "omnibarTextInput",                  // DuckDuckGo
            "mozac_browser_toolbar_url_view",    // Firefox modern
            "toolbar_url",                       // Firefox classic
            "url_bar_title",                     // Firefox Focus
            "location_bar_edit_text",            // Samsung Internet
            "url_field",                         // Opera
            "address_bar",                       // Vivaldi
            "search_engine_edit_text",           // Kiwi
            "browser_url_bar",                  // generic browser UI variants
            "search_bar",                        // generic toolbar search box
            "url_edit_text",                    // generic browser text field
            "toolbar_edit_text"                 // Firefox/Chromium toolbar edits
    );

    private static final Set<String> SUPPORTED_PACKAGES = new HashSet<>(Arrays.asList(
            "com.android.chrome",
            "com.google.android.apps.chrome",
            "com.android.chrome.beta",
            "com.chrome.beta",
            "com.google.android.apps.chrome.dev",
            "com.chrome.dev",
            "com.google.android.apps.chrome.canary",
            "com.chrome.canary",
            "org.mozilla.firefox",
            "org.mozilla.firefox_beta",
            "org.mozilla.fenix",
            "com.brave.browser",
            "com.microsoft.emmx",
            "com.opera.browser",
            "com.opera.mini.native",
            "com.sec.android.app.sbrowser",
            "com.duckduckgo.mobile.android",
            "com.vivaldi.browser",
            "com.kiwibrowser.browser",
            "org.chromium.chrome"
    ));

    private String mLastCapturedUrl = "";
    private long mLastCapturedTime = 0;

    public static boolean isRunning() {
        return sIsRunning;
    }

    public static boolean isAccessibilityServiceEnabled(Context context) {
        if (sIsRunning) return true;
        try {
            android.view.accessibility.AccessibilityManager am =
                    (android.view.accessibility.AccessibilityManager) context.getSystemService(Context.ACCESSIBILITY_SERVICE);
            if (am != null) {
                List<android.accessibilityservice.AccessibilityServiceInfo> list =
                        am.getEnabledAccessibilityServiceList(android.accessibilityservice.AccessibilityServiceInfo.FEEDBACK_ALL_MASK);
                if (list != null) {
                    for (android.accessibilityservice.AccessibilityServiceInfo info : list) {
                        String id = info.getId();
                        if (id != null && id.contains(context.getPackageName()) && id.contains("BrowserAccessibilityService")) {
                            return true;
                        }
                    }
                }
            }

            int accessibilityEnabled = Settings.Secure.getInt(
                    context.getContentResolver(),
                    Settings.Secure.ACCESSIBILITY_ENABLED, 0
            );
            if (accessibilityEnabled == 1) {
                String services = Settings.Secure.getString(
                        context.getContentResolver(),
                        Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
                );
                if (services != null && services.contains(context.getPackageName()) && services.contains("BrowserAccessibilityService")) {
                    return true;
                }
            }
        } catch (Exception ignored) {}
        return false;
    }

    @Override
    protected void onServiceConnected() {
        super.onServiceConnected();
        sIsRunning = true;
        Log.i(TAG, "BrowserAccessibilityService connected and monitoring browser activity (Defender mode)");
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        sIsRunning = false;
        Log.i(TAG, "BrowserAccessibilityService destroyed");
    }

    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        if (event == null) return;

        CharSequence pkg = event.getPackageName();
        if (pkg == null) return;
        String packageName = pkg.toString();

        // ── Per-app screenshot blocking ────────────────────────────────────────
        if (event.getEventType() == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
            handleScreenshotBlock(packageName);
        }

        // ── Browser URL extraction (existing logic) ───────────────────────────
        if (!SUPPORTED_PACKAGES.contains(packageName) && !BrowserActivityManager.KNOWN_BROWSER_PACKAGES.contains(packageName)) {
            return;
        }

        AccessibilityNodeInfo rootNode = getRootInActiveWindow();
        if (rootNode == null) return;

        try {
            String extractedUrl = findUrlInNode(rootNode, packageName);
            if (!TextUtils.isEmpty(extractedUrl)) {
                processCapturedUrl(packageName, extractedUrl);
            }
        } finally {
            rootNode.recycle();
        }
    }

    /**
     * Shows or hides the FLAG_SECURE overlay based on whether the newly-foregrounded
     * package is in the user's screenshot-protection list.
     */
    private void handleScreenshotBlock(String packageName) {
        PhysicalSecurityManager mgr = PhysicalSecurityManager.getInstance(this);
        boolean shouldBlock = mgr.isScreenshotBlockedForPackage(packageName);
        boolean wasBlocked  = (mLastScreenshotBlockedPkg != null);

        if (shouldBlock && !packageName.equals(mLastScreenshotBlockedPkg)) {
            // New protected package in foreground — start / update overlay
            startOverlayService(ScreenshotBlockOverlayService.ACTION_SHOW_OVERLAY);
            mLastScreenshotBlockedPkg = packageName;
            Log.i(TAG, "Screenshot block ON for: " + packageName);
        } else if (!shouldBlock && wasBlocked) {
            // Left the protected app — remove overlay
            startOverlayService(ScreenshotBlockOverlayService.ACTION_HIDE_OVERLAY);
            mLastScreenshotBlockedPkg = null;
            Log.i(TAG, "Screenshot block OFF (left protected app)");
        }
    }

    private void startOverlayService(String action) {
        if (!Settings.canDrawOverlays(this)) return;
        Intent svc = new Intent(this, ScreenshotBlockOverlayService.class);
        svc.setAction(action);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(svc);
        } else {
            startService(svc);
        }
    }

    private String findUrlInNode(AccessibilityNodeInfo node, String packageName) {
        if (node == null) return null;

        String viewId = node.getViewIdResourceName();
        String className = node.getClassName() != null ? node.getClassName().toString() : "";
        boolean maybeUrlBar = false;

        if (viewId != null) {
            String normalizedId = viewId.toLowerCase(Locale.US);
            for (String knownId : URL_BAR_VIEW_IDS) {
                String normalizedKnown = knownId.toLowerCase(Locale.US);
                if (normalizedId.endsWith(":id/" + normalizedKnown)
                        || normalizedId.endsWith("/" + normalizedKnown)
                        || normalizedId.contains(normalizedKnown)) {
                    maybeUrlBar = true;
                    break;
                }
            }
        }

        if (!maybeUrlBar && !className.contains("EditText") && !className.contains("TextView")) {
            // Skip non-text nodes early to avoid false positives in generic web content.
            int childCount = node.getChildCount();
            for (int i = 0; i < childCount; i++) {
                AccessibilityNodeInfo child = node.getChild(i);
                if (child != null) {
                    String found = findUrlInNode(child, packageName);
                    child.recycle();
                    if (found != null) return found;
                }
            }
            return null;
        }

        CharSequence hintText = (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) ? node.getHintText() : null;
        CharSequence[] candidates = new CharSequence[] {
                node.getText(),
                node.getContentDescription(),
                hintText
        };

        for (CharSequence candidate : candidates) {
            if (TextUtils.isEmpty(candidate)) continue;
            String clean = cleanUrl(candidate.toString());
            if (looksLikeUrl(clean)) {
                return clean;
            }
        }

        int childCount = node.getChildCount();
        for (int i = 0; i < childCount; i++) {
            AccessibilityNodeInfo child = node.getChild(i);
            if (child != null) {
                String found = findUrlInNode(child, packageName);
                child.recycle();
                if (found != null) return found;
            }
        }

        return null;
    }

    private String cleanUrl(String raw) {
        if (raw == null) return "";
        String trimmed = raw.trim().replace('\\', '/');
        if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
            return trimmed;
        }
        if (trimmed.startsWith("www.")) {
            return "https://" + trimmed;
        }
        // Normalize plain domain to https://
        if (trimmed.contains(".") && !trimmed.contains(" ") && !trimmed.contains("\n")) {
            return "https://" + trimmed;
        }
        return trimmed;
    }

    private boolean looksLikeUrl(String text) {
        if (TextUtils.isEmpty(text)) return false;
        String normalized = text.trim();
        if (normalized.length() < 4) return false;
        if (normalized.startsWith("http://") || normalized.startsWith("https://")) return true;
        if (normalized.startsWith("www.")) return true;
        return normalized.contains(".") && !normalized.contains(" ") && normalized.indexOf('.') > 0 && normalized.indexOf('.') < normalized.length() - 2;
    }

    private void processCapturedUrl(String packageName, String url) {
        long now = System.currentTimeMillis();
        // Prevent duplicate spam from frequent UI changes within 1.5 seconds
        if (url.equalsIgnoreCase(mLastCapturedUrl) && (now - mLastCapturedTime < 1500)) {
            return;
        }

        mLastCapturedUrl = url;
        mLastCapturedTime = now;

        Log.d(TAG, "Defender captured browser navigation: [" + packageName + "] -> " + url);
        BrowserActivityManager.getInstance(this).recordBrowserNavigation(packageName, url, now);
        try {
            com.kotsafe.security.model.TrafficDeduplicationParser.getInstance(this)
                    .onApiBrowserNavigation(packageName, url, now);
        } catch (Exception ignored) {}


        // Check if URL or Host is blocked in KotSafe Security Actions / Firewall Rules
        try {
            SecurityBlocklistManager blocklistMgr = SecurityBlocklistManager.getInstance(this);
            SecurityRulesDb.SecurityRule rule = blocklistMgr.findUrlBlockRule(url);
            String host = SecurityBlocklistManager.extractHost(url);
            if (host != null && (SecurityBlocklistManager.isOfficialDomain(host) || SecurityBlocklistManager.isTrustedAdOrAnalyticsDomain(host))) {
                return;
            }
            if (rule == null && host != null && !host.isEmpty()) {
                rule = blocklistMgr.findBlockRule(host);
            }

            if (rule != null && rule.enabled && !SecurityRulesDb.SOURCE_HEURISTIC.equalsIgnoreCase(rule.source)) {
                Log.w(TAG, "BLOCKED URL INTERCEPTED (API Mode): " + url + " matching rule: " + rule.value);

                // 1. Increment hit count on rule
                SecurityDatabase.getInstance(this).rules().incrementHitCount(rule.id);

                // 2. Resolve browser app display name
                String appLabel = packageName;
                try {
                    android.content.pm.PackageManager pm = getPackageManager();
                    appLabel = pm.getApplicationLabel(pm.getApplicationInfo(packageName, 0)).toString();
                } catch (Exception ignored) {}

                // 3. Log event as BLOCKED in Firewall Logs
                FirewallLogEntry entry = new FirewallLogEntry();
                entry.timestamp = now;
                entry.packageName = packageName;
                entry.appName = appLabel;
                entry.domainOrUrl = url;
                entry.action = FirewallLogEntry.ACTION_BLOCKED;
                entry.blockReason = (rule.reason != null && !rule.reason.isEmpty()) ? rule.reason : "Firewall URL Block Rule";
                entry.threatVerdict = FirewallLogEntry.VERDICT_MALICIOUS;
                entry.threatSource = "API_SMARTSCREEN";
                FirewallLogDbHelper.getInstance(this).insertLog(entry);

                // 4. Create high-priority alert in AlertStore
                AlertStore.getInstance(this).add(
                        AlertRecord.Severity.HIGH,
                        AlertRecord.AlertType.FIREWALL_BLOCK,
                        "Blocked Website Intercepted",
                        "KotSafe Web Guard blocked " + (host != null ? host : url) + " in " + appLabel + " (Rule: " + entry.blockReason + ")",
                        "KotSafe Web Guard"
                );

                // 5. Navigate the browser back to prevent rendering malicious content
                performGlobalAction(GLOBAL_ACTION_BACK);

                // 6. Launch Firewall Block Page Overlay immediately
                Intent blockIntent = new Intent(this, FirewallBlockPageActivity.class);
                blockIntent.putExtra("target", url);
                blockIntent.putExtra("target_type", "URL");
                blockIntent.putExtra("reason", entry.blockReason);
                blockIntent.putExtra("app_name", appLabel);
                blockIntent.putExtra("package_name", packageName);
                blockIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
                startActivity(blockIntent);
            }
        } catch (Exception e) {
            Log.e(TAG, "Error evaluating URL block policy: " + e.getMessage());
        }
    }

    @Override
    public void onInterrupt() {
        Log.d(TAG, "BrowserAccessibilityService interrupted");
    }
}
