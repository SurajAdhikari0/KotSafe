/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * AppPrivacyScorecardEngine
 * =========================
 * Generates a 0-100 privacy health score for every installed app based on
 * real observed network behaviour captured by CaptureService / ConnectionsRegister.
 *
 * SCORING ALGORITHM
 * -----------------
 * Every app starts at 100 (perfect privacy).  Deductions:
 *
 *   Category                          Max deduction
 *   ─────────────────────────────────────────────────
 *   Commercial tracker domains        -35  (-5 per distinct tracker, max 7)
 *   Cleartext HTTP connections        -15
 *   Background beaconing (screen off) -20  (-5 per background domain, max 4)
 *   High-risk dangerous permissions   -30  (-5 per dangerous perm, max 6)
 *   ─────────────────────────────────────────────────
 *   Minimum possible score              0  (clamped)
 *
 * GRADE BANDS
 *   85–100  EXCELLENT  🟢  Minimal trackers, TLS-only, quiet in background
 *   65– 84  MODERATE   🟡  1–3 analytics SDKs, typical commercial app
 *   40– 64  INVASIVE   🟠  Aggressive cross-app tracking / background beacons
 *    0– 39  HIGH RISK  🔴  Cleartext leaks, excessive trackers, spyware-like
 */

package com.kotsafe.security.model;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PermissionInfo;

import com.kotsafe.security.Log;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class AppPrivacyScorecardEngine {

    private static final String TAG = "AppPrivacyScorecard";

    // ── Known commercial tracker / telemetry domains ──────────────────────────
    private static final Set<String> TRACKER_DOMAINS = new HashSet<>(Arrays.asList(
        // Ad / attribution SDKs
        "app.adjust.com", "app.adjust.io", "s2s.adjust.com",
        "graph.facebook.com", "an.facebook.com",
        "api.appsflyer.com", "t.appsflyer.com",
        "api.kochava.com", "control.kochava.com",
        "api.branch.io",
        "ads.mopub.com",
        "ads.admob.com", "googlesyndication.com", "doubleclick.net",
        "mobile.twitter.com", "analytics.twitter.com",
        "pinpoint.amazonaws.com",
        // Analytics / crash reporters
        "firebase.io", "firebaseio.com", "crashlytics.com",
        "amplitude.com", "api.amplitude.com",
        "api.mixpanel.com", "api2.amplitude.com",
        "sentry.io", "o1.ingest.sentry.io",
        "rollbar.com",
        "bugsnag.com", "notify.bugsnag.com",
        // Device fingerprinting / data brokers
        "deviceatlas.com",
        "fingerprintjs.com"
    ));

    // ── High-risk Android permissions that erode privacy ─────────────────────
    private static final List<String> DANGEROUS_PRIVACY_PERMISSIONS = Arrays.asList(
        Manifest.permission.ACCESS_FINE_LOCATION,
        Manifest.permission.ACCESS_COARSE_LOCATION,
        Manifest.permission.READ_CONTACTS,
        Manifest.permission.READ_CALL_LOG,
        Manifest.permission.RECORD_AUDIO,
        Manifest.permission.CAMERA,
        Manifest.permission.READ_SMS,
        "android.permission.READ_PHONE_STATE",
        "android.permission.PACKAGE_USAGE_STATS",
        "android.permission.BIND_ACCESSIBILITY_SERVICE"
    );

    // ──────────────────────────────────────────────────────────────────────────

    public static class ScorecardResult {
        public final String packageName;
        public final String appLabel;
        public final int score;             // 0–100
        public final String grade;          // EXCELLENT / MODERATE / INVASIVE / HIGH_RISK
        public final String gradeEmoji;
        public final int trackerDomainsFound;
        public final boolean hasCleartextHttp;
        public final int backgroundBeaconDomains;
        public final int dangerousPermissions;
        public final List<String> detectedTrackers;
        public final List<String> detectedPermissions;

        ScorecardResult(String packageName, String appLabel, int score,
                        int trackers, boolean cleartext, int bgBeacons, int perms,
                        List<String> detectedTrackers, List<String> detectedPerms) {
            this.packageName  = packageName;
            this.appLabel     = appLabel;
            this.score        = score;
            this.trackerDomainsFound      = trackers;
            this.hasCleartextHttp         = cleartext;
            this.backgroundBeaconDomains  = bgBeacons;
            this.dangerousPermissions     = perms;
            this.detectedTrackers   = detectedTrackers;
            this.detectedPermissions = detectedPerms;

            if      (score >= 85) { grade = "EXCELLENT";  gradeEmoji = "\uD83D\uDFE2"; }
            else if (score >= 65) { grade = "MODERATE";   gradeEmoji = "\uD83D\uDFE1"; }
            else if (score >= 40) { grade = "INVASIVE";   gradeEmoji = "\uD83D\uDFE0"; }
            else                  { grade = "HIGH_RISK";  gradeEmoji = "\uD83D\uDD34"; }
        }

        /** One-line summary for notification / list view. */
        public String summary() {
            return gradeEmoji + " " + grade + " (" + score + "/100) — "
                + trackerDomainsFound + " trackers"
                + (hasCleartextHttp ? ", cleartext HTTP" : "")
                + (backgroundBeaconDomains > 0 ? ", " + backgroundBeaconDomains + " bg beacons" : "");
        }
    }

    private AppPrivacyScorecardEngine() {}

    /**
     * Computes a privacy score for a single package using live connection data
     * from the ConnectionsRegister ring buffer.
     *
     * @param context   Application context
     * @param packageName   Package to evaluate (e.g. "com.instagram.android")
     * @param connections   Snapshot of all connections observed for this UID
     * @return ScorecardResult with score and breakdown.
     */
    public static ScorecardResult evaluate(Context context, String packageName,
                                           List<ConnectionRecord> connections) {
        final boolean hasPackage = packageName != null && !packageName.trim().isEmpty();

        int score = 100;
        List<String> foundTrackers = new ArrayList<>();
        List<String> foundPerms    = new ArrayList<>();
        boolean hasCleartext       = false;
        int bgBeaconCount          = 0;

        // ── 1. Tracker domains ───────────────────────────────────────────────
        Set<String> seenTrackers = new HashSet<>();
        Set<String> bgBeaconDomains = new HashSet<>();

        if (connections != null) {
            for (ConnectionRecord conn : connections) {
                String host = conn.host != null ? conn.host.toLowerCase() : "";

                for (String tracker : TRACKER_DOMAINS) {
                    if (host.contains(tracker) && !seenTrackers.contains(tracker)) {
                        seenTrackers.add(tracker);
                        foundTrackers.add(tracker);
                        score -= 5;
                        if (score < 0) score = 0;
                    }
                }

                // ── 2. Cleartext HTTP ────────────────────────────────────────
                if (conn.port == 80 || conn.isPlainHttp) {
                    hasCleartext = true;
                }

                // ── 3. Background beaconing (connections made while screen off) ──
                if (conn.madeWhileScreenOff) {
                    bgBeaconDomains.add(host.isEmpty() ? conn.remoteIp : host);
                }
            }
        }

        if (hasCleartext) score -= 15;
        bgBeaconCount = bgBeaconDomains.size();
        int bgPenalty = Math.min(bgBeaconCount * 5, 20);
        score -= bgPenalty;

        // Cap tracker deduction at -35 (7 trackers × 5)
        // (already applied per-tracker above, just clamp)
        score = Math.max(score, 0);

        // ── 4. Dangerous permissions ─────────────────────────────────────────
        int permCount = 0;
        if (context != null && hasPackage) {
            try {
                PackageInfo pi = context.getPackageManager()
                        .getPackageInfo(packageName, PackageManager.GET_PERMISSIONS);
                if (pi.requestedPermissions != null) {
                    for (String perm : pi.requestedPermissions) {
                        if (DANGEROUS_PRIVACY_PERMISSIONS.contains(perm)) {
                            permCount++;
                            foundPerms.add(perm.replace("android.permission.", ""));
                            score -= 5;
                            if (permCount >= 6) break; // max -30
                        }
                    }
                }
            } catch (PackageManager.NameNotFoundException ignored) {}
        }

        score = Math.max(score, 0);

        // App label
        String label = hasPackage ? packageName : "Unknown app";
        if (context != null && hasPackage) {
            try {
                PackageManager pm = context.getPackageManager();
                label = pm.getApplicationLabel(
                        pm.getApplicationInfo(packageName, 0)).toString();
            } catch (Exception ignored) {}
        }

        Log.i(TAG, "Privacy score for " + packageName + ": " + score
                + " (trackers=" + foundTrackers.size()
                + ", cleartext=" + hasCleartext
                + ", bgBeacons=" + bgBeaconCount
                + ", perms=" + permCount + ")");

        return new ScorecardResult(packageName, label, score,
                foundTrackers.size(), hasCleartext, bgBeaconCount, permCount,
                foundTrackers, foundPerms);
    }

    /**
     * Lightweight data object passed in from CaptureService / ConnectionsRegister.
     * The caller maps ConnectionDescriptor fields to this simple struct to keep
     * AppPrivacyScorecardEngine decoupled from the VPN engine internals.
     */
    public static class ConnectionRecord {
        public String host;           // SNI or reverse-DNS hostname (null if unknown)
        public String remoteIp;       // Dotted IP string
        public int    port;           // Remote port
        public boolean isPlainHttp;   // True if captured as cleartext HTTP
        public boolean madeWhileScreenOff;  // True if device screen was off at connection time
    }
}
