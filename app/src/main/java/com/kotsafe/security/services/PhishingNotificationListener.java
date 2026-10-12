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

import android.app.Notification;
import android.os.Bundle;
import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;
import android.text.TextUtils;

import com.kotsafe.security.AppsResolver;
import com.kotsafe.security.Log;
import com.kotsafe.security.model.AlertRecord;
import com.kotsafe.security.model.AlertStore;
import com.kotsafe.security.model.AppDescriptor;
import com.kotsafe.security.model.SecurityBlocklistManager;
import com.kotsafe.security.model.SecurityRulesDb;
import com.kotsafe.security.model.SmartScreenManager;
import com.kotsafe.security.model.ThreatIntelProvider;
import com.kotsafe.security.model.ThreatIntelRouter;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Real-time SMS & Notification Phishing / Smishing Link Guard.
 * Inspects incoming messages in notifications for malicious URLs before the user taps them.
 */
public class PhishingNotificationListener extends NotificationListenerService {
    private static final String TAG = "PhishingNotifListener";

    // URL regex pattern to match web links inside message text
    private static final Pattern URL_PATTERN = Pattern.compile(
            "(https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}(?:/[^\\s]*)?)|" +
            "([a-zA-Z0-9.-]+\\.(?:com|org|net|xyz|top|ru|cn|io|app|cc|tk|ml|ga|cf|gq)/[^\\s]*)",
            Pattern.CASE_INSENSITIVE
    );

    private final ExecutorService mExecutor = Executors.newSingleThreadExecutor();
    private AppsResolver mAppsResolver;

    @Override
    public void onCreate() {
        super.onCreate();
        mAppsResolver = new AppsResolver(this);
        Log.i(TAG, "PhishingNotificationListener initialized");
    }

    @Override
    public void onNotificationPosted(StatusBarNotification sbn) {
        if (sbn == null || sbn.getNotification() == null) return;

        String senderPkg = sbn.getPackageName();
        if (senderPkg == null || senderPkg.equals(getPackageName())) {
            return; // Ignore self notifications
        }

        Notification notification = sbn.getNotification();
        Bundle extras = notification.extras;
        if (extras == null) return;

        CharSequence text = extras.getCharSequence(Notification.EXTRA_TEXT);
        CharSequence bigText = extras.getCharSequence(Notification.EXTRA_BIG_TEXT);
        CharSequence title = extras.getCharSequence(Notification.EXTRA_TITLE);

        StringBuilder combined = new StringBuilder();
        if (title != null) combined.append(title).append(" ");
        if (text != null) combined.append(text).append(" ");
        if (bigText != null) combined.append(bigText).append(" ");

        String fullMessage = combined.toString().trim();
        if (fullMessage.isEmpty()) return;

        List<String> urls = extractUrls(fullMessage);
        if (urls.isEmpty()) return;

        mExecutor.execute(() -> processExtractedUrls(senderPkg, title != null ? title.toString() : "Message", urls));
    }

    public static List<String> extractUrls(String text) {
        if (text == null || text.trim().isEmpty()) return Collections.emptyList();
        List<String> list = new ArrayList<>();
        Matcher matcher = URL_PATTERN.matcher(text);
        while (matcher.find()) {
            String url = matcher.group();
            if (!url.startsWith("http://") && !url.startsWith("https://")) {
                url = "https://" + url;
            }
            if (!list.contains(url)) {
                list.add(url);
            }
        }
        return list;
    }

    private void processExtractedUrls(String senderPkg, String senderTitle, List<String> urls) {
        AppDescriptor senderApp = mAppsResolver.getAppByPackage(senderPkg, 0);
        String appName = senderApp != null ? senderApp.getName() : senderPkg;

        SecurityBlocklistManager blockMgr = SecurityBlocklistManager.getInstance(this);
        ThreatIntelRouter router = ThreatIntelRouter.getInstance(this);

        for (String url : urls) {
            boolean isKnownBlock = false;
            String reason = null;

            if (blockMgr != null) {
                SecurityRulesDb.SecurityRule rule = blockMgr.findUrlBlockRule(url);
                if (rule != null) {
                    isKnownBlock = true;
                    reason = rule.reason != null ? rule.reason : "Blocked Threat Feed";
                }
            }

            if (isKnownBlock) {
                raisePhishingAlert(appName, senderTitle, url, reason, 100);
                continue;
            }

            // Async check threat intelligence
            if (router != null && router.hasAnyProvider()) {
                try {
                    ThreatIntelProvider.ThreatReport report = router.queryDomain(url);
                    if (report != null && (report.isMalicious || report.isSuspicious)) {
                        raisePhishingAlert(
                                appName,
                                senderTitle,
                                url,
                                "Identified as " + report.verdict + " by " + report.provider,
                                report.riskScore
                        );
                    }
                } catch (Exception e) {
                    Log.d(TAG, "TI lookup notice: " + e.getMessage());
                }
            }
        }
    }

    private void raisePhishingAlert(String appName, String senderTitle, String url, String details, int riskScore) {
        Log.w(TAG, "PHISHING LINK INTERCEPTED in " + appName + " (" + senderTitle + "): " + url);

        try {
            AlertStore.getInstance(this).add(
                    AlertRecord.Severity.HIGH,
                    AlertRecord.AlertType.MALWARE,
                    "Phishing Link: " + appName,
                    "Malicious link detected in message from " + senderTitle + ": " + url + " (" + details + ")",
                    appName
            );

            SmartScreenManager.getInstance(this).showSuspiciousWarning(
                    appName,
                    url,
                    "PHISHING LINK",
                    riskScore,
                    "Smishing Guard"
            );
        } catch (Exception e) {
            Log.e(TAG, "raisePhishingAlert error: " + e.getMessage());
        }
    }
}
