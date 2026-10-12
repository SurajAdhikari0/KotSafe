/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * ResponseEngine
 * ==============
 * Central execution engine for non-root, sandbox-compliant remediation actions:
 * - Network Actions: Firewall app isolation, IP/domain sinkholing, restricted mode.
 * - Application Actions: Sandboxed quarantine, system uninstall requests.
 * - Physical Actions: Audio alarm sirens, notification alerts, screen lock queries.
 */

package com.kotsafe.security.security.response;

import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.media.Ringtone;
import android.media.RingtoneManager;
import android.net.Uri;

import com.kotsafe.security.Log;
import com.kotsafe.security.model.QuarantineVaultManager;
import com.kotsafe.security.model.SecurityBlocklistManager;
import com.kotsafe.security.model.SmartScreenManager;
import com.kotsafe.security.model.UnifiedIncidentTimeline;
import com.kotsafe.security.security.event.EventTypes;
import com.kotsafe.security.security.event.SecurityEvent;
import com.kotsafe.security.security.event.SecurityEventBus;

import java.io.File;

public class ResponseEngine {
    private static final String TAG = "ResponseEngine";

    public enum Action {
        BLOCK_NETWORK_APP,
        BLOCK_DESTINATION,
        REQUEST_UNINSTALL,
        QUARANTINE_FILE,
        TRIGGER_ALARM_SIREN,
        ALERT_USER_NOTIFICATION
    }

    private static volatile ResponseEngine sInstance;
    private final Context mContext;

    public static ResponseEngine getInstance(Context context) {
        if (sInstance == null) {
            synchronized (ResponseEngine.class) {
                if (sInstance == null) {
                    sInstance = new ResponseEngine(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    private ResponseEngine(Context context) {
        mContext = context;
    }

    // ── Network Actions ────────────────────────────────────────────────────────

    public void isolateApp(String packageName, String reason) {
        if (packageName == null || packageName.isEmpty()) return;
        if (packageName.equals(mContext.getPackageName())) return; // Self protection
        if (com.kotsafe.security.Utils.isVerifiedGoogleTrustedService(mContext, packageName)
                || com.kotsafe.security.Utils.isEssentialOrBrowserApp(mContext, packageName)) {
            Log.i(TAG, "Prevented isolation of trusted / browser / essential app: " + packageName);
            return;
        }

        Log.w(TAG, "Executing Network Isolation on: " + packageName + " (" + reason + ")");
        SecurityBlocklistManager secMgr = SecurityBlocklistManager.getInstance(mContext);
        secMgr.blockApp(packageName, reason != null ? reason : "Automated Security Response", "RESPONSE_ENGINE");

        recordRemediation("App Isolated", "Cut network access for " + packageName + ": " + reason, packageName);
    }

    public void blockDestination(String destination, String reason) {
        if (destination == null || destination.isEmpty()) return;
        SecurityBlocklistManager secMgr = SecurityBlocklistManager.getInstance(mContext);
        if (destination.matches("^[0-9.]+$") || destination.contains(":")) {
            secMgr.blockIp(destination, reason != null ? reason : "Threat Defense Response", "RESPONSE_ENGINE");
        } else {
            secMgr.blockDomain(destination, reason != null ? reason : "Threat Defense Response", "RESPONSE_ENGINE");
        }
        recordRemediation("Destination Blocked", "Blocked outbound flows to " + destination, null);
    }

    // ── Application Actions ────────────────────────────────────────────────────

    public void requestUninstall(String packageName) {
        if (packageName == null || packageName.isEmpty()) return;
        if (packageName.equals(mContext.getPackageName())) return;
        if (com.kotsafe.security.Utils.isVerifiedGoogleTrustedService(mContext, packageName)) {
            Log.i(TAG, "Prevented uninstall request for trusted Google Core Service: " + packageName);
            return;
        }

        Log.i(TAG, "Prompting user uninstall intent for " + packageName);
        Intent intent = new Intent(Intent.ACTION_DELETE);
        intent.setData(Uri.parse("package:" + packageName));
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        try {
            mContext.startActivity(intent);
            recordRemediation("Uninstall Requested", "Prompted package removal for " + packageName, packageName);
        } catch (Exception e) {
            Log.e(TAG, "Failed launching uninstall intent: " + e.getMessage());
        }
    }

    public boolean quarantineFile(File file, String threatName) {
        if (file == null || !file.exists()) return false;
        try {
            QuarantineVaultManager qm = QuarantineVaultManager.getInstance(mContext);
            boolean ok = qm.quarantineFile(file, threatName, "RESPONSE_ENGINE");
            if (ok) {
                recordRemediation("File Quarantined", "Moved " + file.getName() + " to secure vault", null);
            }
            return ok;
        } catch (Exception e) {
            Log.e(TAG, "Quarantine error: " + e.getMessage());
            return false;
        }
    }

    // ── Physical Actions ───────────────────────────────────────────────────────

    public void triggerAlarmSiren() {
        Log.w(TAG, "SOUNDING ANTI-THEFT ALARM SIREN");
        try {
            Uri alarmUri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_ALARM);
            if (alarmUri == null) alarmUri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_RINGTONE);
            Ringtone ringtone = RingtoneManager.getRingtone(mContext, alarmUri);
            if (ringtone != null) {
                ringtone.play();
            }
            recordRemediation("Audible Alarm Triggered", "Anti-Theft siren engaged on physical tamper", null);
        } catch (Exception e) {
            Log.e(TAG, "Failed to trigger alarm sound: " + e.getMessage());
        }
    }

    private void recordRemediation(String title, String details, String packageName) {
        UnifiedIncidentTimeline.getInstance(mContext).record(
                new UnifiedIncidentTimeline.IncidentEvent.Builder()
                        .type(UnifiedIncidentTimeline.EventType.GENERAL_ALERT)
                        .severity(UnifiedIncidentTimeline.Severity.HIGH)
                        .title("Remediation: " + title)
                        .detail(details)
                        .sourceApp(packageName)
                        .build()
        );

        SecurityEvent.Builder eventBuilder = new SecurityEvent.Builder(SecurityEvent.Domain.CORRELATION, EventTypes.REMEDIATION_EXECUTED)
                .severity(SecurityEvent.Severity.HIGH)
                .title(title)
                .description(details)
                .subject(packageName, -1);
        SecurityEventBus.getInstance().publish(eventBuilder.build());
    }
}
