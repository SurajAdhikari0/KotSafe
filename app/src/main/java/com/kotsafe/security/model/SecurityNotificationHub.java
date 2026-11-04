/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.SystemClock;

import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;
import androidx.core.content.ContextCompat;

import com.kotsafe.security.ActionReceiver;
import com.kotsafe.security.Log;
import com.kotsafe.security.R;
import com.kotsafe.security.activities.AntivirusScanActivity;
import com.kotsafe.security.activities.MainActivity;
import com.kotsafe.security.activities.SecurityActionsActivity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Objects;
import java.util.List;
import java.util.Map;

/**
 * Centralized Notification Hub for KotSafe.
 *
 * Implements Microsoft Defender-grade notification architecture:
 * 1. Unified 3-Tier Channels:
 *    - Status & Sentinel (Low / Silent)
 *    - Scan & Security Reports (Default)
 *    - Critical Threats & Intrusions (High / Heads-up)
 * 2. Anti-Spam Aggregated InboxStyle Threat Card (Collapses multiple alerts into 1 expandable card).
 * 3. Event Throttling & Cooldown (Suppresses duplicate burst events within a 60-second window).
 * 4. In-Place Ongoing Scan Progress Updates.
 */
public class SecurityNotificationHub {
    private static final String TAG = "SecurityNotificationHub";

    // Channels
    public static final String CHAN_STATUS = "kot_chan_status";
    public static final String CHAN_THREATS = "kot_chan_threats";
    public static final String CHAN_REPORTS = "kot_chan_reports";
    public static final String CHAN_REVIEW = "kot_chan_review";

    // Fixed Notification IDs (Guarantees no ID proliferation or notification spam)
    public static final int NOTIF_ID_ONGOING_SENTINEL = 4001;
    public static final int NOTIF_ID_THREAT_SUMMARY  = 4100;
    public static final int NOTIF_ID_SCAN_REPORT     = 4200;

    private static final String NOTIF_GROUP_THREATS = "com.kotsafe.security.THREAT_ALERTS";
    private static final long COOLDOWN_WINDOW_MS = 60_000L; // 60s cooldown for identical threat targets
    private static final int MAX_INBOX_LINES = 7;

    private static volatile SecurityNotificationHub sInstance;
    private final Context mContext;
    private final NotificationManager mNotificationManager;
    private final NotificationManagerCompat mNotificationManagerCompat;

    // Aggregated Threat State
    private final List<ThreatAlertItem> mActiveThreatAlerts = Collections.synchronizedList(new ArrayList<>());
    private final Map<String, Long> mLastAlertTimestamps = new LinkedHashMap<String, Long>() {
        @Override protected boolean removeEldestEntry(Map.Entry<String, Long> eldest) {
            return size() > 256;
        }
    };
    private static final int MAX_ACTIVE_ALERTS = 100;

    public static class ThreatAlertItem {
        public String title;
        public String target; // File name, domain, package, or IOC
        public String threatCategory; // "Spyware", "Ransomware Canary", "C2 Intrusion", "Root Exploit"
        public String severity; // "MALICIOUS" | "SUSPICIOUS"
        public long timestamp;

        public ThreatAlertItem(String title, String target, String threatCategory, String severity) {
            this.title = title;
            this.target = target;
            this.threatCategory = threatCategory;
            this.severity = severity;
            this.timestamp = System.currentTimeMillis();
        }
    }

    public static SecurityNotificationHub getInstance(Context context) {
        if (sInstance == null) {
            synchronized (SecurityNotificationHub.class) {
                if (sInstance == null) {
                    sInstance = new SecurityNotificationHub(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    private SecurityNotificationHub(Context context) {
        mContext = context;
        mNotificationManager = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
        mNotificationManagerCompat = NotificationManagerCompat.from(context);
        createChannels();
    }

    public void createChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && mNotificationManager != null) {
            // 1. Status & Sentinel Channel (Low: silent, no vibration, ongoing background)
            NotificationChannel statusChan = new NotificationChannel(
                    CHAN_STATUS,
                    "Protection Status & Sentinel",
                    NotificationManager.IMPORTANCE_LOW
            );
            statusChan.setDescription("Real-time background security sentinel and scan progress.");
            statusChan.setShowBadge(false);
            mNotificationManager.createNotificationChannel(statusChan);

            // 2. Critical Threats Channel (High: sound, vibration, heads-up card)
            NotificationChannel threatsChan = new NotificationChannel(
                    CHAN_THREATS,
                    "Security Threats & Intrusions",
                    NotificationManager.IMPORTANCE_HIGH
            );
            threatsChan.setDescription("Urgent alerts when malware, ransomware drops, or hostile C2s are detected.");
            threatsChan.enableVibration(true);
            threatsChan.setShowBadge(true);
            mNotificationManager.createNotificationChannel(threatsChan);

            NotificationChannel reviewChan = new NotificationChannel(
                    CHAN_REVIEW, "Suspicious activity for review", NotificationManager.IMPORTANCE_LOW);
            reviewChan.setDescription("Unconfirmed findings; review without an urgent interruption.");
            reviewChan.setSound(null, null);
            reviewChan.enableVibration(false);
            mNotificationManager.createNotificationChannel(reviewChan);

            // 3. Scan & Security Reports Channel (Default: silent/standard, summary digest)
            NotificationChannel reportsChan = new NotificationChannel(
                    CHAN_REPORTS,
                    "Scan & Security Reports",
                    NotificationManager.IMPORTANCE_DEFAULT
            );
            reportsChan.setDescription("Results of completed scans and security audits.");
            reportsChan.setShowBadge(true);
            mNotificationManager.createNotificationChannel(reportsChan);

        }
    }

    // =========================================================================
    // 1. Ongoing Status Sentinel & In-Place Scan Progress (ID: 4001)
    // =========================================================================

    /**
     * Builds or updates the single persistent ongoing status notification for foreground services.
     */
    public Notification buildOngoingSentinelNotification(String title, String subtitle, int progressPercent, boolean isScanning) {
        Intent openApp = new Intent(mContext, MainActivity.class);
        PendingIntent pi = PendingIntent.getActivity(mContext, 0, openApp, PendingIntent.FLAG_IMMUTABLE);

        NotificationCompat.Builder b = new NotificationCompat.Builder(mContext, CHAN_STATUS)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(title)
                .setContentText(subtitle)
                .setContentIntent(pi)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .setColor(ContextCompat.getColor(mContext, R.color.colorAccent));

        if (isScanning && progressPercent >= 0) {
            b.setProgress(100, progressPercent, false);
            b.setSubText("Deep Security Scan: " + progressPercent + "%");
        } else {
            b.setProgress(0, 0, false);
        }

        return b.build();
    }

    public boolean canPostNotification() {
        if (mNotificationManagerCompat != null && !mNotificationManagerCompat.areNotificationsEnabled()) {
            return false;
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            boolean hasRuntime = ContextCompat.checkSelfPermission(mContext, android.Manifest.permission.POST_NOTIFICATIONS)
                    == android.content.pm.PackageManager.PERMISSION_GRANTED;
            boolean enabledInSystem = (mNotificationManagerCompat != null && mNotificationManagerCompat.areNotificationsEnabled());
            return hasRuntime || enabledInSystem;
        }
        return mNotificationManagerCompat != null && mNotificationManagerCompat.areNotificationsEnabled();
    }

    @android.annotation.SuppressLint("MissingPermission")
    public void updateOngoingProgress(String phaseName, int progressPercent) {
        if (!canPostNotification()) return;
        Notification notif = buildOngoingSentinelNotification(
                "KotSafe Real-Time Security",
                phaseName,
                progressPercent,
                true
        );
        try {
            mNotificationManagerCompat.notify(NOTIF_ID_ONGOING_SENTINEL, notif);
        } catch (SecurityException se) {
            Log.e(TAG, "Notification permission missing: " + se.getMessage());
        }
    }

    // =========================================================================
    // 2. Anti-Spam Aggregated Threat Notification (ID: 4100)
    // =========================================================================

    /**
     * Posts a security threat alert with burst throttling and InboxStyle card aggregation.
     * Prevents spamming separate notifications for multiple concurrent threat events.
     */
    @android.annotation.SuppressLint("MissingPermission")
    public synchronized void postThreatAlert(String title, String target, String category, String severity) {
        if (!canPostNotification()) return;
        long now = SystemClock.elapsedRealtime();
        boolean malicious = "MALICIOUS".equals(severity);
        for (ThreatAlertItem existing : mActiveThreatAlerts) {
            if (Objects.equals(existing.target, target) && Objects.equals(existing.threatCategory, category)) {
                // Repeated observations update one active incident, even after the cooldown.
                // A stronger verdict must not be hidden by that cooldown.
                boolean escalated = malicious && !"MALICIOUS".equals(existing.severity);
                existing.timestamp = System.currentTimeMillis();
                if (escalated) {
                    existing.severity = severity;
                    existing.title = title;
                    // Keep the escalated finding visible in the latest inbox lines.
                    mActiveThreatAlerts.remove(existing);
                    mActiveThreatAlerts.add(existing);
                    publishAggregatedThreatCard(true);
                }
                return;
            }
        }
        String dedupeKey = (category != null ? category : "") + "|"
                + (target != null ? target : "") + "|" + severity;
        Long lastTime = mLastAlertTimestamps.get(dedupeKey);
        if (lastTime != null && now - lastTime < COOLDOWN_WINDOW_MS) return;
        mLastAlertTimestamps.put(dedupeKey, now);
        if (mActiveThreatAlerts.size() >= MAX_ACTIVE_ALERTS) {
            // Do not let routine suspicious observations evict unresolved malicious findings.
            int removable = -1;
            for (int i = 0; i < mActiveThreatAlerts.size(); i++) {
                if (!"MALICIOUS".equals(mActiveThreatAlerts.get(i).severity)) { removable = i; break; }
            }
            if (removable < 0 && !malicious) return;
            mActiveThreatAlerts.remove(removable >= 0 ? removable : 0);
        }
        mActiveThreatAlerts.add(new ThreatAlertItem(title, target, category, severity));
        publishAggregatedThreatCard(malicious);
    }

    /**
     * Publishes the consolidated InboxStyle threat summary card.
     */
    public synchronized void publishAggregatedThreatCard() {
        publishAggregatedThreatCard(false);
    }

    private synchronized void publishAggregatedThreatCard(boolean interrupt) {
        if (mActiveThreatAlerts.isEmpty()) {
            mNotificationManagerCompat.cancel(NOTIF_ID_THREAT_SUMMARY);
            return;
        }

        int count = mActiveThreatAlerts.size();
        boolean hasMalicious = false;
        for (ThreatAlertItem item : mActiveThreatAlerts) {
            if ("MALICIOUS".equals(item.severity)) { hasMalicious = true; break; }
        }
        String cardTitle = hasMalicious ? "Security threats need attention" : "Suspicious activity to review";

        Intent viewThreatsIntent = new Intent(mContext, AntivirusScanActivity.class);
        viewThreatsIntent.putExtra("focus_threats", true);
        PendingIntent viewPi = PendingIntent.getActivity(mContext, 101, viewThreatsIntent, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);

        Intent dismissIntent = new Intent(mContext, ActionReceiver.class);
        dismissIntent.setAction(ActionReceiver.ACTION_DISMISS_THREATS);
        PendingIntent dismissPi = PendingIntent.getBroadcast(mContext, 102, dismissIntent, PendingIntent.FLAG_IMMUTABLE);

        NotificationCompat.InboxStyle inboxStyle = new NotificationCompat.InboxStyle();
        inboxStyle.setBigContentTitle(cardTitle);
        inboxStyle.setSummaryText(count + " security finding" + (count > 1 ? "s" : ""));

        // Show most recent threats in the inbox list
        int startIdx = Math.max(0, count - MAX_INBOX_LINES);
        for (int i = startIdx; i < count; i++) {
            ThreatAlertItem item = mActiveThreatAlerts.get(i);
            String line = "• " + item.title + (item.target != null && !item.target.isEmpty() ? " (" + item.target + ")" : "");
            inboxStyle.addLine(line);
        }

        ThreatAlertItem latest = mActiveThreatAlerts.get(count - 1);
        String previewText = (count == 1)
                ? latest.title + " in " + latest.target
                : latest.title + " and " + (count - 1) + " other findings to review.";

        NotificationCompat.Builder b = new NotificationCompat.Builder(mContext, hasMalicious ? CHAN_THREATS : CHAN_REVIEW)
                .setSmallIcon(R.drawable.ic_exclamation_triangle_solid)
                .setContentTitle(cardTitle)
                .setContentText(previewText)
                .setStyle(inboxStyle)
                .setContentIntent(viewPi)
                .setPriority(interrupt ? NotificationCompat.PRIORITY_HIGH : NotificationCompat.PRIORITY_LOW)
                .setCategory(NotificationCompat.CATEGORY_STATUS)
                .setColor(ContextCompat.getColor(mContext, R.color.statusError))
                .setGroup(NOTIF_GROUP_THREATS)
                .setGroupSummary(true)
                .setOnlyAlertOnce(!interrupt)
                .setSilent(!interrupt)
                .setAutoCancel(true)
                .addAction(R.drawable.ic_search, "Review Findings", viewPi)
                .addAction(R.drawable.ic_close, "Dismiss", dismissPi);

        try {
            mNotificationManagerCompat.notify(NOTIF_ID_THREAT_SUMMARY, b.build());
        } catch (SecurityException se) {
            Log.e(TAG, "Notification permission missing: " + se.getMessage());
        }
    }

    public synchronized void clearThreatAlerts() {
        mActiveThreatAlerts.clear();
        mNotificationManagerCompat.cancel(NOTIF_ID_THREAT_SUMMARY);
    }

    // =========================================================================
    // 2b. New Account Device Login Alert (ID: 4300)
    // =========================================================================
    public static final int NOTIF_ID_DEVICE_LOGIN_ALERT = 4300;

    @android.annotation.SuppressLint("MissingPermission")
    public void postDeviceLoginAlert(String deviceModel, String osVersion, String ipAddress) {
        if (!canPostNotification()) return;

        Intent openDevicesIntent = new Intent(mContext, MainActivity.class);
        openDevicesIntent.putExtra("open_connected_devices", true);
        openDevicesIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent pi = PendingIntent.getActivity(mContext, 5001, openDevicesIntent,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);

        String title = "🚨 New Device Linked: " + (deviceModel != null ? deviceModel : "Device");
        String desc = "A new device (" + (osVersion != null ? osVersion : "Unknown OS") + ") logged into your KotSafe account."
                + (ipAddress != null && !ipAddress.isEmpty() ? " IP: " + ipAddress : "")
                + "\nIf this was not you, tap to review or revoke access instantly.";

        NotificationCompat.Builder b = new NotificationCompat.Builder(mContext, CHAN_THREATS)
                .setSmallIcon(R.drawable.ic_exclamation_triangle_solid)
                .setContentTitle(title)
                .setContentText("A new device signed into your KotSafe account.")
                .setStyle(new NotificationCompat.BigTextStyle().bigText(desc))
                .setContentIntent(pi)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setCategory(NotificationCompat.CATEGORY_ALARM)
                .setColor(ContextCompat.getColor(mContext, R.color.statusError))
                .setAutoCancel(true)
                .addAction(R.drawable.ic_search, "Review Devices", pi);

        try {
            mNotificationManagerCompat.notify(NOTIF_ID_DEVICE_LOGIN_ALERT, b.build());
        } catch (SecurityException se) {
            Log.e(TAG, "Notification permission missing: " + se.getMessage());
        }
    }

    // =========================================================================
    // 2c. Quarantine Threat Neutralized Alert (ID: 4120)
    // =========================================================================
    public static final int NOTIF_ID_QUARANTINE_ALERT = 4120;

    @android.annotation.SuppressLint("MissingPermission")
    public void postQuarantineAlert(String fileName, String originalPath, String sha256, long quarantineRecordId) {
        if (!canPostNotification()) return;
        try {
            Intent intent = new Intent(mContext, com.kotsafe.security.activities.AlertsCenterActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
            intent.putExtra("EXTRA_FILTER_QUARANTINE", true);
            PendingIntent pi = PendingIntent.getActivity(
                    mContext,
                    (int) (quarantineRecordId > 0 ? (41200 + (quarantineRecordId % 1000)) : 4120),
                    intent,
                    PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT
            );

            String body = "Isolated & neutralized: " + fileName + ". Tap to review containment or release.";
            NotificationCompat.Builder b = new NotificationCompat.Builder(mContext, CHAN_THREATS)
                    .setSmallIcon(R.drawable.ic_shield)
                    .setContentTitle("Threat Quarantined & Neutralized")
                    .setContentText(body)
                    .setStyle(new NotificationCompat.BigTextStyle().bigText(
                            "File has been encrypted and isolated in KotSafe Sandboxed Vault.\n" +
                            "• Target: " + fileName + "\n" +
                            "• Path: " + (originalPath != null ? originalPath : "Storage") + "\n" +
                            "• Execution disabled (POSIX 0600) & network egress sinkholed.\n\n" +
                            "Tap to review in Alerts Center or release with risk acceptance."
                    ))
                    .setContentIntent(pi)
                    .setPriority(NotificationCompat.PRIORITY_HIGH)
                    .setCategory(NotificationCompat.CATEGORY_ALARM)
                    .setColor(ContextCompat.getColor(mContext, R.color.statusError))
                    .setAutoCancel(true)
                    .addAction(R.drawable.ic_shield, "Review in Alerts", pi);

            mNotificationManagerCompat.notify(NOTIF_ID_QUARANTINE_ALERT, b.build());
            Log.i(TAG, "Quarantine notification posted for " + fileName);
        } catch (Exception e) {
            Log.e(TAG, "Failed to post quarantine notification: " + e.getMessage());
        }
    }

    // =========================================================================
    // 2d. Remote Mobile SOC Incident Alert (ID: 4130)
    // =========================================================================
    public static final int NOTIF_ID_REMOTE_SOC_ALERT = 4130;

    @android.annotation.SuppressLint("MissingPermission")
    public void postRemoteSocThreatAlert(String workstationName, String workstationId, String title, String description) {
        if (!canPostNotification()) return;
        try {
            Intent quarantineIntent = new Intent(mContext, com.kotsafe.security.receivers.RemoteSocActionReceiver.class);
            quarantineIntent.setAction(com.kotsafe.security.receivers.RemoteSocActionReceiver.ACTION_QUARANTINE);
            quarantineIntent.putExtra(com.kotsafe.security.receivers.RemoteSocActionReceiver.EXTRA_TARGET_DEVICE_ID, workstationId);
            quarantineIntent.putExtra(com.kotsafe.security.receivers.RemoteSocActionReceiver.EXTRA_WORKSTATION_NAME, workstationName);
            PendingIntent quarantinePi = PendingIntent.getBroadcast(
                    mContext,
                    4131,
                    quarantineIntent,
                    PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT
            );

            Intent dismissIntent = new Intent(mContext, com.kotsafe.security.receivers.RemoteSocActionReceiver.class);
            dismissIntent.setAction(com.kotsafe.security.receivers.RemoteSocActionReceiver.ACTION_DISMISS);
            PendingIntent dismissPi = PendingIntent.getBroadcast(
                    mContext,
                    4132,
                    dismissIntent,
                    PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT
            );

            NotificationCompat.Builder b = new NotificationCompat.Builder(mContext, CHAN_THREATS)
                    .setSmallIcon(R.drawable.ic_exclamation_triangle_solid)
                    .setContentTitle("🚨 Remote Threat: " + (workstationName != null ? workstationName : "Workstation"))
                    .setContentText(title != null ? title : "Suspicious activity detected on workstation")
                    .setStyle(new NotificationCompat.BigTextStyle().bigText(
                            "Workstation Sentinel Incident:\n" +
                            "• Host: " + (workstationName != null ? workstationName : "Workstation") + "\n" +
                            "• Incident: " + title + "\n" +
                            "• Details: " + description + "\n\n" +
                            "Tap 'Quarantine' to instantly sever this machine from the network."
                    ))
                    .setPriority(NotificationCompat.PRIORITY_HIGH)
                    .setCategory(NotificationCompat.CATEGORY_ALARM)
                    .setColor(ContextCompat.getColor(mContext, R.color.statusError))
                    .setAutoCancel(true)
                    .addAction(R.drawable.ic_shield, "🔒 Quarantine Workstation", quarantinePi)
                    .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Dismiss", dismissPi);

            mNotificationManagerCompat.notify(NOTIF_ID_REMOTE_SOC_ALERT, b.build());
            Log.i(TAG, "Remote SOC notification posted for workstation: " + workstationName);
        } catch (Exception e) {
            Log.e(TAG, "Failed posting remote SOC alert: " + e.getMessage());
        }
    }

    // =========================================================================
    // 2b. Protection Degraded Warning (ID: 4150) — C-001 / H-001 fix
    // =========================================================================

    private static final int NOTIF_ID_PROTECTION_DEGRADED = 4150;

    /**
     * Posts a sticky "Limited Real-Time Protection" warning notification when
     * MANAGE_EXTERNAL_STORAGE is not granted, making the storage permission gap
     * visible to the user instead of silently degrading.
     * Tapping the notification deep-links to Android Settings > All Files Access.
     */
    @android.annotation.SuppressLint("MissingPermission")
    public void postProtectionDegradedAlert(String title, String body) {
        if (!canPostNotification()) return;
        try {
            android.net.Uri settingsUri = android.net.Uri.parse(
                    "package:" + mContext.getPackageName());
            Intent settingsIntent;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                settingsIntent = new Intent(
                        android.provider.Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                        settingsUri);
            } else {
                settingsIntent = new Intent(
                        android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                        settingsUri);
            }
            settingsIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            PendingIntent pi = PendingIntent.getActivity(
                    mContext, 4150, settingsIntent,
                    PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);

            NotificationCompat.Builder builder = new NotificationCompat.Builder(mContext, CHAN_THREATS)
                    .setSmallIcon(android.R.drawable.ic_dialog_alert)
                    .setContentTitle(title)
                    .setContentText(body)
                    .setStyle(new NotificationCompat.BigTextStyle().bigText(body))
                    .setContentIntent(pi)
                    .setPriority(NotificationCompat.PRIORITY_DEFAULT)
                    .setOngoing(true)          // Sticky — stays until user grants permission
                    .setAutoCancel(false);

            mNotificationManagerCompat.notify(NOTIF_ID_PROTECTION_DEGRADED, builder.build());
            Log.i(TAG, "Protection Degraded notification posted (MANAGE_EXTERNAL_STORAGE missing).");
        } catch (Exception e) {
            Log.e(TAG, "Failed to post protection degraded alert: " + e.getMessage());
        }
    }

    /** Dismisses the protection degraded notification once permission is granted. */
    public void dismissProtectionDegradedAlert() {
        mNotificationManagerCompat.cancel(NOTIF_ID_PROTECTION_DEGRADED);
    }

    // =========================================================================
    // 3. Scan Completion & Security Reports (ID: 4200)
    // =========================================================================

    /**
     * Publishes a clean, non-spammy scan completion report card.
     */
    @android.annotation.SuppressLint("MissingPermission")
    public void postScanCompleteNotification(AntivirusScanEngine.ScanResult result) {
        if (result == null || !canPostNotification()) return;

        Intent openReport = new Intent(mContext, AntivirusScanActivity.class);
        PendingIntent pi = PendingIntent.getActivity(mContext, 201, openReport, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);

        if (result.threatsDetected > 0 || result.suspiciousDetected > 0) {
            mNotificationManagerCompat.cancel(NOTIF_ID_SCAN_REPORT);
        }
        if (result.threatsDetected > 0) {
            // Threats detected -> publish aggregated high-priority threat card
            postThreatAlert(
                    "Deep Scan Found Threats",
                    result.threatsDetected + " Threat(s) detected",
                    "Scan Verdict",
                    "MALICIOUS"
            );
        } else if (result.suspiciousDetected > 0) {
            postThreatAlert("Scan found suspicious activity", "Latest device scan", "Scan Review", "SUSPICIOUS");
        } else {
            // No findings within the scanned scope is not a guarantee that the device is secure.
            String title = "Device scan complete: no threats found";
            String summary = String.format(java.util.Locale.US,
                    "Security Score: %d/100 • %d apps, %d files scanned (0 threats)",
                    result.securityScore, result.totalPackagesScanned, result.totalStorageScanned);

            NotificationCompat.Builder b = new NotificationCompat.Builder(mContext, CHAN_REPORTS)
                    .setSmallIcon(R.drawable.ic_check_solid)
                    .setContentTitle(title)
                    .setSilent(true)
                    .setContentText(summary)
                    .setContentIntent(pi)
                    .setPriority(NotificationCompat.PRIORITY_DEFAULT)
                    .setColor(ContextCompat.getColor(mContext, R.color.colorAccent))
                    .setAutoCancel(true);

            try {
                mNotificationManagerCompat.notify(NOTIF_ID_SCAN_REPORT, b.build());
            } catch (SecurityException se) {
                Log.e(TAG, "Notification permission missing: " + se.getMessage());
            }
        }
    }
}
