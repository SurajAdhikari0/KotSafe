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
import java.util.HashMap;
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
    private final Map<String, Long> mLastAlertTimestamps = new HashMap<>();

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
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(mContext, android.Manifest.permission.POST_NOTIFICATIONS)
                    != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                return false;
            }
        }
        return mNotificationManagerCompat.areNotificationsEnabled();
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
        // Cooldown & Deduplication check
        long now = SystemClock.elapsedRealtime();
        String dedupeKey = (category != null ? category : "") + "|" + (target != null ? target : "");
        Long lastTime = mLastAlertTimestamps.get(dedupeKey);
        if (lastTime != null && (now - lastTime) < COOLDOWN_WINDOW_MS) {
            Log.d(TAG, "Throttling duplicate threat alert within cooldown window: " + dedupeKey);
            return;
        }
        mLastAlertTimestamps.put(dedupeKey, now);

        // Add to active alerts list
        mActiveThreatAlerts.add(new ThreatAlertItem(title, target, category, severity));

        publishAggregatedThreatCard();
    }

    /**
     * Publishes the consolidated InboxStyle threat summary card.
     */
    public synchronized void publishAggregatedThreatCard() {
        if (mActiveThreatAlerts.isEmpty()) {
            mNotificationManagerCompat.cancel(NOTIF_ID_THREAT_SUMMARY);
            return;
        }

        int count = mActiveThreatAlerts.size();
        String cardTitle = (count == 1)
                ? "⚠️ Security Threat Detected"
                : "⚠️ " + count + " Security Threats Detected";

        Intent viewThreatsIntent = new Intent(mContext, AntivirusScanActivity.class);
        viewThreatsIntent.putExtra("focus_threats", true);
        PendingIntent viewPi = PendingIntent.getActivity(mContext, 101, viewThreatsIntent, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);

        Intent dismissIntent = new Intent(mContext, ActionReceiver.class);
        dismissIntent.setAction(ActionReceiver.ACTION_DISMISS_THREATS);
        PendingIntent dismissPi = PendingIntent.getBroadcast(mContext, 102, dismissIntent, PendingIntent.FLAG_IMMUTABLE);

        NotificationCompat.InboxStyle inboxStyle = new NotificationCompat.InboxStyle();
        inboxStyle.setBigContentTitle(cardTitle);
        inboxStyle.setSummaryText(count + " active threat" + (count > 1 ? "s" : ""));

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
                : latest.title + " and " + (count - 1) + " other threats detected.";

        NotificationCompat.Builder b = new NotificationCompat.Builder(mContext, CHAN_THREATS)
                .setSmallIcon(R.drawable.ic_exclamation_triangle_solid)
                .setContentTitle(cardTitle)
                .setContentText(previewText)
                .setStyle(inboxStyle)
                .setContentIntent(viewPi)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setCategory(NotificationCompat.CATEGORY_ALARM)
                .setColor(ContextCompat.getColor(mContext, R.color.statusError))
                .setGroup(NOTIF_GROUP_THREATS)
                .setGroupSummary(true)
                .setOnlyAlertOnce(true)
                .setAutoCancel(true)
                .addAction(R.drawable.ic_search, "Review Threats", viewPi)
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

        if (result.threatsDetected > 0) {
            // Threats detected -> publish aggregated high-priority threat card
            postThreatAlert(
                    "Deep Scan Found Threats",
                    result.threatsDetected + " Threat(s) detected",
                    "Scan Verdict",
                    "MALICIOUS"
            );
        } else {
            // Clean scan -> gentle completion card on reports channel
            String title = "🛡️ Device Scan Complete: Secure";
            String summary = String.format(java.util.Locale.US,
                    "Security Score: %d/100 • %d apps, %d files scanned (0 threats)",
                    result.securityScore, result.totalPackagesScanned, result.totalStorageScanned);

            NotificationCompat.Builder b = new NotificationCompat.Builder(mContext, CHAN_REPORTS)
                    .setSmallIcon(R.drawable.ic_check_solid)
                    .setContentTitle(title)
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
