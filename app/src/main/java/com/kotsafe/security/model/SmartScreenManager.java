/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.os.Build;
import android.util.Base64;

import androidx.core.app.NotificationCompat;

import com.kotsafe.security.CaptureService;
import com.kotsafe.security.Log;
import com.kotsafe.security.R;
import com.kotsafe.security.activities.SmartScreenAlertActivity;
import com.kotsafe.security.server.FirewallBlockHttpServer;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * SmartScreen popup + notification manager.
 *
 * Shows a high-visibility alert when the security engine confirms a threat.
 * The alert can be:
 *   a) A full-screen dialog (SmartScreenAlertActivity) for critical installs
 *   b) A persistent notification for network-level detections
 *
 * Always non-blocking: the network path is never paused waiting for user response.
 */
public class SmartScreenManager {
    private static final String TAG = "SmartScreenManager";

    private static final String CHANNEL_ID_THREATS = "kotsafe_threats";
    private static final String CHANNEL_ID_WARNINGS = "kotsafe_warnings";
    private static final int NOTIF_BASE_ID = 9000;

    private static SmartScreenManager sInstance;
    private final Context mContext;
    private int mNotifCounter = NOTIF_BASE_ID;

    public static synchronized SmartScreenManager getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new SmartScreenManager(context.getApplicationContext());
        }
        return sInstance;
    }

    private SmartScreenManager(Context context) {
        mContext = context;
        createChannels();
    }

    private void createChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationManager nm = mContext.getSystemService(NotificationManager.class);
            if (nm == null) return;

            // Threat channel — high importance, always sounds
            NotificationChannel threats = new NotificationChannel(
                    CHANNEL_ID_THREATS,
                    "Threat Alerts",
                    NotificationManager.IMPORTANCE_HIGH);
            threats.setDescription("Confirmed malware or malicious network activity");
            threats.enableVibration(true);
            nm.createNotificationChannel(threats);

            // Warning channel — medium importance
            NotificationChannel warnings = new NotificationChannel(
                    CHANNEL_ID_WARNINGS,
                    "Security Warnings",
                    NotificationManager.IMPORTANCE_DEFAULT);
            warnings.setDescription("Suspicious activity that needs review");
            nm.createNotificationChannel(warnings);
        }
    }

    // ─── App Install Threat ───────────────────────────────────────────────────

    /**
     * Shows a high-priority alert that a newly installed app is confirmed malicious.
     * Launches SmartScreenAlertActivity as a dialog overlay.
     */
    public void showInstallAlert(Context context, String appName, String packageName,
                                  String sha256, String verdict,
                                  ThreatIntelProvider.ThreatReport report) {
        Log.i(TAG, "SmartScreen INSTALL ALERT: " + appName + " verdict=" + verdict);

        String details = (report.malwareFamily != null && !report.malwareFamily.isEmpty())
                ? "Family: " + report.malwareFamily + " | " + report.provider
                : "Confirmed malicious by " + report.provider;

        SecurityNotificationHub.getInstance(mContext).postThreatAlert(
                "Malicious App: " + appName,
                packageName,
                "App Install Threat",
                "MALICIOUS"
        );
    }

    // ─── Network Threat ───────────────────────────────────────────────────────

    /**
     * Shows a notification when a network connection matches a malicious IOC.
     */
    public void showNetworkThreat(String appName, String iocValue, String iocType,
                                   String verdict, String provider) {
        Log.i(TAG, "SmartScreen NETWORK THREAT: " + iocValue + " from " + appName);

        SecurityNotificationHub.getInstance(mContext).postThreatAlert(
                "Hostile C2: " + iocValue,
                appName,
                "Network C2",
                "MALICIOUS"
        );
    }

    /**
     * Shows a warning notification for suspicious (not confirmed) activity.
     */
    public void showSuspiciousWarning(String appName, String iocValue, String iocType,
                                       int riskScore, String provider) {
        Log.i(TAG, "SmartScreen WARNING: " + iocValue + " score=" + riskScore);

        SecurityNotificationHub.getInstance(mContext).postThreatAlert(
                "Suspicious " + iocType + ": " + iocValue,
                appName,
                "Network Warning",
                "SUSPICIOUS"
        );
    }

    // ─── Storage / File Threat ────────────────────────────────────────────────

    public void showFileThreat(String fileName, String filePath, String sha256,
                                String malwareFamily, String provider) {
        Log.i(TAG, "SmartScreen FILE THREAT: " + fileName);

        SecurityNotificationHub.getInstance(mContext).postThreatAlert(
                "Malicious File: " + fileName,
                filePath,
                "Storage Threat",
                "MALICIOUS"
        );
    }

    // ─── Firewall Block Page ──────────────────────────────────────────────────

    private final java.util.Map<String, Long> mBlockPageCooldown = new java.util.concurrent.ConcurrentHashMap<>();
    private static volatile String sLastBrowserPackage = null;
    private static volatile long sLastBrowserTime = 0;

    public static void noteBrowserActivity(String packageName) {
        if (packageName != null && !packageName.isEmpty()) {
            sLastBrowserPackage = packageName;
            sLastBrowserTime = System.currentTimeMillis();
        }
    }

    private static final int NOTIF_ID_FIREWALL_BLOCK = 4300;

    private String extractBaseDomain(String target) {
        if (target == null || target.isEmpty()) return "";
        try {
            String host = target;
            if (host.contains("://")) {
                host = Uri.parse(host).getHost();
            } else if (host.contains("/")) {
                host = host.substring(0, host.indexOf('/'));
            }
            if (host != null && host.contains(":")) {
                host = host.substring(0, host.indexOf(':'));
            }
            return host != null ? host.toLowerCase(java.util.Locale.US) : target.toLowerCase(java.util.Locale.US);
        } catch (Exception ignored) {
            return target.toLowerCase(java.util.Locale.US);
        }
    }

    /**
     * Presents an enterprise-style Firewall Block Page when a user or app visits a blocked
     * domain, site, URL, or hash.
     */
    public void showFirewallBlockPage(String target, String targetType,
                                       String reason, String appName, String packageName) {
        if (target == null || target.isEmpty()) return;
        long now = System.currentTimeMillis();
        String baseKey = extractBaseDomain(target);
        Long last = mBlockPageCooldown.get(baseKey);
        if (last != null && (now - last) < 60000) {
            return; // Debounce repetitive triggers for the same target within 60s to prevent noise
        }
        mBlockPageCooldown.put(baseKey, now);

        Log.i(TAG, "Firewall BLOCK PAGE: " + target + " [" + targetType + "] from " + appName + " (" + packageName + ")");

        // Ensure HTTP Block Server is running on port 8090
        try {
            FirewallBlockHttpServer.getInstance(mContext).start();
        } catch (Exception ignored) {}

        String rawUrl = target.startsWith("http") ? target : "https://" + target;
        String b64Url = Base64.encodeToString(rawUrl.getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP);
        String blockUrl = "http://127.0.0.1:" + FirewallBlockHttpServer.HTTP_PORT + "/ips/block/webcat?cat=66&pl=1&lu=0&url=" + b64Url
                + "&target=" + Uri.encode(target)
                + "&type=" + Uri.encode(targetType != null ? targetType : "SITE")
                + "&reason=" + Uri.encode(reason != null ? reason : "Security Policy")
                + "&app=" + Uri.encode(appName != null ? appName : "Web Browser");

        // Resolve browser package for same-browser display ONLY if the initiating app is a browser
        String targetBrowserPkg = null;
        if (isBrowserPackage(packageName)) {
            targetBrowserPkg = packageName;
            noteBrowserActivity(packageName);
        }

        // Prepare browser intent for block template
        Intent browserIntent = new Intent(Intent.ACTION_VIEW, Uri.parse(blockUrl));
        if (targetBrowserPkg != null) {
            browserIntent.setPackage(targetBrowserPkg);
            browserIntent.putExtra("com.android.browser.application_id", targetBrowserPkg);
        }
        browserIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);

        // Intent to view complete Firewall Block Details page
        Intent intent = new Intent(mContext, com.kotsafe.security.activities.FirewallBlockPageActivity.class);
        intent.putExtra("target", target);
        intent.putExtra("target_type", targetType);
        intent.putExtra("reason", reason);
        intent.putExtra("app_name", appName);
        intent.putExtra("package_name", packageName);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);

        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            flags |= PendingIntent.FLAG_IMMUTABLE;
        }
        PendingIntent pi = PendingIntent.getActivity(mContext, (int) (now & 0xFFFF), intent, flags);
        PendingIntent browserPi = PendingIntent.getActivity(mContext, (int) ((now + 1) & 0xFFFF), browserIntent, flags);

        // Display high-priority Heads-Up Notification with full-screen intent so the warning is UNMISSABLE
        String typeLabel = "Resource";
        if ("SITE".equalsIgnoreCase(targetType) || "DOMAIN".equalsIgnoreCase(targetType)) typeLabel = "Website";
        else if ("URL".equalsIgnoreCase(targetType)) typeLabel = "URL";
        else if ("IP".equalsIgnoreCase(targetType)) typeLabel = "IP Address";
        else if ("HASH".equalsIgnoreCase(targetType) || "FILE".equalsIgnoreCase(targetType)) typeLabel = "File";
        else if ("APP".equalsIgnoreCase(targetType)) typeLabel = "Application";

        String title = "🛑 " + typeLabel + " Blocked by Administrator";
        String body = target + " is blocked by your administrator. Tap to view warning or contact admin.";

        // Always use direct native FirewallBlockPageActivity alert (no 127.0.0.1 browser redirect)
        PendingIntent primaryPi = pi;

        // Note: FirewallBlockPageActivity will be opened when user taps the notification
        // Do not force background startActivity which disrupts the user.

        showFirewallNotification(CaptureService.NOTIFY_CHAN_MALWARE_DETECTION, title, body, primaryPi, pi, pi);
    }

    private void showFirewallNotification(String channelId, String title, String body,
                                          PendingIntent primaryIntent, PendingIntent browserPi, PendingIntent detailsPi) {
        try {
            NotificationManager nm = (NotificationManager)
                    mContext.getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm == null) return;

            NotificationCompat.Builder builder = new NotificationCompat.Builder(mContext, channelId)
                    .setSmallIcon(R.drawable.ic_shield)
                    .setContentTitle(title)
                    .setContentText(body)
                    .setStyle(new NotificationCompat.BigTextStyle().bigText(body))
                    .setPriority(NotificationCompat.PRIORITY_HIGH)
                    .setCategory(NotificationCompat.CATEGORY_STATUS)
                    .setOnlyAlertOnce(true)
                    .setAutoCancel(true);

            if (primaryIntent != null) {
                builder.setContentIntent(primaryIntent);
                // Do NOT set fullScreenIntent: Enterprise firewall drops must notify the user via notification tray,
                // never aggressively hijack or interrupt the active foreground application.
            }

            if (browserPi != null) {
                builder.addAction(R.drawable.ic_shield, "VIEW WARNING", browserPi);
            }
            if (detailsPi != null) {
                builder.addAction(R.drawable.ic_search, "UNBLOCK / DETAILS", detailsPi);
            }

            nm.notify(NOTIF_ID_FIREWALL_BLOCK, builder.build());
        } catch (Exception e) {
            Log.e(TAG, "showFirewallNotification error: " + e.getMessage());
        }
    }

    public boolean isBrowserPackage(String pkg) {
        if (pkg == null || pkg.isEmpty()) return false;
        String p = pkg.toLowerCase(java.util.Locale.US);
        if (p.contains("chrome") || p.contains("browser") || p.contains("firefox") ||
            p.contains("opera") || p.contains("duckduckgo") || p.contains("brave") ||
            p.contains("edge") || p.contains("vivaldi") || p.contains("kiwi") || p.contains("samsung")) {
            return true;
        }
        try {
            Intent testIntent = new Intent(Intent.ACTION_VIEW, Uri.parse("http://www.google.com"));
            PackageManager pm = mContext.getPackageManager();
            List<ResolveInfo> list = pm.queryIntentActivities(testIntent, PackageManager.MATCH_DEFAULT_ONLY);
            for (ResolveInfo info : list) {
                if (info.activityInfo != null && pkg.equals(info.activityInfo.packageName)) {
                    return true;
                }
            }
        } catch (Exception ignored) {}
        return false;
    }

    // ─── Internal ─────────────────────────────────────────────────────────────

    private void showNotification(String channelId, String title, String body,
                                   PendingIntent intent, boolean isFullScreen) {
        try {
            NotificationManager nm = (NotificationManager)
                    mContext.getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm == null) return;

            NotificationCompat.Builder builder = new NotificationCompat.Builder(mContext, channelId)
                    .setSmallIcon(R.drawable.ic_shield)
                    .setContentTitle(title)
                    .setContentText(body)
                    .setStyle(new NotificationCompat.BigTextStyle().bigText(body))
                    .setPriority(CHANNEL_ID_THREATS.equals(channelId)
                            ? NotificationCompat.PRIORITY_HIGH
                            : NotificationCompat.PRIORITY_DEFAULT)
                    .setOnlyAlertOnce(true)
                    .setAutoCancel(true);

            if (intent != null) builder.setContentIntent(intent);

            nm.notify(NOTIF_ID_FIREWALL_BLOCK, builder.build());
        } catch (Exception e) {
            Log.e(TAG, "showNotification error: " + e.getMessage());
        }
    }

    private PendingIntent buildOpenIntent(String packageName, String sha256, String verdict) {
        Intent i = new Intent(mContext, SmartScreenAlertActivity.class);
        i.putExtra("package_name", packageName);
        i.putExtra("sha256", sha256);
        i.putExtra("verdict", verdict);
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            flags |= PendingIntent.FLAG_IMMUTABLE;
        }
        return PendingIntent.getActivity(mContext, 4301, i, flags);
    }
}
