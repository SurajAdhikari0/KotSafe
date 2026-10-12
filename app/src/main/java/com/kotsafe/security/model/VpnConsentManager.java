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
import android.net.VpnService;
import android.os.Build;
import android.provider.Settings;

import androidx.core.app.NotificationCompat;

import com.kotsafe.security.CaptureService;
import com.kotsafe.security.R;
import com.kotsafe.security.activities.MainActivity;
import com.kotsafe.security.model.ScanModeConfig.CaptureState;

/**
 * Manages VPN consent state, Always-on VPN checks, and degraded telemetry warnings.
 */
public class VpnConsentManager {
    private static final String CHANNEL_ID = "vpn_degraded_status";
    private static final int NOTIFICATION_ID = 4091;

    /**
     * Determines the current network capture telemetry state.
     */
    public static CaptureState getCaptureState(Context context) {
        if (CaptureService.isServiceActive()) {
            return CaptureState.VPN_ACTIVE;
        }

        Intent prepareIntent = null;
        try {
            prepareIntent = VpnService.prepare(context);
        } catch (Exception e) {
            e.printStackTrace();
        }

        if (prepareIntent != null) {
            return CaptureState.VPN_CONSENT_REQUIRED;
        }

        // If prepared but inactive, check if aggregate stats or standby
        return CaptureState.AGGREGATE_STATS_ONLY;
    }

    /**
     * Checks if real-time per-packet C2 inspection is degraded.
     */
    public static boolean isRealTimeProtectionDegraded(Context context) {
        return getCaptureState(context) != CaptureState.VPN_ACTIVE;
    }

    /**
     * Posts a degraded inspection warning notification when real-time VPN capture
     * is inactive after a reboot or external VPN takeover.
     */
    public static void postDegradedStatusNotification(Context context) {
        NotificationManager nm = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm == null) return;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    context.getString(R.string.protection_status),
                    NotificationManager.IMPORTANCE_HIGH
            );
            channel.setDescription("Alerts when real-time network inspection is degraded");
            nm.createNotificationChannel(channel);
        }

        Intent openAppIntent = new Intent(context, MainActivity.class);
        openAppIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent pi = PendingIntent.getActivity(
                context,
                0,
                openAppIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M ? PendingIntent.FLAG_IMMUTABLE : 0)
        );

        NotificationCompat.Builder builder = new NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(context.getString(R.string.status_degraded))
                .setContentText(context.getString(R.string.vpn_degraded_body))
                .setStyle(new NotificationCompat.BigTextStyle().bigText(context.getString(R.string.vpn_degraded_body)))
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setAutoCancel(true)
                .setContentIntent(pi);

        nm.notify(NOTIFICATION_ID, builder.build());
    }

    /**
     * Creates an Intent to navigate directly to system VPN Settings
     * so the user can enable "Always-on VPN".
     */
    public static Intent getAlwaysOnVpnSettingsIntent() {
        return new Intent(Settings.ACTION_VPN_SETTINGS);
    }
}
