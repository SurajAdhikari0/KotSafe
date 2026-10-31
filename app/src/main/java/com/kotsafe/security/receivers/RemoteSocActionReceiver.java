/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.receivers;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.os.Looper;
import android.widget.Toast;

import androidx.core.app.NotificationManagerCompat;

import com.kotsafe.security.Log;
import com.kotsafe.security.model.CloudSyncManager;
import com.kotsafe.security.model.SecurityNotificationHub;

/**
 * Handles actionable notifications for Remote Mobile SOC quarantine commands.
 * When desktop EDR reports suspicious C2 or process anomalies, tapping "Quarantine Workstation"
 * invokes this receiver to dispatch a network isolation command back to the workstation.
 */
public class RemoteSocActionReceiver extends BroadcastReceiver {
    private static final String TAG = "RemoteSocActionReceiver";

    public static final String ACTION_QUARANTINE = "com.kotsafe.security.action.QUARANTINE_WORKSTATION";
    public static final String ACTION_DISMISS = "com.kotsafe.security.action.DISMISS_SOC_ALERT";
    public static final String ACTION_SIMULATE_ALERT = "com.kotsafe.security.action.SIMULATE_SOC_ALERT";

    public static final String EXTRA_TARGET_DEVICE_ID = "extra_target_device_id";
    public static final String EXTRA_WORKSTATION_NAME = "extra_workstation_name";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (context == null || intent == null) return;
        String action = intent.getAction();
        Log.i(TAG, "onReceive action: " + action);

        if (ACTION_SIMULATE_ALERT.equals(action) || "com.kotsafe.security.SIMULATE_SOC_ALERT".equals(action)) {
            SecurityNotificationHub.getInstance(context).postRemoteSocThreatAlert(
                    "Kali Linux Workstation",
                    "desktop_sentinel_01",
                    "C2 Cobalt Strike Beacon Detected",
                    "Process 'powershell.exe' (PID 4812) initiated unauthorized outbound beacon to 185.220.101.5:443"
            );
            return;
        }

        // Always dismiss notification on tap
        NotificationManagerCompat.from(context).cancel(SecurityNotificationHub.NOTIF_ID_REMOTE_SOC_ALERT);

        if (ACTION_QUARANTINE.equals(action)) {
            String targetDeviceId = intent.getStringExtra(EXTRA_TARGET_DEVICE_ID);
            String workstationName = intent.getStringExtra(EXTRA_WORKSTATION_NAME);
            if (targetDeviceId == null || targetDeviceId.isEmpty()) {
                Log.w(TAG, "Cannot quarantine: targetDeviceId is empty");
                return;
            }

            Log.w(TAG, "🚨 Triggering emergency remote isolation for: " + targetDeviceId);
            CloudSyncManager sync = CloudSyncManager.getInstance(context);
            if (sync != null) {
                sync.dispatchRemoteDefenseCommand(
                        targetDeviceId,
                        "ISOLATE_WORKSTATION",
                        () -> {
                            new Handler(Looper.getMainLooper()).post(() ->
                                    Toast.makeText(context, "🔒 " + (workstationName != null ? workstationName : "Workstation") + " quarantined successfully!", Toast.LENGTH_LONG).show()
                            );
                        },
                        error -> {
                            new Handler(Looper.getMainLooper()).post(() ->
                                    Toast.makeText(context, "Failed to quarantine: " + error, Toast.LENGTH_SHORT).show()
                            );
                        }
                );
            }
        }
    }
}
