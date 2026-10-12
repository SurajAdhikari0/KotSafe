/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.content.Intent;

import androidx.appcompat.app.AlertDialog;

import com.kotsafe.security.CaptureService;
import com.kotsafe.security.R;
import com.kotsafe.security.activities.MainActivity;

/**
 * Utility helper to check VPN state and prompt users when a feature
 * (e.g. firewall blocking, live connection monitoring) requires the VPN service.
 */
public class VpnAlertHelper {
    public static final String EXTRA_REQUEST_START_VPN = "com.kotsafe.security.REQUEST_START_VPN";

    /**
     * Returns true if the VPN / CaptureService is actively running.
     */
    public static boolean isVpnActive() {
        return CaptureService.isServiceActive();
    }

    /**
     * Displays an educational alert dialog informing the user that the VPN
     * must be running for live packet interception and firewall enforcement.
     *
     * @param context       Activity context
     * @param featureName   e.g. "Firewall Blocking", "Network Access Control"
     * @param explanation   Contextual description of the current action
     */
    public static void showVpnRequiredDialog(Context context, String featureName, String explanation) {
        if (context == null) return;

        new AlertDialog.Builder(context)
                .setTitle("VPN Required for " + featureName)
                .setMessage(explanation + "\n\n" +
                        "KotSafe uses an Android VPN service to filter packets and enforce firewall blocks. " +
                        "Security scanning and your rules database work offline, but live blocking and real-time capture " +
                        "require the VPN to be turned on.")
                .setIcon(R.drawable.ic_shield)
                .setPositiveButton("Turn On VPN", (dialog, which) -> {
                    openHomeToStartVpn(context);
                })
                .setNegativeButton("Dismiss", null)
                .show();
    }

    /**
     * Launches MainActivity and requests starting the VPN capture.
     */
    public static void openHomeToStartVpn(Context context) {
        if (context == null) return;
        Intent intent = new Intent(context, MainActivity.class);
        intent.putExtra(EXTRA_REQUEST_START_VPN, true);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        context.startActivity(intent);
    }
}
