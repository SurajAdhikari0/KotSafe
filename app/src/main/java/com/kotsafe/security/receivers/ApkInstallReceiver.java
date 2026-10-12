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
 */

package com.kotsafe.security.receivers;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInstaller;
import android.widget.Toast;

import com.kotsafe.security.Log;

/**
 * BroadcastReceiver for handling completion of PackageInstaller sessions.
 * Handles user confirmation (STATUS_PENDING_USER_ACTION), success, and failures.
 */
public class ApkInstallReceiver extends BroadcastReceiver {
    private static final String TAG = "ApkInstallReceiver";
    public static final String ACTION_INSTALL_STATUS = "com.kotsafe.security.ACTION_APK_INSTALL_STATUS";
    public static final String EXTRA_STATUS = "install_status";
    public static final String EXTRA_MESSAGE = "install_message";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null) return;

        int status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE);
        String message = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE);

        // Notify active activity
        Intent statusBroadcast = new Intent(ACTION_INSTALL_STATUS);
        statusBroadcast.setPackage(context.getPackageName());
        statusBroadcast.putExtra(EXTRA_STATUS, status);
        statusBroadcast.putExtra(EXTRA_MESSAGE, message);
        context.sendBroadcast(statusBroadcast);

        switch (status) {
            case PackageInstaller.STATUS_PENDING_USER_ACTION:
                // Android requires user confirmation to proceed with installation.
                Intent confirmIntent;
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                    confirmIntent = intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent.class);
                } else {
                    confirmIntent = intent.getParcelableExtra(Intent.EXTRA_INTENT);
                }
                if (confirmIntent != null) {
                    confirmIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    context.startActivity(confirmIntent);
                }
                break;

            case PackageInstaller.STATUS_SUCCESS:
                Toast.makeText(context, "App installed successfully!", Toast.LENGTH_LONG).show();
                Log.d(TAG, "Package installed successfully");
                break;

            case PackageInstaller.STATUS_FAILURE:
            case PackageInstaller.STATUS_FAILURE_ABORTED:
            case PackageInstaller.STATUS_FAILURE_BLOCKED:
            case PackageInstaller.STATUS_FAILURE_CONFLICT:
            case PackageInstaller.STATUS_FAILURE_INCOMPATIBLE:
            case PackageInstaller.STATUS_FAILURE_INVALID:
            case PackageInstaller.STATUS_FAILURE_STORAGE:
                if (status != PackageInstaller.STATUS_FAILURE_ABORTED) {
                    String reason = (message != null && !message.isEmpty()) ? message : "Installation failed (code " + status + ")";
                    Toast.makeText(context, reason, Toast.LENGTH_LONG).show();
                }
                Log.w(TAG, "Install failed: status=" + status + ", message=" + message);
                break;
        }
    }
}
