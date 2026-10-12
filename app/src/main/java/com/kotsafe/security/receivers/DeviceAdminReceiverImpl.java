package com.kotsafe.security.receivers;

import android.app.admin.DeviceAdminReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;
import android.widget.Toast;

import androidx.annotation.NonNull;

public class DeviceAdminReceiverImpl extends DeviceAdminReceiver {
    private static final String TAG = "DeviceAdminReceiver";

    @Override
    public void onEnabled(@NonNull Context context, @NonNull Intent intent) {
        super.onEnabled(context, intent);
        Log.i(TAG, "Device Admin Privileges Enabled");
        Toast.makeText(context, "Anti-Theft Device Admin Protection Enabled", Toast.LENGTH_SHORT).show();
    }

    @Override
    public void onDisabled(@NonNull Context context, @NonNull Intent intent) {
        super.onDisabled(context, intent);
        Log.w(TAG, "Device Admin Privileges Disabled");
        Toast.makeText(context, "Anti-Theft Device Admin Protection Disabled", Toast.LENGTH_SHORT).show();
    }
}
