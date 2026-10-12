package com.kotsafe.security.receivers;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import com.kotsafe.security.model.PhysicalSecurityManager;

public class SimStateReceiver extends BroadcastReceiver {
    private static final String TAG = "SimStateReceiver";

    @Override
    public void onReceive(Context context, Intent intent) {
        if ("android.intent.action.SIM_STATE_CHANGED".equals(intent.getAction())) {
            PhysicalSecurityManager manager = PhysicalSecurityManager.getInstance(context);
            if (manager.isSimSwapDetectionEnabled()) {
                Log.w(TAG, "SIM state changed while SIM-swap detection active!");
            }
        }
    }
}
