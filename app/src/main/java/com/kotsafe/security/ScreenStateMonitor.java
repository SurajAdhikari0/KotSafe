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

package com.kotsafe.security;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.PowerManager;

public class ScreenStateMonitor {
    private static final String TAG = "ScreenStateMonitor";
    private final Context mContext;
    private final ScreenStateListener mListener;
    private BroadcastReceiver mReceiver;
    private boolean mIsMonitoring = false;

    public interface ScreenStateListener {
        void onScreenStateChanged(boolean isScreenOn);
    }

    public ScreenStateMonitor(Context context, ScreenStateListener listener) {
        mContext = context.getApplicationContext();
        mListener = listener;
    }

    public synchronized void startMonitoring() {
        if (mIsMonitoring)
            return;

        mReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                if (intent == null)
                    return;

                String action = intent.getAction();
                if (Intent.ACTION_SCREEN_ON.equals(action)) {
                    Log.d(TAG, "Screen turned ON");
                    if (mListener != null)
                        mListener.onScreenStateChanged(true);
                } else if (Intent.ACTION_SCREEN_OFF.equals(action)) {
                    Log.d(TAG, "Screen turned OFF");
                    if (mListener != null)
                        mListener.onScreenStateChanged(false);
                }
            }
        };

        IntentFilter filter = new IntentFilter();
        filter.addAction(Intent.ACTION_SCREEN_ON);
        filter.addAction(Intent.ACTION_SCREEN_OFF);
        mContext.registerReceiver(mReceiver, filter);

        mIsMonitoring = true;
        Log.d(TAG, "Screen state monitoring started, initial isScreenOn=" + isScreenOn());
    }

    public synchronized void stopMonitoring() {
        if (!mIsMonitoring)
            return;

        if (mReceiver != null) {
            try {
                mContext.unregisterReceiver(mReceiver);
            } catch (IllegalArgumentException e) {
                Log.w(TAG, "Receiver not registered: " + e.getMessage());
            }
            mReceiver = null;
        }

        mIsMonitoring = false;
        Log.d(TAG, "Screen state monitoring stopped");
    }

    public boolean isScreenOn() {
        PowerManager pm = (PowerManager) mContext.getSystemService(Context.POWER_SERVICE);
        return (pm != null) && pm.isInteractive();
    }

    public boolean isMonitoring() {
        return mIsMonitoring;
    }
}
