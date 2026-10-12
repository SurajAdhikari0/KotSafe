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

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.os.Build;

import androidx.annotation.NonNull;

import com.kotsafe.security.model.NetworkType;
import com.kotsafe.security.model.WifiThreatDetector;
import java.util.concurrent.Executors;

/**
 * Monitors active network connection type (Wi-Fi, Cellular, Roaming).
 */
public class NetworkStateMonitor {
    private static final String TAG = "NetworkStateMonitor";

    private final Context mContext;
    private final ConnectivityManager mConnectivityManager;
    private final NetworkStateListener mListener;
    private ConnectivityManager.NetworkCallback mCallback;
    private NetworkType mCurrentType = NetworkType.NONE;
    private boolean mIsMonitoring = false;

    public interface NetworkStateListener {
        void onNetworkTypeChanged(NetworkType newType);
    }

    public NetworkStateMonitor(Context context, NetworkStateListener listener) {
        mContext = context.getApplicationContext();
        mConnectivityManager = (ConnectivityManager) mContext.getSystemService(Context.CONNECTIVITY_SERVICE);
        mListener = listener;
        mCurrentType = resolveCurrentNetworkType();
    }

    public synchronized void startMonitoring() {
        if (mIsMonitoring || mConnectivityManager == null)
            return;

        mCallback = new ConnectivityManager.NetworkCallback() {
            @Override
            public void onAvailable(@NonNull Network network) {
                checkAndUpdate();
                // Trigger Wi-Fi threat scan (Evil Twin + ARP Spoof) on every new network
                triggerWifiThreatScan();
            }

            @Override
            public void onCapabilitiesChanged(@NonNull Network network, @NonNull NetworkCapabilities capabilities) {
                checkAndUpdate();
            }

            @Override
            public void onLost(@NonNull Network network) {
                checkAndUpdate();
            }
        };

        try {
            NetworkRequest request = new NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .build();
            mConnectivityManager.registerNetworkCallback(request, mCallback);
            mIsMonitoring = true;
            Log.d(TAG, "Network state monitoring started, initial type: " + mCurrentType);
        } catch (Exception e) {
            Log.e(TAG, "Failed to register network callback: " + e.getMessage());
        }
    }

    public synchronized void stopMonitoring() {
        if (!mIsMonitoring || mConnectivityManager == null || mCallback == null)
            return;

        try {
            mConnectivityManager.unregisterNetworkCallback(mCallback);
        } catch (Exception e) {
            Log.e(TAG, "Failed to unregister network callback: " + e.getMessage());
        }
        mCallback = null;
        mIsMonitoring = false;
        Log.d(TAG, "Network state monitoring stopped");
    }

    public synchronized NetworkType getCurrentNetworkType() {
        return mCurrentType;
    }

    private synchronized void checkAndUpdate() {
        NetworkType newType = resolveCurrentNetworkType();
        if (newType != mCurrentType) {
            Log.i(TAG, "Network type changed: " + mCurrentType + " -> " + newType);
            mCurrentType = newType;
            if (mListener != null) {
                mListener.onNetworkTypeChanged(newType);
            }
        }
    }

    public NetworkType resolveCurrentNetworkType() {
        if (mConnectivityManager == null)
            return NetworkType.NONE;

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                Network active = mConnectivityManager.getActiveNetwork();
                if (active != null) {
                    NetworkCapabilities caps = mConnectivityManager.getNetworkCapabilities(active);
                    return networkTypeOf(caps);
                }
            }

            @SuppressWarnings("deprecation")
            Network[] all = mConnectivityManager.getAllNetworks();
            if (all != null) {
                for (Network n : all) {
                    NetworkCapabilities caps = mConnectivityManager.getNetworkCapabilities(n);
                    NetworkType t = networkTypeOf(caps);
                    if (t != NetworkType.NONE)
                        return t;
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error resolving network type: " + e.getMessage());
        }
        return NetworkType.NONE;
    }

    private NetworkType networkTypeOf(NetworkCapabilities caps) {
        if (caps == null)
            return NetworkType.NONE;

        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
            return NetworkType.WIFI;
        } else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
            if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING)) {
                return NetworkType.MOBILE;
            } else {
                return NetworkType.ROAMING;
            }
        }
        return NetworkType.NONE;
    }

    /**
     * Runs WifiThreatDetector off the main thread so it can do I/O
     * (/proc/net/arp read and WifiManager.getScanResults).
     */
    private void triggerWifiThreatScan() {
        final Context ctx = mContext;
        Executors.newSingleThreadExecutor().execute(() -> WifiThreatDetector.scan(ctx));
    }
}
