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
 * * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.os.ParcelFileDescriptor;
import android.os.PowerManager;
import android.os.RemoteException;

import androidx.annotation.NonNull;
import androidx.core.content.pm.PackageInfoCompat;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.interfaces.MitmListener;
import com.kotsafe.security.model.Prefs;
import com.kotsafe.security.mitm.MitmAPI;

import java.io.IOException;
import java.lang.ref.WeakReference;

public class MitmAddon {
    public static final long PACKAGE_VERSION_CODE = 26;
    public static final String PACKAGE_VERSION_NAME = "2.4";
    public static final String REPOSITORY = "https://github.com/CyberResercher/Kotsafe";
    private static final String TAG = "MitmAddon";
    private final Context mContext;
    private final MitmListener mReceiver;
    private final Messenger mMessenger;
    private Messenger mService;
    private boolean mStopRequested;

    public MitmAddon(Context ctx, MitmListener receiver) {
        // Important: the application context is required here, otherwise bind/unbind will not work properly
        mContext = ctx.getApplicationContext();
        mReceiver = receiver;
        mMessenger = new Messenger(new ReplyHandler(ctx.getMainLooper(), receiver));
    }

    private final ServiceConnection mConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName className, IBinder service) {
            Log.i(TAG, "Service connected");
            mService = new Messenger(service);

            if(mStopRequested)
                stopProxy();
            else
                mReceiver.onMitmServiceConnect();
        }

        @Override
        public void onServiceDisconnected(ComponentName className) {
            Log.i(TAG, "Service disconnected");
            disconnect(); // call unbind to prevent new connections
            mReceiver.onMitmServiceDisconnect();
        }

        @Override
        public void onBindingDied(ComponentName name) {
            Log.w(TAG, "onBindingDied");
            disconnect();
            mReceiver.onMitmServiceDisconnect();
        }

        @Override
        public void onNullBinding(ComponentName name) {
            Log.w(TAG, "onNullBinding");
            disconnect();
            mReceiver.onMitmServiceDisconnect();
        }
    };

    public static long getInstalledVersion(Context ctx) {
        try {
            PackageInfo pInfo = Utils.getPackageInfo(ctx.getPackageManager(), MitmAPI.PACKAGE_NAME, 0);
            return PackageInfoCompat.getLongVersionCode(pInfo);
        } catch (PackageManager.NameNotFoundException e) {
            return -1;
        }
    }

    public static @NonNull String getInstalledVersionName(Context ctx) {
        try {
            PackageInfo pInfo = Utils.getPackageInfo(ctx.getPackageManager(), MitmAPI.PACKAGE_NAME, 0);
            return pInfo.versionName;
        } catch (PackageManager.NameNotFoundException e) {
            return "";
        }
    }

    public static int getUid(Context ctx) {
        try {
            return Utils.getPackageUid(ctx.getPackageManager(), MitmAPI.PACKAGE_NAME, 0);
        } catch (PackageManager.NameNotFoundException e) {
            return -1;
        }
    }

    // Built-in in-app TLS decryption engine is always installed and up-to-date
    public static @NonNull String getNewVersionAvailable(Context ctx) {
        return "";
    }

    public static void ignoreNewVersion(Context ctx) {
    }

    // Built-in TLS decryption engine is always available
    public static boolean isInstalled(Context ctx) {
        return true;
    }

    public static String getGithubReleaseUrl(String version) {
        return REPOSITORY;
    }

    // Built-in TLS decryption is supported on all Android versions
    public static boolean isSupportedTarget() {
        return true;
    }

    public static void setCAInstallationSkipped(Context ctx, boolean skipped) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ctx);
        prefs.edit()
                .putBoolean(Prefs.PREF_CA_INSTALLATION_SKIPPED, skipped)
                .apply();
    }

    public static boolean isCAInstallationSkipped(Context ctx) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ctx);
        return prefs.getBoolean(Prefs.PREF_CA_INSTALLATION_SKIPPED, true);
    }

    public static void setDecryptionSetupDone(Context ctx, boolean done) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ctx);
        prefs.edit()
                .putBoolean(Prefs.PREF_TLS_DECRYPTION_SETUP_DONE, done)
                .apply();
    }

    public static boolean needsSetup(Context ctx) {
        // Built-in TLS decryption is fully automated, requiring zero manual setup or uploading
        return false;
    }

    private static class ReplyHandler extends Handler {
        private final WeakReference<MitmListener> mReceiver;

        ReplyHandler(Looper looper, MitmListener receiver) {
            super(looper);
            mReceiver = new WeakReference<>(receiver);
        }

        @Override
        public void handleMessage(@NonNull Message msg) {
            Log.d(TAG, "Message: " + msg.what);

            MitmListener receiver = mReceiver.get();
            if(receiver == null)
                return;

            if(msg.what == MitmAPI.MSG_GET_CA_CERTIFICATE) {
                String ca_pem = null;

                if(msg.getData() != null) {
                    Bundle res = msg.getData();
                    ca_pem = res.getString(MitmAPI.CERTIFICATE_RESULT);
                }

                receiver.onMitmGetCaCertificateResult(ca_pem);
            }
        }
    }

    private boolean mConnected = false;

    // Asynchronously connect to the service. The onConnect callback will be called.
    public boolean connect(int extra_flags) {
        mConnected = true;
        new Handler(Looper.getMainLooper()).post(() -> {
            if(mReceiver != null)
                mReceiver.onMitmServiceConnect();
        });
        return true;
    }

    // This must be always called after connect, e.g. in the OnDestroy
    public void disconnect() {
        mConnected = false;
        if(mService != null) {
            Log.i(TAG, "Unbinding service...");
            try {
                mContext.unbindService(mConnection);
            } catch (IllegalArgumentException ignored) {
                Log.w(TAG, "unbindService failed");
            }
            mService = null;
        }
    }

    public boolean isConnected() {
        return mConnected;
    }

    public boolean requestCaCertificate() {
        new Thread(() -> {
            String ca_pem = com.kotsafe.security.tls.TlsCaManager.getInstance(mContext).getCaCertificatePem();
            new Handler(Looper.getMainLooper()).post(() -> {
                if(mReceiver != null)
                    mReceiver.onMitmGetCaCertificateResult(ca_pem);
            });
        }, "CA-Gen-Thread").start();
        return true;
    }

    // Start the mitm proxy and returns a ParcelFileDescriptor for the data communication.
    // The proxy can be stopped by closing the descriptor and then calling disconnect().
    public ParcelFileDescriptor startProxy(MitmAPI.MitmConfig conf) {
        if(mService == null) {
            Log.e(TAG, "Not connected");
            return null;
        }

        ParcelFileDescriptor[] pair;
        try {
            pair = ParcelFileDescriptor.createReliableSocketPair();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

        // Note: ParcelFileDescriptor must be passed as parcelable
        Message msg = Message.obtain(null, MitmAPI.MSG_START_MITM, 0, 0, pair[0]);

        Bundle bundle = new Bundle();
        bundle.putSerializable(MitmAPI.MITM_CONFIG, conf);
        msg.setData(bundle);

        try {
            mService.send(msg);
        } catch (RemoteException | NullPointerException e) {
            e.printStackTrace();
            Utils.safeClose(pair[0]);
            Utils.safeClose(pair[1]);
            return null;
        }

        // The other end of the pipe is sent, close it locally
        Utils.safeClose(pair[0]);

        return pair[1];
    }

    public boolean stopProxy() {
        if(mService == null) {
            Log.i(TAG, "Not connected, postponing stop message");
            mStopRequested = true;
            return true;
        }

        Log.i(TAG, "Send stop message");
        Message msg = Message.obtain(null, MitmAPI.MSG_STOP_MITM);
        try {
            mService.send(msg);
            mStopRequested = false;
            return true;
        } catch (RemoteException e) {
            e.printStackTrace();
            return false;
        }
    }

    // NOTE: doze could be disabled by KotSafe itself, however this is moved to the addon to avoid
    // any issues with the REQUEST_IGNORE_BATTERY_OPTIMIZATIONS Google Play policies
    public boolean disableDoze() {
        if(mService == null)
            return false;

        Log.i(TAG, "Send disable doze");
        Message msg = Message.obtain(null, MitmAPI.MSG_DISABLE_DOZE);
        try {
            mService.send(msg);
            return true;
        } catch (RemoteException e) {
            e.printStackTrace();
            return false;
        }
    }

    public static boolean isDozeEnabled(Context context) {
        final PowerManager manager = (PowerManager) context.getSystemService(Context.POWER_SERVICE);

        return (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) && (manager != null)
                && !manager.isIgnoringBatteryOptimizations(MitmAPI.PACKAGE_NAME);
    }
}
