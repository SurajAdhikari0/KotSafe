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
 *
 * Copyright 2026 - KotSafe
 */

package com.kotsafe.security.model;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.os.Build;

import com.kotsafe.security.Log;
import com.kotsafe.security.Utils;
import com.kotsafe.security.services.BrowserAccessibilityService;

import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Orchestrator for API-Mode Passive Traffic Monitoring (Defender-style No-VPN Monitoring).
 * Automatically initializes and runs zero-permission monitors immediately on install,
 * and coordinates Usage Stats, Wi-Fi Security, and Browser Accessibility.
 */
public class ApiTrafficMonitorManager {
    private static final String TAG = "ApiTrafficMonMgr";
    private static volatile ApiTrafficMonitorManager sInstance;

    private final Context mContext;
    private final ExecutorService mExecutor;
    private final NetworkStatsUsageMonitor mUsageMonitor;
    private final WifiSecurityMonitor mWifiMonitor;
    private boolean mInitialized = false;

    public static ApiTrafficMonitorManager getInstance(Context context) {
        if (sInstance == null) {
            synchronized (ApiTrafficMonitorManager.class) {
                if (sInstance == null) {
                    sInstance = new ApiTrafficMonitorManager(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    private ApiTrafficMonitorManager(Context context) {
        mContext = context;
        mExecutor = Executors.newSingleThreadExecutor();
        mUsageMonitor = NetworkStatsUsageMonitor.getInstance(context);
        mWifiMonitor = WifiSecurityMonitor.getInstance(context);
    }

    public synchronized void initialize() {
        if (mInitialized) return;
        mInitialized = true;
        Log.i(TAG, "Initializing API-Mode Passive Protection Subsystem");

        // 1. Start NetworkStats polling if granted
        if (NetworkStatsUsageMonitor.hasUsageStatsPermission(mContext)) {
            mUsageMonitor.startMonitoring();
        }

        // 2. Register network change listener for Wi-Fi security checks
        try {
            ConnectivityManager cm = (ConnectivityManager) mContext.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                cm.registerDefaultNetworkCallback(new ConnectivityManager.NetworkCallback() {
                    @Override
                    public void onAvailable(Network network) {
                        mExecutor.execute(mWifiMonitor::checkCurrentWifiSecurity);
                    }
                });
            }
        } catch (Exception e) {
            Log.d(TAG, "NetworkCallback registration: " + e.getMessage());
        }

        // 3. Start Background Exfiltration Sentinel
        BackgroundExfiltrationSentinel.getInstance(mContext).start();

        // 4. Start Real-Time Download Folder Watcher
        DownloadFolderWatcher.getInstance(mContext).start();

        // 5. Trigger immediate zero-permission package static scan on background thread
        mExecutor.execute(this::runImmediatePackageScan);
    }

    /**
     * Immediate zero-permission PackageManager scan on installed applications.
     */
    public void runImmediatePackageScan() {
        try {
            PackageManager pm = mContext.getPackageManager();
            List<PackageInfo> packages = pm.getInstalledPackages(0);
            SecurityBlocklistManager secBl = SecurityBlocklistManager.getInstance(mContext);

            for (PackageInfo pi : packages) {
                if (Utils.classifyAppInstall(pi.applicationInfo) == Utils.AppInstallClass.SYSTEM) {
                    continue; // Skip system apps
                }

                String pkgName = pi.packageName;
                String appLabel = pi.applicationInfo.loadLabel(pm).toString();
                String apkPath = pi.applicationInfo.sourceDir;
                String sha256 = "";

                try {
                    File file = new File(apkPath);
                    if (file.exists() && file.canRead()) {
                        sha256 = calculateFileSha256(file);
                    }
                } catch (Exception ignored) {}

                boolean isBlocked = false;
                String threatName = null;

                if (secBl != null && !sha256.isEmpty()) {
                    if (secBl.isFastBlocked(sha256)) {
                        isBlocked = true;
                        threatName = "Known Malicious Hash (" + sha256.substring(0, 8) + ")";
                    } else if (secBl.isFastBlocked(pkgName)) {
                        isBlocked = true;
                        threatName = "Blacklisted Package";
                    }
                }

                TrafficDeduplicationParser.getInstance(mContext).onApiAppScanEvent(
                        pkgName,
                        appLabel,
                        sha256,
                        isBlocked,
                        threatName
                );
            }
        } catch (Exception e) {
            Log.e(TAG, "runImmediatePackageScan error: " + e.getMessage());
        }
    }

    private static String calculateFileSha256(File file) {
        try (FileInputStream fis = new FileInputStream(file)) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[8192];
            int read;
            while ((read = fis.read(buf)) != -1) {
                md.update(buf, 0, read);
            }
            byte[] digest = md.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    public boolean isBrowserProtectionActive() {
        return BrowserAccessibilityService.isAccessibilityServiceEnabled(mContext);
    }

    public boolean isUsageStatsActive() {
        return NetworkStatsUsageMonitor.hasUsageStatsPermission(mContext);
    }

    public boolean isWifiProtectionActive() {
        return WifiSecurityMonitor.hasLocationPermission(mContext);
    }
}
