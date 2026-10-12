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

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;

import androidx.core.content.ContextCompat;

import com.kotsafe.security.Log;

import java.util.List;

/**
 * Passive Wi-Fi Security Monitor (API Mode).
 * Inspects connected wireless networks to detect unencrypted / open APs, weak WEP security,
 * and potential rogue AP man-in-the-middle threats.
 */
public class WifiSecurityMonitor {
    private static final String TAG = "WifiSecurityMonitor";
    private static volatile WifiSecurityMonitor sInstance;

    private final Context mContext;
    private String mLastCheckedSsid = "";
    private long mLastCheckTime = 0;

    public static WifiSecurityMonitor getInstance(Context context) {
        if (sInstance == null) {
            synchronized (WifiSecurityMonitor.class) {
                if (sInstance == null) {
                    sInstance = new WifiSecurityMonitor(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    private WifiSecurityMonitor(Context context) {
        mContext = context;
    }

    public static boolean hasLocationPermission(Context context) {
        boolean fine = ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED;
        boolean coarse = ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED;
        if (fine || coarse) return true;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return ContextCompat.checkSelfPermission(context, Manifest.permission.NEARBY_WIFI_DEVICES) == PackageManager.PERMISSION_GRANTED;
        }
        return false;
    }

    public static boolean isLocationServiceEnabled(Context context) {
        try {
            android.location.LocationManager lm = (android.location.LocationManager) context.getSystemService(Context.LOCATION_SERVICE);
            if (lm == null) return false;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                return lm.isLocationEnabled();
            } else {
                return lm.isProviderEnabled(android.location.LocationManager.GPS_PROVIDER) ||
                       lm.isProviderEnabled(android.location.LocationManager.NETWORK_PROVIDER);
            }
        } catch (Exception e) {
            return false;
        }
    }

    public static String getActiveNetworkType(Context context) {
        try {
            ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) return "none";
            Network activeNetwork = cm.getActiveNetwork();
            if (activeNetwork == null) return "none";
            NetworkCapabilities caps = cm.getNetworkCapabilities(activeNetwork);
            if (caps == null) return "none";
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return "wifi";
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) return "cellular";
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) return "ethernet";
        } catch (Exception ignored) {}
        return "none";
    }

    public static String getCarrierName(Context context) {
        try {
            android.telephony.TelephonyManager tm = (android.telephony.TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
            if (tm != null) {
                String name = tm.getNetworkOperatorName();
                if (name != null && !name.trim().isEmpty()) return name.trim();
                name = tm.getSimOperatorName();
                if (name != null && !name.trim().isEmpty()) return name.trim();
            }
        } catch (Exception ignored) {}
        return "Mobile Cellular";
    }

    /**
     * Inspects active network for Wi-Fi vulnerabilities.
     */
    @android.annotation.SuppressLint("MissingPermission")
    public void checkCurrentWifiSecurity() {
        try {
            ConnectivityManager cm = (ConnectivityManager) mContext.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) return;

            Network activeNetwork = cm.getActiveNetwork();
            if (activeNetwork == null) return;

            NetworkCapabilities caps = cm.getNetworkCapabilities(activeNetwork);
            if (caps == null || !caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                return; // Not on Wi-Fi
            }

            WifiManager wm = (WifiManager) mContext.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            if (wm == null) return;

            WifiInfo wifiInfo = null;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && caps.getTransportInfo() instanceof WifiInfo) {
                wifiInfo = (WifiInfo) caps.getTransportInfo();
            }
            if (wifiInfo == null) {
                wifiInfo = wm.getConnectionInfo();
            }
            if (wifiInfo == null) return;

            String ssid = wifiInfo.getSSID();
            if (ssid != null && ssid.startsWith("\"") && ssid.endsWith("\"")) {
                ssid = ssid.substring(1, ssid.length() - 1);
            }
            if (ssid == null || ssid.isEmpty() || "<unknown ssid>".equalsIgnoreCase(ssid)) {
                ssid = "Active Wi-Fi Network";
            }

            String bssid = wifiInfo.getBSSID();
            if (bssid == null) bssid = "00:00:00:00:00:00";

            long now = System.currentTimeMillis();
            if (ssid.equalsIgnoreCase(mLastCheckedSsid) && (now - mLastCheckTime < 120_000L)) {
                return; // Rate limit checks to once every 2 minutes for same SSID
            }
            mLastCheckedSsid = ssid;
            mLastCheckTime = now;

            String securityType = "WPA2/WPA3";
            boolean isInsecure = false;
            String threatDetails = "";

            if (hasLocationPermission(mContext)) {
                List<ScanResult> scanResults = null;
                try {
                    scanResults = wm.getScanResults();
                } catch (SecurityException ignored) {}
                if (scanResults != null) {
                    for (ScanResult sr : scanResults) {
                        if (bssid.equalsIgnoreCase(sr.BSSID) || ssid.equalsIgnoreCase(sr.SSID)) {
                            String capsStr = sr.capabilities != null ? sr.capabilities.toUpperCase() : "";
                            if (!capsStr.contains("WPA") && !capsStr.contains("WEP") && !capsStr.contains("EAP") && !capsStr.contains("SAE")) {
                                isInsecure = true;
                                securityType = "OPEN / UNENCRYPTED";
                                threatDetails = "Connected to an open unencrypted Wi-Fi network. Traffic may be intercepted via eavesdropping or rogue AP MITM.";
                            } else if (capsStr.contains("WEP")) {
                                isInsecure = true;
                                securityType = "WEP (DEPRECATED / WEAK)";
                                threatDetails = "Connected to network using obsolete WEP cipher. Easily cracked in seconds by nearby attackers.";
                            }
                            break;
                        }
                    }
                }
            }

            // Also check for captive portal detection
            if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL)) {
                isInsecure = true;
                threatDetails = (threatDetails.isEmpty() ? "" : threatDetails + " ") + "Captive portal interception detected.";
            }

            if (isInsecure) {
                Log.w(TAG, "Wi-Fi Security Warning: [" + ssid + "] " + threatDetails);
                TrafficDeduplicationParser.getInstance(mContext).onApiWifiSecurityEvent(
                        ssid,
                        bssid,
                        securityType,
                        threatDetails
                );
            }
        } catch (Exception e) {
            Log.d(TAG, "checkCurrentWifiSecurity: " + e.getMessage());
        }
    }
}
