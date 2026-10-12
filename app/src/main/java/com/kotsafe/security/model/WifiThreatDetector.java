/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * WifiThreatDetector
 * ==================
 * Detects Wi-Fi Evil Twin and ARP Spoofing attacks.
 *
 * THREAT 1 - Evil Twin / Rogue AP
 * --------------------------------
 * An attacker broadcasts a duplicate SSID with:
 *   - A different BSSID (MAC address) than the legitimate AP
 *   - A weaker/absent security suite (e.g. WPA2 → Open)
 *   - Higher signal strength to force the device to connect
 *
 * Detection: We cache {SSID -> {BSSID, security_caps}} across connections.
 * If the BSSID or security mode changes unexpectedly on a known SSID, alert.
 *
 * THREAT 2 - ARP Cache Poisoning
 * --------------------------------
 * An attacker on the LAN sends gratuitous ARP replies associating their MAC
 * address with the default gateway IP, routing all victim traffic through them.
 *
 * Detection: We read /proc/net/arp to find the gateway MAC at connection time,
 * then poll for MAC changes within the same session.
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.net.ConnectivityManager;
import android.net.DhcpInfo;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;

import androidx.preference.PreferenceManager;

import com.kotsafe.security.Log;
import com.kotsafe.security.security.event.EventTypes;
import com.kotsafe.security.security.event.SecurityEvent;
import com.kotsafe.security.security.event.SecurityEventBus;

import java.io.BufferedReader;
import java.io.FileReader;
import java.net.InetAddress;
import java.util.List;

/**
 * Upgraded replacement/companion for {@link WifiSecurityMonitor}.
 * Call {@link #scan(Context)} whenever the device connects to a new Wi-Fi network
 * (e.g. from NetworkStateMonitor).
 */
public final class WifiThreatDetector {

    private static final String TAG = "WifiThreatDetector";

    // SharedPreference keys for persisting the trusted BSSID per SSID
    private static final String PREF_PREFIX_BSSID    = "wifitd_bssid_";
    private static final String PREF_PREFIX_CAPS     = "wifitd_caps_";
    private static final String PREF_PREFIX_GW_MAC   = "wifitd_gwmac_";

    private WifiThreatDetector() {}

    /**
     * Main entry point. Runs both Evil-Twin and ARP-spoof checks for the
     * currently connected Wi-Fi network.
     *
     * Should be called off the main thread (performs I/O).
     */
    public static void scan(Context context) {
        try {
            WifiManager wm = (WifiManager)
                    context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            ConnectivityManager cm = (ConnectivityManager)
                    context.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (wm == null || cm == null) return;

            Network activeNet = cm.getActiveNetwork();
            if (activeNet == null) return;
            NetworkCapabilities caps = cm.getNetworkCapabilities(activeNet);
            if (caps == null || !caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return;

            WifiInfo info = null;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && caps.getTransportInfo() instanceof WifiInfo) {
                info = (WifiInfo) caps.getTransportInfo();
            }
            if (info == null) {
                info = wm.getConnectionInfo();
            }
            if (info == null) return;

            String ssid = sanitizeSsid(info.getSSID());
            String bssid = info.getBSSID();
            if (ssid == null || ssid.isEmpty() || "<unknown ssid>".equalsIgnoreCase(ssid)) return;
            if (bssid == null || bssid.equals("02:00:00:00:00:00")) return;

            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);

            // ──────────────────────────────────────────────────────────────
            // CHECK 1: Evil Twin — BSSID / Security-suite change on known SSID
            // ──────────────────────────────────────────────────────────────
            String secCaps = getSecurityCaps(wm, bssid, ssid);
            String savedBssid = prefs.getString(PREF_PREFIX_BSSID + ssid, null);
            String savedCaps  = prefs.getString(PREF_PREFIX_CAPS  + ssid, null);

            if (savedBssid == null) {
                // First time we've seen this SSID — save as trusted baseline
                prefs.edit()
                        .putString(PREF_PREFIX_BSSID + ssid, bssid)
                        .putString(PREF_PREFIX_CAPS  + ssid, secCaps)
                        .apply();
                Log.i(TAG, "Saved baseline for SSID '" + ssid + "': BSSID=" + bssid + " caps=" + secCaps);
            } else {
                boolean bssidChanged = !savedBssid.equalsIgnoreCase(bssid);
                boolean capsWeakened = isWeakerSecurity(savedCaps, secCaps);

                if (bssidChanged || capsWeakened) {
                    String detail = "";
                    if (bssidChanged) detail += "BSSID changed: " + savedBssid + " → " + bssid + ". ";
                    if (capsWeakened) detail += "Security weakened: " + savedCaps + " → " + secCaps + ". ";

                    Log.e(TAG, "EVIL TWIN DETECTED for SSID '" + ssid + "': " + detail);

                    SecurityEvent ev = new SecurityEvent.Builder(
                                SecurityEvent.Domain.NETWORK, EventTypes.WIFI_EVIL_TWIN)
                            .severity(SecurityEvent.Severity.CRITICAL)
                            .title("⚠\uFE0F Evil Twin AP Detected: " + ssid)
                            .description(
                                "The Wi-Fi network '" + ssid + "' appears to be an impersonation "
                                + "by a rogue access point. " + detail
                                + "Do NOT transmit sensitive data. Disconnect immediately.")
                            .attribute("ssid",       ssid)
                            .attribute("bssid_now",  bssid)
                            .attribute("bssid_prev", savedBssid)
                            .attribute("caps_now",   secCaps)
                            .attribute("caps_prev",  savedCaps)
                            .build();

                    SecurityEventBus.getInstance().publish(ev);

                    // Update saved baseline to new observed state
                    prefs.edit()
                            .putString(PREF_PREFIX_BSSID + ssid, bssid)
                            .putString(PREF_PREFIX_CAPS  + ssid, secCaps)
                            .apply();
                }
            }

            // ──────────────────────────────────────────────────────────────
            // CHECK 2: ARP Cache Poisoning — gateway MAC consistency
            // ──────────────────────────────────────────────────────────────
            DhcpInfo dhcp = wm.getDhcpInfo();
            if (dhcp != null && dhcp.gateway != 0) {
                String gatewayIp = intToIp(dhcp.gateway);
                String currentMac = getArpMac(gatewayIp);
                if (currentMac != null) {
                    String savedGwMac = prefs.getString(PREF_PREFIX_GW_MAC + ssid + "_" + bssid, null);
                    if (savedGwMac == null) {
                        prefs.edit()
                                .putString(PREF_PREFIX_GW_MAC + ssid + "_" + bssid, currentMac)
                                .apply();
                        Log.i(TAG, "Saved gateway MAC for [" + ssid + "]: " + gatewayIp + " → " + currentMac);
                    } else if (!savedGwMac.equalsIgnoreCase(currentMac)) {
                        Log.e(TAG, "ARP SPOOF DETECTED on [" + ssid + "]: gateway " + gatewayIp
                                + " MAC changed " + savedGwMac + " → " + currentMac);

                        SecurityEvent ev = new SecurityEvent.Builder(
                                    SecurityEvent.Domain.NETWORK, EventTypes.WIFI_ARP_SPOOF)
                                .severity(SecurityEvent.Severity.CRITICAL)
                                .title("\uD83D\uDD34 ARP Spoofing Detected on " + ssid)
                                .description(
                                    "The MAC address of your default gateway (" + gatewayIp
                                    + ") has changed unexpectedly from " + savedGwMac
                                    + " to " + currentMac + ". "
                                    + "This indicates an active Man-in-the-Middle ARP poisoning attack.")
                                .attribute("ssid",       ssid)
                                .attribute("gateway_ip", gatewayIp)
                                .attribute("mac_prev",   savedGwMac)
                                .attribute("mac_now",    currentMac)
                                .build();

                        SecurityEventBus.getInstance().publish(ev);

                        // Update saved MAC to current observed value
                        prefs.edit()
                                .putString(PREF_PREFIX_GW_MAC + ssid + "_" + bssid, currentMac)
                                .apply();
                    }
                }
            }

        } catch (Exception e) {
            Log.d(TAG, "scan error: " + e.getMessage());
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────────────────

    private static String sanitizeSsid(String raw) {
        if (raw == null) return "";
        if (raw.startsWith("\"") && raw.endsWith("\"") && raw.length() > 1)
            return raw.substring(1, raw.length() - 1);
        return raw;
    }

    /** Returns the security capability string for the currently connected BSSID. */
    @android.annotation.SuppressLint("MissingPermission")
    private static String getSecurityCaps(WifiManager wm, String bssid, String ssid) {
        try {
            List<ScanResult> results = wm.getScanResults();
            if (results != null) {
                for (ScanResult r : results) {
                    if (bssid.equalsIgnoreCase(r.BSSID) || ssid.equalsIgnoreCase(r.SSID)) {
                        return r.capabilities != null ? r.capabilities.toUpperCase() : "UNKNOWN";
                    }
                }
            }
        } catch (Exception ignored) {}
        return "UNKNOWN";
    }

    /**
     * Returns true when the new security suite is weaker than the saved baseline
     * (e.g. was WPA2 and is now OPEN).
     */
    private static boolean isWeakerSecurity(String saved, String current) {
        if (saved == null || current == null) return false;
        boolean savedHadEncryption = saved.contains("WPA") || saved.contains("SAE")
                || saved.contains("WEP") || saved.contains("EAP");
        boolean currentHasEncryption = current.contains("WPA") || current.contains("SAE")
                || current.contains("WEP") || current.contains("EAP");
        return savedHadEncryption && !currentHasEncryption;
    }

    /**
     * Reads /proc/net/arp to find the MAC address for a given IP.
     * Returns null if the IP is not found or the file is unreadable.
     */
    private static String getArpMac(String ip) {
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/net/arp"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.trim().split("\\s+");
                // Format: IP, HW type, Flags, HW address, Mask, Device
                if (parts.length >= 4 && parts[0].equals(ip)) {
                    String mac = parts[3];
                    // Skip invalid/incomplete entries
                    if (mac.equals("00:00:00:00:00:00") || mac.equals("*")) continue;
                    return mac.toLowerCase();
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    /** Converts a little-endian int IP (as returned by DhcpInfo) to a dotted string. */
    private static String intToIp(int ip) {
        return  (ip & 0xFF) + "."
              + ((ip >> 8)  & 0xFF) + "."
              + ((ip >> 16) & 0xFF) + "."
              + ((ip >> 24) & 0xFF);
    }
}
