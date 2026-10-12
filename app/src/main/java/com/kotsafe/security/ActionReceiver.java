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

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

import androidx.core.app.NotificationManagerCompat;

import android.os.Build;

import com.kotsafe.security.model.AppDescriptor;
import com.kotsafe.security.model.Blocklist;

import com.kotsafe.security.model.AntivirusScanEngine;
import com.kotsafe.security.model.NetworkSecurityMonitor;
import com.kotsafe.security.model.Prefs;
import com.kotsafe.security.services.AntivirusScanService;

import java.io.File;

public class ActionReceiver extends BroadcastReceiver {
    public static final String EXTRA_UNBLOCK_APP = "unblock_app";
    public static final String ACTION_SIMULATE_ATTACK = BuildConfig.APPLICATION_ID + ".SIMULATE_ATTACK";
    public static final String ACTION_SIMULATE_ATTACK_LEGACY = "com.kotsafe.security.SIMULATE_ATTACK";
    public static final String ACTION_DISMISS_THREATS = BuildConfig.APPLICATION_ID + ".DISMISS_THREATS";
    public static final String ACTION_SET_PAIRING = BuildConfig.APPLICATION_ID + ".SET_PAIRING";
    public static final String ACTION_SET_PAIRING_LEGACY = "com.kotsafe.security.SET_PAIRING";
    public static final String ACTION_START_EXIT_NODE = BuildConfig.APPLICATION_ID + ".ACTION_START_EXIT_NODE";
    public static final String ACTION_START_EXIT_NODE_LEGACY = "com.kotsafe.security.ACTION_START_EXIT_NODE";
    public static final String ACTION_STOP_EXIT_NODE = BuildConfig.APPLICATION_ID + ".ACTION_STOP_EXIT_NODE";
    public static final String ACTION_STOP_EXIT_NODE_LEGACY = "com.kotsafe.security.ACTION_STOP_EXIT_NODE";
    public static final String EXTRA_IS_EXIT = "extra_is_exit";
    public static final String EXTRA_TOKEN = "extra_token";
    public static final String EXTRA_BUNDLE = "extra_bundle";
    private static final String TAG = "ActionReceiver";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null) return;
        String action = intent.getAction();

        if (ACTION_SET_PAIRING.equals(action) || ACTION_SET_PAIRING_LEGACY.equals(action)) {
            String token = intent.getStringExtra(EXTRA_TOKEN);
            String bundle = intent.getStringExtra(EXTRA_BUNDLE);
            boolean isExit = intent.getBooleanExtra(EXTRA_IS_EXIT, false);
            if (token != null && !token.isEmpty()) {
                android.content.SharedPreferences prefs = androidx.preference.PreferenceManager.getDefaultSharedPreferences(context);
                android.content.SharedPreferences.Editor edit = prefs.edit()
                        .putString(Prefs.PREF_P2P_BACKEND_PAIRING, token);

                if (isExit) {
                    edit.putBoolean(com.kotsafe.security.p2p.GatewayPreferenceKeys.EXIT_ENABLED, true)
                        .putBoolean(com.kotsafe.security.p2p.GatewayPreferenceKeys.CLIENT_ENABLED, false)
                        .putBoolean(Prefs.PREF_SOCKS5_ENABLED_KEY, false);
                } else {
                    edit.putBoolean(com.kotsafe.security.p2p.GatewayPreferenceKeys.CLIENT_ENABLED, true)
                        .putBoolean(com.kotsafe.security.p2p.GatewayPreferenceKeys.EXIT_ENABLED, false)
                        .putBoolean(Prefs.PREF_SOCKS5_ENABLED_KEY, true)
                        .putString(Prefs.PREF_SOCKS5_PROXY_IP_KEY, "127.0.0.1")
                        .putString(Prefs.PREF_SOCKS5_PROXY_HOST_KEY, "127.0.0.1")
                        .putString(Prefs.PREF_SOCKS5_PROXY_PORT_KEY, "8095")
                        .putBoolean(Prefs.PREF_SOCKS5_AUTH_ENABLED_KEY, false)
                        .putString(Prefs.PREF_BLOCK_QUIC, Prefs.BLOCK_QUIC_MODE_ALWAYS)
                        .putString(Prefs.PREF_IP_MODE, Prefs.IP_MODE_BOTH);
                }

                if (bundle != null && !bundle.isEmpty()) {
                    edit.putString(com.kotsafe.security.p2p.GatewayPreferenceKeys.PAIRING_BUNDLE, bundle);
                    try {
                        com.kotsafe.security.p2p.SecurePairingBundle parsed =
                                com.kotsafe.security.p2p.SecurePairingBundle.parse(bundle);
                        if (parsed != null && parsed.controlUrl != null && !parsed.controlUrl.isEmpty()) {
                            if (com.kotsafe.security.model.backend.BackendProviderFactory.isRelayEndpoint(parsed.controlUrl)) {
                                edit.putString("personal_gateway_relay_mode", parsed.controlUrl.contains("trycloudflare.com") ? "cloudflare_tunnel" : "direct_vps");
                            } else {
                                edit.putString("personal_gateway_relay_mode", "custom");
                                edit.putString("personal_gateway_custom_relay_url", parsed.controlUrl);
                            }
                            com.kotsafe.security.model.backend.BackendProviderFactory.invalidateCache();
                        }
                        com.kotsafe.security.model.backend.CustomHttpProvider.configureCipher(parsed.room, parsed.pairingSecret);
                        if (!isExit) {
                            String profName = "Exit Node (" + (parsed.room.length() > 8 ? parsed.room.substring(0, 8) : parsed.room) + ")";
                            com.kotsafe.security.p2p.GatewayProfile prof = new com.kotsafe.security.p2p.GatewayProfile(
                                    "prof_" + System.currentTimeMillis(), profName, bundle, token, System.currentTimeMillis());
                            com.kotsafe.security.p2p.GatewayProfileManager.saveProfile(context, prof);
                            com.kotsafe.security.p2p.GatewayProfileManager.setActiveProfile(context, prof);
                        }
                    } catch (Exception ignored) {}
                }
                edit.commit();
                Log.i(TAG, "Pairing token and configuration saved (isExit=" + isExit + "): " + token);

                if (isExit) {
                    CaptureService.updateSocks5Proxy(null, 0);
                    com.kotsafe.security.model.backend.CustomHttpProvider.resetAllConnections();
                    com.kotsafe.security.model.P2PExitNodeService.start(context);
                    com.kotsafe.security.model.P2PExitNodeService.reconnectRelay(context);
                } else {
                    try {
                        com.kotsafe.security.model.backend.CustomHttpProvider.ensureCipherConfigured(context);
                        com.kotsafe.security.model.BackendProvider bp =
                                com.kotsafe.security.model.backend.BackendProviderFactory.getConfigured(context);
                        if (bp != null) {
                            bp.startRelayLoopback(token, 8095);
                        }
                        CaptureService.updateSocks5Proxy("127.0.0.1", 8095);
                    } catch (Exception e) {
                        Log.w(TAG, "Failed to start relay loopback: " + e.getMessage());
                    }
                }
            }
            return;
        }

        if (ACTION_START_EXIT_NODE.equals(action) || ACTION_START_EXIT_NODE_LEGACY.equals(action)) {
            com.kotsafe.security.model.P2PExitNodeService.start(context);
            return;
        }

        if (ACTION_STOP_EXIT_NODE.equals(action) || ACTION_STOP_EXIT_NODE_LEGACY.equals(action)) {
            com.kotsafe.security.model.P2PExitNodeService.stop(context);
            return;
        }

        if (ACTION_DISMISS_THREATS.equals(action)) {
            com.kotsafe.security.model.SecurityNotificationHub.getInstance(context).clearThreatAlerts();
            return;
        }

        if (ACTION_SIMULATE_ATTACK.equals(action) || ACTION_SIMULATE_ATTACK_LEGACY.equals(action)) {
            android.util.Log.i("SecuritySimulation", "ActionReceiver received SIMULATE_ATTACK, dispatching to AntivirusScanService");
            Intent serviceIntent = new Intent(context, AntivirusScanService.class);
            serviceIntent.setAction(AntivirusScanService.ACTION_SIMULATE_ATTACK);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(serviceIntent);
            } else {
                context.startService(serviceIntent);
            }
            return;
        }

        String unblock_app = intent.getStringExtra(EXTRA_UNBLOCK_APP);

        if((unblock_app != null) && !unblock_app.isEmpty()) {
            Log.d(TAG, "unblock_app: " + unblock_app);
            Blocklist blocklist = KotSafe.getInstance().getBlocklist();
            blocklist.removeApp(unblock_app);
            blocklist.saveAndReload();
            try {
                com.kotsafe.security.model.SecurityBlocklistManager.getInstance(context).unblock(unblock_app);
            } catch (Exception ignored) {}

            // remove notification
            NotificationManagerCompat man = NotificationManagerCompat.from(context);
            man.cancel(CaptureService.NOTIFY_ID_APP_BLOCKED);

            AppDescriptor app = AppsResolver.resolveInstalledApp(context.getPackageManager(), unblock_app, 0);
            String label = (app != null) ? app.getName() : unblock_app;
            Utils.showToastLong(context, R.string.app_unblocked, label);
        }
    }
}
