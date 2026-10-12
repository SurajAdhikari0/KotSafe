/*
 * This file is part of KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.fragments.prefs;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.text.InputType;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.appcompat.app.AlertDialog;
import androidx.preference.EditTextPreference;
import androidx.preference.Preference;
import androidx.preference.PreferenceManager;

import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.kotsafe.security.CaptureService;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.activities.FirewallActivity;
import com.kotsafe.security.activities.prefs.PortMapActivity;
import com.kotsafe.security.model.Prefs;
import com.kotsafe.security.model.UpnpPortMapper;
import com.kotsafe.security.util.WakeOnLanHelper;

public class StreamingProxySettingsFragment extends SettingsSubFragment {

    @Override
    public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
        setPreferencesFromResource(R.xml.pref_streaming_proxy, rootKey);

        // 1. Port Mapping & Redirection (Local)
        Preference portMapPref = findPreference("port_mapping");
        if (portMapPref != null) {
            portMapPref.setOnPreferenceClickListener(p -> {
                startActivity(new Intent(requireContext(), PortMapActivity.class));
                return true;
            });
        }

        // 2. Automated Router Port Mapping (UPnP / NAT-PMP)
        Preference upnpPref = findPreference("upnp_auto_port_map");
        if (upnpPref != null) {
            upnpPref.setOnPreferenceClickListener(p -> {
                showUpnpAutoMapDialog();
                return true;
            });
        }

        // 3. Remote Wake-on-LAN (WoL)
        Preference wolPref = findPreference("wake_on_lan_tool");
        if (wolPref != null) {
            wolPref.setOnPreferenceClickListener(p -> {
                showWakeOnLanDialog();
                return true;
            });
        }

        // 4. WireGuard Mode (Private VPN Tunnel)
        Preference wireguardPref = findPreference("wireguard_tunnel_settings");
        if (wireguardPref != null) {
            wireguardPref.setOnPreferenceClickListener(p -> {
                showWireGuardDialog();
                return true;
            });
        }

        // 5. NetGuard Mode (Local No-Root Firewall)
        Preference netguardPref = findPreference("netguard_firewall_settings");
        if (netguardPref != null) {
            netguardPref.setOnPreferenceClickListener(p -> {
                startActivity(new Intent(requireContext(), FirewallActivity.class));
                return true;
            });
        }

        // 6. AdGuard Mode (DNS Proxy & Ad Shield)
        Preference adguardPref = findPreference("adguard_dns_settings");
        if (adguardPref != null) {
            adguardPref.setOnPreferenceClickListener(p -> {
                new MaterialAlertDialogBuilder(requireContext())
                        .setTitle("🛑 AdGuard Mode (DNS Shield & Firewall)")
                        .setMessage("KotSafe implements on-device AdGuard mode through encrypted DNS-over-HTTPS (DoH) and host blocklists.\n\n"
                                + "🔒 Mandatory Authentication: Always use authenticated DoH/DoT endpoints with TLS certificate validation to prevent DNS hijacking.\n\n"
                                + "Choose where to configure:")
                        .setPositiveButton("🛡️ Tracker & Host Lists", (d, w) -> {
                            Preference target = new Preference(requireContext());
                            target.setKey("adblock_settings");
                            if (getActivity() instanceof com.kotsafe.security.activities.prefs.SettingsActivity) {
                                ((com.kotsafe.security.activities.prefs.SettingsActivity) getActivity())
                                        .onPreferenceStartFragment(this, target);
                            }
                        })
                        .setNeutralButton("🌐 Encrypted DNS", (d, w) -> {
                            Preference dnsPref = new Preference(requireContext());
                            dnsPref.setKey("dns_settings");
                            if (getActivity() instanceof com.kotsafe.security.activities.prefs.SettingsActivity) {
                                ((com.kotsafe.security.activities.prefs.SettingsActivity) getActivity())
                                        .onPreferenceStartFragment(this, dnsPref);
                            }
                        })
                        .setNegativeButton(R.string.cancel_action, (d, w) -> d.dismiss())
                        .show();
                return true;
            });
        }

        // Streaming & Exporter Preferences
        EditTextPreference colHost = findPreference(Prefs.PREF_COLLECTOR_HOST_KEY);
        if (colHost != null) {
            colHost.setOnPreferenceChangeListener((preference, newValue) -> Utils.validateHostOrIp(newValue.toString()));
        }

        EditTextPreference colPort = findPreference(Prefs.PREF_COLLECTOR_PORT_KEY);
        if (colPort != null) {
            colPort.setOnBindEditTextListener(editText -> editText.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_FLAG_SIGNED));
            colPort.setOnPreferenceChangeListener((preference, newValue) -> Utils.validatePort(newValue.toString()));
        }

        EditTextPreference httpPort = findPreference(Prefs.PREF_HTTP_SERVER_PORT);
        if (httpPort != null) {
            httpPort.setOnPreferenceChangeListener((preference, newValue) -> Utils.validatePort(newValue.toString()));
        }
    }

    private void showUpnpAutoMapDialog() {
        Context ctx = requireContext();
        String gw = com.kotsafe.security.ai.OfflineKnowledgeEngine.getDetectedLocalGateway(ctx);
        if (gw == null || gw.isEmpty()) gw = "192.168.1.1";
        String localIp = UpnpPortMapper.getLocalWifiIpAddress();

        new MaterialAlertDialogBuilder(ctx)
                .setTitle("⚡ Automated Router Port Mapping (UPnP / NAT-PMP)")
                .setMessage("Instruct your home Wi-Fi / ONT router to automatically forward external Port 1080 to this device using UPnP IGD and NAT-PMP (RFC 6886).\n\n"
                        + "• Detected Router Gateway: " + gw + "\n"
                        + "• Local Device IP: " + (localIp != null ? localIp : "Not connected to Wi-Fi") + "\n"
                        + "• Target WAN Port: 1080 (TCP)\n\n"
                        + "🔒 Security Reminder: Ensure your SOCKS5 proxy has username & password authentication enabled to prevent open-proxy scanning!")
                .setPositiveButton("⚡ Map Port 1080 Now", (dialog, which) -> {
                    executeUpnpMapping(1080);
                })
                .setNegativeButton(R.string.cancel_action, (dialog, which) -> dialog.dismiss())
                .show();
    }

    private void executeUpnpMapping(int port) {
        Context ctx = requireContext();
        AlertDialog progressDialog = new MaterialAlertDialogBuilder(ctx)
                .setTitle("Broadcasting UPnP / NAT-PMP...")
                .setMessage("Sending SSDP discovery and NAT-PMP request to router gateway on port " + port + "...")
                .setCancelable(false)
                .create();
        progressDialog.show();

        UpnpPortMapper.mapPortAsync(port, (success, message) -> {
            if (getActivity() == null) return;
            getActivity().runOnUiThread(() -> {
                progressDialog.dismiss();
                new MaterialAlertDialogBuilder(ctx)
                        .setTitle(success ? "✅ Port Forwarding Succeeded!" : "⚠️ Router Response")
                        .setMessage(message)
                        .setPositiveButton(R.string.ok, (d, w) -> d.dismiss())
                        .show();
            });
        });
    }

    private void showWakeOnLanDialog() {
        Context ctx = requireContext();
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ctx);
        String savedMac = prefs.getString("pref_saved_wol_mac", "AA:BB:CC:DD:EE:FF");
        String savedHost = prefs.getString("pref_saved_wol_host", "255.255.255.255");

        android.widget.LinearLayout layout = new android.widget.LinearLayout(ctx);
        layout.setOrientation(android.widget.LinearLayout.VERTICAL);
        layout.setPadding(48, 24, 48, 24);

        TextView tvHint = new TextView(ctx);
        tvHint.setText("Send a WoL Magic Packet to wake your sleeping home computer or server when connecting from outside:");
        tvHint.setPadding(0, 0, 0, 16);
        layout.addView(tvHint);

        EditText etMac = new EditText(ctx);
        etMac.setHint("MAC Address (e.g. AA:BB:CC:DD:EE:FF)");
        etMac.setText(savedMac);
        layout.addView(etMac);

        EditText etHost = new EditText(ctx);
        etHost.setHint("Broadcast IP (default: 255.255.255.255)");
        etHost.setText(savedHost);
        layout.addView(etHost);

        new MaterialAlertDialogBuilder(ctx)
                .setTitle("📡 Remote Wake-on-LAN (WoL)")
                .setView(layout)
                .setPositiveButton("⚡ Send Magic Packet", (dialog, which) -> {
                    String mac = etMac.getText().toString().trim();
                    String host = etHost.getText().toString().trim();
                    if (!mac.isEmpty()) {
                        prefs.edit().putString("pref_saved_wol_mac", mac).putString("pref_saved_wol_host", host).apply();
                        WakeOnLanHelper.sendWakeOnLanAsync(mac, host, 9, new WakeOnLanHelper.WakeCallback() {
                            @Override
                            public void onSuccess(String targetMac) {
                                if (getActivity() != null) {
                                    getActivity().runOnUiThread(() -> android.widget.Toast.makeText(ctx, "✅ Magic Packet dispatched to " + targetMac, android.widget.Toast.LENGTH_LONG).show());
                                }
                            }

                            @Override
                            public void onError(String errorMessage) {
                                if (getActivity() != null) {
                                    getActivity().runOnUiThread(() -> android.widget.Toast.makeText(ctx, "⚠️ WoL Error: " + errorMessage, android.widget.Toast.LENGTH_LONG).show());
                                }
                            }
                        });
                    }
                })
                .setNegativeButton(R.string.cancel_action, (dialog, which) -> dialog.dismiss())
                .show();
    }

    private void showWireGuardDialog() {
        Context ctx = requireContext();
        boolean vpnActive = CaptureService.isServiceActive();
        new MaterialAlertDialogBuilder(ctx)
                .setTitle("⚡ WireGuard Mode (Private VPN Tunnel)")
                .setMessage("KotSafe runs an on-device zero-copy C kernel (`KotEngine`) utilizing Curve25519 key exchange, ChaCha20-Poly1305 encryption, and BLAKE2s hashing.\n\n"
                        + "• VPN Engine Status: " + (vpnActive ? "✅ **ACTIVE & ROUTING**" : "⏸️ **STANDBY**") + "\n\n"
                        + "🔒 Mandatory Authentication Setup: Always enforce cryptographic Curve25519 public/private key-pair authentication with Pre-Shared Key (PSK) verification.\n\n"
                        + "Tap below to manage capture settings or interface binding:")
                .setPositiveButton("⚙️ Capture Settings", (dialog, which) -> {
                    Preference capPref = new Preference(requireContext());
                    capPref.setKey("capture_engine_settings");
                    if (getActivity() instanceof com.kotsafe.security.activities.prefs.SettingsActivity) {
                        ((com.kotsafe.security.activities.prefs.SettingsActivity) getActivity())
                                .onPreferenceStartFragment(this, capPref);
                    }
                })
                .setNegativeButton(R.string.cancel_action, (dialog, which) -> dialog.dismiss())
                .show();
    }
}
