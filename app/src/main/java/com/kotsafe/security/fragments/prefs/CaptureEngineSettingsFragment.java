/*
 * This file is part of KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.fragments.prefs;

import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.preference.DropDownPreference;
import androidx.preference.Preference;
import androidx.preference.PreferenceManager;
import androidx.preference.SwitchPreference;

import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.snackbar.Snackbar;
import com.kotsafe.security.CaptureService;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.activities.MainActivity;
import com.kotsafe.security.activities.prefs.VpnExemptionsActivity;
import com.kotsafe.security.model.Prefs;
import com.kotsafe.security.model.VpnAlertHelper;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Enumeration;

public class CaptureEngineSettingsFragment extends SettingsSubFragment {

    private final Handler mMainHandler = new Handler(Looper.getMainLooper());
    private ConnectivityManager.NetworkCallback mNetworkCallback;
    private final Runnable mRefreshRunnable = () -> {
        if (!isAdded()) return;
        DropDownPreference capInterface = findPreference(Prefs.PREF_CAPTURE_INTERFACE);
        if (capInterface != null) {
            refreshInterfaces(capInterface);
        }
    };

    @Override
    public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
        setPreferencesFromResource(R.xml.pref_capture_engine, rootKey);

        DropDownPreference capInterface = findPreference(Prefs.PREF_CAPTURE_INTERFACE);
        if (capInterface != null) {
            setupCaptureInterface(capInterface);
        }

        SwitchPreference rootCapture = findPreference(Prefs.PREF_ROOT_CAPTURE);
        if (rootCapture != null) {
            if (!Utils.isRootAvailable()) {
                rootCapture.setVisible(false);
            }
        }

        Preference vpnExceptions = findPreference(Prefs.PREF_VPN_EXCEPTIONS);
        if (vpnExceptions != null) {
            vpnExceptions.setOnPreferenceClickListener(preference -> {
                startActivity(new Intent(requireContext(), VpnExemptionsActivity.class));
                return true;
            });
        }

        SwitchPreference alwaysOnVpnPref = findPreference(Prefs.PREF_ALWAYS_ON_VPN);
        if (alwaysOnVpnPref != null) {
            setupAlwaysOnVpn(alwaysOnVpnPref);
        }
    }

    private void setupCaptureInterface(@NonNull DropDownPreference capInterface) {
        capInterface.setSummaryProvider(null);
        refreshInterfaces(capInterface);

        capInterface.setOnPreferenceChangeListener((preference, newValue) -> {
            String newInterface = (String) newValue;
            capInterface.setValue(newInterface);
            try {
                capInterface.setSummary(getResponsiveSummary(newInterface));
            } catch (Exception ignored) {
            }

            if (CaptureService.isServiceActive()) {
                String friendly = getFriendlySummaryName(newInterface);
                if (getView() != null) {
                    Snackbar.make(
                            getView(),
                            getString(R.string.capture_interface_restart_notice, friendly),
                            Snackbar.LENGTH_LONG
                    ).setAction(R.string.restart, v -> {
                        Context c = getContext();
                        if (c != null) {
                            CaptureService.stopService();
                            Toast.makeText(c, R.string.restarting_vpn, Toast.LENGTH_SHORT).show();
                            Intent intent = new Intent(c, MainActivity.class);
                            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
                            intent.putExtra(VpnAlertHelper.EXTRA_REQUEST_START_VPN, true);
                            startActivity(intent);
                        }
                    }).show();
                }
            }
            return true;
        });
    }

    private void setupAlwaysOnVpn(SwitchPreference pref) {
        updateAlwaysOnVpnStatus(pref);

        pref.setOnPreferenceChangeListener((preference, newValue) -> {
            boolean enable = (Boolean) newValue;
            Context ctx = requireContext();
            Prefs.setAlwaysOnVpn(PreferenceManager.getDefaultSharedPreferences(ctx), enable);

            if (enable) {
                // Turn on start_at_boot and restart_on_disconnect for full continuous protection
                SwitchPreference startAtBoot = findPreference(Prefs.PREF_START_AT_BOOT);
                if (startAtBoot != null && !startAtBoot.isChecked()) {
                    startAtBoot.setChecked(true);
                    PreferenceManager.getDefaultSharedPreferences(ctx)
                            .edit()
                            .putBoolean(Prefs.PREF_START_AT_BOOT, true)
                            .apply();
                }

                SwitchPreference restartOnDisconnect = findPreference(Prefs.PREF_RESTART_ON_DISCONNECT);
                if (restartOnDisconnect != null && !restartOnDisconnect.isChecked()) {
                    restartOnDisconnect.setChecked(true);
                    PreferenceManager.getDefaultSharedPreferences(ctx)
                            .edit()
                            .putBoolean(Prefs.PREF_RESTART_ON_DISCONNECT, true)
                            .apply();
                }

                showAlwaysOnVpnDialog(true);
            } else {
                if (isSystemAlwaysOnVpnActive(ctx)) {
                    showAlwaysOnVpnDialog(false);
                }
            }

            updateAlwaysOnVpnStatus(pref);
            return true;
        });
    }

    private void updateAlwaysOnVpnStatus(SwitchPreference pref) {
        Context context = getContext();
        if (context == null || pref == null) return;

        boolean systemActive = isSystemAlwaysOnVpnActive(context);
        boolean inAppActive = Prefs.isAlwaysOnVpn(context, PreferenceManager.getDefaultSharedPreferences(context));
        boolean isActive = systemActive || inAppActive;

        pref.setChecked(isActive);
        if (systemActive) {
            pref.setSummary(R.string.always_on_vpn_summary_enabled);
        } else if (inAppActive) {
            pref.setSummary(R.string.always_on_vpn_summary_in_app);
        } else {
            pref.setSummary(R.string.always_on_vpn_summary_disabled);
        }
    }

    private void showAlwaysOnVpnDialog(boolean enabling) {
        new MaterialAlertDialogBuilder(requireContext())
                .setTitle(R.string.always_on_vpn_dialog_title)
                .setMessage(enabling ? R.string.always_on_vpn_dialog_enable_msg : R.string.always_on_vpn_dialog_disable_msg)
                .setPositiveButton(R.string.open_vpn_settings, (dialog, which) -> {
                    try {
                        startActivity(new Intent(Settings.ACTION_VPN_SETTINGS));
                    } catch (Exception e) {
                        try {
                            startActivity(new Intent("android.net.vpn.SETTINGS"));
                        } catch (Exception ignored) {
                        }
                    }
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    public static boolean isSystemAlwaysOnVpnActive(Context context) {
        if (CaptureService.isAlwaysOnVPN()) {
            return true;
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && CaptureService.isLockdownVPN()) {
            return true;
        }
        try {
            String alwaysOnApp = Settings.Secure.getString(context.getContentResolver(), "always_on_vpn_app");
            return context.getPackageName().equals(alwaysOnApp);
        } catch (Exception ignored) {
        }
        return false;
    }

    private void registerNetworkCallback() {
        if (mNetworkCallback != null) return;
        Context ctx = getContext();
        if (ctx == null) return;
        ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) return;

        mNetworkCallback = new ConnectivityManager.NetworkCallback() {
            @Override
            public void onAvailable(@NonNull Network network) {
                scheduleInterfaceRefresh();
            }

            @Override
            public void onLost(@NonNull Network network) {
                scheduleInterfaceRefresh();
            }

            @Override
            public void onCapabilitiesChanged(@NonNull Network network, @NonNull NetworkCapabilities networkCapabilities) {
                scheduleInterfaceRefresh();
            }

            @Override
            public void onLinkPropertiesChanged(@NonNull Network network, @NonNull LinkProperties linkProperties) {
                scheduleInterfaceRefresh();
            }
        };

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                cm.registerDefaultNetworkCallback(mNetworkCallback);
            } else {
                NetworkRequest req = new NetworkRequest.Builder().build();
                cm.registerNetworkCallback(req, mNetworkCallback);
            }
        } catch (Exception ignored) {
        }
    }

    private void unregisterNetworkCallback() {
        if (mNetworkCallback == null) return;
        Context ctx = getContext();
        if (ctx != null) {
            ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm != null) {
                try {
                    cm.unregisterNetworkCallback(mNetworkCallback);
                } catch (Exception ignored) {
                }
            }
        }
        mNetworkCallback = null;
        mMainHandler.removeCallbacks(mRefreshRunnable);
    }

    private void scheduleInterfaceRefresh() {
        mMainHandler.removeCallbacks(mRefreshRunnable);
        mMainHandler.postDelayed(mRefreshRunnable, 250);
    }

    @Override
    public void onStart() {
        super.onStart();
        registerNetworkCallback();
    }

    @Override
    public void onStop() {
        super.onStop();
        unregisterNetworkCallback();
    }

    @Override
    public void onResume() {
        super.onResume();
        SwitchPreference alwaysOnVpnPref = findPreference(Prefs.PREF_ALWAYS_ON_VPN);
        if (alwaysOnVpnPref != null) {
            updateAlwaysOnVpnStatus(alwaysOnVpnPref);
        }

        DropDownPreference capInterface = findPreference(Prefs.PREF_CAPTURE_INTERFACE);
        if (capInterface != null) {
            refreshInterfaces(capInterface);
        }
    }

    @Override
    public void onDestroyView() {
        mMainHandler.removeCallbacks(mRefreshRunnable);
        super.onDestroyView();
    }

    private void refreshInterfaces(DropDownPreference capInterface) {
        if (capInterface == null) return;
        Context ctx = getContext();
        if (ctx == null) return;

        ArrayList<String> labels = new ArrayList<>();
        ArrayList<String> values = new ArrayList<>();

        // 1. Primary smart option: Internet (Auto-switch)
        labels.add("🌐 " + getString(R.string.internet) + " (Auto-Switch) ★");
        values.add("@inet");

        // 2. All interfaces
        labels.add("🔀 " + getString(R.string.all_interfaces) + " (any)");
        values.add("any");

        ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
        String activeIfName = null;
        if (cm != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                Network activeNet = cm.getActiveNetwork();
                if (activeNet != null) {
                    LinkProperties lp = cm.getLinkProperties(activeNet);
                    if (lp != null) {
                        activeIfName = lp.getInterfaceName();
                    }
                }
            } catch (Exception ignored) {
            }
        }

        try {
            Enumeration<NetworkInterface> ifaces = Utils.getNetworkInterfaces();
            while (ifaces.hasMoreElements()) {
                NetworkInterface iface = ifaces.nextElement();
                String name = iface.getName();
                if (name == null) continue;

                // Filter internal loopback, dummy, and VPN tunnels to prevent circular loop selection
                if (name.startsWith("tun") || name.startsWith("dummy") || name.startsWith("sit")
                        || name.startsWith("ip_vti") || name.startsWith("imq") || name.startsWith("ip6tnl")
                        || name.startsWith("lo")) {
                    continue;
                }

                if (!iface.isUp()) continue;

                String ipStr = extractIp(iface);
                boolean isActive = name.equals(activeIfName);
                String friendlyType = getFriendlyInterfaceType(name);
                StringBuilder sb = new StringBuilder();
                sb.append(friendlyType).append(" (").append(name).append(")");
                if (!ipStr.isEmpty()) {
                    sb.append(" • ").append(formatCompactIp(ipStr));
                }
                if (isActive) {
                    sb.append(" [Active]");
                }

                labels.add(sb.toString());
                values.add(name);
            }
        } catch (SocketException e) {
            e.printStackTrace();
        }

        // Retain user's current selection if it temporarily went offline
        String currentVal = capInterface.getValue();
        if (currentVal != null && !currentVal.isEmpty() && !values.contains(currentVal)) {
            String friendlyType = getFriendlyInterfaceType(currentVal);
            labels.add(friendlyType + " (" + currentVal + ") [Offline]");
            values.add(currentVal);
        }

        capInterface.setEntryValues(values.toArray(new String[0]));
        capInterface.setEntries(labels.toArray(new String[0]));

        if (currentVal == null || currentVal.isEmpty()) {
            capInterface.setValue("@inet");
        }
        try {
            capInterface.setSummaryProvider(null);
            capInterface.setSummary(getResponsiveSummary(capInterface.getValue()));
        } catch (Exception ignored) {
        }
    }

    private CharSequence getResponsiveSummary(String val) {
        Context ctx = getContext();
        if (ctx == null) return "";

        ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
        String activeIfName = null;
        String activeTypeName = null;
        String activeIp = null;

        if (cm != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                Network activeNet = cm.getActiveNetwork();
                if (activeNet != null) {
                    LinkProperties lp = cm.getLinkProperties(activeNet);
                    if (lp != null) {
                        activeIfName = lp.getInterfaceName();
                        activeIp = extractIp(lp);
                    }
                    NetworkCapabilities caps = cm.getNetworkCapabilities(activeNet);
                    if (caps != null) {
                        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                            activeTypeName = "Wi-Fi";
                        } else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                            activeTypeName = "Cellular";
                        } else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
                            activeTypeName = "Ethernet";
                        } else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH)) {
                            activeTypeName = "Bluetooth";
                        }
                    }
                }
            } catch (Exception ignored) {
            }
        }

        if (val == null || "@inet".equals(val)) {
            if (activeTypeName != null) {
                StringBuilder sb = new StringBuilder("Auto-Switch (Active: ").append(activeTypeName);
                if (activeIfName != null) {
                    sb.append(" [").append(activeIfName).append("]");
                }
                if (activeIp != null && !activeIp.isEmpty()) {
                    sb.append(" • ").append(formatCompactIp(activeIp));
                }
                sb.append(")");
                return sb.toString();
            } else {
                return "Auto-Switch (Offline • No active internet)";
            }
        }

        if ("any".equals(val)) {
            return "Promiscuous mode • Capture on all network interfaces";
        }

        // Specific interface
        String friendlyType = getFriendlyInterfaceType(val);
        boolean isActive = val.equals(activeIfName);
        String ifIp = "";
        boolean isUp = false;
        try {
            NetworkInterface iface = NetworkInterface.getByName(val);
            if (iface != null && iface.isUp()) {
                isUp = true;
                ifIp = extractIp(iface);
            }
        } catch (Exception ignored) {
        }

        StringBuilder sb = new StringBuilder(friendlyType).append(" (").append(val).append(")");
        if (!ifIp.isEmpty()) {
            sb.append(" • ").append(formatCompactIp(ifIp));
        }
        if (isActive) {
            sb.append(" [Active]");
        } else if (isUp) {
            sb.append(" [Online]");
        } else {
            sb.append(" [Disconnected]");
        }
        return sb.toString();
    }

    private String extractIp(NetworkInterface iface) {
        if (iface == null) return "";
        String fallbackIp = "";
        try {
            Enumeration<InetAddress> addrs = iface.getInetAddresses();
            while (addrs.hasMoreElements()) {
                InetAddress addr = addrs.nextElement();
                if (!addr.isLoopbackAddress() && !addr.isLinkLocalAddress()) {
                    String hostAddr = addr.getHostAddress();
                    if (hostAddr != null) {
                        if (hostAddr.contains("%")) {
                            hostAddr = hostAddr.substring(0, hostAddr.indexOf("%"));
                        }
                        if (addr instanceof Inet4Address) {
                            return hostAddr; // Prefer IPv4
                        }
                        if (fallbackIp.isEmpty()) {
                            fallbackIp = hostAddr;
                        }
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return fallbackIp;
    }

    private String extractIp(LinkProperties lp) {
        if (lp == null) return "";
        String fallbackIp = "";
        try {
            for (LinkAddress la : lp.getLinkAddresses()) {
                InetAddress addr = la.getAddress();
                if (!addr.isLoopbackAddress() && !addr.isLinkLocalAddress()) {
                    String hostAddr = addr.getHostAddress();
                    if (hostAddr != null) {
                        if (hostAddr.contains("%")) {
                            hostAddr = hostAddr.substring(0, hostAddr.indexOf("%"));
                        }
                        if (addr instanceof Inet4Address) {
                            return hostAddr; // Prefer IPv4
                        }
                        if (fallbackIp.isEmpty()) {
                            fallbackIp = hostAddr;
                        }
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return fallbackIp;
    }

    public static String formatCompactIp(String ip) {
        if (ip == null || ip.isEmpty()) return "";
        if (ip.contains(":") && ip.length() > 20) {
            int firstColon = ip.indexOf(':');
            int secondColon = ip.indexOf(':', firstColon + 1);
            int lastColon = ip.lastIndexOf(':');
            if (secondColon != -1 && lastColon > secondColon) {
                return ip.substring(0, secondColon) + ":…:" + ip.substring(lastColon + 1);
            }
        }
        return ip;
    }

    private String getFriendlyInterfaceType(String name) {
        if (name == null) return "🌐 Interface";
        if (name.startsWith("wlan")) {
            return "📡 Wi-Fi";
        } else if (name.startsWith("rmnet") || name.startsWith("ccmni") || name.startsWith("pdp") || name.startsWith("wwan")) {
            return "📶 Cellular";
        } else if (name.startsWith("eth")) {
            return "🔌 Ethernet";
        } else if (name.startsWith("rndis") || name.startsWith("usb")) {
            return "🔗 USB Tether";
        } else if (name.startsWith("bt-pan") || name.startsWith("bnep")) {
            return "📱 Bluetooth";
        } else if (name.startsWith("p2p")) {
            return "🛰️ Wi-Fi Direct";
        }
        return "🌐 Interface";
    }

    private String getFriendlySummaryName(String val) {
        if (val == null || "@inet".equals(val)) {
            return "Internet (Auto-Switch)";
        }
        if ("any".equals(val)) {
            return "All Interfaces";
        }
        return getFriendlyInterfaceType(val) + " (" + val + ")";
    }
}
