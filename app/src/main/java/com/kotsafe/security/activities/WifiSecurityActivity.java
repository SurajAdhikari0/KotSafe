/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.activities;

import android.animation.ObjectAnimator;
import android.animation.PropertyValuesHolder;
import android.animation.ValueAnimator;
import android.Manifest;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.DashPathEffect;
import android.graphics.Paint;
import android.annotation.SuppressLint;
import android.graphics.RectF;
import android.graphics.Shader;
import android.graphics.SweepGradient;
import android.graphics.Typeface;
import android.view.Gravity;
import android.view.animation.LinearInterpolator;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.RouteInfo;
import android.net.Uri;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.RelativeLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.widget.Toolbar;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import com.kotsafe.security.CaptureService;
import com.kotsafe.security.R;
import com.kotsafe.security.model.WifiSecurityMonitor;
import com.google.android.material.button.MaterialButton;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class WifiSecurityActivity extends BaseActivity {
    private static final int REQ_WIFI_PERM = 201;

    private View mCardPermissionNotice;
    private TextView mTvPermissionNotice;
    private MaterialButton mBtnGrantPermission;
    private ImageView mIvWifiStatusIcon;
    private View mWifiIconContainer;
    private TextView mTvSsid;
    private TextView mTvBssid;
    private TextView mTvGradeBadge;
    private TextView mTvSecuritySummary;

    private TextView mTvSecurityType;
    private TextView mTvCaptivePortal;
    private TextView mTvMitmRisk;

    private TextView mTvSignal;
    private ProgressBar mPbSignalMeter;
    private TextView mTvFrequency;
    private TextView mTvLinkSpeed;
    private TextView mTvWifiStandard;
    private TextView mTvWifiMapSummary;
    private ViewGroup mWifiMapContainer;

    private TextView mTvLocalIp;
    private TextView mTvGateway;
    private TextView mTvSubnet;
    private TextView mTvDns;

    private MaterialButton mBtnShield;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_wifi_security);

        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        }
        toolbar.setNavigationOnClickListener(v -> finish());

        bindViews();
        setupActions();
    }

    private void bindViews() {
        mCardPermissionNotice = findViewById(R.id.card_permission_notice);
        mTvPermissionNotice = findViewById(R.id.tv_permission_notice);
        mBtnGrantPermission = findViewById(R.id.btn_grant_permission);
        mIvWifiStatusIcon = findViewById(R.id.iv_wifi_status_icon);
        mWifiIconContainer = findViewById(R.id.wifi_icon_container);
        mTvSsid = findViewById(R.id.tv_wifi_ssid);
        mTvBssid = findViewById(R.id.tv_wifi_bssid);
        mTvGradeBadge = findViewById(R.id.tv_wifi_grade_badge);
        mTvSecuritySummary = findViewById(R.id.tv_wifi_security_summary);

        mTvSecurityType = findViewById(R.id.tv_val_security_type);
        mTvCaptivePortal = findViewById(R.id.tv_val_captive_portal);
        mTvMitmRisk = findViewById(R.id.tv_val_mitm_risk);

        mTvSignal = findViewById(R.id.tv_val_signal);
        mPbSignalMeter = findViewById(R.id.pb_signal_meter);
        mTvFrequency = findViewById(R.id.tv_val_frequency);
        mTvLinkSpeed = findViewById(R.id.tv_val_link_speed);
        mTvWifiStandard = findViewById(R.id.tv_val_wifi_standard);
        mTvWifiMapSummary = findViewById(R.id.tv_wifi_map_summary);
        mWifiMapContainer = findViewById(R.id.wifi_map_container);

        mTvLocalIp = findViewById(R.id.tv_val_local_ip);
        mTvGateway = findViewById(R.id.tv_val_gateway);
        mTvSubnet = findViewById(R.id.tv_val_subnet);
        mTvDns = findViewById(R.id.tv_val_dns);

        mBtnShield = findViewById(R.id.btn_wifi_shield);
    }

    private void setupActions() {
        if (mBtnGrantPermission != null) {
            mBtnGrantPermission.setOnClickListener(v -> requestWifiPermission());
        }
        findViewById(R.id.btn_wifi_refresh).setOnClickListener(v -> {
            inspectWifiSecurity();
            Toast.makeText(this, "Wi-Fi diagnostics refreshed", Toast.LENGTH_SHORT).show();
        });

        mBtnShield.setOnClickListener(v -> {
            if (CaptureService.isServiceActive()) {
                Toast.makeText(this, "KotSafe VPN protection is already active", Toast.LENGTH_SHORT).show();
            } else {
                Intent intent = new Intent(this, MainActivity.class);
                intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
                startActivity(intent);
                finish();
            }
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        inspectWifiSecurity();
    }

    @SuppressLint("MissingPermission")
    @SuppressWarnings("deprecation")
    private void inspectWifiSecurity() {
        ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        WifiManager wm = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);

        boolean hasPerm = WifiSecurityMonitor.hasLocationPermission(this);
        boolean locEnabled = WifiSecurityMonitor.isLocationServiceEnabled(this);

        if (!hasPerm) {
            mCardPermissionNotice.setVisibility(View.VISIBLE);
            if (mTvPermissionNotice != null) {
                mTvPermissionNotice.setText("Grant Location permission to reveal exact Wi-Fi SSID and AP hardware details.");
            }
            if (mBtnGrantPermission != null) {
                mBtnGrantPermission.setText("Grant");
                mBtnGrantPermission.setOnClickListener(v -> requestWifiPermission());
            }
        } else if (!locEnabled) {
            mCardPermissionNotice.setVisibility(View.VISIBLE);
            if (mTvPermissionNotice != null) {
                mTvPermissionNotice.setText("Location service is turned off. Turn on device Location in Settings to detect Wi-Fi SSID.");
            }
            if (mBtnGrantPermission != null) {
                mBtnGrantPermission.setText("Turn On");
                mBtnGrantPermission.setOnClickListener(v -> {
                    try {
                        startActivity(new Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS));
                    } catch (Exception e) {
                        Toast.makeText(this, "Please enable Location in quick settings", Toast.LENGTH_SHORT).show();
                    }
                });
            }
        } else {
            mCardPermissionNotice.setVisibility(View.GONE);
        }

        if (cm == null || wm == null) {
            setDisconnectedState();
            return;
        }

        Network activeNetwork = cm.getActiveNetwork();
        NetworkCapabilities caps = (activeNetwork != null) ? cm.getNetworkCapabilities(activeNetwork) : null;
        LinkProperties linkProps = (activeNetwork != null) ? cm.getLinkProperties(activeNetwork) : null;

        if (caps == null || !caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
            if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                inspectCellularSecurity(caps, linkProps);
                return;
            }
            setDisconnectedState();
            return;
        }

        WifiInfo wifiInfo = null;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && caps.getTransportInfo() instanceof WifiInfo) {
            wifiInfo = (WifiInfo) caps.getTransportInfo();
        }
        if (wifiInfo == null) {
            wifiInfo = wm.getConnectionInfo();
        }
        if (wifiInfo == null) {
            setDisconnectedState();
            return;
        }

        // 1. SSID & BSSID
        String ssid = wifiInfo.getSSID();
        if (ssid != null && ssid.startsWith("\"") && ssid.endsWith("\"")) {
            ssid = ssid.substring(1, ssid.length() - 1);
        }
        if (ssid == null || ssid.isEmpty() || "<unknown ssid>".equalsIgnoreCase(ssid)) {
            if (!hasPerm) {
                ssid = "Active Wi-Fi (Permission Required for SSID)";
            } else if (!locEnabled) {
                ssid = "Active Wi-Fi (Device Location Off)";
            } else {
                ssid = "Connected Wi-Fi";
            }
        }
        mTvSsid.setText(ssid);

        String bssid = wifiInfo.getBSSID();
        if (bssid == null || bssid.equals("02:00:00:00:00:00")) {
            if (!hasPerm) {
                bssid = "Hidden (Grant Permission)";
            } else if (!locEnabled) {
                bssid = "Hidden (Enable Location)";
            } else {
                bssid = "Hardware AP Protected";
            }
        }
        mTvBssid.setText("BSSID: " + bssid);

        // 2. Encryption & Security Grade Evaluation
        String securityType = "WPA2-PSK (AES-CCMP)";
        String grade = "GRADE B";
        int gradeColor = Color.parseColor("#3B82F6");
        String summary = "Protected Network: Uses robust WPA2-Personal authentication with AES cipher encryption.";

        boolean isCaptivePortal = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL);
        boolean isOpen = false;
        boolean isWep = false;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            int sec = wifiInfo.getCurrentSecurityType();
            if (sec == WifiInfo.SECURITY_TYPE_OPEN) {
                isOpen = true;
            } else if (sec == WifiInfo.SECURITY_TYPE_WEP) {
                isWep = true;
            } else if (sec == WifiInfo.SECURITY_TYPE_SAE || sec == WifiInfo.SECURITY_TYPE_OWE) {
                securityType = "WPA3-Personal (SAE)";
                grade = "GRADE A";
                gradeColor = Color.parseColor("#10B981");
                summary = "Highest Security: WPA3 Simultaneous Authentication of Equals (SAE) with forward secrecy.";
            } else if (sec == WifiInfo.SECURITY_TYPE_EAP || sec == WifiInfo.SECURITY_TYPE_EAP_WPA3_ENTERPRISE) {
                securityType = "WPA2/WPA3-Enterprise";
                grade = "GRADE A";
                gradeColor = Color.parseColor("#10B981");
                summary = "Enterprise Grade: Uses 802.1X authentication server with individual per-user encryption.";
            }
        }

        if (hasPerm && (!isOpen && !isWep)) {
            List<ScanResult> scanResults = null;
            try {
                scanResults = wm.getScanResults();
            } catch (SecurityException ignored) {}
            if (scanResults != null) {
                for (ScanResult sr : scanResults) {
                    if (bssid.equalsIgnoreCase(sr.BSSID) || ssid.equalsIgnoreCase(sr.SSID)) {
                        String capsStr = (sr.capabilities != null) ? sr.capabilities.toUpperCase(Locale.ROOT) : "";
                        if (!capsStr.contains("WPA") && !capsStr.contains("WEP") && !capsStr.contains("EAP") && !capsStr.contains("SAE")) {
                            isOpen = true;
                        } else if (capsStr.contains("WEP")) {
                            isWep = true;
                        } else if (capsStr.contains("SAE")) {
                            securityType = "WPA3-Personal (SAE)";
                            grade = "GRADE A";
                            gradeColor = Color.parseColor("#10B981");
                            summary = "Highest Security: Modern WPA3 encryption with protected management frames.";
                        }
                        break;
                    }
                }
            }
        }

        if (isOpen) {
            securityType = "Open / Unencrypted (No Password)";
            grade = "GRADE F";
            gradeColor = Color.parseColor("#EF4444");
            summary = "DANGEROUS: Unencrypted Public Network! All cleartext packets can be intercepted by nearby listeners. Enable KotSafe VPN Shield immediately.";
        } else if (isWep) {
            securityType = "WEP (Obsolete / Cracked)";
            grade = "GRADE D";
            gradeColor = Color.parseColor("#F59E0B");
            summary = "WEAK CIPHER: WEP security is broken and can be cracked in minutes by automated tools.";
        }

        List<ScanResult> nearbyScans = null;
        if (hasPerm) {
            try {
                nearbyScans = wm.getScanResults();
            } catch (SecurityException ignored) {}
        }
        RogueApState rogueApState = detectRogueApState(ssid, bssid, nearbyScans);
        if (rogueApState.isSuspicious) {
            if (isOpen || isWep) {
                summary = rogueApState.detail + " " + summary;
            } else {
                summary = rogueApState.detail + " " + summary;
            }
            grade = rogueApState.isSuspicious ? "GRADE F" : grade;
            gradeColor = Color.parseColor("#EF4444");
        }

        mTvGradeBadge.setText(grade);
        mTvGradeBadge.setBackgroundTintList(ColorStateList.valueOf(gradeColor));
        mTvSecurityType.setText(securityType);
        mTvSecuritySummary.setText(summary);
        mTvSecuritySummary.setBackgroundTintList(ColorStateList.valueOf(Color.argb(30, Color.red(gradeColor), Color.green(gradeColor), Color.blue(gradeColor))));

        if (mIvWifiStatusIcon != null) {
            mIvWifiStatusIcon.setImageTintList(ColorStateList.valueOf(gradeColor));
        }
        if (mWifiIconContainer != null) {
            mWifiIconContainer.setBackgroundTintList(ColorStateList.valueOf(Color.argb(35, Color.red(gradeColor), Color.green(gradeColor), Color.blue(gradeColor))));
        }

        // 3. Captive Portal & MITM Risk
        if (isCaptivePortal) {
            mTvCaptivePortal.setText("Captive Portal Intercept Active");
            mTvCaptivePortal.setTextColor(Color.parseColor("#F59E0B"));
            if (rogueApState.isSuspicious) {
                mTvMitmRisk.setText(rogueApState.label);
                mTvMitmRisk.setTextColor(Color.parseColor("#EF4444"));
            } else {
                mTvMitmRisk.setText("Elevated Risk (Portal Intercept)");
                mTvMitmRisk.setTextColor(Color.parseColor("#F59E0B"));
            }
        } else {
            mTvCaptivePortal.setText("Clean (Direct Internet Access)");
            mTvCaptivePortal.setTextColor(Color.parseColor("#10B981"));
            if (rogueApState.isSuspicious) {
                mTvMitmRisk.setText(rogueApState.label);
                mTvMitmRisk.setTextColor(Color.parseColor("#EF4444"));
            } else {
                mTvMitmRisk.setText(isOpen ? "High Risk (Unencrypted Link)" : "Low Risk (Encrypted Channel)");
                mTvMitmRisk.setTextColor(isOpen ? Color.parseColor("#EF4444") : Color.parseColor("#10B981"));
            }
        }

        // 4. Signal, RSSI & Frequency
        int rssi = wifiInfo.getRssi();
        int signalQuality = Math.max(5, Math.min(100, 2 * (rssi + 100)));
        mTvSignal.setText(rssi + " dBm (" + signalQuality + "% • " + getSignalLabel(signalQuality) + ")");
        mPbSignalMeter.setProgress(signalQuality);
        int meterColor = (signalQuality > 70) ? Color.parseColor("#10B981") : (signalQuality > 40 ? Color.parseColor("#F59E0B") : Color.parseColor("#EF4444"));
        mPbSignalMeter.setProgressTintList(ColorStateList.valueOf(meterColor));

        int freq = wifiInfo.getFrequency();
        String freqLabel = formatFrequency(freq);
        mTvFrequency.setText(freqLabel);

        int linkSpeed = wifiInfo.getLinkSpeed();
        mTvLinkSpeed.setText(linkSpeed > 0 ? linkSpeed + " Mbps" : "Auto Negotiated");

        mTvWifiStandard.setText(getWifiStandardName(wifiInfo));

        // 5. IP Routing & Gateway
        if (linkProps != null) {
            String localIp = "Unknown";
            for (LinkAddress addr : linkProps.getLinkAddresses()) {
                if (addr.getAddress() instanceof Inet4Address) {
                    localIp = addr.getAddress().getHostAddress();
                    mTvSubnet.setText(addr.getAddress().getHostAddress() + "/" + addr.getPrefixLength());
                    break;
                }
            }
            mTvLocalIp.setText(localIp);

            String gateway = "Unknown";
            for (RouteInfo route : linkProps.getRoutes()) {
                if (route.isDefaultRoute() && route.getGateway() != null) {
                    gateway = route.getGateway().getHostAddress();
                    break;
                }
            }
            mTvGateway.setText(gateway);

            List<InetAddress> dnsServers = linkProps.getDnsServers();
            if (dnsServers != null && !dnsServers.isEmpty()) {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < dnsServers.size(); i++) {
                    if (i > 0) sb.append(", ");
                    sb.append(dnsServers.get(i).getHostAddress());
                }
                mTvDns.setText(sb.toString());
            } else {
                mTvDns.setText("Default DHCP");
            }
        }

        renderNearbyWifiMap(wm, wifiInfo);

        // 6. Shield Button Status
        boolean vpnActive = CaptureService.isServiceActive();
        if (vpnActive) {
            mBtnShield.setText(R.string.wifi_shield_active);
            mBtnShield.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor("#10B981")));
        } else {
            mBtnShield.setText(R.string.wifi_shield_now);
            mBtnShield.setBackgroundTintList(null);
        }
    }

    public static RogueApState detectRogueApState(String currentSsid, String currentBssid, List<ScanResult> scanResults) {
        if (currentSsid == null || currentSsid.trim().isEmpty()) {
            return new RogueApState(false, "Low Risk (Encrypted)", "No active SSID available for rogue AP comparison.");
        }

        String safeCurrentSsid = currentSsid.replace("\"", "").trim();
        String safeCurrentBssid = currentBssid == null ? "" : currentBssid.trim();
        boolean duplicateSsid = false;
        boolean weakSecurity = false;
        String duplicateMessage = "";

        if (scanResults != null) {
            for (ScanResult result : scanResults) {
                if (result == null || result.SSID == null || result.SSID.trim().isEmpty()) continue;
                String candidateSsid = result.SSID.replace("\"", "").trim();
                if (!candidateSsid.equalsIgnoreCase(safeCurrentSsid)) continue;

                String candidateBssid = result.BSSID == null ? "" : result.BSSID.trim();
                if (!candidateBssid.equalsIgnoreCase(safeCurrentBssid) && !candidateBssid.isEmpty()) {
                    duplicateSsid = true;
                    duplicateMessage = "Duplicate SSID '" + safeCurrentSsid + "' is broadcasting from multiple BSSIDs, which is a common rogue AP or evil twin pattern.";
                }

                String capsStr = (result.capabilities != null) ? result.capabilities.toUpperCase(Locale.ROOT) : "";
                if (!capsStr.contains("WPA") && !capsStr.contains("WEP") && !capsStr.contains("EAP") && !capsStr.contains("SAE")) {
                    weakSecurity = true;
                    duplicateMessage = "Duplicate SSID '" + safeCurrentSsid + "' appears with an unencrypted or weak security profile, suggesting a spoofed access point.";
                }
            }
        }

        if (duplicateSsid || weakSecurity) {
            String label = weakSecurity ? "Critical Risk (Unsafe Wi‑Fi Clone)" : "High Risk (Rogue AP / Evil Twin)";
            return new RogueApState(true, label, duplicateMessage.isEmpty() ? "A duplicate SSID is present on a different access point, which may indicate a rogue AP or evil twin." : duplicateMessage);
        }

        return new RogueApState(false, "Low Risk (Encrypted)", "No duplicate SSID or rogue AP marker was detected for the active network.");
    }

    public static final class RogueApState {
        public final boolean isSuspicious;
        public final String label;
        public final String detail;

        public RogueApState(boolean isSuspicious, String label, String detail) {
            this.isSuspicious = isSuspicious;
            this.label = label;
            this.detail = detail;
        }
    }

    @SuppressLint("MissingPermission")
    private void renderNearbyWifiMap(WifiManager wifiManager, WifiInfo currentInfo) {
        if (mWifiMapContainer == null) return;
        mWifiMapContainer.removeAllViews();

        if (wifiManager == null) {
            if (mTvWifiMapSummary != null) mTvWifiMapSummary.setText("No data");
            return;
        }

        if (!WifiSecurityMonitor.hasLocationPermission(this)) {
            TextView empty = new TextView(this);
            empty.setText("Location permission required to scan nearby Wi-Fi networks.");
            empty.setTextSize(11f);
            empty.setTextColor(Color.parseColor("#94A3B8"));
            empty.setPadding(0, 8, 0, 0);
            mWifiMapContainer.addView(empty);
            if (mTvWifiMapSummary != null) mTvWifiMapSummary.setText("Permission required");
            return;
        }

        List<ScanResult> scanResults = null;
        try {
            scanResults = wifiManager.getScanResults();
        } catch (SecurityException ignored) {}
        if (scanResults == null || scanResults.isEmpty()) {
            TextView empty = new TextView(this);
            empty.setText("No nearby networks detected yet. Refresh or move closer to the router.");
            empty.setTextSize(11f);
            empty.setTextColor(Color.parseColor("#94A3B8"));
            empty.setPadding(0, 8, 0, 0);
            mWifiMapContainer.addView(empty);
            if (mTvWifiMapSummary != null) mTvWifiMapSummary.setText("0 networks");
            return;
        }

        java.util.ArrayList<ScanResult> sorted = new java.util.ArrayList<>(scanResults);
        sorted.sort((a, b) -> Integer.compare(b.level, a.level));

        String currentBssid = currentInfo != null ? currentInfo.getBSSID() : null;
        String currentSsid = currentInfo != null ? currentInfo.getSSID() : null;
        if (currentSsid != null && currentSsid.startsWith("\"") && currentSsid.endsWith("\"")) {
            currentSsid = currentSsid.substring(1, currentSsid.length() - 1);
        }

        // 1. High-Visibility Radar Viewfinder
        WifiRadarScopeView radarScope = new WifiRadarScopeView(this);
        LinearLayout.LayoutParams radarLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dp(220));
        radarScope.setLayoutParams(radarLp);
        mWifiMapContainer.addView(radarScope);

        java.util.ArrayList<WifiMapNode> nodesList = new java.util.ArrayList<>();
        WifiMapNode connectedNode = null;

        for (int i = 0; i < sorted.size(); i++) {
            ScanResult result = sorted.get(i);
            if (result == null || result.SSID == null || result.SSID.trim().isEmpty()) continue;

            boolean isCurrent = (currentBssid != null && currentBssid.equalsIgnoreCase(result.BSSID))
                    || (currentSsid != null && currentSsid.equalsIgnoreCase(result.SSID));

            WifiMapNode node = new WifiMapNode(result.SSID, result.BSSID, result.level, result.frequency, result.capabilities, isCurrent);
            if (isCurrent && connectedNode == null) {
                connectedNode = node;
            } else {
                nodesList.add(node);
            }
        }

        radarScope.setData(nodesList, connectedNode);

        if (mTvWifiMapSummary != null) {
            mTvWifiMapSummary.setText((connectedNode != null ? 1 : 0) + " connected • " + sorted.size() + " detected");
        }

        // 2. High-Contrast Breakdown List of Nearby APs
        LinearLayout listHeader = new LinearLayout(this);
        listHeader.setOrientation(LinearLayout.HORIZONTAL);
        listHeader.setGravity(Gravity.CENTER_VERTICAL);
        listHeader.setPadding(dp(2), dp(12), dp(2), dp(4));

        TextView tvTitle = new TextView(this);
        tvTitle.setText("Detected Wireless Access Points (" + sorted.size() + ")");
        tvTitle.setTextSize(12f);
        tvTitle.setTypeface(Typeface.DEFAULT_BOLD);
        tvTitle.setTextColor(Color.parseColor("#3B82F6"));
        listHeader.addView(tvTitle);
        mWifiMapContainer.addView(listHeader);

        int maxListItems = Math.min(sorted.size(), 8);
        for (int i = 0; i < maxListItems; i++) {
            ScanResult sr = sorted.get(i);
            if (sr == null || sr.SSID == null || sr.SSID.trim().isEmpty()) continue;

            boolean isCurrent = (currentBssid != null && currentBssid.equalsIgnoreCase(sr.BSSID))
                    || (currentSsid != null && currentSsid.equalsIgnoreCase(sr.SSID));

            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setGravity(Gravity.CENTER_VERTICAL);
            row.setPadding(dp(10), dp(8), dp(10), dp(8));
            row.setBackgroundResource(R.drawable.bg_badge_neutral);
            if (isCurrent) {
                row.getBackground().setTint(Color.parseColor("#203B82F6"));
            } else {
                row.getBackground().setTint(Color.argb(22, 148, 163, 184));
            }
            LinearLayout.LayoutParams rowLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            rowLp.topMargin = dp(4);
            row.setLayoutParams(rowLp);

            // Signal Icon
            ImageView ivSignal = new ImageView(this);
            LinearLayout.LayoutParams ivLp = new LinearLayout.LayoutParams(dp(20), dp(20));
            ivLp.rightMargin = dp(10);
            ivSignal.setLayoutParams(ivLp);
            ivSignal.setImageResource(R.drawable.ic_wifi);
            int sigColor = isCurrent ? Color.parseColor("#3B82F6") : getSignalColor(sr.level);
            ivSignal.setImageTintList(ColorStateList.valueOf(sigColor));
            row.addView(ivSignal);

            // Info Column
            LinearLayout infoCol = new LinearLayout(this);
            infoCol.setOrientation(LinearLayout.VERTICAL);
            LinearLayout.LayoutParams infoLp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
            infoCol.setLayoutParams(infoLp);

            TextView tvSsid = new TextView(this);
            String safeSsid = sr.SSID.replace("\"", "");
            tvSsid.setText(isCurrent ? (safeSsid + " [Connected]") : safeSsid);
            tvSsid.setTextSize(12f);
            tvSsid.setTypeface(Typeface.DEFAULT_BOLD);
            tvSsid.setTextColor(isCurrent ? Color.parseColor("#2563EB") : Color.parseColor("#1E293B"));
            infoCol.addView(tvSsid);

            TextView tvDetails = new TextView(this);
            String freqStr = (sr.frequency > 4900) ? "5 GHz" : "2.4 GHz";
            int ch = (sr.frequency < 3000) ? (sr.frequency - 2407) / 5 : (sr.frequency - 5000) / 5;
            String caps = sr.capabilities != null ? sr.capabilities : "";
            String sec = caps.contains("SAE") ? "WPA3" : (caps.contains("WPA") ? "WPA2" : "Open");
            tvDetails.setText(sr.BSSID + " • " + freqStr + " (Ch " + ch + ") • " + sec);
            tvDetails.setTextSize(10f);
            tvDetails.setTextColor(Color.parseColor("#64748B"));
            infoCol.addView(tvDetails);

            row.addView(infoCol);

            // Signal dBm & Quality badge
            TextView tvDbm = new TextView(this);
            int quality = Math.max(0, Math.min(100, (sr.level + 100) * 2));
            tvDbm.setText(sr.level + " dBm\n" + quality + "%");
            tvDbm.setTextSize(10f);
            tvDbm.setGravity(Gravity.END);
            tvDbm.setTypeface(Typeface.DEFAULT_BOLD);
            tvDbm.setTextColor(sigColor);
            row.addView(tvDbm);

            mWifiMapContainer.addView(row);
        }
    }

    public static final class WifiMapNode {
        public final String ssid;
        public final String bssid;
        public final int level;
        public final int frequency;
        public final String capabilities;
        public final boolean isConnected;
        public float x;
        public float y;
        public int color;

        public WifiMapNode(String ssid, String bssid, int level, int frequency, String capabilities, boolean isConnected) {
            this.ssid = ssid;
            this.bssid = bssid;
            this.level = level;
            this.frequency = frequency;
            this.capabilities = capabilities;
            this.isConnected = isConnected;
            if (isConnected) {
                this.color = Color.parseColor("#38BDF8"); // Light Sky Blue
            } else if (level >= -60) {
                this.color = Color.parseColor("#10B981"); // Emerald
            } else if (level >= -75) {
                this.color = Color.parseColor("#F59E0B"); // Amber
            } else {
                this.color = Color.parseColor("#EF4444"); // Red
            }
        }
    }

    public static final class WifiRadarScopeView extends View {
        private final List<WifiMapNode> mNodes = new ArrayList<>();
        private WifiMapNode mConnectedNode;
        private float mSweepAngle = 0f;
        private ValueAnimator mSweepAnimator;

        private final Paint mBgPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint mStrokePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint mRingPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint mGridPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint mTextPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint mChipBgPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint mChipStrokePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint mNodePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint mLinePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint mSweepPaint = new Paint(Paint.ANTI_ALIAS_FLAG);

        public WifiRadarScopeView(Context context) {
            super(context);
            init();
        }

        private void init() {
            setWillNotDraw(false);

            mBgPaint.setStyle(Paint.Style.FILL);
            mBgPaint.setColor(Color.parseColor("#0A1128")); // Deep navy tactical radar

            mStrokePaint.setStyle(Paint.Style.STROKE);
            mStrokePaint.setColor(Color.parseColor("#1E293B"));
            mStrokePaint.setStrokeWidth(dpToPx(1.5f));

            mRingPaint.setStyle(Paint.Style.STROKE);
            mRingPaint.setColor(Color.parseColor("#1E3A8A")); // Royal blue radar ring
            mRingPaint.setStrokeWidth(dpToPx(1.2f));

            mGridPaint.setStyle(Paint.Style.STROKE);
            mGridPaint.setColor(Color.parseColor("#1E293B"));
            mGridPaint.setStrokeWidth(dpToPx(1f));
            mGridPaint.setPathEffect(new DashPathEffect(new float[]{dpToPx(4), dpToPx(4)}, 0));

            mTextPaint.setColor(Color.parseColor("#94A3B8"));
            mTextPaint.setTextSize(dpToPx(9f));
            mTextPaint.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));

            mChipBgPaint.setStyle(Paint.Style.FILL);
            mChipBgPaint.setColor(Color.parseColor("#E60F172A")); // High-contrast solid dark pill

            mChipStrokePaint.setStyle(Paint.Style.STROKE);
            mChipStrokePaint.setColor(Color.parseColor("#334155"));
            mChipStrokePaint.setStrokeWidth(dpToPx(1f));

            mLinePaint.setStyle(Paint.Style.STROKE);
            mLinePaint.setColor(Color.parseColor("#38BDF8"));
            mLinePaint.setStrokeWidth(dpToPx(1.8f));
            mLinePaint.setPathEffect(new DashPathEffect(new float[]{dpToPx(5), dpToPx(3)}, 0));

            mSweepPaint.setStyle(Paint.Style.FILL);

            mSweepAnimator = ValueAnimator.ofFloat(0f, 360f);
            mSweepAnimator.setDuration(3500L);
            mSweepAnimator.setRepeatCount(ValueAnimator.INFINITE);
            mSweepAnimator.setInterpolator(new LinearInterpolator());
            mSweepAnimator.addUpdateListener(animation -> {
                mSweepAngle = (float) animation.getAnimatedValue();
                invalidate();
            });
        }

        @Override
        protected void onAttachedToWindow() {
            super.onAttachedToWindow();
            if (mSweepAnimator != null && !mSweepAnimator.isRunning()) {
                mSweepAnimator.start();
            }
        }

        @Override
        protected void onDetachedFromWindow() {
            super.onDetachedFromWindow();
            if (mSweepAnimator != null) {
                mSweepAnimator.cancel();
            }
        }

        public void setData(List<WifiMapNode> nodes, WifiMapNode connectedNode) {
            mNodes.clear();
            if (nodes != null) {
                mNodes.addAll(nodes);
            }
            mConnectedNode = connectedNode;
            recalculateNodePositions();
            invalidate();
        }

        @Override
        protected void onSizeChanged(int w, int h, int oldw, int oldh) {
            super.onSizeChanged(w, h, oldw, oldh);
            recalculateNodePositions();
        }

        private void recalculateNodePositions() {
            int w = getWidth();
            int h = getHeight();
            if (w <= 0 || h <= 0) return;

            float cx = w / 2f;
            float cy = h / 2f;
            float maxR = Math.min(cx, cy) - dpToPx(30f);
            if (maxR <= dpToPx(20f)) maxR = dpToPx(60f);

            List<WifiMapNode> allList = new ArrayList<>();
            if (mConnectedNode != null) allList.add(mConnectedNode);
            for (WifiMapNode n : mNodes) {
                if (mConnectedNode == null || !n.bssid.equalsIgnoreCase(mConnectedNode.bssid)) {
                    allList.add(n);
                }
            }

            int count = Math.min(allList.size(), 6);
            double[] candidateAngles = new double[]{140.0, 220.0, 310.0, 180.0, 270.0, 0.0};
            for (int i = 0; i < count; i++) {
                WifiMapNode node = allList.get(i);
                // Normalized signal: -100 dBm (0.0) to -35 dBm (1.0)
                float norm = Math.max(0f, Math.min(1f, (node.level + 100f) / 65f));
                // Stronger signals closer to center, weaker signals near maxR
                float r = maxR * (0.92f - norm * 0.55f);

                double angle;
                if (node.isConnected) {
                    angle = Math.toRadians(50.0); // Dedicated quadrant for connected AP
                } else {
                    angle = Math.toRadians(candidateAngles[i % candidateAngles.length]);
                }

                node.x = (float) (cx + Math.cos(angle) * r);
                node.y = (float) (cy + Math.sin(angle) * r);
            }
        }

        @Override
        @SuppressLint("DrawAllocation")
        protected void onDraw(Canvas canvas) {
            super.onDraw(canvas);
            int w = getWidth();
            int h = getHeight();
            if (w <= 0 || h <= 0) return;

            float cx = w / 2f;
            float cy = h / 2f;
            float maxR = Math.min(cx, cy) - dpToPx(30f);

            // 1. Tactical Radar Background Card
            RectF bgRect = new RectF(0, 0, w, h);
            canvas.drawRoundRect(bgRect, dpToPx(14f), dpToPx(14f), mBgPaint);
            canvas.drawRoundRect(bgRect, dpToPx(14f), dpToPx(14f), mStrokePaint);

            // 2. Concentric Distance Rings
            float rInner = maxR * 0.35f;
            float rMid = maxR * 0.65f;
            float rOuter = maxR * 0.95f;

            canvas.drawCircle(cx, cy, rInner, mRingPaint);
            canvas.drawCircle(cx, cy, rMid, mRingPaint);
            canvas.drawCircle(cx, cy, rOuter, mRingPaint);

            // 3. Crosshairs
            canvas.drawLine(cx - rOuter, cy, cx + rOuter, cy, mGridPaint);
            canvas.drawLine(cx, cy - rOuter, cx, cy + rOuter, mGridPaint);

            // 4. Ring dBm Labels along top axis
            drawTextCentered(canvas, "-40 dBm", cx, cy - rInner - dpToPx(2f), mTextPaint);
            drawTextCentered(canvas, "-65 dBm", cx, cy - rMid - dpToPx(2f), mTextPaint);
            drawTextCentered(canvas, "-85 dBm", cx, cy - rOuter - dpToPx(2f), mTextPaint);

            // 5. Rotating Radar Sweep Beam
            canvas.save();
            canvas.rotate(mSweepAngle, cx, cy);
            Paint sweepBeam = new Paint(Paint.ANTI_ALIAS_FLAG);
            sweepBeam.setColor(Color.parseColor("#38BDF8"));
            sweepBeam.setStrokeWidth(dpToPx(1.5f));
            sweepBeam.setAlpha(180);
            canvas.drawLine(cx, cy, cx + rOuter, cy, sweepBeam);

            // Subtle sweep glow wedge behind the line
            Shader sweepShader = new SweepGradient(cx, cy,
                    new int[]{Color.TRANSPARENT, Color.TRANSPARENT, Color.parseColor("#2638BDF8"), Color.TRANSPARENT},
                    new float[]{0f, 0.85f, 0.99f, 1f});
            mSweepPaint.setShader(sweepShader);
            canvas.drawCircle(cx, cy, rOuter, mSweepPaint);
            canvas.restore();

            // 6. Connected Node Vector Link
            if (mConnectedNode != null && mConnectedNode.x > 0 && mConnectedNode.y > 0) {
                canvas.drawLine(cx, cy, mConnectedNode.x, mConnectedNode.y, mLinePaint);
            }

            // 7. Center Device Node ("YOU")
            mNodePaint.setColor(Color.parseColor("#10B981"));
            mNodePaint.setAlpha(70);
            canvas.drawCircle(cx, cy, dpToPx(11f), mNodePaint);
            mNodePaint.setAlpha(255);
            canvas.drawCircle(cx, cy, dpToPx(5.5f), mNodePaint);
            drawPillBadge(canvas, "YOU", cx, cy - dpToPx(13f), Color.parseColor("#10B981"), Color.parseColor("#FFFFFF"));

            // 8. Detected AP Nodes
            List<WifiMapNode> allNodes = new ArrayList<>();
            if (mConnectedNode != null) allNodes.add(mConnectedNode);
            for (WifiMapNode n : mNodes) {
                if (mConnectedNode == null || !n.bssid.equalsIgnoreCase(mConnectedNode.bssid)) {
                    allNodes.add(n);
                }
            }

            int count = Math.min(allNodes.size(), 6);
            for (int i = 0; i < count; i++) {
                WifiMapNode node = allNodes.get(i);
                if (node.x <= 0 || node.y <= 0) continue;

                // Outer glowing halo
                mNodePaint.setColor(node.color);
                mNodePaint.setAlpha(80);
                canvas.drawCircle(node.x, node.y, dpToPx(node.isConnected ? 12f : 9f), mNodePaint);

                // Inner solid dot
                mNodePaint.setAlpha(255);
                canvas.drawCircle(node.x, node.y, dpToPx(node.isConnected ? 6f : 4.5f), mNodePaint);

                // Chip pill label (push away from center)
                String cleanSsid = node.ssid != null ? node.ssid.replace("\"", "").trim() : "Unknown";
                if (cleanSsid.length() > 14) cleanSsid = cleanSsid.substring(0, 12) + "…";
                String chipText = cleanSsid + " (" + node.level + " dBm)" + (node.isConnected ? " ✓" : "");

                int textColor = node.isConnected ? Color.parseColor("#60A5FA") : Color.parseColor("#F8FAFC");
                float labelY = (node.y >= cy) ? node.y + dpToPx(13f) : node.y - dpToPx(13f);
                drawPillBadge(canvas, chipText, node.x, labelY, node.color, textColor);
            }
        }

        private void drawTextCentered(Canvas canvas, String text, float x, float y, Paint paint) {
            float textWidth = paint.measureText(text);
            canvas.drawText(text, x - textWidth / 2f, y, paint);
        }

        private void drawPillBadge(Canvas canvas, String text, float centerX, float centerY, int dotColor, int textColor) {
            Paint textP = new Paint(Paint.ANTI_ALIAS_FLAG);
            textP.setColor(textColor);
            textP.setTextSize(dpToPx(9.5f));
            textP.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));

            float textW = textP.measureText(text);
            float padX = dpToPx(6f);
            float padY = dpToPx(3f);
            float pillW = textW + padX * 2;
            float pillH = dpToPx(15f);

            float left = centerX - pillW / 2f;
            float top = centerY - pillH / 2f;
            RectF pillRect = new RectF(left, top, left + pillW, top + pillH);

            canvas.drawRoundRect(pillRect, dpToPx(5f), dpToPx(5f), mChipBgPaint);
            canvas.drawRoundRect(pillRect, dpToPx(5f), dpToPx(5f), mChipStrokePaint);

            Paint.FontMetrics fm = textP.getFontMetrics();
            float baseline = centerY - (fm.ascent + fm.descent) / 2f;
            canvas.drawText(text, left + padX, baseline, textP);
        }

        private float dpToPx(float dp) {
            return dp * getResources().getDisplayMetrics().density;
        }
    }

    private void animatePulse(View view, long delay, float startScale, float endScale, float alphaStart, float alphaEnd) {
        PropertyValuesHolder[] holders = new PropertyValuesHolder[] {
                PropertyValuesHolder.ofFloat(View.SCALE_X, startScale, endScale),
                PropertyValuesHolder.ofFloat(View.SCALE_Y, startScale, endScale),
                PropertyValuesHolder.ofFloat(View.ALPHA, alphaStart, alphaEnd)
        };

        ObjectAnimator animator = ObjectAnimator.ofPropertyValuesHolder(view, holders);
        animator.setDuration(1800L);
        animator.setRepeatCount(ValueAnimator.INFINITE);
        animator.setRepeatMode(ValueAnimator.REVERSE);
        animator.setStartDelay(delay);
        animator.setInterpolator(new android.view.animation.AccelerateDecelerateInterpolator());
        animator.start();
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private int getSignalColor(int level) {
        if (level >= -50) return Color.parseColor("#10B981");
        if (level >= -70) return Color.parseColor("#F59E0B");
        return Color.parseColor("#EF4444");
    }

    private void inspectCellularSecurity(NetworkCapabilities caps, LinkProperties linkProps) {
        String carrier = WifiSecurityMonitor.getCarrierName(this);
        mTvSsid.setText("Mobile Cellular (" + carrier + ")");
        mTvBssid.setText("Carrier Radio APN / Tower Link");

        String grade = "GRADE A • CELLULAR";
        int gradeColor = Color.parseColor("#10B981");
        mTvGradeBadge.setText(grade);
        mTvGradeBadge.setBackgroundTintList(ColorStateList.valueOf(gradeColor));

        mTvSecurityType.setText("3GPP Cellular Encryption (LTE/5G)");
        String summary = "Protected Mobile Cellular: Data transmitted over your cellular carrier is authenticated and encrypted via 3GPP standards. P2P Gateway is notified that uplink is Mobile Cellular.";
        mTvSecuritySummary.setText(summary);
        mTvSecuritySummary.setBackgroundTintList(ColorStateList.valueOf(Color.argb(30, Color.red(gradeColor), Color.green(gradeColor), Color.blue(gradeColor))));

        mTvCaptivePortal.setText("Clean (Direct Cellular Access)");
        mTvCaptivePortal.setTextColor(Color.parseColor("#10B981"));
        mTvMitmRisk.setText("Low Risk (Carrier Authenticated)");
        mTvMitmRisk.setTextColor(Color.parseColor("#10B981"));

        int downKbps = caps.getLinkDownstreamBandwidthKbps();
        if (downKbps > 0) {
            double mbps = downKbps / 1000.0;
            mTvSignal.setText(String.format(java.util.Locale.US, "Active • ~%.1f Mbps Downlink", mbps));
            int pct = (int) Math.min(100, Math.max(10, mbps * 2));
            mPbSignalMeter.setProgress(pct);
            mPbSignalMeter.setProgressTintList(ColorStateList.valueOf(Color.parseColor("#10B981")));
            mTvLinkSpeed.setText(String.format(java.util.Locale.US, "%.1f Mbps", mbps));
        } else {
            mTvSignal.setText("Active Cellular Link");
            mPbSignalMeter.setProgress(75);
            mPbSignalMeter.setProgressTintList(ColorStateList.valueOf(Color.parseColor("#10B981")));
            mTvLinkSpeed.setText("Carrier Dynamic");
        }

        mTvFrequency.setText("Cellular Radio Spectrum");
        mTvWifiStandard.setText("Mobile Broadband (4G LTE / 5G NR)");

        if (linkProps != null) {
            String localIp = "Unknown";
            for (LinkAddress addr : linkProps.getLinkAddresses()) {
                if (addr.getAddress() instanceof Inet4Address) {
                    localIp = addr.getAddress().getHostAddress();
                    mTvSubnet.setText(addr.getAddress().getHostAddress() + "/" + addr.getPrefixLength());
                    break;
                }
            }
            mTvLocalIp.setText(localIp);

            String gateway = "Carrier Gateway";
            for (RouteInfo route : linkProps.getRoutes()) {
                if (route.isDefaultRoute() && route.getGateway() != null) {
                    gateway = route.getGateway().getHostAddress();
                    break;
                }
            }
            mTvGateway.setText(gateway);

            List<InetAddress> dnsServers = linkProps.getDnsServers();
            if (dnsServers != null && !dnsServers.isEmpty()) {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < dnsServers.size(); i++) {
                    if (i > 0) sb.append(", ");
                    sb.append(dnsServers.get(i).getHostAddress());
                }
                mTvDns.setText(sb.toString());
            } else {
                mTvDns.setText("Carrier Cellular DNS");
            }
        }

        boolean vpnActive = CaptureService.isServiceActive();
        if (vpnActive) {
            mBtnShield.setText(R.string.wifi_shield_active);
            mBtnShield.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor("#10B981")));
        } else {
            mBtnShield.setText(R.string.wifi_shield_now);
            mBtnShield.setBackgroundTintList(null);
        }

        if (mCardPermissionNotice != null) {
            mCardPermissionNotice.setVisibility(View.GONE);
        }
    }

    private void setDisconnectedState() {
        mTvSsid.setText(R.string.wifi_not_connected);
        mTvBssid.setText("Not Available");
        mTvGradeBadge.setText("OFFLINE");
        mTvGradeBadge.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor("#64748B")));
        if (mIvWifiStatusIcon != null) {
            mIvWifiStatusIcon.setImageTintList(ColorStateList.valueOf(Color.parseColor("#64748B")));
        }
        if (mWifiIconContainer != null) {
            mWifiIconContainer.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor("#2064748B")));
        }
        mTvSecuritySummary.setText(R.string.wifi_not_connected_desc);
        mTvSecurityType.setText("None");
        mTvCaptivePortal.setText("None");
        mTvMitmRisk.setText("None");
        mTvSignal.setText("No Signal");
        mPbSignalMeter.setProgress(0);
        mTvFrequency.setText("None");
        mTvLinkSpeed.setText("0 Mbps");
        mTvWifiStandard.setText("Unknown");
        mTvLocalIp.setText("Not Assigned");
        mTvGateway.setText("Not Assigned");
        mTvSubnet.setText("Not Assigned");
        mTvDns.setText("Not Assigned");
    }

    private String getSignalLabel(int quality) {
        if (quality >= 80) return "Excellent";
        if (quality >= 60) return "Good";
        if (quality >= 40) return "Fair";
        return "Weak";
    }

    private String formatFrequency(int freq) {
        if (freq <= 0) return "Unknown";
        if (freq < 3000) {
            int ch = (freq - 2407) / 5;
            return String.format(Locale.US, "%.2f GHz (2.4 GHz Band • Ch %d)", freq / 1000.0, ch);
        } else if (freq < 5900) {
            int ch = (freq - 5000) / 5;
            return String.format(Locale.US, "%.2f GHz (5 GHz Band • Ch %d)", freq / 1000.0, ch);
        } else {
            return String.format(Locale.US, "%.2f GHz (6 GHz Wi-Fi 6E/7 Band)", freq / 1000.0);
        }
    }

    @SuppressLint("SwitchIntDef")
    private String getWifiStandardName(WifiInfo info) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            int std = info.getWifiStandard();
            switch (std) {
                case 8: // ScanResult.WIFI_STANDARD_11BE
                    return "Wi-Fi 7 (802.11be)";
                case 6: // ScanResult.WIFI_STANDARD_11AX
                    return "Wi-Fi 6 (802.11ax)";
                case 5: // ScanResult.WIFI_STANDARD_11AC
                    return "Wi-Fi 5 (802.11ac)";
                case 4: // ScanResult.WIFI_STANDARD_11N
                    return "Wi-Fi 4 (802.11n)";
                case 3: // ScanResult.WIFI_STANDARD_11G
                    return "802.11g Legacy";
                case 2: // ScanResult.WIFI_STANDARD_11A
                    return "802.11a Legacy";
                case 1: // ScanResult.WIFI_STANDARD_11B
                    return "802.11b Legacy";
            }
        }
        return (info.getFrequency() > 4000) ? "Wi-Fi 5 (802.11ac)" : "Wi-Fi 4 (802.11n)";
    }

    private void requestWifiPermission() {
        boolean hasPerm = WifiSecurityMonitor.hasLocationPermission(this);
        if (hasPerm) {
            if (!WifiSecurityMonitor.isLocationServiceEnabled(this)) {
                try {
                    startActivity(new Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS));
                } catch (Exception e) {
                    Toast.makeText(this, "Please turn on Location in quick settings", Toast.LENGTH_SHORT).show();
                }
            } else {
                inspectWifiSecurity();
            }
            return;
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            boolean previouslyRequested = getSharedPreferences("wifi_sec_prefs", MODE_PRIVATE)
                    .getBoolean("perm_requested", false);
            if (previouslyRequested && !ActivityCompat.shouldShowRequestPermissionRationale(this, Manifest.permission.ACCESS_FINE_LOCATION)) {
                Toast.makeText(this, "Please enable Location permission in App Settings", Toast.LENGTH_LONG).show();
                try {
                    Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
                    intent.setData(Uri.parse("package:" + getPackageName()));
                    startActivity(intent);
                } catch (Exception ignored) {
                }
                return;
            }
            getSharedPreferences("wifi_sec_prefs", MODE_PRIVATE).edit().putBoolean("perm_requested", true).apply();
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ActivityCompat.requestPermissions(this,
                    new String[]{
                            Manifest.permission.ACCESS_FINE_LOCATION,
                            Manifest.permission.ACCESS_COARSE_LOCATION,
                            Manifest.permission.NEARBY_WIFI_DEVICES
                    },
                    REQ_WIFI_PERM);
        } else {
            ActivityCompat.requestPermissions(this,
                    new String[]{
                            Manifest.permission.ACCESS_FINE_LOCATION,
                            Manifest.permission.ACCESS_COARSE_LOCATION
                    },
                    REQ_WIFI_PERM);
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == REQ_WIFI_PERM) {
            boolean granted = false;
            for (int res : grantResults) {
                if (res == PackageManager.PERMISSION_GRANTED) {
                    granted = true;
                    break;
                }
            }
            if (granted) {
                Toast.makeText(this, "Permission granted. Refreshing Wi-Fi diagnostics...", Toast.LENGTH_SHORT).show();
            } else {
                Toast.makeText(this, "Permission denied. SSID & AP details will remain hidden.", Toast.LENGTH_SHORT).show();
            }
        }
        inspectWifiSecurity();
    }
}
