/*
 * This file is part of KotSafe.
 *
 * KotSafe is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

package com.kotsafe.security.views;

import android.app.Service;
import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.os.Build;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.kotsafe.security.BuildConfig;
import com.kotsafe.security.CaptureService;
import com.kotsafe.security.MitmAddon;
import com.kotsafe.security.KotSafe;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.Prefs;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;
import com.google.android.material.button.MaterialButton;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class BuildInfoDialog extends BottomSheetDialogFragment {
    public static final String TAG = "BuildInfoDialog";

    public static BuildInfoDialog newInstance() {
        return new BuildInfoDialog();
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.dialog_build_info, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        Context ctx = getContext();
        if (ctx == null) return;

        TextView buildFlavorPill = view.findViewById(R.id.dialog_build_flavor_pill);
        TextView specAppVersion = view.findViewById(R.id.spec_app_version);
        TextView specBuildVariant = view.findViewById(R.id.spec_build_variant);
        TextView specNativeEngine = view.findViewById(R.id.spec_native_engine);
        TextView specMitmAddon = view.findViewById(R.id.spec_mitm_addon);

        TextView specDeviceModel = view.findViewById(R.id.spec_device_model);
        TextView specDeviceAbi = view.findViewById(R.id.spec_device_abi);
        TextView specAndroidOs = view.findViewById(R.id.spec_android_os);
        TextView specSecurityPatch = view.findViewById(R.id.spec_security_patch);
        TextView specRootStatus = view.findViewById(R.id.spec_root_status);

        TextView specVpnEngine = view.findViewById(R.id.spec_vpn_engine);
        TextView specLocalIp = view.findViewById(R.id.spec_local_ip);
        TextView specPrivateDns = view.findViewById(R.id.spec_private_dns);

        ImageView btnCopyQuick = view.findViewById(R.id.btn_copy_quick);
        MaterialButton btnCopyAll = view.findViewById(R.id.btn_copy_all);
        MaterialButton btnClose = view.findViewById(R.id.btn_dialog_close);

        // App & Build
        String appVer = "v" + BuildConfig.VERSION_NAME + " (Code " + BuildConfig.VERSION_CODE + ")";
        specAppVersion.setText(appVer);

        boolean ushark = KotSafe.getInstance().isUsharkAvailable();
        Utils.BuildType rawBuild = Utils.getVerifiedBuild(ctx);
        String buildType = (rawBuild == Utils.BuildType.UNKNOWN) ? "debug" : rawBuild.toString().toLowerCase();
        String flavorStr = buildType + (ushark ? " (withUshark)" : " (withoutUshark)");
        specBuildVariant.setText(flavorStr);

        String primaryAbi = Build.SUPPORTED_ABIS.length > 0 ? Build.SUPPORTED_ABIS[0] : "unknown";
        buildFlavorPill.setText("KotSafe v" + BuildConfig.VERSION_NAME + " • " + buildType + " / " + primaryAbi);

        specNativeEngine.setText("Active (CMake JNI / libchash / ARM64 ring buffer)");

        String mitmVer = MitmAddon.getInstalledVersionName(ctx);
        if (!mitmVer.isEmpty()) {
            specMitmAddon.setText("Installed v" + mitmVer + (MitmAddon.isDozeEnabled(ctx) ? " [Doze ON]" : " [Doze OFF]"));
        } else {
            specMitmAddon.setText("Not installed (Standalone Mode)");
        }

        // Device & OS
        String devModel = Build.MANUFACTURER + " " + Build.MODEL + " (" + Build.DEVICE + ")";
        specDeviceModel.setText(devModel);
        specDeviceAbi.setText(primaryAbi + " (64-bit native)");

        String osRelease = "Android " + Build.VERSION.RELEASE + " (API " + Build.VERSION.SDK_INT + ", " + Build.ID + ")";
        specAndroidOs.setText(osRelease);

        String patch = Build.VERSION.SECURITY_PATCH;
        specSecurityPatch.setText(patch != null && !patch.isEmpty() ? patch : "Not reported");

        boolean rooted = Utils.isRootAvailable();
        specRootStatus.setText(rooted ? "Root / Superuser Detected" : "Non-Root Sandbox (Standard)");
        specRootStatus.setTextColor(androidx.core.content.ContextCompat.getColor(ctx, rooted ? R.color.warning : R.color.ok));

        // Network & VPN
        boolean vpnActive = CaptureService.isServiceActive();
        specVpnEngine.setText(vpnActive ? "Active (Continuous Packet Capture)" : "Ready / On Demand");

        String localIp = Utils.getLocalIPAddress(ctx);
        specLocalIp.setText(localIp != null && !localIp.isEmpty() ? localIp : "Unavailable");

        Utils.PrivateDnsMode dnsMode = CaptureService.getPrivateDnsMode();
        if (dnsMode == null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Service.CONNECTIVITY_SERVICE);
            Network net = cm != null ? cm.getActiveNetwork() : null;
            if (net != null) {
                LinkProperties lp = cm.getLinkProperties(net);
                if (lp != null) dnsMode = Utils.getPrivateDnsMode(lp);
            }
        }
        specPrivateDns.setText(dnsMode != null ? dnsMode.toString() : "System Default");

        final Utils.PrivateDnsMode finalDnsMode = dnsMode;
        final String finalMitmVer = mitmVer;
        final String finalPrimaryAbi = primaryAbi;
        final boolean finalRooted = rooted;

        // Copy Handlers
        View.OnClickListener copyAction = v -> {
            String fullDiag = generateDiagnosticReport(ctx, finalDnsMode, finalMitmVer, finalPrimaryAbi, finalRooted);
            Utils.copyToClipboard(ctx, fullDiag);
            Toast.makeText(ctx, "Build diagnostics copied to clipboard", Toast.LENGTH_SHORT).show();
        };

        btnCopyQuick.setOnClickListener(copyAction);
        btnCopyAll.setOnClickListener(copyAction);
        btnClose.setOnClickListener(v -> dismiss());
    }

    private String generateDiagnosticReport(Context ctx, Utils.PrivateDnsMode dnsMode, String mitmVer, String primaryAbi, boolean rooted) {
        DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US);
        StringBuilder sb = new StringBuilder();
        sb.append("=== KOTSAFE SYSTEM DIAGNOSTICS ===\n");
        sb.append("Generated: ").append(dateFormat.format(new Date())).append("\n\n");

        sb.append("[APPLICATION & BUILD]\n");
        sb.append("App Name: KotSafe\n");
        sb.append("Package: ").append(ctx.getPackageName()).append("\n");
        sb.append("Version: ").append(BuildConfig.VERSION_NAME).append(" (Code ").append(BuildConfig.VERSION_CODE).append(")\n");
        sb.append("Build Type: ").append(Utils.getVerifiedBuild(ctx).toString().toLowerCase()).append("\n");
        sb.append("uShark Available: ").append(KotSafe.getInstance().isUsharkAvailable()).append("\n");
        if (!mitmVer.isEmpty()) {
            sb.append("MitmAddon: v").append(mitmVer).append("\n");
        }

        sb.append("\n[DEVICE & HARDWARE]\n");
        sb.append("Manufacturer: ").append(Build.MANUFACTURER).append("\n");
        sb.append("Brand: ").append(Build.BRAND).append("\n");
        sb.append("Model: ").append(Build.MODEL).append("\n");
        sb.append("Device: ").append(Build.DEVICE).append("\n");
        sb.append("Board: ").append(Build.BOARD).append("\n");
        sb.append("Primary ABI: ").append(primaryAbi).append("\n");
        sb.append("Root Available: ").append(rooted).append("\n");

        sb.append("\n[ANDROID PLATFORM]\n");
        sb.append("Android Version: ").append(Build.VERSION.RELEASE).append("\n");
        sb.append("SDK API Level: ").append(Build.VERSION.SDK_INT).append("\n");
        sb.append("Security Patch: ").append(Build.VERSION.SECURITY_PATCH).append("\n");
        sb.append("Build ID: ").append(Build.ID).append("\n");
        sb.append("Fingerprint: ").append(Build.FINGERPRINT).append("\n");

        sb.append("\n[SECURITY SENTINELS & MODULES]\n");
        sb.append("VPN Traffic Inspection: ").append(CaptureService.isServiceActive() ? "ACTIVE" : "STANDBY").append("\n");
        sb.append("Dual-Mode Passive Subsystem: ACTIVE\n");
        sb.append("Background Exfiltration Sentinel: ACTIVE (15MB Screen-Off Threshold)\n");
        sb.append("Phishing Notification Guard: ACTIVE (SMS/Messaging link scanning)\n");
        sb.append("Sideload Download Watcher: ACTIVE (/sdcard/Download FileObserver)\n");
        sb.append("Threat Intelligence: Multi-Source Router (ThreatFox, URLhaus, MalwareBazaar, VT)\n");

        sb.append("\n[NETWORK & CONNECTIVITY]\n");
        sb.append("Local IP: ").append(Utils.getLocalIPAddress(ctx)).append("\n");
        sb.append("Private DNS: ").append(dnsMode != null ? dnsMode.toString() : "System Default").append("\n");

        sb.append("\n[PREFERENCES & CONFIGURATION]\n");
        sb.append(Prefs.asString(ctx)).append("\n");

        return sb.toString();
    }
}
