/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * EventNormalizer
 * ===============
 * Translates raw subsystem callbacks into normalized SecurityEvent models
 * and dispatches them onto the central SecurityEventBus.
 */

package com.kotsafe.security.security.event;

import android.content.Context;

import com.kotsafe.security.Utils;
import com.kotsafe.security.model.AppIntelligenceEngine;
import com.kotsafe.security.model.ConnectionDescriptor;
import com.kotsafe.security.model.PhysicalSecurityEngine;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class EventNormalizer {
    private static volatile EventNormalizer sInstance;
    private final Context mContext;
    private final Map<Integer, String> mUidCorrelationMap = new ConcurrentHashMap<>();

    public static EventNormalizer getInstance(Context context) {
        if (sInstance == null) {
            synchronized (EventNormalizer.class) {
                if (sInstance == null) {
                    sInstance = new EventNormalizer(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    private EventNormalizer(Context context) {
        mContext = context;
    }

    // 1. Network Events
    public void publishNetworkConnection(ConnectionDescriptor conn, boolean isBlocked, String blockReason) {
        if (conn == null) return;

        SecurityEvent.Severity severity = isBlocked ? SecurityEvent.Severity.HIGH : SecurityEvent.Severity.INFO;
        String eventType = isBlocked ? EventTypes.FIREWALL_BLOCK : EventTypes.NETWORK_CONNECTION;
        String title = isBlocked ? "Firewall Blocked Connection: " + conn.dst_ip : "Outbound Socket: " + conn.dst_ip;

        String subjectPkg = "";
        try {
            String[] pkgs = mContext.getPackageManager().getPackagesForUid(conn.uid);
            if (pkgs != null && pkgs.length > 0) {
                subjectPkg = pkgs[0];
            }
        } catch (Exception ignored) {}

        String protoStr = (conn.l7proto != null && !conn.l7proto.isEmpty()) ? conn.l7proto : ("IP_PROTO_" + conn.ipproto);

        SecurityEvent.Builder builder = new SecurityEvent.Builder(SecurityEvent.Domain.NETWORK, eventType)
                .severity(severity)
                .title(title)
                .description("Destination: " + conn.dst_ip + ":" + conn.dst_port + " | Protocol: " + protoStr)
                .subject(subjectPkg, conn.uid)
                .attribute("dst_ip", conn.dst_ip)
                .attribute("dst_port", conn.dst_port)
                .attribute("protocol", protoStr)
                .attribute("is_blocked", isBlocked);

        if (conn.info != null && !conn.info.isEmpty()) {
            builder.attribute("domain", conn.info);
        }
        if (blockReason != null) {
            builder.attribute("block_reason", blockReason);
        }

        SecurityEventBus.getInstance().publish(builder.build());
    }

    public void publishDnsQuery(String domain, String clientPackage, int uid, boolean isBlocked) {
        SecurityEvent.Severity severity = isBlocked ? SecurityEvent.Severity.HIGH : SecurityEvent.Severity.INFO;
        SecurityEvent.Builder builder = new SecurityEvent.Builder(SecurityEvent.Domain.NETWORK, EventTypes.DNS_QUERY)
                .severity(severity)
                .title((isBlocked ? "DNS Sinkholed: " : "DNS Query: ") + domain)
                .description("Domain lookup for " + domain + (isBlocked ? " (Sinkholed by KotSafe)" : " (Resolved)"))
                .subject(clientPackage, uid)
                .attribute("domain", domain)
                .attribute("is_blocked", isBlocked);

        SecurityEventBus.getInstance().publish(builder.build());
    }

    // 2. Antivirus & EDR Events
    public void publishAppScanResult(AppIntelligenceEngine.AppSecurityProfile profile, String verdict, int riskScore) {
        if (profile == null) return;

        SecurityEvent.Severity severity;
        if ("MALICIOUS".equals(verdict)) severity = SecurityEvent.Severity.CRITICAL;
        else if ("SUSPICIOUS".equals(verdict)) severity = SecurityEvent.Severity.HIGH;
        else if ("MONITOR".equals(verdict)) severity = SecurityEvent.Severity.MEDIUM;
        else severity = SecurityEvent.Severity.INFO;

        SecurityEvent.Builder builder = new SecurityEvent.Builder(SecurityEvent.Domain.ANTIVIRUS, EventTypes.APK_DETECTED)
                .severity(severity)
                .title("App Scanned: " + profile.appName)
                .description("Verdict: " + verdict + " (Risk Score: " + riskScore + "/100)")
                .subject(profile.packageName, profile.uid)
                .attribute("app_name", profile.appName)
                .attribute("sha256", profile.sha256)
                .attribute("is_sideloaded", profile.isSideloaded)
                .attribute("is_vetted", profile.isVettedStoreInstall)
                .attribute("installer", profile.installerPackage)
                .attribute("risk_score", riskScore)
                .attribute("verdict", verdict);

        SecurityEventBus.getInstance().publish(builder.build());
    }

    // 3. Physical Security Events
    public void publishPhysicalReport(PhysicalSecurityEngine.PhysicalSecurityReport report) {
        if (report == null) return;

        SecurityEvent.Severity severity;
        if ("CRITICAL".equals(report.physicalGrade)) severity = SecurityEvent.Severity.CRITICAL;
        else if ("HIGH_RISK".equals(report.physicalGrade)) severity = SecurityEvent.Severity.HIGH;
        else if ("MODERATE".equals(report.physicalGrade)) severity = SecurityEvent.Severity.MEDIUM;
        else severity = SecurityEvent.Severity.INFO;

        SecurityEvent.Builder builder = new SecurityEvent.Builder(SecurityEvent.Domain.PHYSICAL, EventTypes.DEVICE_POSTURE_CHANGED)
                .severity(severity)
                .title("Physical Security Posture: " + report.physicalGrade)
                .description("Physical Posture Score: " + report.physicalScore + "/100")
                .attribute("score", report.physicalScore)
                .attribute("grade", report.physicalGrade)
                .attribute("is_usb_connected", report.isUsbConnected)
                .attribute("is_adb_enabled", report.isAdbOverUsbEnabled)
                .attribute("is_keyboard_attached", report.isExternalKeyboardAttached)
                .attribute("is_sim_present", report.isSimCardPresent)
                .attribute("is_encrypted", report.isDeviceEncrypted);

        SecurityEventBus.getInstance().publish(builder.build());
    }

    public void publishBadUsbDetected(String deviceName) {
        SecurityEvent.Builder builder = new SecurityEvent.Builder(SecurityEvent.Domain.PHYSICAL, EventTypes.BAD_USB_HID_DETECTED)
                .severity(SecurityEvent.Severity.CRITICAL)
                .title("BadUSB / Rubber Ducky Detected")
                .description("Unauthorized external alphanumeric keyboard detected: " + deviceName)
                .attribute("device_name", deviceName);

        SecurityEventBus.getInstance().publish(builder.build());
    }
}
