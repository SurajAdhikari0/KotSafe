/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * EventTypes
 * ==========
 * Standardized security event categories across Firewall, Antivirus/EDR,
 * and Physical Security domains.
 */

package com.kotsafe.security.security.event;

public final class EventTypes {
    private EventTypes() {}

    // 1. Firewall & Network Events
    public static final String NETWORK_CONNECTION = "NETWORK_CONNECTION";
    public static final String NETWORK_BEACON = "NETWORK_BEACON";               // NEW: C2 beaconing / RAT heartbeat
    public static final String DNS_QUERY = "DNS_QUERY";
    public static final String MALICIOUS_IP = "MALICIOUS_IP";
    public static final String MALICIOUS_DOMAIN = "MALICIOUS_DOMAIN";
    public static final String TLS_FINGERPRINT_JA3 = "TLS_FINGERPRINT_JA3";
    public static final String FIREWALL_BLOCK = "FIREWALL_BLOCK";
    public static final String UNUSUAL_TRAFFIC_BURST = "UNUSUAL_TRAFFIC_BURST";

    // 2. Antivirus & EDR Events
    public static final String APK_DETECTED = "APK_DETECTED";
    public static final String APP_INSTALLED = "APP_INSTALLED";
    public static final String APP_UPDATED = "APP_UPDATED";
    public static final String MALWARE_HASH = "MALWARE_HASH";
    public static final String YARA_MATCH = "YARA_MATCH";
    public static final String SUSPICIOUS_PERMISSIONS = "SUSPICIOUS_PERMISSIONS";
    public static final String CERTIFICATE_ANOMALY = "CERTIFICATE_ANOMALY";
    public static final String APP_BEHAVIOR_ANOMALY = "APP_BEHAVIOR_ANOMALY";
    public static final String FILE_THREAT = "FILE_THREAT";

    // 3. Physical Security Events
    public static final String USB_ATTACHED = "USB_ATTACHED";
    public static final String USB_DETACHED = "USB_DETACHED";
    public static final String BAD_USB_HID_DETECTED = "BAD_USB_HID_DETECTED";
    public static final String USB_JUICE_JACKING = "USB_JUICE_JACKING";         // NEW: Data-line active during charging
    public static final String ADB_STATE_CHANGED = "ADB_STATE_CHANGED";
    public static final String SIM_STATE_CHANGED = "SIM_STATE_CHANGED";
    public static final String CHARGER_STATE_CHANGED = "CHARGER_STATE_CHANGED";
    public static final String DEVICE_POSTURE_CHANGED = "DEVICE_POSTURE_CHANGED";
    public static final String PHYSICAL_THEFT_TRIGGER = "PHYSICAL_THEFT_TRIGGER";

    // 5. Wi-Fi Attack Events
    public static final String WIFI_EVIL_TWIN = "WIFI_EVIL_TWIN";               // NEW: Rogue duplicate AP
    public static final String WIFI_ARP_SPOOF = "WIFI_ARP_SPOOF";               // NEW: Gateway MAC changed
    public static final String WIFI_CAPTIVE_PORTAL = "WIFI_CAPTIVE_PORTAL";     // Existing (extended)

    // 6. App Privacy Scorecard Events
    public static final String APP_PRIVACY_SCORE = "APP_PRIVACY_SCORE";         // NEW: Score computed for an app

    // 4. Correlated & Composite Incidents
    public static final String CORRELATED_INCIDENT = "CORRELATED_INCIDENT";
    public static final String POLICY_VIOLATION = "POLICY_VIOLATION";
    public static final String REMEDIATION_EXECUTED = "REMEDIATION_EXECUTED";
}
