/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * SecurityPolicyEngine
 * ====================
 * Sits between the Risk/Correlation Engine and the ResponseEngine.
 * Applies configurable policy evaluation taking into account:
 * - Active SecurityMode (Standard, Strict, Public Wi-Fi, USB Shield, Anti-Theft)
 * - Device Security Posture score
 * - Threat Severity and Confidence
 */

package com.kotsafe.security.security.policy;

import android.content.Context;

import com.kotsafe.security.Log;
import com.kotsafe.security.security.event.EventTypes;
import com.kotsafe.security.security.event.SecurityEvent;
import com.kotsafe.security.security.event.SecurityEventBus;
import com.kotsafe.security.security.response.ResponseEngine;

public class SecurityPolicyEngine implements SecurityEventBus.SecurityEventListener {
    private static final String TAG = "SecurityPolicyEngine";

    private static volatile SecurityPolicyEngine sInstance;
    private final Context mContext;
    private final ResponseEngine mResponseEngine;

    public static SecurityPolicyEngine getInstance(Context context) {
        if (sInstance == null) {
            synchronized (SecurityPolicyEngine.class) {
                if (sInstance == null) {
                    sInstance = new SecurityPolicyEngine(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    private SecurityPolicyEngine(Context context) {
        mContext = context;
        mResponseEngine = ResponseEngine.getInstance(context);
        SecurityEventBus.getInstance().subscribe(this);
    }

    @Override
    public void onSecurityEvent(SecurityEvent event) {
        if (event == null) return;
        evaluatePolicy(event);
    }

    public void evaluatePolicy(SecurityEvent event) {
        SecurityModes.Mode activeMode = SecurityModes.getActiveMode(mContext);
        String eventType = event.getEventType();
        SecurityEvent.Severity severity = event.getSeverity();
        String pkg = event.getSubjectPackage();

        Log.d(TAG, "Evaluating policy under mode [" + activeMode + "] for event " + eventType + " (" + severity + ")");

        // Policy Rule 1: Immediate isolation ONLY on verified CRITICAL correlated incidents or confirmed malware
        // Never isolate host applications merely because a network packet/tracker was blocked by the firewall!
        if (severity == SecurityEvent.Severity.CRITICAL && pkg != null && !pkg.isEmpty()) {
            if (EventTypes.CORRELATED_INCIDENT.equals(eventType)
                    || EventTypes.MALWARE_HASH.equals(eventType)
                    || EventTypes.YARA_MATCH.equals(eventType)) {
                mResponseEngine.isolateApp(pkg, "Critical Policy Rule Violation: " + event.getTitle());
                mResponseEngine.requestUninstall(pkg);
                return;
            }
        }

        // Policy Rule 2: Strict Mode Zero-Tolerance (applied only to verified malware or system threat events)
        if (activeMode == SecurityModes.Mode.STRICT) {
            if (severity == SecurityEvent.Severity.HIGH && pkg != null && !pkg.isEmpty()) {
                if (EventTypes.CORRELATED_INCIDENT.equals(eventType)
                        || EventTypes.MALWARE_HASH.equals(eventType)
                        || EventTypes.YARA_MATCH.equals(eventType)) {
                    mResponseEngine.isolateApp(pkg, "Strict Security Mode enforcement on HIGH severity event");
                }
            }
        }

        // Policy Rule 3: Anti-Theft Guard
        if (activeMode == SecurityModes.Mode.ANTI_THEFT) {
            if (EventTypes.PHYSICAL_THEFT_TRIGGER.equals(eventType) || EventTypes.SIM_STATE_CHANGED.equals(eventType)) {
                mResponseEngine.triggerAlarmSiren();
            }
        }

        // Policy Rule 4: USB & Hardware Shield
        if (activeMode == SecurityModes.Mode.USB_HARDWARE_SHIELD) {
            if (EventTypes.BAD_USB_HID_DETECTED.equals(eventType)) {
                mResponseEngine.triggerAlarmSiren();
                if (pkg != null && !pkg.isEmpty()) {
                    mResponseEngine.isolateApp(pkg, "USB Shield: Protected against BadUSB exfiltration");
                }
            }
        }

        // Policy Rule 5: Threat Intel Malicious IP Block
        if (EventTypes.MALICIOUS_IP.equals(eventType)) {
            String ip = event.getAttribute("indicator", null);
            if (ip != null && !ip.isEmpty()) {
                mResponseEngine.blockDestination(ip, "Automated TI Block Policy");
            }
        }
    }
}
