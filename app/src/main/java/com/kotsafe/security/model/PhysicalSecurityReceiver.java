/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * PhysicalSecurityReceiver
 * ========================
 * Listens for real-time physical events:
 * 1. Charger Unplug (Anti-Theft Alarm while device is locked)
 * 2. USB Peripheral Attached / Detached (BadUSB injection defense)
 * 3. USB State Change (Juice Jacking: unauthorized MTP/ADB data channel)
 * 4. SIM State Changed (SIM Swapping defense)
 * Dispatches normalized events to SecurityEventBus.
 */

package com.kotsafe.security.model;

import android.app.KeyguardManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.hardware.usb.UsbManager;

import com.kotsafe.security.Log;
import com.kotsafe.security.security.event.EventTypes;
import com.kotsafe.security.security.event.SecurityEvent;
import com.kotsafe.security.security.event.SecurityEventBus;
import com.kotsafe.security.security.policy.SecurityModes;
import com.kotsafe.security.security.response.ResponseEngine;

public class PhysicalSecurityReceiver extends BroadcastReceiver {
    private static final String TAG = "PhysicalSecurityReceiver";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null || intent.getAction() == null) return;
        String action = intent.getAction();

        // Vector 1: Charger Unplugged while Phone is Locked
        if (Intent.ACTION_POWER_DISCONNECTED.equals(action)) {
            KeyguardManager km = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
            boolean isLocked = (km != null && km.isDeviceLocked());

            Log.w(TAG, "Charger disconnected. Device locked: " + isLocked);

            SecurityEvent.Severity severity = isLocked ? SecurityEvent.Severity.HIGH : SecurityEvent.Severity.INFO;
            String eventType = isLocked ? EventTypes.PHYSICAL_THEFT_TRIGGER : EventTypes.CHARGER_STATE_CHANGED;

            SecurityEvent.Builder eventBuilder = new SecurityEvent.Builder(SecurityEvent.Domain.PHYSICAL, eventType)
                    .severity(severity)
                    .title(isLocked ? "Anti-Theft Alert: Power Disconnected" : "Power Disconnected")
                    .description(isLocked ? "Power cable was disconnected while device was locked." : "Power disconnected by user.")
                    .attribute("is_locked", isLocked);

            SecurityEventBus.getInstance().publish(eventBuilder.build());

            if (isLocked && SecurityModes.getActiveMode(context) == SecurityModes.Mode.ANTI_THEFT) {
                ResponseEngine.getInstance(context).triggerAlarmSiren();
            }
        }

        // Vector 2: Hardware USB Device Plugged In (BadUSB Inspection)
        else if (UsbManager.ACTION_USB_DEVICE_ATTACHED.equals(action)) {
            Log.i(TAG, "Hardware USB peripheral attached. Auditing BadUSB exposure.");

            SecurityEvent.Builder eventBuilder = new SecurityEvent.Builder(SecurityEvent.Domain.PHYSICAL, EventTypes.USB_ATTACHED)
                    .severity(SecurityEvent.Severity.INFO)
                    .title("USB Peripheral Attached")
                    .description("External USB hardware device was plugged in.");
            SecurityEventBus.getInstance().publish(eventBuilder.build());

            PhysicalSecurityEngine.PhysicalSecurityReport report = PhysicalSecurityEngine.evaluate(context);
            if (report.isExternalKeyboardAttached) {
                String devList = String.join(", ", report.attachedUsbDevices);
                Log.e(TAG, "BadUSB / Rubber Ducky HID Keyboard Attached: " + devList);

                SecurityEvent.Builder badUsbEvent = new SecurityEvent.Builder(SecurityEvent.Domain.PHYSICAL, EventTypes.BAD_USB_HID_DETECTED)
                        .severity(SecurityEvent.Severity.CRITICAL)
                        .title("BadUSB Keystroke Device Attached")
                        .description("Unauthorized external alphanumeric keyboard detected: " + devList)
                        .attribute("devices", devList);
                SecurityEventBus.getInstance().publish(badUsbEvent.build());

                // Vector 2 Active Defense Interception:
                PhysicalSecurityManager psm = PhysicalSecurityManager.getInstance(context);
                if (psm.isBadUsbAutoLockEnabled()) {
                    Log.w(TAG, "[ACTIVE INTERCEPTION] BadUSB detected (" + devList + ")! Neutralizing keystroke injection immediately.");
                    // 1. Force hardware screen lock (if admin active) OR launch zero-permission focus trap overlay
                    psm.lockOrTrapFocus("BadUSB / Rubber Ducky Attached (" + devList + ")");
                    // 2. Immediate Firewall Lockdown: sever outbound socket flows
                    psm.setFirewallLockdownEnabled(true);
                    // 3. Trigger audible alarm
                    ResponseEngine.getInstance(context).triggerAlarmSiren();
                }
            }
        }

        // Vector 3: USB State Changed — Juice-Jacking Detection
        // Fires whenever USB connection mode changes (charging-only → MTP/ADB/PTP data channel)
        else if (UsbJuiceJackingDetector.ACTION_USB_STATE.equals(action)) {
            boolean alerted = UsbJuiceJackingDetector.inspect(context, intent);
            if (alerted) {
                Log.e(TAG, "JUICE JACKING: unauthorized USB data channel is active on charging cable.");
            }
        }

        // Vector 4: SIM Card Removal / Swap
        else if ("android.intent.action.SIM_STATE_CHANGED".equals(action)) {
            Log.w(TAG, "SIM card state change broadcast received.");
            PhysicalSecurityEngine.PhysicalSecurityReport report = PhysicalSecurityEngine.evaluate(context);
            if (!report.isSimCardPresent) {
                SecurityEvent.Builder simEvent = new SecurityEvent.Builder(SecurityEvent.Domain.PHYSICAL, EventTypes.SIM_STATE_CHANGED)
                        .severity(SecurityEvent.Severity.HIGH)
                        .title("SIM Card Ejected / Absent")
                        .description("Physical SIM card was removed or altered on the device.");
                SecurityEventBus.getInstance().publish(simEvent.build());
            }
        }
    }
}
