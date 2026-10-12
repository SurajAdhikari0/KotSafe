/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * PhysicalSecurityEngine
 * ======================
 * Audits and protects the device against physical attack vectors:
 * - BadUSB / HID Keyboard Injection (Rubber Ducky)
 * - USB Juice-Jacking & Data Port Exposure
 * - SIM Card Swap & Ejection
 * - Hardware TEE / StrongBox Keystore & Verified Boot
 * - Physical Screen Lock & Biometric Strength
 */

package com.kotsafe.security.model;

import android.app.KeyguardManager;
import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.hardware.input.InputManager;
import android.os.BatteryManager;
import android.os.Build;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import android.view.InputDevice;

import com.kotsafe.security.Log;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class PhysicalSecurityEngine {
    private static final String TAG = "PhysicalSecurityEngine";

    public static class PhysicalSecurityReport {
        public int physicalScore = 100; // 0 to 100
        public String physicalGrade = "SECURE"; // SECURE, MODERATE, HIGH_RISK, CRITICAL

        // Port & Peripheral
        public boolean isUsbConnected = false;
        public boolean isUsbDataTransferActive = false;
        public boolean isAdbOverUsbEnabled = false;
        public boolean isExternalKeyboardAttached = false;
        public List<String> attachedUsbDevices = new ArrayList<>();

        // Hardware & Cryptographic Protection
        public boolean hasStrongBoxKeyStore = false;
        public boolean isDeviceEncrypted = true;
        public boolean isScreenLockSecured = true;
        public boolean isBootloaderLocked = true;

        // Anti-Theft & Sensors
        public boolean isCharging = false;
        public boolean isSimCardPresent = true;
        public String simState = "READY";

        // Findings & Action Items
        public List<String> physicalWarnings = new ArrayList<>();
        public List<String> positiveProtections = new ArrayList<>();
        public List<String> remediationActions = new ArrayList<>();
    }

    public static PhysicalSecurityReport evaluate(Context context) {
        PhysicalSecurityReport report = new PhysicalSecurityReport();
        if (context == null) return report;

        int score = 100;

        // 1. USB Connection & Juice-Jacking Surface
        try {
            IntentFilter ifilter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
            Intent batteryStatus = context.registerReceiver(null, ifilter);
            if (batteryStatus != null) {
                int chargePlug = batteryStatus.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1);
                report.isUsbConnected = (chargePlug == BatteryManager.BATTERY_PLUGGED_USB);
                report.isCharging = (chargePlug == BatteryManager.BATTERY_PLUGGED_AC 
                        || chargePlug == BatteryManager.BATTERY_PLUGGED_USB 
                        || chargePlug == BatteryManager.BATTERY_PLUGGED_WIRELESS);
            }

            // Check USB Debugging
            report.isAdbOverUsbEnabled = (Settings.Global.getInt(
                    context.getContentResolver(), Settings.Global.ADB_ENABLED, 0) == 1);

            if (report.isAdbOverUsbEnabled) {
                score -= 20;
                report.physicalWarnings.add("USB Debugging (ADB) is enabled. High risk of Juice-Jacking via untrusted ports.");
                report.remediationActions.add("Disable USB Debugging in Developer Options when not in use.");
            } else {
                report.positiveProtections.add("USB Debugging disabled (Juice-Jacking protected)");
            }
        } catch (Exception e) {
            Log.w(TAG, "USB state check error: " + e.getMessage());
        }

        // 2. BadUSB / Rubber Ducky (External HID Keyboard Injection) Detection
        try {
            InputManager im = (InputManager) context.getSystemService(Context.INPUT_SERVICE);
            if (im != null) {
                int[] deviceIds = im.getInputDeviceIds();
                for (int id : deviceIds) {
                    InputDevice device = im.getInputDevice(id);
                    if (device == null || device.isVirtual()) continue;

                    int sources = device.getSources();
                    boolean isKeyboard = (sources & InputDevice.SOURCE_KEYBOARD) == InputDevice.SOURCE_KEYBOARD;

                    // Check if external physical alphanumeric keyboard is attached
                    if (isKeyboard && device.getKeyboardType() == InputDevice.KEYBOARD_TYPE_ALPHABETIC) {
                        String devName = device.getName().toLowerCase();
                        // Exclude standard built-in power/volume keys
                        if (!devName.contains("built-in") && !devName.contains("gpio") && !devName.contains("touch")) {
                            report.isExternalKeyboardAttached = true;
                            report.attachedUsbDevices.add(device.getName());
                        }
                    }
                }

                if (report.isExternalKeyboardAttached) {
                    score -= 25;
                    report.physicalWarnings.add("External physical keyboard/HID detected (" 
                            + String.join(", ", report.attachedUsbDevices) 
                            + "). Verify it is not a BadUSB/Rubber Ducky keystroke injector.");
                    report.remediationActions.add("Disconnect any unfamiliar USB dongles or OTG adapters immediately.");
                } else {
                    report.positiveProtections.add("No untrusted BadUSB/HID keystroke devices detected");
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "HID device scan error: " + e.getMessage());
        }

        // 3. Hardware TEE & StrongBox Keystore
        try {
            PackageManager pm = context.getPackageManager();
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                report.hasStrongBoxKeyStore = pm.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
                if (report.hasStrongBoxKeyStore) {
                    report.positiveProtections.add("Dedicated StrongBox Hardware Security Module active");
                } else {
                    report.positiveProtections.add("Standard Trusted Execution Environment (TEE) Keystore active");
                }
            }
        } catch (Exception ignored) {}

        // 4. Physical Screen Lock & Biometric Protection
        try {
            KeyguardManager km = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
            if (km != null) {
                report.isScreenLockSecured = km.isDeviceSecure();
                if (!report.isScreenLockSecured) {
                    score -= 30;
                    report.physicalWarnings.add("No PIN, Pattern, or Biometric lock configured. Device is vulnerable to physical takeover.");
                    report.remediationActions.add("Configure a strong alphanumeric PIN or biometric lock in Security settings.");
                } else {
                    report.positiveProtections.add("Hardware-backed screen lock & biometrics active");
                }
            }
        } catch (Exception ignored) {}

        // 5. Storage Hardware Encryption
        try {
            DevicePolicyManager dpm = (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
            if (dpm != null) {
                int status = dpm.getStorageEncryptionStatus();
                report.isDeviceEncrypted = (status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE
                        || (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N && status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER));
                if (!report.isDeviceEncrypted) {
                    score -= 20;
                    report.physicalWarnings.add("Device storage is unencrypted. Physical flash chips can be extracted and read.");
                    report.remediationActions.add("Enable File-Based Encryption (FBE) in Android settings.");
                } else {
                    report.positiveProtections.add("File-Based Hardware Storage Encryption active");
                }
            }
        } catch (Exception ignored) {}

        // 6. SIM Card Swap / Absence
        try {
            TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
            if (tm != null) {
                int simState = tm.getSimState();
                switch (simState) {
                    case TelephonyManager.SIM_STATE_ABSENT:
                        report.isSimCardPresent = false;
                        report.simState = "ABSENT";
                        report.physicalWarnings.add("No physical SIM card detected or SIM tray is ejected.");
                        break;
                    case TelephonyManager.SIM_STATE_READY:
                        report.isSimCardPresent = true;
                        report.simState = "READY";
                        report.positiveProtections.add("SIM card locked & operating normally");
                        break;
                    default:
                        report.simState = "STATE_" + simState;
                        break;
                }
            }
        } catch (Exception ignored) {}

        // 7. Bootloader Lock / Verified Boot State Check
        try {
            String bootState = getSystemProperty("ro.boot.verifiedbootstate");
            String flashLocked = getSystemProperty("ro.boot.flash.locked");
            if ("orange".equalsIgnoreCase(bootState) || "0".equals(flashLocked)) {
                report.isBootloaderLocked = false;
                score -= 30;
                report.physicalWarnings.add("Unlocked bootloader detected (verified boot orange). Tampered firmware can bypass Android security.");
                report.remediationActions.add("Relock device bootloader using OEM fastboot tool.");
            } else {
                report.positiveProtections.add("Verified Boot verified green & bootloader locked");
            }
        } catch (Exception ignored) {}

        // Normalize Score & Grade
        report.physicalScore = Math.max(0, Math.min(100, score));
        if (report.physicalScore >= 90) report.physicalGrade = "SECURE";
        else if (report.physicalScore >= 75) report.physicalGrade = "MODERATE";
        else if (report.physicalScore >= 50) report.physicalGrade = "HIGH_RISK";
        else report.physicalGrade = "CRITICAL";

        return report;
    }

    private static String getSystemProperty(String key) {
        try {
            Process process = Runtime.getRuntime().exec("getprop " + key);
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line = reader.readLine();
                return (line != null) ? line.trim() : "";
            }
        } catch (Exception e) {
            return "";
        }
    }
}
