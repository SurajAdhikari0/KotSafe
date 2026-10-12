/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * SecurityModes
 * =============
 * Configurable security profiles that adjust policy sensitivity:
 * - STANDARD: Balanced daily defense.
 * - STRICT: Aggressive firewall restrictions, immediate app isolation.
 * - PUBLIC_WIFI: Enhanced DNS sinkhole, strict egress filtering, unencrypted HTTP warnings.
 * - USB_HARDWARE_SHIELD: Automatic network killswitch upon untrusted HID keyboard connection.
 * - ANTI_THEFT: Audible alarm on charger disconnect while locked; SIM swap protection.
 */

package com.kotsafe.security.security.policy;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.preference.PreferenceManager;

public class SecurityModes {
    public enum Mode {
        STANDARD("Standard Protection", "Balanced threat defense for daily usage"),
        STRICT("Strict Security", "Aggressive network blocking and zero-trust app policies"),
        PUBLIC_WIFI("Public Wi-Fi Shield", "Enhanced DNS sinkhole and unencrypted flow blocking"),
        USB_HARDWARE_SHIELD("USB & Hardware Shield", "Automatic port isolation and BadUSB defense"),
        ANTI_THEFT("Anti-Theft Guard", "Physical tampering alarm and SIM protection");

        public final String title;
        public final String description;

        Mode(String title, String description) {
            this.title = title;
            this.description = description;
        }
    }

    private static final String PREF_SECURITY_MODE = "kotsafe_active_security_mode";

    public static Mode getActiveMode(Context context) {
        if (context == null) return Mode.STANDARD;
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        String name = prefs.getString(PREF_SECURITY_MODE, Mode.STANDARD.name());
        try {
            return Mode.valueOf(name);
        } catch (Exception e) {
            return Mode.STANDARD;
        }
    }

    public static void setActiveMode(Context context, Mode mode) {
        if (context == null || mode == null) return;
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        prefs.edit().putString(PREF_SECURITY_MODE, mode.name()).apply();
    }
}
