package com.kotsafe.security.model;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;

public final class FirewallPolicy {
    private FirewallPolicy() {
    }

    public static boolean shouldRestoreFirewallOnBoot(Context context, SharedPreferences prefs) {
        if (prefs == null || context == null) {
            return false;
        }

        if (!Prefs.startAtBoot(prefs)) {
            return false;
        }

        if (Prefs.isRootCaptureEnabled(prefs)) {
            return false;
        }

        return Prefs.isFirewallEnabled(context, prefs);
    }

    public static boolean isSupportedBootAction(String action) {
        return Intent.ACTION_BOOT_COMPLETED.equals(action)
                || "android.intent.action.QUICKBOOT_POWERON".equals(action)
                || "android.intent.action.USER_UNLOCKED".equals(action)
                || Intent.ACTION_MY_PACKAGE_REPLACED.equals(action);
    }

    public static boolean shouldBlockScreenOff(SharedPreferences prefs, boolean screenOn) {
        if (prefs == null || screenOn) {
            return false;
        }

        return Prefs.isFirewallScreenOffBlock(prefs);
    }

    public static boolean shouldForceWhitelistMode(SharedPreferences prefs, boolean screenOn, boolean whitelistMode) {
        return whitelistMode || shouldBlockScreenOff(prefs, screenOn);
    }
}
