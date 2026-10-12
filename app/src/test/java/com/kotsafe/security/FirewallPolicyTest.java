package com.kotsafe.security;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.preference.PreferenceManager;

import com.kotsafe.security.model.FirewallPolicy;
import com.kotsafe.security.model.Prefs;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;

@RunWith(RobolectricTestRunner.class)
public class FirewallPolicyTest {
    private SharedPreferences prefs() {
        return PreferenceManager.getDefaultSharedPreferences(RuntimeEnvironment.getApplication());
    }

    @Test
    public void testShouldRestoreFirewallOnBoot_whenFirewallEnabledAndBootEnabled() {
        SharedPreferences prefs = prefs();
        prefs.edit()
                .putBoolean(Prefs.PREF_START_AT_BOOT, true)
                .putBoolean(Prefs.PREF_FIREWALL, true)
                .putBoolean(Prefs.PREF_ROOT_CAPTURE, false)
                .apply();

        assertTrue(FirewallPolicy.shouldRestoreFirewallOnBoot(RuntimeEnvironment.getApplication(), prefs));
    }

    @Test
    public void testShouldRestoreFirewallOnBoot_whenFirewallDisabled() {
        SharedPreferences prefs = prefs();
        prefs.edit()
                .putBoolean(Prefs.PREF_START_AT_BOOT, true)
                .putBoolean(Prefs.PREF_FIREWALL, false)
                .putBoolean(Prefs.PREF_ROOT_CAPTURE, false)
                .apply();

        assertFalse(FirewallPolicy.shouldRestoreFirewallOnBoot(RuntimeEnvironment.getApplication(), prefs));
    }

    @Test
    public void testShouldRestoreFirewallOnBoot_whenBootStartDisabled() {
        SharedPreferences prefs = prefs();
        prefs.edit()
                .putBoolean(Prefs.PREF_START_AT_BOOT, false)
                .putBoolean(Prefs.PREF_FIREWALL, true)
                .putBoolean(Prefs.PREF_ROOT_CAPTURE, false)
                .apply();

        assertFalse(FirewallPolicy.shouldRestoreFirewallOnBoot(RuntimeEnvironment.getApplication(), prefs));
    }

    @Test
    public void testIsSupportedBootAction_includesAndroidBootVariants() {
        assertTrue(FirewallPolicy.isSupportedBootAction(android.content.Intent.ACTION_BOOT_COMPLETED));
        assertTrue(FirewallPolicy.isSupportedBootAction("android.intent.action.QUICKBOOT_POWERON"));
        assertTrue(FirewallPolicy.isSupportedBootAction("android.intent.action.USER_UNLOCKED"));
        assertTrue(FirewallPolicy.isSupportedBootAction(android.content.Intent.ACTION_MY_PACKAGE_REPLACED));
        assertFalse(FirewallPolicy.isSupportedBootAction("android.intent.action.LOCKED_BOOT_COMPLETED"));
        assertFalse(FirewallPolicy.isSupportedBootAction("android.intent.action.SCREEN_ON"));
    }

    @Test
    public void testShouldBlockScreenOff_whenEnabledAndDisplayIsOff() {
        SharedPreferences prefs = prefs();
        prefs.edit()
                .putBoolean(Prefs.PREF_FIREWALL_SCREEN_OFF_BLOCK, true)
                .apply();

        assertTrue(FirewallPolicy.shouldBlockScreenOff(prefs, false));
    }

    @Test
    public void testShouldForceWhitelistMode_whenScreenOffProtectionOrWhitelistIsEnabled() {
        SharedPreferences prefs = prefs();
        prefs.edit()
                .putBoolean(Prefs.PREF_FIREWALL_SCREEN_OFF_BLOCK, true)
                .putBoolean(Prefs.PREF_FIREWALL_WHITELIST_MODE, false)
                .apply();

        assertTrue(FirewallPolicy.shouldForceWhitelistMode(prefs, false, false));
        assertTrue(FirewallPolicy.shouldForceWhitelistMode(prefs, true, true));
        assertFalse(FirewallPolicy.shouldForceWhitelistMode(prefs, true, false));
    }

    @Test
    public void testShouldBlockScreenOff_whenScreenIsOnOrFeatureDisabled() {
        SharedPreferences prefs = prefs();
        prefs.edit()
                .putBoolean(Prefs.PREF_FIREWALL_SCREEN_OFF_BLOCK, false)
                .apply();

        assertFalse(FirewallPolicy.shouldBlockScreenOff(prefs, false));
        assertFalse(FirewallPolicy.shouldBlockScreenOff(prefs, true));
    }
}
