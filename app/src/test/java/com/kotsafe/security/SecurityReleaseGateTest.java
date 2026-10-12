package com.kotsafe.security;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.preference.PreferenceManager;
import androidx.test.core.app.ApplicationProvider;

import com.kotsafe.security.model.Prefs;
import com.kotsafe.security.model.SecurityReleaseGate;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

@RunWith(RobolectricTestRunner.class)
@Config(application = TestKotSafe.class)
public class SecurityReleaseGateTest {

    private Context context;
    private SharedPreferences prefs;

    @Before
    public void setUp() {
        KotSafe.isUnderTest = true;
        context = ApplicationProvider.getApplicationContext();
        prefs = PreferenceManager.getDefaultSharedPreferences(context);
        prefs.edit().clear().commit();
    }

    @Test
    public void testEvaluateReady_whenAllCoreGatesAreArmed() {
        prefs.edit()
                .putBoolean(Prefs.PREF_FIREWALL, true)
                .putBoolean(Prefs.PREF_MALWARE_DETECTION, true)
                .putBoolean(Prefs.PREF_FIREWALL_SCREEN_OFF_BLOCK, true)
                .putBoolean(Prefs.PREF_START_AT_BOOT, true)
                .commit();

        SecurityReleaseGate.CheckResult result = SecurityReleaseGate.evaluate(context, prefs);

        Assert.assertTrue(result.ready);
        Assert.assertTrue(result.firewallReady);
        Assert.assertTrue(result.screenOffReady);
        Assert.assertTrue(result.antivirusReady);
        Assert.assertTrue(result.failures.isEmpty());
    }

    @Test
    public void testEvaluateFails_whenFirewallGatesAreMissing() {
        prefs.edit()
                .putBoolean(Prefs.PREF_FIREWALL, false)
                .putBoolean(Prefs.PREF_MALWARE_DETECTION, true)
                .putBoolean(Prefs.PREF_FIREWALL_SCREEN_OFF_BLOCK, false)
                .putBoolean(Prefs.PREF_START_AT_BOOT, false)
                .commit();

        SecurityReleaseGate.CheckResult result = SecurityReleaseGate.evaluate(context, prefs);

        Assert.assertFalse(result.ready);
        Assert.assertFalse(result.firewallReady);
        Assert.assertFalse(result.screenOffReady);
        Assert.assertTrue(result.antivirusReady);
        Assert.assertFalse(result.failures.isEmpty());
        Assert.assertTrue(result.summary().contains("Firewall not enabled")
                || result.summary().contains("Screen-off background protection is disabled"));
    }
}
