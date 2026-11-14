package com.kotsafe.security.ai;

import android.app.Application;
import android.content.Context;
import androidx.preference.PreferenceManager;
import androidx.test.core.app.ApplicationProvider;
import com.kotsafe.security.model.DefenderManager;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import static org.junit.Assert.*;

@RunWith(RobolectricTestRunner.class)
@Config(application = Application.class, sdk = 33, manifest = Config.NONE)
public class AutopilotSafetyTest {
    @Test public void uncertainIntelligenceCannotTriggerAutomaticBlocking() {
        com.kotsafe.security.model.ThreatIntelProvider.ThreatReport report =
                new com.kotsafe.security.model.ThreatIntelProvider.ThreatReport();
        assertFalse(AutonomousSocAnalyst.confirmsMalicious(null));
        assertFalse(AutonomousSocAnalyst.confirmsMalicious(report));
        report.isMalicious = true;
        report.confidence = .8f;
        report.riskScore = 95;
        assertFalse(AutonomousSocAnalyst.confirmsMalicious(report));
        report.confidence = .95f;
        assertTrue(AutonomousSocAnalyst.confirmsMalicious(report));
        report.isSuspicious = true;
        assertFalse(AutonomousSocAnalyst.confirmsMalicious(report));
    }
    @Test public void appHashAndMalformedTargetsCannotBecomeDomainBlocks() {
        assertFalse(AutonomousSocAnalyst.isNetworkTarget("HASH", "a".repeat(64)));
        assertFalse(AutonomousSocAnalyst.isNetworkTarget("APP", "com.example.app"));
        assertFalse(AutonomousSocAnalyst.isNetworkTarget("DOMAIN", "https://example.org/payment?token=secret"));
        assertFalse(AutonomousSocAnalyst.isNetworkTarget("DOMAIN", "example.org/path"));
        assertFalse(AutonomousSocAnalyst.isNetworkTarget("IP", "999.2.3.4"));
        assertTrue(AutonomousSocAnalyst.isNetworkTarget("IP", "192.0.2.1"));
        assertTrue(AutonomousSocAnalyst.isNetworkTarget("DOMAIN", "example.org"));
    }

    @Test public void eitherAutopilotSwitchCanPauseAutomaticActions() {
        Context context = ApplicationProvider.getApplicationContext();
        android.content.SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        prefs.edit().putBoolean(AiConfig.PREF_AUTOPILOT_RESOLVE, true)
                .putBoolean(DefenderManager.PREF_DEFENDER_AUTO_PILOT, false).commit();
        assertFalse(new AiConfig(context).isAutopilotEnabled());
        prefs.edit().putBoolean(AiConfig.PREF_AUTOPILOT_RESOLVE, false)
                .putBoolean(DefenderManager.PREF_DEFENDER_AUTO_PILOT, true).commit();
        assertFalse(new AiConfig(context).isAutopilotEnabled());
    }
}
