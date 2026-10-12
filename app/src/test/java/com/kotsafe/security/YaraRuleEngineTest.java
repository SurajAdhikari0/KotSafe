package com.kotsafe.security;

import com.kotsafe.security.model.YaraRuleEngine;

import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Arya-style synthetic safe verification test suite for KotSafe's YaraRuleEngine.
 * Validates malware family detection and false-positive resistance without real malicious payloads.
 */
public class YaraRuleEngineTest {

    private Map<String, YaraRuleEngine.YaraRule> mRulesByName;

    @Before
    public void setUp() {
        mRulesByName = new HashMap<>();
        List<YaraRuleEngine.YaraRule> rules = YaraRuleEngine.buildDefaultRules();
        for (YaraRuleEngine.YaraRule r : rules) {
            mRulesByName.put(r.name, r);
        }
    }

    @Test
    public void testRulesRegisteredCount() {
        assertTrue("Expected at least 20 default YARA rules", mRulesByName.size() >= 20);
        assertTrue(mRulesByName.containsKey("Android_Spyware_EpicFury"));
        assertTrue(mRulesByName.containsKey("Android_Banker_SharkBot"));
        assertTrue(mRulesByName.containsKey("Android_Banker_FluBot"));
        assertTrue(mRulesByName.containsKey("Android_Fraud_Joker"));
        assertTrue(mRulesByName.containsKey("Android_Rootkit_Triada"));
        assertTrue(mRulesByName.containsKey("Android_Banker_BlackRock"));
    }

    @Test
    public void testBenignContentDoesNotTriggerMalwareRules() {
        String benignApp = "package com.example.mycalculator;\n" +
                "import android.app.Activity;\n" +
                "import android.os.Bundle;\n" +
                "public class MainActivity extends Activity {\n" +
                "   protected void onCreate(Bundle b) { super.onCreate(b); }\n" +
                "}";
        byte[] bytes = benignApp.getBytes(StandardCharsets.UTF_8);

        for (YaraRuleEngine.YaraRule rule : mRulesByName.values()) {
            YaraRuleEngine.YaraMatch match = rule.evaluate(bytes, "classes.dex");
            assertNull("Benign app code should not trigger: " + rule.name, match);
        }
    }

    @Test
    public void testEpicFurySyntheticVector() {
        YaraRuleEngine.YaraRule rule = mRulesByName.get("Android_Spyware_EpicFury");
        assertNotNull(rule);

        // 1. Synthetic malicious vector
        String maliciousSynthetic = "Lcom/red/alertx/NotificationDispatcher; pushy.me /api/v1/update_user_token upload_contacts_url";
        YaraRuleEngine.YaraMatch match = rule.evaluate(maliciousSynthetic.getBytes(StandardCharsets.UTF_8), "classes.dex");
        assertNotNull("Should detect Operation Epic Fury synthetic vector", match);
        assertEquals("Android_Spyware_EpicFury", match.ruleName);

        // 2. Benign app using pushy.me legitimately without surveillance stubs
        String benignPushy = "Lme/pushy/sdk/Pushy; registerPushNotifications(); benign telemetry";
        YaraRuleEngine.YaraMatch benignMatch = rule.evaluate(benignPushy.getBytes(StandardCharsets.UTF_8), "classes.dex");
        assertNull("Benign Pushy SDK without surveillance routines should NOT trigger", benignMatch);
    }

    @Test
    public void testSharkBotSyntheticVector() {
        YaraRuleEngine.YaraRule rule = mRulesByName.get("Android_Banker_SharkBot");
        assertNotNull(rule);

        // 1. Synthetic ATS vector
        String maliciousAts = "Lcom/threat/payload; ats_service auto_transfer intercept_sms_code";
        YaraRuleEngine.YaraMatch match = rule.evaluate(maliciousAts.getBytes(StandardCharsets.UTF_8), "classes.dex");
        assertNotNull("Should detect SharkBot ATS banking trojan", match);

        // 2. Benign app with accessibility click only
        String benignAccessibility = "onAccessibilityEvent(accessibility_event_type_view_clicked); standard UI helper";
        YaraRuleEngine.YaraMatch benignMatch = rule.evaluate(benignAccessibility.getBytes(StandardCharsets.UTF_8), "classes.dex");
        assertNull("Standard accessibility click alone should NOT trigger SharkBot", benignMatch);
    }

    @Test
    public void testFluBotSyntheticVector() {
        YaraRuleEngine.YaraRule rule = mRulesByName.get("Android_Banker_FluBot");
        assertNotNull(rule);

        String maliciousFluBot = "tracking_package_delivery send_sms_to_all_contacts open_fake_url";
        YaraRuleEngine.YaraMatch match = rule.evaluate(maliciousFluBot.getBytes(StandardCharsets.UTF_8), "classes.dex");
        assertNotNull("Should detect FluBot SMS spreading banker vector", match);
    }

    @Test
    public void testJokerBillingFraudSyntheticVector() {
        YaraRuleEngine.YaraRule rule = mRulesByName.get("Android_Fraud_Joker");
        assertNotNull(rule);

        String maliciousJoker = "auto_confirm_wap get_verification_code_sms sub_silent_carrier";
        YaraRuleEngine.YaraMatch match = rule.evaluate(maliciousJoker.getBytes(StandardCharsets.UTF_8), "classes.dex");
        assertNotNull("Should detect Joker silent WAP billing fraud", match);
    }

    @Test
    public void testTriadaRootkitSyntheticVector() {
        YaraRuleEngine.YaraRule rule = mRulesByName.get("Android_Rootkit_Triada");
        assertNotNull(rule);

        String maliciousTriada = "inject_zygote ptrace_attach_process /system/bin/app_process";
        YaraRuleEngine.YaraMatch match = rule.evaluate(maliciousTriada.getBytes(StandardCharsets.UTF_8), "classes.dex");
        assertNotNull("Should detect Triada Zygote injection rootkit vector", match);
    }

    @Test
    public void testBlackRockSyntheticVector() {
        YaraRuleEngine.YaraRule rule = mRulesByName.get("Android_Banker_BlackRock");
        assertNotNull(rule);

        String malicious = "com.blackrock.bank inject_fake_login steal_credentials_sms";
        YaraRuleEngine.YaraMatch match = rule.evaluate(malicious.getBytes(StandardCharsets.UTF_8), "classes.dex");
        assertNotNull("Should match BlackRock banking trojan pattern", match);
    }
}
