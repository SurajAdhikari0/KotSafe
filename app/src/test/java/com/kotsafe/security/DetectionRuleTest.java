package com.kotsafe.security;

import com.kotsafe.security.model.DetectionRule;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.*;

public class DetectionRuleTest {

    @Test
    public void testRuleModelCreation() {
        DetectionRule rule = new DetectionRule();
        rule.id = "RULE-TEST-001";
        rule.name = "Test Trojan Rule";
        rule.severity = DetectionRule.SEVERITY_CRITICAL;
        rule.triggerSchedule = DetectionRule.TRIGGER_ON_SCAN;
        rule.target = DetectionRule.TARGET_APP;
        rule.description = "Test rule description";
        rule.mitreTechniques.addAll(Arrays.asList("T1418", "T1453"));
        rule.remediation = "Uninstall app";

        DetectionRule.RuleCondition c1 = new DetectionRule.RuleCondition();
        c1.field = "isSideloaded";
        c1.operator = "equals";
        c1.value = true;
        rule.conditions.add(c1);

        assertEquals("RULE-TEST-001", rule.id);
        assertEquals("Test Trojan Rule", rule.name);
        assertEquals("CRITICAL", rule.severity);
        assertEquals("ON_SCAN", rule.triggerSchedule);
        assertEquals("app", rule.target);
        assertEquals(2, rule.mitreTechniques.size());
        assertEquals("T1418", rule.mitreTechniques.get(0));
        assertEquals(1, rule.conditions.size());
        assertTrue(rule.enabled);
    }


    @Test
    public void testEvaluateAppRuleMatching() {
        DetectionRule rule = new DetectionRule();
        rule.id = "RULE-BANKING";
        rule.target = "app";
        rule.matchType = "all";
        rule.enabled = true;

        DetectionRule.RuleCondition c1 = new DetectionRule.RuleCondition();
        c1.field = "isSideloaded";
        c1.operator = "equals";
        c1.value = true;
        rule.conditions.add(c1);

        DetectionRule.RuleCondition c2 = new DetectionRule.RuleCondition();
        c2.field = "permissions";
        c2.operator = "contains_all";
        c2.valuesList = Arrays.asList("android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_ACCESSIBILITY_SERVICE");
        rule.conditions.add(c2);

        // Case 1: Match - sideloaded app with both permissions
        List<String> badAppPerms = Arrays.asList(
                "android.permission.INTERNET",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.BIND_ACCESSIBILITY_SERVICE"
        );
        assertTrue(rule.evaluateApp(null, true, badAppPerms));

        // Case 2: No match - Play Store app (not sideloaded)
        assertFalse(rule.evaluateApp(null, false, badAppPerms));

        // Case 3: No match - Missing accessibility permission
        List<String> partialPerms = Arrays.asList(
                "android.permission.INTERNET",
                "android.permission.SYSTEM_ALERT_WINDOW"
        );
        assertFalse(rule.evaluateApp(null, true, partialPerms));
    }

    @Test
    public void testEvaluateNetworkRuleMatching() {
        DetectionRule rule = new DetectionRule();
        rule.id = "RULE-DGA";
        rule.target = "network";
        rule.matchType = "any";
        rule.enabled = true;

        DetectionRule.RuleCondition cDomain = new DetectionRule.RuleCondition();
        cDomain.field = "domain";
        cDomain.operator = "regex";
        cDomain.value = ".*\\.(top|xyz|duckdns\\.org|clickfunax\\.top)$";
        rule.conditions.add(cDomain);

        DetectionRule.RuleCondition cEntropy = new DetectionRule.RuleCondition();
        cEntropy.field = "dgaEntropy";
        cEntropy.operator = "greater_than";
        cEntropy.value = 3.8;
        rule.conditions.add(cEntropy);

        // Matches regex domain
        assertTrue(rule.evaluateNetwork("clickfunax.top", "1.2.3.4", 80, 2.1));
        assertTrue(rule.evaluateNetwork("malicious-c2.duckdns.org", "1.2.3.4", 443, 2.1));

        // Matches high entropy DGA
        assertTrue(rule.evaluateNetwork("kjshdf834jksdf87.com", "1.2.3.4", 443, 4.1));

        // Normal domain - does not match
        assertFalse(rule.evaluateNetwork("google.com", "142.250.190.46", 443, 2.2));
    }

    @Test
    public void testEvaluateFileRuleMatching() {
        DetectionRule rule = new DetectionRule();
        rule.id = "RULE-RANSOM";
        rule.target = "file";
        rule.matchType = "any";
        rule.enabled = true;

        DetectionRule.RuleCondition cStrings = new DetectionRule.RuleCondition();
        cStrings.field = "content_strings";
        cStrings.operator = "contains_any";
        cStrings.valuesList = Arrays.asList("files have been encrypted", "send bitcoin", ".onion/restore");
        rule.conditions.add(cStrings);

        // Match
        assertTrue(rule.evaluateFile("/sdcard/Download/readme.txt", "readme.txt",
                Collections.singletonList("All your files have been encrypted! Contact us at .onion/restore")));

        // No match
        assertFalse(rule.evaluateFile("/sdcard/Download/notes.txt", "notes.txt",
                Collections.singletonList("Meeting notes for Monday.")));
    }

    @Test
    public void testDirectIocMatching() {
        DetectionRule rule = new DetectionRule();
        rule.id = "RULE-IOC-TEST";
        rule.target = "network";
        rule.enabled = true;
        rule.iocDomains.add("malicious-c2.top");
        rule.iocDomains.add("clickfunax.top");
        rule.iocIps.add("185.220.101.5");
        rule.iocIps.add("45.154.255.88");

        assertTrue(rule.hasIocs());
        assertTrue(rule.getIocsSummary().contains("2 Domains"));
        assertTrue(rule.getIocsSummary().contains("2 IPs"));

        // Direct domain IOC match
        assertTrue(rule.evaluateNetwork("subdomain.malicious-c2.top", "1.1.1.1", 443, 1.0));
        assertTrue(rule.lastMatchedIoc.contains("malicious-c2.top"));

        // Direct IP IOC match
        assertTrue(rule.evaluateNetwork("benign.com", "185.220.101.5", 80, 1.0));
        assertTrue(rule.lastMatchedIoc.contains("185.220.101.5"));

        // Benign traffic does not match
        assertFalse(rule.evaluateNetwork("google.com", "8.8.8.8", 443, 1.0));
    }

    @Test
    public void testSha256IocMatching() {
        DetectionRule rule = new DetectionRule();
        rule.id = "RULE-HASH-TEST";
        rule.target = "app";
        rule.enabled = true;
        rule.iocSha256.add("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

        assertTrue(rule.hasIocs());
        assertTrue(rule.getIocsSummary().contains("1 Hashes"));

        // Match by SHA256 hash
        assertTrue(rule.evaluateApp(null, false, Collections.emptyList(),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        assertTrue(rule.lastMatchedIoc.contains("Known Threat Hash IOC"));

        // Mismatched hash
        assertFalse(rule.evaluateApp(null, false, Collections.emptyList(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    }
}
