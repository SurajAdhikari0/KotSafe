/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.kotsafe.security.model.CompoundRule;
import com.kotsafe.security.model.SecurityRulesDb;

import org.junit.Test;

public class CompoundRuleTest {

    @Test
    public void testPortMatching() {
        // Single port
        assertTrue(CompoundRule.matchesPort(80, "80"));
        assertFalse(CompoundRule.matchesPort(443, "80"));

        // Port list
        assertTrue(CompoundRule.matchesPort(80, "80,443,8080"));
        assertTrue(CompoundRule.matchesPort(443, "80,443,8080"));
        assertFalse(CompoundRule.matchesPort(8081, "80,443,8080"));

        // Port range
        assertTrue(CompoundRule.matchesPort(8050, "8000-8080"));
        assertTrue(CompoundRule.matchesPort(8000, "8000-8080"));
        assertTrue(CompoundRule.matchesPort(8080, "8000-8080"));
        assertFalse(CompoundRule.matchesPort(8081, "8000-8080"));
        assertFalse(CompoundRule.matchesPort(7999, "8000-8080"));

        // Port exclusion
        assertFalse(CompoundRule.matchesPort(443, "!443"));
        assertTrue(CompoundRule.matchesPort(80, "!443"));
    }

    @Test
    public void testCompoundRuleMatching() {
        CompoundRule rule = new CompoundRule.Builder()
                .setName("Block Suspicious Outbound Telemetry")
                .setPackageName("com.untrusted.app")
                .setPortRange("8000-8999")
                .setProtocol("TCP")
                .setDomainPattern("*.telemetry.evil.com")
                .setAction(SecurityRulesDb.ACTION_BLOCK)
                .build();

        // 1. All conditions match
        assertTrue(rule.matches(
                "com.untrusted.app",
                "1.2.3.4",
                8080,
                "collector.telemetry.evil.com",
                "TCP",
                null
        ));

        // 2. Different package -> Fail
        assertFalse(rule.matches(
                "com.trusted.app",
                "1.2.3.4",
                8080,
                "collector.telemetry.evil.com",
                "TCP",
                null
        ));

        // 3. Port outside range -> Fail
        assertFalse(rule.matches(
                "com.untrusted.app",
                "1.2.3.4",
                443,
                "collector.telemetry.evil.com",
                "TCP",
                null
        ));

        // 4. Domain outside wildcard -> Fail
        assertFalse(rule.matches(
                "com.untrusted.app",
                "1.2.3.4",
                8080,
                "good-telemetry.com",
                "TCP",
                null
        ));

        // 5. Wrong protocol -> Fail
        assertFalse(rule.matches(
                "com.untrusted.app",
                "1.2.3.4",
                8080,
                "collector.telemetry.evil.com",
                "UDP",
                null
        ));
    }

    @Test
    public void testCidrMatchingInCompoundRule() {
        CompoundRule rule = new CompoundRule.Builder()
                .setName("Block Internal Subnet Exfiltration")
                .setIpOrCidr("192.168.1.0/24")
                .setAction(SecurityRulesDb.ACTION_BLOCK)
                .build();

        assertTrue(rule.matches("com.any.app", "192.168.1.50", 80, "any.com", "TCP", null));
        assertTrue(rule.matches("com.any.app", "192.168.1.1", 443, null, "TCP", null));
        assertFalse(rule.matches("com.any.app", "192.168.2.1", 80, null, "TCP", null));
        assertFalse(rule.matches("com.any.app", "10.0.0.1", 80, null, "TCP", null));
    }

    @Test
    public void testJa3MatchingInCompoundRule() {
        String cobaltStrikeJa3 = "a0e9f5d64349fb13191bc781f81f42e1";
        CompoundRule rule = new CompoundRule.Builder()
                .setName("Block Cobalt Strike C2 Fingerprint")
                .setJa3Hash(cobaltStrikeJa3)
                .setAction(SecurityRulesDb.ACTION_BLOCK)
                .build();

        assertTrue(rule.matches("com.malware.beacon", "45.33.32.156", 443, "c2.evil.com", "TCP", cobaltStrikeJa3));
        assertFalse(rule.matches("com.clean.browser", "45.33.32.156", 443, "c2.evil.com", "TCP", "clean_hash_1234567890"));
    }

    @Test
    public void testJsonSerialization() {
        CompoundRule original = new CompoundRule.Builder()
                .setName("Rate Limit Ad Network")
                .setPackageName("com.sample.*")
                .setDomainPattern("*.doubleclick.net")
                .setRateLimitPerMin(30.0)
                .setAction(SecurityRulesDb.ACTION_RATE_LIMIT)
                .setReason("Throttling aggressive banner reload")
                .build();

        String json = original.toJson();
        assertNotNull(json);
        assertTrue(json.contains("doubleclick.net"));
        assertTrue(json.contains("RATE_LIMIT"));

        CompoundRule restored = CompoundRule.fromJson(json);
        assertNotNull(restored);
        assertEquals("Rate Limit Ad Network", restored.name);
        assertEquals("com.sample.*", restored.packageName);
        assertEquals("*.doubleclick.net", restored.domainPattern);
        assertEquals(30.0, restored.rateLimitPerMin, 0.001);
        assertEquals(SecurityRulesDb.ACTION_RATE_LIMIT, restored.action);
    }
}
