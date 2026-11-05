package com.kotsafe.security.model;

import static org.junit.Assert.*;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;

public class FirewallRuleParserTest {
    @Test public void parsesOnlyLiteralAddressesAndValidPrefixes() {
        assertEquals("192.0.2.5/32", FirewallRuleParser.ip("192.0.2.5"));
        assertEquals("192.0.2.0/24", FirewallRuleParser.ip("192.0.2.0/24"));
        assertTrue(FirewallRuleParser.ip("2001:db8::1/64").endsWith("/64"));
        for (String invalid : new String[]{"example.com", "999.0.0.1", "1.2.3.4/33", "2001:db8::/129", "01.2.3.4", "1.2.3.4/-1"})
            assertNull(invalid, FirewallRuleParser.ip(invalid));
    }
    @Test public void normalizesDomainNamesWithoutResolvingThem() {
        assertEquals("example.test", FirewallRuleParser.domain("EXAMPLE.test."));
        assertEquals("xn--bcher-kva.example", FirewallRuleParser.domain("bücher.example"));
        for (String invalid : new String[]{"https://example.test/path", "not a host", "-bad.example", "a..test", "192.0.2.1"})
            assertNull(invalid, FirewallRuleParser.domain(invalid));
    }
    @Test public void loadsDomainsAndIpsWithoutConvertingDomainsToSharedCdnIps() {
        List<String> hosts = new ArrayList<>(), ips = new ArrayList<>();
        FirewallRuleParser.feedLine("malware.example # comment", hosts, ips);
        FirewallRuleParser.feedLine("198.51.100.0/24", hosts, ips);
        FirewallRuleParser.feedLine("2001:db8:3::/48", hosts, ips);
        assertEquals(1, hosts.size());
        assertEquals("malware.example", hosts.get(0));
        assertEquals(2, ips.size());
    }
    @Test public void supportsHostsFormatAndIgnoresCommentsAndMalformedRules() {
        List<String> hosts = new ArrayList<>(), ips = new ArrayList<>();
        FirewallRuleParser.feedLine("0.0.0.0 c2.example dropper.example", hosts, ips);
        FirewallRuleParser.feedLine("# description", hosts, ips);
        FirewallRuleParser.feedLine("// description", hosts, ips);
        FirewallRuleParser.feedLine("invalid hostname line", hosts, ips);
        FirewallRuleParser.feedLine("198.51.100.5/99", hosts, ips);
        FirewallRuleParser.feedLine("999.999.1.1", hosts, ips);
        assertEquals(2, hosts.size());
        assertTrue(ips.isEmpty());
    }
    @Test public void acceptsMixedPackageAndNumericSystemExceptions() {
        int[] uids = FirewallRuleParser.uids(java.util.Arrays.asList("1000", "android", "com.android.systemui", "10055", "com.uninstalled.app"),
                name -> name.equals("android") ? 1000 : name.equals("com.android.systemui") ? 10055 : -1);
        assertArrayEquals(new int[]{1000, 10055}, uids);
    }
}
