package com.kotsafe.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.kotsafe.security.model.ThreatIntelManager;

import org.junit.Test;

public class ThreatIntelManagerTest {

    @Test
    public void testCleanDomain() {
        assertEquals("vegamoviess.mobi", ThreatIntelManager.cleanDomain("https://vegamoviess.mobi/"));
        assertEquals("vegamoviess.mobi", ThreatIntelManager.cleanDomain("http://vegamoviess.mobi:443/download/file.apk?id=1#frag"));
        assertEquals("vegamoviess.mobi", ThreatIntelManager.cleanDomain("vegamoviess.mobi:8080"));
        assertEquals("vegamoviess.mobi", ThreatIntelManager.cleanDomain("\"vegamoviess.mobi\""));
        assertEquals("vegamoviess.mobi", ThreatIntelManager.cleanDomain("  vegamoviess.mobi  "));
        assertEquals("sub.domain.co.uk", ThreatIntelManager.cleanDomain("https://sub.domain.co.uk/"));
    }

    @Test
    public void testCleanIp() {
        assertEquals("198.51.100.14", ThreatIntelManager.cleanIp("198.51.100.14:8080"));
        assertEquals("198.51.100.14", ThreatIntelManager.cleanIp("http://198.51.100.14:80/"));
        assertEquals("198.51.100.14", ThreatIntelManager.cleanIp(" 198.51.100.14 "));
        assertEquals("2001:db8::1", ThreatIntelManager.cleanIp("[2001:db8::1]:8080"));
    }

    @Test
    public void testPrivateOrLocalIp() {
        assertTrue(ThreatIntelManager.isPrivateOrLocalIp("127.0.0.1"));
        assertTrue(ThreatIntelManager.isPrivateOrLocalIp("127.0.0.1:8088"));
        assertTrue(ThreatIntelManager.isPrivateOrLocalIp("localhost"));
        assertTrue(ThreatIntelManager.isPrivateOrLocalIp("192.168.1.1"));
        assertTrue(ThreatIntelManager.isPrivateOrLocalIp("10.0.2.16:53"));
        assertTrue(ThreatIntelManager.isPrivateOrLocalIp("172.20.10.2"));
        assertFalse(ThreatIntelManager.isPrivateOrLocalIp("8.8.8.8"));
        assertFalse(ThreatIntelManager.isPrivateOrLocalIp("198.51.100.14"));
    }

    @Test
    public void testCleanHash() {
        String expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assertEquals(expected, ThreatIntelManager.cleanHash("sha256:" + expected));
        assertEquals(expected, ThreatIntelManager.cleanHash("SHA256: " + expected.toUpperCase()));
        assertEquals(expected, ThreatIntelManager.cleanHash("\"" + expected + "\""));
        assertTrue(ThreatIntelManager.isHash(expected));
    }

    @Test
    public void testVirusTotalUrlGeneration() {
        // Domain with full URL prefix should extract clean domain and route to domain report
        assertEquals("https://www.virustotal.com/gui/domain/vegamoviess.mobi",
                ThreatIntelManager.getVirusTotalUrl("https://vegamoviess.mobi/", ThreatIntelManager.IndicatorType.DOMAIN));

        // URL without path routes to domain report to avoid 404
        assertEquals("https://www.virustotal.com/gui/domain/vegamoviess.mobi",
                ThreatIntelManager.getVirusTotalUrl("https://vegamoviess.mobi/", ThreatIntelManager.IndicatorType.URL));

        // Public IP
        assertEquals("https://www.virustotal.com/gui/ip-address/198.51.100.14",
                ThreatIntelManager.getVirusTotalUrl("198.51.100.14:8080", ThreatIntelManager.IndicatorType.IP));

        // Hash
        String hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assertEquals("https://www.virustotal.com/gui/file/" + hash,
                ThreatIntelManager.getVirusTotalUrl("sha256:" + hash, ThreatIntelManager.IndicatorType.HASH));
    }

    @Test
    public void testAlienVaultOtxUrlGeneration() {
        // Domain with full URL prefix should extract clean domain for OTX to prevent 404
        assertEquals("https://otx.alienvault.com/indicator/domain/vegamoviess.mobi",
                ThreatIntelManager.getOtxUrl("https://vegamoviess.mobi/", ThreatIntelManager.IndicatorType.DOMAIN));

        // URL type should extract clean domain because OTX has no /indicator/url/ endpoint
        assertEquals("https://otx.alienvault.com/indicator/domain/vegamoviess.mobi",
                ThreatIntelManager.getOtxUrl("https://vegamoviess.mobi/", ThreatIntelManager.IndicatorType.URL));

        // Public IP
        assertEquals("https://otx.alienvault.com/indicator/ip/198.51.100.14",
                ThreatIntelManager.getOtxUrl("198.51.100.14:8080", ThreatIntelManager.IndicatorType.IP));

        // Hash
        String hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assertEquals("https://otx.alienvault.com/indicator/file/" + hash,
                ThreatIntelManager.getOtxUrl("sha256:" + hash, ThreatIntelManager.IndicatorType.HASH));
    }
}
