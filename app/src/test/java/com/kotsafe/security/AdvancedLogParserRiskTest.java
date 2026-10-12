package com.kotsafe.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.kotsafe.security.model.parser.AdvancedLogParser;
import com.kotsafe.security.model.parser.AdvancedLogParser.ParsedUrl;
import com.kotsafe.security.model.parser.AdvancedLogParser.RiskLevel;

import org.junit.Test;

public class AdvancedLogParserRiskTest {

    @Test
    public void testDirectIpLiteralIsNotSuspicious() {
        ParsedUrl parsed = AdvancedLogParser.parseUrl("http://129.227.192.33/");
        assertEquals(RiskLevel.SAFE, parsed.riskAssessment.riskLevel);
        assertEquals(0, parsed.riskAssessment.riskScore);
        assertTrue(parsed.riskAssessment.riskFlags.isEmpty());
    }

    @Test
    public void testCleartextHttpIsNotSuspicious() {
        ParsedUrl parsed = AdvancedLogParser.parseUrl("http://example.com/welcome/index.html");
        assertEquals(RiskLevel.SAFE, parsed.riskAssessment.riskLevel);
        assertEquals(0, parsed.riskAssessment.riskScore);
        assertTrue(parsed.riskAssessment.riskFlags.isEmpty());
    }

    @Test
    public void testTrackingParametersAreNotSuspicious() {
        ParsedUrl parsed = AdvancedLogParser.parseUrl("https://www.google.com/search?q=kotsafe&utm_source=newsletter&utm_medium=email");
        assertTrue(parsed.hasTrackingParams());
        assertEquals(RiskLevel.SAFE, parsed.riskAssessment.riskLevel);
        assertEquals(0, parsed.riskAssessment.riskScore);
    }

    @Test
    public void testTrackerDomainIsNotSuspicious() {
        ParsedUrl parsed = AdvancedLogParser.parseUrl("https://google-analytics.com/collect?v=1&tid=UA-12345");
        assertTrue(parsed.riskAssessment.isKnownTracker);
        assertEquals(RiskLevel.SAFE, parsed.riskAssessment.riskLevel);
        assertEquals(0, parsed.riskAssessment.riskScore);
    }

    @Test
    public void testConfirmedMalwareC2IsHighRisk() {
        ParsedUrl parsed = AdvancedLogParser.parseUrl("http://167.160.187.43/c2/beacon");
        assertEquals(RiskLevel.HIGH_RISK, parsed.riskAssessment.riskLevel);
        assertTrue(parsed.riskAssessment.riskScore >= 85);
        assertFalse(parsed.riskAssessment.riskFlags.isEmpty());
    }

    @Test
    public void testConfirmedSqlInjectionIsHighRisk() {
        ParsedUrl parsed = AdvancedLogParser.parseUrl("http://portal.com/login?username=admin%27+or+1%3D1--");
        assertEquals(RiskLevel.HIGH_RISK, parsed.riskAssessment.riskLevel);
        assertTrue(parsed.riskAssessment.riskScore >= 85);
        assertFalse(parsed.riskAssessment.riskFlags.isEmpty());
    }

    @Test
    public void testConfirmedXssIsHighRisk() {
        ParsedUrl parsed = AdvancedLogParser.parseUrl("http://search.com/results?query=%3Cscript%3Ealert(1)%3C/script%3E");
        assertEquals(RiskLevel.HIGH_RISK, parsed.riskAssessment.riskLevel);
        assertTrue(parsed.riskAssessment.riskScore >= 85);
    }

    @Test
    public void testUntrustedApkDownloadIsSuspicious() {
        ParsedUrl parsed = AdvancedLogParser.parseUrl("http://untrusted-unknown-site.org/malicious_payload.apk");
        assertEquals(RiskLevel.SUSPICIOUS, parsed.riskAssessment.riskLevel);
        assertTrue(parsed.riskAssessment.riskScore >= 60);
    }
}
