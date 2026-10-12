/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security;

import com.kotsafe.security.model.WebCategoryEngine;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Unit tests for the Web Category classification logic.
 *
 * Uses {@link WebCategoryEngineTestHelper} — a context-free mirror of the
 * production {@link WebCategoryEngine} — so these run as pure JVM tests.
 */
public class WebCategoryEngineTest {

    private WebCategoryEngine.ClassificationResult classify(String domain, String url) {
        return WebCategoryEngineTestHelper.classify(domain, url);
    }

    // ── Malware / C2 ──────────────────────────────────────────────────────────

    @Test
    public void testCobaltStrikeDomain() {
        WebCategoryEngine.ClassificationResult r = classify("cobaltstrike.evil.net", null);
        assertEquals(WebCategoryEngine.Category.MALWARE_C2, r.category);
        assertEquals(WebCategoryEngine.PolicyAction.BLOCK, r.action);
    }

    @Test
    public void testSuspiciousTkTLD() {
        WebCategoryEngine.ClassificationResult r = classify("malwaredrop.tk", null);
        assertEquals(WebCategoryEngine.Category.MALWARE_C2, r.category);
    }

    @Test
    public void testSuspiciousTkTLD2() {
        // .tk is in the narrow suspicious TLD set (free hosting, widely abused)
        WebCategoryEngine.ClassificationResult r = classify("randommalware.tk", null);
        assertEquals(WebCategoryEngine.Category.MALWARE_C2, r.category);
    }

    @Test
    public void testMalwareKeywordInUrl() {
        WebCategoryEngine.ClassificationResult r = classify("cdn.example.com",
                "https://cdn.example.com/api/dropper/payload");
        assertEquals(WebCategoryEngine.Category.MALWARE_C2, r.category);
    }

    // ── Phishing ──────────────────────────────────────────────────────────────

    @Test
    public void testPhishingDomain() {
        WebCategoryEngine.ClassificationResult r = classify("paypal-secure-login.example.com", null);
        assertEquals(WebCategoryEngine.Category.PHISHING, r.category);
        assertEquals(WebCategoryEngine.PolicyAction.BLOCK, r.action);
    }

    @Test
    public void testPhishingInUrlPath() {
        WebCategoryEngine.ClassificationResult r = classify("trustedsite.com",
                "https://trustedsite.com/login-verify/account");
        assertEquals(WebCategoryEngine.Category.PHISHING, r.category);
    }

    // ── Adult ────────────────────────────────────────────────────────────────

    @Test
    public void testAdultDomain() {
        WebCategoryEngine.ClassificationResult r = classify("pornhub.com", null);
        assertEquals(WebCategoryEngine.Category.ADULT, r.category);
        assertNotEquals(WebCategoryEngine.PolicyAction.ALLOW, r.action);
    }

    @Test
    public void testAdultKeywordInUrl() {
        WebCategoryEngine.ClassificationResult r = classify("cdn.example.com",
                "https://cdn.example.com/xxx/content");
        assertEquals(WebCategoryEngine.Category.ADULT, r.category);
    }

    // ── Gambling ─────────────────────────────────────────────────────────────

    @Test
    public void testGamblingDomain() {
        WebCategoryEngine.ClassificationResult r = classify("bet365.com", null);
        assertEquals(WebCategoryEngine.Category.GAMBLING, r.category);
        assertNotEquals(WebCategoryEngine.PolicyAction.ALLOW, r.action);
    }

    @Test
    public void testCasinoKeyword() {
        WebCategoryEngine.ClassificationResult r = classify("mycasino.example.net", null);
        assertEquals(WebCategoryEngine.Category.GAMBLING, r.category);
    }

    // ── Social ───────────────────────────────────────────────────────────────

    @Test
    public void testFacebookDefaultAllow() {
        WebCategoryEngine.ClassificationResult r = classify("facebook.com", null);
        assertEquals(WebCategoryEngine.Category.SOCIAL, r.category);
        assertEquals(WebCategoryEngine.PolicyAction.ALLOW, r.action);
    }

    @Test
    public void testTikTok() {
        WebCategoryEngine.ClassificationResult r = classify("tiktok.com", null);
        assertEquals(WebCategoryEngine.Category.SOCIAL, r.category);
    }

    @Test
    public void testReddit() {
        WebCategoryEngine.ClassificationResult r = classify("reddit.com", null);
        assertEquals(WebCategoryEngine.Category.SOCIAL, r.category);
    }

    // ── Ads / Trackers ────────────────────────────────────────────────────────

    @Test
    public void testDoubleClick() {
        WebCategoryEngine.ClassificationResult r = classify("doubleclick.net", null);
        assertEquals(WebCategoryEngine.Category.ADS_TRACKERS, r.category);
    }

    @Test
    public void testAnalyticsSubdomain() {
        WebCategoryEngine.ClassificationResult r = classify("analytics.example.com", null);
        assertEquals(WebCategoryEngine.Category.ADS_TRACKERS, r.category);
    }

    @Test
    public void testAppsflyer() {
        WebCategoryEngine.ClassificationResult r = classify("appsflyer.com", null);
        assertEquals(WebCategoryEngine.Category.ADS_TRACKERS, r.category);
    }

    // ── Streaming ────────────────────────────────────────────────────────────

    @Test
    public void testNetflixAllow() {
        WebCategoryEngine.ClassificationResult r = classify("netflix.com", null);
        assertEquals(WebCategoryEngine.Category.STREAMING, r.category);
        assertEquals(WebCategoryEngine.PolicyAction.ALLOW, r.action);
    }

    @Test
    public void testYoutube() {
        WebCategoryEngine.ClassificationResult r = classify("youtube.com", null);
        assertEquals(WebCategoryEngine.Category.STREAMING, r.category);
    }

    // ── Crypto ───────────────────────────────────────────────────────────────

    @Test
    public void testCryptoMiningPool() {
        WebCategoryEngine.ClassificationResult r = classify("nanopool.org", null);
        assertEquals(WebCategoryEngine.Category.CRYPTO, r.category);
        assertNotEquals(WebCategoryEngine.PolicyAction.ALLOW, r.action);
    }

    // ── VPN / Proxy ───────────────────────────────────────────────────────────

    @Test
    public void testNordVpn() {
        WebCategoryEngine.ClassificationResult r = classify("nordvpn.com", null);
        assertEquals(WebCategoryEngine.Category.VPN_PROXY, r.category);
        assertNotEquals(WebCategoryEngine.PolicyAction.ALLOW, r.action);
    }

    @Test
    public void testProxyKeyword() {
        WebCategoryEngine.ClassificationResult r = classify("proxy.example.com", null);
        assertEquals(WebCategoryEngine.Category.VPN_PROXY, r.category);
    }

    // ── Unknown ───────────────────────────────────────────────────────────────

    @Test
    public void testUnknownDomain() {
        WebCategoryEngine.ClassificationResult r = classify("legitbusiness.com", null);
        assertEquals(WebCategoryEngine.Category.UNKNOWN, r.category);
        assertEquals(WebCategoryEngine.PolicyAction.ALLOW, r.action);
    }

    @Test
    public void testNullDomainReturnsUnknown() {
        WebCategoryEngine.ClassificationResult r = classify(null, null);
        assertEquals(WebCategoryEngine.Category.UNKNOWN, r.category);
    }

    @Test
    public void testEmptyDomainReturnsUnknown() {
        WebCategoryEngine.ClassificationResult r = classify("", null);
        assertEquals(WebCategoryEngine.Category.UNKNOWN, r.category);
    }

    // ── Risk scores ──────────────────────────────────────────────────────────

    @Test
    public void testMalwareCategoryHasMaxRisk() {
        WebCategoryEngine.ClassificationResult r = classify("cobaltstrike.evil.net", null);
        assertEquals(100, r.riskBoost);
    }

    @Test
    public void testPhishingRiskIsHigh() {
        WebCategoryEngine.ClassificationResult r = classify("paypal-secure-verify.badsite.com", null);
        assertTrue("Risk should be >= 80, was " + r.riskBoost, r.riskBoost >= 80);
    }

    @Test
    public void testUnknownHasZeroRisk() {
        WebCategoryEngine.ClassificationResult r = classify("legitbusiness.com", null);
        assertEquals(0, r.riskBoost);
    }

    // ── Priority ordering ────────────────────────────────────────────────────

    @Test
    public void testMalwareBeatsAdult() {
        // Domain has BOTH adult keyword AND cobaltrike C2 keyword → C2 must win
        WebCategoryEngine.ClassificationResult r = classify("pornhub-cobaltstrike.example.net", null);
        assertEquals(WebCategoryEngine.Category.MALWARE_C2, r.category);
    }

    @Test
    public void testMalwareBeatsGambling() {
        WebCategoryEngine.ClassificationResult r = classify("casino-backdoor.evil.net", null);
        assertEquals(WebCategoryEngine.Category.MALWARE_C2, r.category);
    }
}
