package com.kotsafe.security.model;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class BuiltInThreatSignatureCatalogTest {

    @Test
    public void detectsKnownSeedSignature() {
        String hash = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        BuiltInThreatSignatureCatalog.SignatureRule rule = BuiltInThreatSignatureCatalog.lookup(hash);

        assertNotNull(rule);
        assertEquals("SEED_MALWARE_SIGNATURE", rule.family);
        assertEquals("Seed signature loaded from the built-in catalog.", rule.reason);
    }

    @Test
    public void normalizesHashInput() {
        String hash = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        BuiltInThreatSignatureCatalog.SignatureRule rule = BuiltInThreatSignatureCatalog.lookup("SHA256:" + hash.toUpperCase());

        assertNotNull(rule);
        assertEquals("SEED_MALWARE_SIGNATURE", rule.family);
    }

    @Test
    public void unknownHashIsNotMatched() {
        String hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assertNull(BuiltInThreatSignatureCatalog.lookup(hash));
    }

    @Test
    public void behavioralQuarantinePolicyOnlyFlagsHighRiskAnomalies() {
        assertTrue(AppBehaviorProfileManager.isQuarantineEligible("CRITICAL", "COVERT_BEACONING"));
        assertTrue(AppBehaviorProfileManager.isQuarantineEligible("HIGH", "UNEXPECTED_PORT"));
        assertFalse(AppBehaviorProfileManager.isQuarantineEligible("LOW", "UNEXPECTED_PORT"));
        assertFalse(AppBehaviorProfileManager.isQuarantineEligible("MEDIUM", "BENIGN"));
    }
}
