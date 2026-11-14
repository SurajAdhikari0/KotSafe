package com.kotsafe.security.model;

import org.junit.Test;
import static org.junit.Assert.*;

public class ReputationHostTest {
    @Test public void sendsOnlyHostnameForReputation() {
        assertEquals("example.org", ThreatIntelRouter.reputationHost("https://user:secret@EXAMPLE.org:8443/pay?token=secret#account"));
        assertEquals("example.org", ThreatIntelRouter.reputationHost("example.org?token=secret"));
        assertNull(ThreatIntelRouter.reputationHost("file:///private/document"));
        assertNull(ThreatIntelRouter.reputationHost("https:///missing-host?token=secret"));
    }
}
