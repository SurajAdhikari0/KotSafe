package com.kotsafe.security.model;
import static org.junit.Assert.*;
import org.junit.Test;

public class WifiThreatDetectorTest {
    @Test public void missingScanResultsDoNotMeanEncryptionWasRemoved() {
        assertFalse(WifiThreatDetector.isWeakerSecurity("[WPA2-PSK-CCMP][ESS]", "UNKNOWN"));
        assertFalse(WifiThreatDetector.isWeakerSecurity("[WPA2-PSK-CCMP][ESS]", ""));
        assertFalse(WifiThreatDetector.isWeakerSecurity("[WPA2-PSK-CCMP][ESS]", null));
    }
    @Test public void sameSecurityWhileRoamingDoesNotTriggerDowngrade() {
        assertFalse(WifiThreatDetector.isWeakerSecurity("[WPA2-PSK-CCMP][ESS]", "[WPA2-PSK-CCMP][ESS]"));
    }
    @Test public void observedOpenNetworkAfterEncryptionStillTriggersReview() {
        assertTrue(WifiThreatDetector.isWeakerSecurity("[WPA2-PSK-CCMP][ESS]", "[ESS]"));
    }
}
