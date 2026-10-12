package com.kotsafe.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import android.net.wifi.ScanResult;

import com.kotsafe.security.activities.WifiSecurityActivity;

import org.junit.Test;

import java.util.Arrays;
import java.util.List;

public class WifiSecurityRogueDetectionTest {
    @Test
    public void flags_duplicate_ssid_with_different_bssid_as_rogue_ap() {
        List<ScanResult> scanResults = Arrays.asList(
                makeScanResult("HomeWiFi", "AA:AA:AA:AA:AA:AA", "[WPA2-PSK-CCMP]"),
                makeScanResult("HomeWiFi", "BB:BB:BB:BB:BB:BB", "[WPA2-PSK-CCMP]"),
                makeScanResult("CafeGuest", "CC:CC:CC:CC:CC:CC", "[WPA2-PSK-CCMP]")
        );

        WifiSecurityActivity.RogueApState state = WifiSecurityActivity.detectRogueApState(
                "HomeWiFi",
                "AA:AA:AA:AA:AA:AA",
                scanResults
        );

        assertTrue(state.isSuspicious);
        assertEquals("High Risk (Rogue AP / Evil Twin)", state.label);
    }

    @Test
    public void accepts_clean_wifi_when_no_duplicate_ssid_exists() {
        List<ScanResult> scanResults = Arrays.asList(
                makeScanResult("HomeWiFi", "AA:AA:AA:AA:AA:AA", "[WPA2-PSK-CCMP]"),
                makeScanResult("OfficeNet", "DD:DD:DD:DD:DD:DD", "[WPA3-SAE]")
        );

        WifiSecurityActivity.RogueApState state = WifiSecurityActivity.detectRogueApState(
                "HomeWiFi",
                "AA:AA:AA:AA:AA:AA",
                scanResults
        );

        assertTrue(!state.isSuspicious);
        assertEquals("Low Risk (Encrypted)", state.label);
    }

    private static ScanResult makeScanResult(String ssid, String bssid, String capabilities) {
        ScanResult result = new ScanResult();
        result.SSID = ssid;
        result.BSSID = bssid;
        result.capabilities = capabilities;
        result.level = -60;
        return result;
    }
}
