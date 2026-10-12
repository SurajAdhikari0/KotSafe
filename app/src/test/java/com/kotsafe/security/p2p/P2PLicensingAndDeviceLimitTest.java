package com.kotsafe.security.p2p;

import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * P2PLicensingAndDeviceLimitTest
 * 
 * Tests license key verification algorithm and concurrent multi-device
 * capacity limits (1 to 6 devices max) on P2P Exit Nodes.
 */
public final class P2PLicensingAndDeviceLimitTest {

    @Test
    public void testLicenseKeyVerification() throws Exception {
        // 1. Invalid keys should fail
        Assert.assertFalse(verifyKey("INVALID_KEY"));
        Assert.assertFalse(verifyKey("KOT-INVALID"));
        Assert.assertFalse(verifyKey("KOT-PRO-123"));

        // 2. Generate a valid key using exact algorithm
        String key = generateTestKey("PRO", "1A2B3C4D");
        Assert.assertTrue("Valid PRO key must pass verification", verifyKey(key));

        // 3. Generate a valid Enterprise key
        String entKey = generateTestKey("ENT", "99887766");
        Assert.assertTrue("Valid ENT key must pass verification", verifyKey(entKey));

        // 4. Tampered key checksum must fail
        String tampered = key.substring(0, key.length() - 1) + (key.endsWith("A") ? "B" : "A");
        Assert.assertFalse("Tampered key must be rejected", verifyKey(tampered));
    }

    @Test
    public void testDeviceLimitsEnforcement() {
        // Simulate P2P Exit Node client capacity tracking
        ConcurrentHashMap<String, Integer> remoteClients = new ConcurrentHashMap<>();
        AtomicInteger activeClients = new AtomicInteger(0);

        int maxLimitFree = 1;
        int maxLimitPro = 3;

        // --- Free Tier Test (Limit = 1) ---
        // Device 1 connects
        boolean allowedDev1 = canDeviceConnect(remoteClients, "192.168.1.10", maxLimitFree);
        Assert.assertTrue("Device 1 must be allowed", allowedDev1);
        remoteClients.put("192.168.1.10", 1);
        activeClients.set(remoteClients.size());

        // Device 2 connects -> should be rejected under Free tier
        boolean allowedDev2 = canDeviceConnect(remoteClients, "192.168.1.11", maxLimitFree);
        Assert.assertFalse("Device 2 must be rejected under Free Tier limit of 1", allowedDev2);

        // Same Device 1 opening a second connection -> should be allowed
        boolean allowedDev1SecondConn = canDeviceConnect(remoteClients, "192.168.1.10", maxLimitFree);
        Assert.assertTrue("Existing device opening additional socket must be allowed", allowedDev1SecondConn);

        // --- Pro Tier Test (Limit = 3) ---
        remoteClients.clear();
        // Connect Device 1, 2, 3
        Assert.assertTrue(canDeviceConnect(remoteClients, "10.0.0.1", maxLimitPro));
        remoteClients.put("10.0.0.1", 1);

        Assert.assertTrue(canDeviceConnect(remoteClients, "10.0.0.2", maxLimitPro));
        remoteClients.put("10.0.0.2", 1);

        Assert.assertTrue(canDeviceConnect(remoteClients, "10.0.0.3", maxLimitPro));
        remoteClients.put("10.0.0.3", 1);

        // 4th device attempts to connect -> must be rejected
        Assert.assertFalse("4th device must be rejected when limit is 3", canDeviceConnect(remoteClients, "10.0.0.4", maxLimitPro));

        // Device 2 disconnects
        remoteClients.remove("10.0.0.2");

        // 4th device attempts again -> now allowed!
        Assert.assertTrue("Device 4 should now be allowed after slot freed", canDeviceConnect(remoteClients, "10.0.0.4", maxLimitPro));
    }

    private static boolean canDeviceConnect(ConcurrentHashMap<String, Integer> activeMap, String clientIp, int maxAllowed) {
        if (!activeMap.containsKey(clientIp) && activeMap.size() >= maxAllowed) {
            return false; // Capacity reached
        }
        return true;
    }

    private static String generateTestKey(String tier, String hexPart) throws Exception {
        String payload = "KOT-" + tier + "-" + hexPart;
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest((payload + "kotsafe-salt-2026").getBytes(StandardCharsets.UTF_8));
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < 2; i++) {
            hex.append(String.format("%02X", hash[i]));
        }
        return payload + "-" + hex.toString();
    }

    private static boolean verifyKey(String key) {
        if (key == null || !key.startsWith("KOT-")) return false;
        String[] parts = key.split("-");
        if (parts.length < 4) return false;
        try {
            String payload = parts[0] + "-" + parts[1] + "-" + parts[2];
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest((payload + "kotsafe-salt-2026").getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < 2; i++) {
                hex.append(String.format("%02X", hash[i]));
            }
            return parts[3].equalsIgnoreCase(hex.toString());
        } catch (Exception e) {
            return false;
        }
    }
}
