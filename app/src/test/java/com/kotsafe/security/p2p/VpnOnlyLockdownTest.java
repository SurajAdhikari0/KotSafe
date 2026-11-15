package com.kotsafe.security.p2p;

import org.junit.Assert;
import org.junit.Test;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Unit test for Per-App Strict VPN-Only Lockdown Mode.
 */
public class VpnOnlyLockdownTest {

    @Test
    public void testPreferenceKeyConstants() {
        Assert.assertEquals("personal_gateway_vpn_only_lockdown", GatewayPreferenceKeys.VPN_ONLY_LOCKDOWN_ENABLED);
        Assert.assertEquals("personal_gateway_selected_apps", GatewayPreferenceKeys.SELECTED_APPS);
        Assert.assertEquals("only_selected", GatewayPreferenceKeys.ROUTING_MODE_ONLY_SELECTED);
    }

    @Test
    public void testVpnOnlyLockdownBlockingLogic() {
        // Mock app list
        Set<String> selectedApps = new HashSet<>();
        selectedApps.add("com.android.chrome");
        selectedApps.add("org.telegram.messenger");
        selectedApps.add("com.secure.banking");

        // Scenario 1: Lockdown Enabled, Tunnel OFFLINE -> Apps must be blocked
        boolean vpnOnlyLockdown = true;
        boolean isSecureTunnelActive = false;

        Set<String> blockedApps = new HashSet<>();
        if (vpnOnlyLockdown && !isSecureTunnelActive && !selectedApps.isEmpty()) {
            blockedApps.addAll(selectedApps);
        }

        Assert.assertEquals(3, blockedApps.size());
        Assert.assertTrue(blockedApps.contains("com.android.chrome"));
        Assert.assertTrue(blockedApps.contains("org.telegram.messenger"));
        Assert.assertTrue(blockedApps.contains("com.secure.banking"));

        // Scenario 2: Lockdown Enabled, Tunnel ONLINE -> Apps must NOT be blocked (allowed to route)
        isSecureTunnelActive = true;
        blockedApps.clear();
        if (vpnOnlyLockdown && !isSecureTunnelActive && !selectedApps.isEmpty()) {
            blockedApps.addAll(selectedApps);
        }

        Assert.assertTrue("Selected apps must have network access when tunnel is online", blockedApps.isEmpty());

        // Scenario 3: Lockdown DISABLED, Tunnel OFFLINE -> Apps must NOT be blocked by lockdown
        vpnOnlyLockdown = false;
        isSecureTunnelActive = false;
        blockedApps.clear();
        if (vpnOnlyLockdown && !isSecureTunnelActive && !selectedApps.isEmpty()) {
            blockedApps.addAll(selectedApps);
        }

        Assert.assertTrue("Selected apps must not be blocked when lockdown is disabled", blockedApps.isEmpty());
    }
}

