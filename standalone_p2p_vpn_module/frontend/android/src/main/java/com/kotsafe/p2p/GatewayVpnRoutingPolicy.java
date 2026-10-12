package com.kotsafe.p2p;

/**
 * Small, explicit decision point for the main app's VPN packet engine.
 * The caller must never choose normal client Internet for protected flows when
 * the returned decision is BLOCK. That enforcement is what prevents IP leaks.
 */
public final class GatewayVpnRoutingPolicy {
    public enum Decision { TUNNEL, BLOCK }

    private GatewayVpnRoutingPolicy() { }

    public static Decision decide(boolean gatewayEnabled, GatewayHealthMonitor health) {
        if (!gatewayEnabled) throw new IllegalArgumentException("gateway policy is not active");
        if (health == null) throw new IllegalArgumentException("health monitor is required");
        return health.shouldBlockProtectedTraffic() ? Decision.BLOCK : Decision.TUNNEL;
    }
}
