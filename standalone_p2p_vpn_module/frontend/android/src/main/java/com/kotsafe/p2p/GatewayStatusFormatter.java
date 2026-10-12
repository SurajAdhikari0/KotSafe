package com.kotsafe.p2p;

/** Builds the text for the Personal Gateway status card and foreground notification. */
public final class GatewayStatusFormatter {
    private GatewayStatusFormatter() { }

    public static String format(GatewayHealthMonitor.Snapshot snapshot) {
        switch (snapshot.status) {
            case CONNECTED_UNVERIFIED:
                return pathName(snapshot.path) + " connected; verifying exit IP";
            case VERIFIED:
                return pathName(snapshot.path) + " connected • Exit IP verified: " + snapshot.exitIp
                        + " • " + snapshot.sentBytes + " B sent / " + snapshot.receivedBytes + " B received";
            case BLOCKED:
                return "Blocked • " + snapshot.detail;
            case ERROR:
                return "Disconnected • " + snapshot.detail;
            case DISCONNECTED:
            default:
                return "Disconnected";
        }
    }

    private static String pathName(GatewayHealthMonitor.Path path) {
        return path == GatewayHealthMonitor.Path.DIRECT ? "Direct" : "Relay";
    }
}
