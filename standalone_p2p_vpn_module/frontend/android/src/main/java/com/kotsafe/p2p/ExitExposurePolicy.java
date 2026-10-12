package com.kotsafe.p2p;

/** Rejects the unsafe design of exposing a raw SOCKS server on Wi-Fi/mobile interfaces. */
public final class ExitExposurePolicy {
    public enum Listener { LOOPBACK_COMPATIBILITY, ENCRYPTED_TUNNEL_ONLY }

    private ExitExposurePolicy() { }

    public static void validate(Listener listener, String bindAddress, boolean authenticated) {
        if (listener == null) throw new IllegalArgumentException("listener is required");
        if (!authenticated) throw new IllegalArgumentException("an exit route must always authenticate its peer");
        if (listener == Listener.LOOPBACK_COMPATIBILITY &&
                !("127.0.0.1".equals(bindAddress) || "::1".equals(bindAddress))) {
            throw new IllegalArgumentException("compatibility listener must bind loopback only");
        }
        if (listener == Listener.ENCRYPTED_TUNNEL_ONLY && bindAddress != null) {
            throw new IllegalArgumentException("encrypted tunnel mode must not publish a raw listening address");
        }
    }
}
