package com.kotsafe.p2p;

/**
 * User-visible routing policy. Availability is supplied by the connectivity
 * controller after its authenticated ICE/STUN direct-connect attempt.
 */
public final class TransportSelectionPolicy {
    public enum Mode {
        /** Prefer the low-latency direct encrypted UDP path; relay only if necessary. */
        AUTOMATIC,
        /** Never send traffic through the Oracle/VPS relay. Block if P2P cannot connect. */
        DIRECT_ONLY,
        /** Useful for difficult NATs and debugging; always use the encrypted relay path. */
        RELAY_ONLY
    }

    public enum Path { DIRECT, RELAY, BLOCKED }

    private TransportSelectionPolicy() { }

    public static Path choose(Mode mode, boolean directReady, boolean relayReady) {
        if (mode == null) throw new IllegalArgumentException("mode is required");
        switch (mode) {
            case AUTOMATIC:
                if (directReady) return Path.DIRECT;
                return relayReady ? Path.RELAY : Path.BLOCKED;
            case DIRECT_ONLY:
                return directReady ? Path.DIRECT : Path.BLOCKED;
            case RELAY_ONLY:
                return relayReady ? Path.RELAY : Path.BLOCKED;
            default:
                throw new IllegalStateException("unknown mode");
        }
    }

    public static String blockedReason(Mode mode) {
        return mode == Mode.DIRECT_ONLY
                ? "Direct connection is unavailable. Relay use is disabled by your setting."
                : "No encrypted route to the selected exit is available.";
    }
}
