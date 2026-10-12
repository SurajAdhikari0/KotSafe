/*
 * This file is part of KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.model;

import java.util.List;

/**
 * Contract every optional signaling backend (Firebase, self-hosted, or any
 * other provider) must satisfy. Nothing else in the app talks to a specific
 * backend directly — P2PExitNodeSettings only ever calls through this
 * interface, chosen once in the Backend Setup Wizard and stored via
 * Prefs.PREF_P2P_BACKEND_TYPE / PREF_P2P_BACKEND_CONFIG.
 *
 * When no backend is configured ("none"), the app behaves exactly as it did
 * before this file existed: pure QR / manual-paste pairing, no live push.
 */
public interface BackendProvider {

    /** Called on network change, periodic refresh, or app foreground (host side). */
    void publishCandidates(String pairingToken, List<Candidate> candidates);

    /** Client side: start receiving live candidate updates for a pairing. */
    void subscribeToCandidates(String pairingToken, CandidateListener listener);

    /** Stop receiving updates (call from onPause/onDestroy or when switching backends). */
    void unsubscribe(String pairingToken);

    /** Host side: ask the backend to mint a new pairing token. */
    void createPairing(String deviceId, PairingCallback callback);

    /** Invalidate a pairing so old links/QRs stop working — call on token rotation. */
    void revokePairing(String pairingToken, RevokeCallback callback);

    /** Relay/TURN candidate this provider can offer, or null if it has none. */
    Candidate getRelayCandidate();

    /** Verify this provider is actually reachable before letting the wizard proceed. */
    void testConnection(ConnectionTestCallback callback);

    /** Starts a local relay loopback on localPort that tunnels SOCKS5 streams over the backend relay. Returns bound port. */
    default int startRelayLoopback(String pairingToken, int localPort) { return 0; }

    /** Stops any active local relay loopback. */
    default void stopRelayLoopback() {}

    /** Exit Node host side: broadcast telemetry stats (battery, Wi-Fi, etc) to paired clients. */
    default void sendTelemetry(String pairingToken, org.json.JSONObject telemetry) {}

    /** Reconnect any transport tunnel for this pairing (e.g. after network interface handoff). */
    default void reconnectTunnel(String pairingToken) {}

    /** Host side: request a v2 SecurePairingBundle for QR code pairing. */
    default void createPairingBundle(String deviceId, PairingBundleCallback callback) {
        callback.onError("v2 pairing not supported by this provider");
    }

    /** Client side: claim a v2 pairing bundle via the control service. */
    default void claimPairing(com.kotsafe.security.p2p.SecurePairingBundle bundle, String clientDeviceId, ClaimCallback callback) {
        callback.onError("v2 pairing claim not supported by this provider");
    }

    interface CandidateListener {
        void onCandidatesUpdated(List<Candidate> candidates);
        void onError(String message);
    }

    interface PairingCallback {
        void onPairingCreated(String token, long expiresAtMillis);
        void onError(String message);
    }

    interface PairingBundleCallback {
        void onSuccess(String exitToken, com.kotsafe.security.p2p.SecurePairingBundle bundle);
        void onError(String message);
    }

    interface ClaimCallback {
        void onSuccess(String clientToken, long expiresInSeconds);
        void onError(String message);
    }

    interface RevokeCallback {
        void onResult(boolean revoked);
    }

    interface ConnectionTestCallback {
        void onResult(boolean success, String message);
    }
}
