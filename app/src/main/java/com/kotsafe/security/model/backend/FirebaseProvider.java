/*
 * This file is part of KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.model.backend;

import android.content.Context;

import androidx.annotation.NonNull;

import com.kotsafe.security.model.BackendProvider;
import com.kotsafe.security.model.Candidate;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.firestore.DocumentReference;
import com.google.firebase.firestore.DocumentSnapshot;
import com.google.firebase.firestore.FirebaseFirestore;
import com.google.firebase.firestore.ListenerRegistration;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Firestore-backed BackendProvider using the USER'S OWN Firebase project
 * (initialized dynamically from wizard-entered projectId/apiKey/appId — never
 * a hardcoded project). Requires firestore.rules + the createPairing /
 * cleanupExpiredPairings Cloud Functions from the kotsafe-relay repo's
 * firebase-functions/ directory to be deployed on that project.
 */
public class FirebaseProvider implements BackendProvider {

    private static final String APP_NAME = "kotsafe-user-backend";
    private static final long PAIRING_TTL_MILLIS = 24L * 60 * 60 * 1000;

    private final FirebaseFirestore mDb;
    private final Map<String, ListenerRegistration> mListeners = new ConcurrentHashMap<>();

    public FirebaseProvider(Context context, String projectId, String apiKey, String appId) {
        FirebaseApp app;
        try {
            app = FirebaseApp.getInstance(APP_NAME);
        } catch (IllegalStateException notInitYet) {
            FirebaseOptions options = new FirebaseOptions.Builder()
                    .setProjectId(projectId)
                    .setApiKey(apiKey)
                    .setApplicationId(appId)
                    .build();
            app = FirebaseApp.initializeApp(context.getApplicationContext(), options, APP_NAME);
        }
        mDb = FirebaseFirestore.getInstance(app);
        // Anonymous auth so Firestore rules (request.auth != null) are satisfied
        // without asking the user to sign in to anything.
        FirebaseAuth.getInstance(app).signInAnonymously();
    }

    @Override
    public void createPairing(String deviceId, PairingCallback callback) {
        String token = generateToken();
        long expiresAt = System.currentTimeMillis() + PAIRING_TTL_MILLIS;

        Map<String, Object> doc = new HashMap<>();
        doc.put("candidates", new ArrayList<>());
        doc.put("updatedAt", System.currentTimeMillis());
        doc.put("expiresAt", expiresAt);
        doc.put("ownerDeviceId", deviceId);

        mDb.collection("pairings").document(token).set(doc)
                .addOnSuccessListener(unused -> callback.onPairingCreated(token, expiresAt))
                .addOnFailureListener(e -> callback.onError(e.getMessage()));
    }

    @Override
    public void publishCandidates(String pairingToken, List<Candidate> candidates) {
        List<Map<String, Object>> serialized = new ArrayList<>();
        for (Candidate c : candidates) {
            Map<String, Object> m = new HashMap<>();
            m.put("type", c.type.name());
            m.put("host", c.host);
            m.put("port", c.port);
            m.put("discoveredAt", c.discoveredAt);
            serialized.add(m);
        }
        Map<String, Object> update = new HashMap<>();
        update.put("candidates", serialized);
        update.put("updatedAt", System.currentTimeMillis());
        mDb.collection("pairings").document(pairingToken).set(update, com.google.firebase.firestore.SetOptions.merge());
    }

    @Override
    public void subscribeToCandidates(String pairingToken, CandidateListener listener) {
        unsubscribe(pairingToken); // avoid duplicate listeners on re-subscribe
        DocumentReference ref = mDb.collection("pairings").document(pairingToken);
        ListenerRegistration reg = ref.addSnapshotListener((snapshot, error) -> {
            if (error != null) {
                listener.onError(error.getMessage());
                return;
            }
            if (snapshot == null || !snapshot.exists()) {
                listener.onError("pairing_not_found_or_expired");
                return;
            }
            listener.onCandidatesUpdated(parseCandidates(snapshot));
        });
        mListeners.put(pairingToken, reg);
    }

    @Override
    public void unsubscribe(String pairingToken) {
        ListenerRegistration reg = mListeners.remove(pairingToken);
        if (reg != null) reg.remove();
    }

    @Override
    public void revokePairing(String pairingToken, RevokeCallback callback) {
        mDb.collection("pairings").document(pairingToken).delete()
                .addOnSuccessListener(unused -> callback.onResult(true))
                .addOnFailureListener(e -> callback.onResult(false));
        unsubscribe(pairingToken);
    }

    @Override
    public Candidate getRelayCandidate() {
        return null; // Firestore has no TURN relay; pair with a self-hosted coturn if needed.
    }

    @Override
    public void testConnection(ConnectionTestCallback callback) {
        String probeDoc = "_healthcheck_" + System.currentTimeMillis();
        DocumentReference ref = mDb.collection("pairings").document(probeDoc);
        Map<String, Object> data = new HashMap<>();
        data.put("candidates", new ArrayList<>());
        data.put("updatedAt", System.currentTimeMillis());
        data.put("expiresAt", System.currentTimeMillis() + 60_000);

        ref.set(data)
                .addOnSuccessListener(unused -> ref.delete()
                        .addOnSuccessListener(u2 -> callback.onResult(true, "OK"))
                        .addOnFailureListener(e -> callback.onResult(true, "Write OK, cleanup failed: " + e.getMessage())))
                .addOnFailureListener(e -> callback.onResult(false, "Firestore write failed: " + e.getMessage()));
    }

    @SuppressWarnings("unchecked")
    private List<Candidate> parseCandidates(@NonNull DocumentSnapshot snapshot) {
        List<Candidate> result = new ArrayList<>();
        List<Map<String, Object>> raw = (List<Map<String, Object>>) snapshot.get("candidates");
        if (raw == null) return result;
        for (Map<String, Object> m : raw) {
            try {
                Candidate.Type type;
                try { type = Candidate.Type.valueOf(String.valueOf(m.get("type"))); }
                catch (IllegalArgumentException e) { type = Candidate.Type.STUN; }
                String host = String.valueOf(m.get("host"));
                int port = ((Number) m.get("port")).intValue();
                Candidate c = new Candidate(type, host, port);
                if (m.get("discoveredAt") instanceof Number) {
                    c.discoveredAt = ((Number) m.get("discoveredAt")).longValue();
                }
                result.add(c);
            } catch (Exception ignored) { /* skip malformed entry */ }
        }
        return result;
    }

    private static String generateToken() {
        final String CHARS = "abcdef0123456789";
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder(32);
        for (int i = 0; i < 32; i++) sb.append(CHARS.charAt(random.nextInt(CHARS.length())));
        return sb.toString();
    }
}
