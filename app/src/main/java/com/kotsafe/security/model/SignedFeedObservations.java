package com.kotsafe.security.model;

import android.content.Context;
import android.content.SharedPreferences;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/** Advisory matches only. This class never adds a firewall or antivirus rule. */
public final class SignedFeedObservations {
    private static final Map<String,Long> active = new HashMap<>();
    private static String loadedGeneration = "";
    private static long loadedVersion, issued, expires;

    public static synchronized void observe(Context context, String type, String value) {
        if (value == null || value.isEmpty()) return;
        SharedPreferences prefs = SignedFeedWorker.state(context);
        long version = prefs.getLong("version", 0);
        if (version == 0 || !SignedFeedWorker.enabled(context)) return;
        String generation = prefs.getString("generation", "");
        long now = System.currentTimeMillis()/1000;
        try {
            if (version != loadedVersion || !generation.equals(loadedGeneration)) {
                IntelligenceSnapshotStore store = SignedFeedWorker.store(context, SignedFeedWorker.account());
                active.clear();
                if (!store.restore(now)) return;
                IntelligenceManifestV2Verifier.Snapshot snapshot = store.snapshot();
                if (snapshot.version != version) return;
                for (IntelligenceManifestV2Verifier.Indicator row : snapshot.indicators) {
                    String key = row.type+" "+row.value;
                    Long previous = active.get(key);
                    if (previous == null || previous < row.validUntil) active.put(key,row.validUntil);
                }
                issued = snapshot.issuedAt;
                expires = snapshot.expiresAt;
                loadedGeneration = generation;
                loadedVersion = version;
                Set<String> seen = new HashSet<>(prefs.getStringSet("seen", Collections.emptySet()));
                if (seen.retainAll(active.keySet())) prefs.edit().putStringSet("seen",seen).apply();
            }
            if (active.isEmpty() || now < issued || now >= expires) return;
            String key = type+" "+IntelligenceManifestV2Verifier.normalize(type,value);
            Long until = active.get(key);
            if (until == null || now >= until) return;
            Set<String> previous = prefs.getStringSet("seen", Collections.emptySet());
            if (previous.contains(key)) return;
            Set<String> seen = new HashSet<>(previous);
            seen.add(key);
            prefs.edit().putStringSet("seen",seen).putString("lastFinding",key)
                    .putLong("findingTime",now).apply();
        } catch (IOException | IllegalArgumentException ignored) {
            // Failure of advisory evidence must never interrupt packet or file processing.
        }
    }

    private SignedFeedObservations() {}
}
