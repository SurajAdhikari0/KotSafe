package com.kotsafe.security.model;

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.net.URI;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

/** Explicit opt-in integration point. Invoke on an executor, never the UI thread. */
public final class IntelligenceV2SyncCoordinator {
    public interface DeviceCredential {
        String tenantScope();
        String deviceId();
        /** Short-lived device-scoped token obtained through a separately trusted enrollment. */
        String bearerToken() throws IOException;
    }
    public interface ManifestFetcher {
        byte[] fetch(URI endpoint, DeviceCredential credential) throws IOException;
    }
    private final IntelligenceSnapshotStore store;
    private final IntelligenceManifestV2Verifier verifier;
    private final ManifestFetcher fetcher;
    private final Set<String> hosts;
    private final AtomicBoolean syncing=new AtomicBoolean();

    public IntelligenceV2SyncCoordinator(IntelligenceSnapshotStore store, IntelligenceManifestV2Verifier verifier,
                                        Set<String> allowedHosts, ManifestFetcher fetcher) {
        if (store==null || verifier==null || allowedHosts==null || allowedHosts.isEmpty() || fetcher==null)
            throw new IllegalArgumentException("Explicit sync configuration required");
        this.store=store; this.verifier=verifier; this.fetcher=fetcher;
        Set<String> copy=new HashSet<>();
        for (String host:allowedHosts) {
            if (host==null || !host.matches("[a-z0-9][a-z0-9.-]{0,252}")) throw new IllegalArgumentException("Invalid configured origin");
            copy.add(host);
        }
        hosts=Collections.unmodifiableSet(copy);
    }

    public IntelligenceManifestV2Verifier.Snapshot sync(boolean optedIn, URI endpoint,
                                                       DeviceCredential credential, long nowSeconds) throws IOException {
        if (!optedIn) throw new IOException("Intelligence sync requires explicit opt-in");
        if (endpoint==null || !"https".equals(endpoint.getScheme()) || endpoint.getHost()==null
                || !hosts.contains(endpoint.getHost().toLowerCase(Locale.ROOT)) || endpoint.getRawUserInfo()!=null
                || endpoint.getFragment()!=null || (endpoint.getPort()!=-1 && endpoint.getPort()!=443))
            throw new IOException("Unapproved intelligence HTTPS origin");
        if (credential==null || !verifier.tenantScope().equals(credential.tenantScope())
                || credential.deviceId()==null || !credential.deviceId().matches("[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}"))
            throw new IOException("Device-scoped credentials required");
        if (!syncing.compareAndSet(false,true)) throw new IOException("Intelligence sync already running");
        try { return store.install(fetcher.fetch(endpoint,credential),nowSeconds); }
        finally { syncing.set(false); }
    }

    /** HTTPS transport with platform certificate validation, no redirect/token forwarding. */
    public static final class HttpsFetcher implements ManifestFetcher {
        @Override public byte[] fetch(URI endpoint, DeviceCredential credential) throws IOException {
            if (!"https".equals(endpoint.getScheme())) throw new IOException("HTTPS required");
            String token=credential.bearerToken();
            if (token==null || !token.matches("[\\x21-\\x7e]{32,8192}")) throw new IOException("Invalid device credential");
            HttpsURLConnection connection=(HttpsURLConnection)endpoint.toURL().openConnection();
            try {
                connection.setInstanceFollowRedirects(false);
                connection.setConnectTimeout(8000); connection.setReadTimeout(10000);
                connection.setRequestMethod("GET"); connection.setRequestProperty("Accept","application/json");
                connection.setRequestProperty("Authorization","Bearer "+token);
                connection.setRequestProperty("X-KotSafe-Device-Id",credential.deviceId());
                int response=connection.getResponseCode();
                if (response!=200) throw new IOException("Intelligence service returned HTTP "+response);
                if (connection.getContentLengthLong()>IntelligenceManifestV2Verifier.MAX_ENVELOPE_BYTES)
                    throw new IOException("Intelligence response exceeds limit");
                try(java.io.InputStream input=connection.getInputStream()) {
                    byte[] raw=IntelligenceSnapshotStore.readBounded(input);
                    Object parsed=IntelligenceManifestV2Verifier.parse(raw,IntelligenceManifestV2Verifier.MAX_ENVELOPE_BYTES);
                    // The authenticated pilot/gateway may use its standard data wrapper.
                    if (parsed instanceof java.util.Map && ((java.util.Map<?,?>)parsed).size()==1
                            && ((java.util.Map<?,?>)parsed).containsKey("data"))
                        return new com.google.gson.Gson().toJson(((java.util.Map<?,?>)parsed).get("data")).getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    return raw;
                }
            } finally { connection.disconnect(); }
        }
    }
}
