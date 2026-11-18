package com.kotsafe.security.model;

import static org.junit.Assert.*;
import android.app.Application;
import android.util.AtomicFile;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

@RunWith(RobolectricTestRunner.class)
@Config(application=Application.class,sdk=34,manifest=Config.NONE)
public class IntelligenceManifestV2Test {
    // Synthetic test-only seed 00..1f. Never provision this key in an app release.
    private static final byte[] PUBLIC=Hex.decode("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8");
    private static final String PAYLOAD="{\"audience\":\"android\",\"expires_at\":200,\"indicators\":[{\"id\":\"url\",\"type\":\"url\",\"valid_until\":190,\"value\":\"https://example.test/Path?x=A&x=b\"},{\"id\":\"ipv6\",\"type\":\"ip\",\"valid_until\":200,\"value\":\"2001:db8::1\"},{\"id\":\"hash\",\"type\":\"sha256\",\"valid_until\":200,\"value\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}],\"issued_at\":100,\"schema_version\":2,\"tenant_scope\":\"tenant-a\",\"version\":2}";
    private static final String SIGNATURE="QLAemXIDBTlJV9WwkQIFxzjqmsLsVZR144TJH0+D6DOJljULR8eOxFSxenNB4u+NhuEhZsrbgVJVqYX3lOOzDQ==";

    private IntelligenceManifestV2Verifier verifier(String tenant) {
        return new IntelligenceManifestV2Verifier(Collections.singletonMap("fixture",PUBLIC),tenant);
    }
    private byte[] envelope(String payload,String signature) throws Exception {
        return new JSONObject().put("key_id","fixture").put("payload",payload).put("signature",signature).toString().getBytes(StandardCharsets.UTF_8);
    }
    private byte[] golden() throws Exception { return envelope(PAYLOAD,SIGNATURE); }
    private byte[] signed(String payload) throws Exception {
        byte[] seed=new byte[32]; for(int i=0;i<32;i++)seed[i]=(byte)i;
        Ed25519Signer signer=new Ed25519Signer(); signer.init(true,new Ed25519PrivateKeyParameters(seed,0));
        byte[] bytes=("kotsafe-intelligence-v1:"+payload).getBytes(StandardCharsets.UTF_8);
        signer.update(bytes,0,bytes.length);
        return envelope(payload,Base64.toBase64String(signer.generateSignature()));
    }
    private static void rejects(Throwing action) throws Exception {
        try { action.run(); fail("Expected validation rejection"); } catch(IOException expected) { }
    }
    private interface Throwing { void run() throws Exception; }

    @Test public void pythonGoldenSignatureAndExactUrlAreVerified() throws Exception {
        IntelligenceManifestV2Verifier.Snapshot snapshot=verifier("tenant-a").verify(golden(),150,0);
        assertEquals(2,snapshot.version); assertEquals(3,snapshot.indicators.size());
        assertEquals("https://example.test/Path?x=A&x=b",snapshot.indicators.get(0).value);
        assertEquals("2001:db8::1",snapshot.indicators.get(1).value);
    }

    @Test public void tamperScopeAudienceExpiryReplayAndUnknownKeyAreRejected() throws Exception {
        IntelligenceManifestV2Verifier verifier=verifier("tenant-a");
        rejects(()->verifier.verify(envelope(PAYLOAD.replace("Path","Other"),SIGNATURE),150,0));
        rejects(()->verifier("tenant-b").verify(golden(),150,0));
        rejects(()->verifier.verify(signed(PAYLOAD.replace("android","desktop")),150,0));
        rejects(()->verifier.verify(golden(),200,0));
        rejects(()->verifier.verify(golden(),99,0));
        rejects(()->verifier.verify(golden(),150,2));
        byte[] wrong=new JSONObject(new String(golden(),StandardCharsets.UTF_8)).put("key_id","unknown").toString().getBytes(StandardCharsets.UTF_8);
        rejects(()->verifier.verify(wrong,150,0));
    }

    @Test public void malformedDuplicateAndUnsupportedIndicatorPayloadsAreRejected() throws Exception {
        IntelligenceManifestV2Verifier verifier=verifier("tenant-a");
        for(String bad:Arrays.asList(PAYLOAD.replace("\"schema_version\":2","\"schema_version\":true"),
                PAYLOAD.replace("\"version\":2","\"version\":2,\"version\":3"),
                PAYLOAD.replace("\"type\":\"sha256\"","\"type\":\"process_execution\""),
                PAYLOAD.replace("\"valid_until\":190","\"valid_until\":201"),
                PAYLOAD.replace("https://example.test/Path?x=A&x=b","https://user:password@example.test/")))
            rejects(()->verifier.verify(signed(bad),150,0));
        rejects(()->verifier.verify(new byte[IntelligenceManifestV2Verifier.MAX_ENVELOPE_BYTES+1],150,0));
        assertEquals("2001:db8::1",IntelligenceManifestV2Verifier.normalize("ip","2001:0db8::1"));
        rejects(()->IntelligenceManifestV2Verifier.normalize("ip","example.test"));
    }

    @Test public void atomicCacheRestoresExpiredWatermarkAndBlocksStaleWriters() throws Exception {
        File directory=Files.createTempDirectory("intelligence-cache-").toFile();
        IntelligenceSnapshotStore first=new IntelligenceSnapshotStore(directory,verifier("tenant-a"));
        IntelligenceSnapshotStore stale=new IntelligenceSnapshotStore(directory,verifier("tenant-a"));
        assertFalse(stale.restore(150)); first.install(golden(),150);
        rejects(()->stale.install(golden(),150)); assertEquals(2,stale.lastVersion());
        IntelligenceSnapshotStore restored=new IntelligenceSnapshotStore(directory,verifier("tenant-a"));
        assertTrue(restored.restore(201)); assertEquals(2,restored.lastVersion()); assertTrue(restored.active(201).isEmpty());
        assertEquals(3,first.active(150).size()); assertEquals(2,first.active(195).size());
    }

    @Test public void interruptedAtomicInstallLeavesPreviousSnapshotAvailable() throws Exception {
        File directory=Files.createTempDirectory("intelligence-interrupt-").toFile();
        IntelligenceSnapshotStore store=new IntelligenceSnapshotStore(directory,verifier("tenant-a"));
        store.install(golden(),150);
        AtomicFile atomic=new AtomicFile(new File(directory,"intelligence-v2.json"));
        FileOutputStream interrupted=atomic.startWrite(); interrupted.write("partial".getBytes(StandardCharsets.UTF_8)); interrupted.close();
        IntelligenceSnapshotStore recovered=new IntelligenceSnapshotStore(directory,verifier("tenant-a"));
        assertTrue(recovered.restore(150)); assertEquals(2,recovered.lastVersion());
        assertEquals(3,recovered.active(150).size());
        rejects(()->recovered.install(envelope(PAYLOAD.replace("Path","Tampered"),SIGNATURE),150));
        assertEquals(3,recovered.active(150).size());
        File[] files=directory.listFiles(); assertNotNull(files);
        for(File file:files) assertTrue(file.getName().startsWith("intelligence-v2"));
    }

    @Test public void consumerPublisherWithdrawalSurvivesRestartAndRejectsReplay() throws Exception {
        // Generated by signed_reviewed_feed with the existing synthetic fixture signer.
        org.json.JSONArray envelopes;
        try (java.io.InputStream in = getClass().getResourceAsStream("/android-publisher-pilot.json")) {
            assertNotNull(in);
            envelopes = new org.json.JSONArray(new String(IntelligenceSnapshotStore.readBounded(in), StandardCharsets.UTF_8));
        }
        byte[] first = envelopes.getJSONObject(0).toString().getBytes(StandardCharsets.UTF_8);
        byte[] withdrawal = envelopes.getJSONObject(1).toString().getBytes(StandardCharsets.UTF_8);
        File directory = Files.createTempDirectory("consumer-publisher-").toFile();
        IntelligenceManifestV2Verifier verifier = verifier("kotsafe-android-public");
        IntelligenceSnapshotStore store = new IntelligenceSnapshotStore(directory, verifier);
        store.install(first, 100);
        assertEquals(2, store.active(100).size());
        assertEquals("domain", store.active(100).get(0).type);
        assertEquals("pilot.invalid", store.active(100).get(0).value);
        byte[] hash = java.security.MessageDigest.getInstance("SHA-256")
                .digest("KotSafe harmless pilot fixture".getBytes(StandardCharsets.UTF_8));
        assertEquals("sha256", store.active(160).get(0).type);
        assertEquals(Hex.toHexString(hash), store.active(160).get(0).value);
        assertEquals(1, store.active(160).size());
        assertTrue(store.active(180).isEmpty());
        store.install(withdrawal, 150);
        IntelligenceSnapshotStore recovered = new IntelligenceSnapshotStore(directory, verifier);
        assertTrue(recovered.restore(151));
        assertTrue(recovered.active(151).isEmpty());
        rejects(() -> recovered.install(first, 151));
    }

    @Test public void coordinatorRequiresOptInApprovedHttpsAndMatchingDeviceTenant() throws Exception {
        IntelligenceManifestV2Verifier verifier=verifier("tenant-a");
        IntelligenceSnapshotStore store=new IntelligenceSnapshotStore(Files.createTempDirectory("intelligence-sync-").toFile(),verifier);
        AtomicInteger fetched=new AtomicInteger(); AtomicInteger tokens=new AtomicInteger();
        IntelligenceV2SyncCoordinator.DeviceCredential credential=new IntelligenceV2SyncCoordinator.DeviceCredential() {
            public String tenantScope(){return "tenant-a";} public String deviceId(){return "android-fixture";}
            public String bearerToken(){tokens.incrementAndGet();return "synthetic-device-token-00000000000000";}
        };
        IntelligenceV2SyncCoordinator coordinator=new IntelligenceV2SyncCoordinator(store,verifier,
                Collections.singleton("intel.example.test"),(endpoint,proof)->{fetched.incrementAndGet();try{return golden();}catch(Exception error){throw new IOException(error);}});
        URI approved=new URI("https://intel.example.test/v1/manifest?audience=android");
        rejects(()->coordinator.sync(false,approved,credential,150));
        rejects(()->coordinator.sync(true,new URI("http://intel.example.test/v1/manifest"),credential,150));
        rejects(()->coordinator.sync(true,new URI("https://attacker.example/v1/manifest"),credential,150));
        assertEquals(0,fetched.get()); assertEquals(0,tokens.get());
        assertEquals(2,coordinator.sync(true,approved,credential,150).version); assertEquals(1,fetched.get());
        assertEquals(2,coordinator.sync(true,approved,credential,151).version);
        rejects(()->coordinator.sync(true,approved,credential,200));
        assertEquals(3,store.active(150).size());
    }

    @Test
    public void dynamicYaraRulesAndMlWeightsAreSignedAndExtracted() throws Exception {
        IntelligenceManifestV2Verifier verifier = verifier("tenant-a");
        String payload = new JSONObject()
                .put("audience", "android")
                .put("schema_version", 2)
                .put("tenant_scope", "tenant-a")
                .put("version", 5)
                .put("issued_at", 100)
                .put("expires_at", 300)
                .put("indicators", new org.json.JSONArray().put(new JSONObject()
                        .put("id", "ind-1")
                        .put("type", "sha256")
                        .put("value", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                        .put("valid_until", 250)))
                .put("dynamic_yara_rules", new org.json.JSONArray().put(new JSONObject()
                        .put("name", "Dynamic_Trojan_Anatsa")
                        .put("tags", "trojan,banking")
                        .put("description", "Dynamic Anatsa Signature")
                        .put("severity", "MALICIOUS")
                        .put("match_all", false)
                        .put("patterns", new org.json.JSONArray().put("com.anatsa.payload").put("inject_overlay"))))
                .put("dynamic_ml_weights", new JSONObject()
                        .put("bankBaseWeight", 0.55)
                        .put("maliciousThreshold", 0.65))
                .toString();

        byte[] envelope = signed(payload);
        IntelligenceManifestV2Verifier.Snapshot snapshot = verifier.verify(envelope, 150, 4);

        assertNotNull(snapshot);
        assertEquals(5, snapshot.version);
        assertEquals(1, snapshot.indicators.size());
        assertEquals(1, snapshot.dynamicYaraRules.size());
        assertEquals("Dynamic_Trojan_Anatsa", snapshot.dynamicYaraRules.get(0).name);
        assertEquals(2, snapshot.dynamicYaraRules.get(0).stringPatterns.size());
        assertEquals(2, snapshot.dynamicMlWeights.size());
        assertEquals(0.55f, snapshot.dynamicMlWeights.get("bankBaseWeight"), 0.001f);
        assertEquals(0.65f, snapshot.dynamicMlWeights.get("maliciousThreshold"), 0.001f);
    }
}
