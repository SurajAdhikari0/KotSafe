package com.kotsafe.security;

import com.kotsafe.security.model.AppPrivacyScorecardEngine;
import com.kotsafe.security.model.BeaconingAnomalyDetector;
import com.kotsafe.security.model.QuantumSafeHandshake;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

@RunWith(RobolectricTestRunner.class)
@Config(application = TestKotSafe.class)
public class Phase1And2SecurityFeaturesTest {

    @Before
    public void setUp() {
        KotSafe.isUnderTest = true;
    }

    @Test
    public void testAppPrivacyScorecard_EvaluatesTrackersAndCleartext() {
        List<AppPrivacyScorecardEngine.ConnectionRecord> records = new ArrayList<>();

        // Add 2 distinct commercial tracker domains
        AppPrivacyScorecardEngine.ConnectionRecord r1 = new AppPrivacyScorecardEngine.ConnectionRecord();
        r1.host = "app.adjust.com";
        r1.remoteIp = "1.2.3.4";
        r1.port = 443;
        r1.isPlainHttp = false;
        records.add(r1);

        AppPrivacyScorecardEngine.ConnectionRecord r2 = new AppPrivacyScorecardEngine.ConnectionRecord();
        r2.host = "graph.facebook.com";
        r2.remoteIp = "2.3.4.5";
        r2.port = 443;
        r2.isPlainHttp = false;
        records.add(r2);

        // Add cleartext HTTP flow
        AppPrivacyScorecardEngine.ConnectionRecord r3 = new AppPrivacyScorecardEngine.ConnectionRecord();
        r3.host = "insecure-cdn.com";
        r3.remoteIp = "3.4.5.6";
        r3.port = 80;
        r3.isPlainHttp = true;
        records.add(r3);

        // Add background beacon
        AppPrivacyScorecardEngine.ConnectionRecord r4 = new AppPrivacyScorecardEngine.ConnectionRecord();
        r4.host = "telemetry.example.com";
        r4.remoteIp = "4.5.6.7";
        r4.port = 443;
        r4.madeWhileScreenOff = true;
        records.add(r4);

        // Score deductions:
        // 100 - (2 trackers * 5 = 10) - (cleartext = 15) - (1 bg beacon * 5 = 5) = 70
        // Expected score: 70 -> MODERATE
        AppPrivacyScorecardEngine.ScorecardResult res =
                AppPrivacyScorecardEngine.evaluate(null, "com.test.sample", records);

        Assert.assertNotNull(res);
        Assert.assertEquals(70, res.score);
        Assert.assertEquals("MODERATE", res.grade);
        Assert.assertEquals(2, res.trackerDomainsFound);
        Assert.assertTrue(res.hasCleartextHttp);
        Assert.assertEquals(1, res.backgroundBeaconDomains);
    }

    @Test
    public void testAppPrivacyScorecard_CleanAppReceivesExcellentScore() {
        List<AppPrivacyScorecardEngine.ConnectionRecord> records = new ArrayList<>();

        AppPrivacyScorecardEngine.ConnectionRecord r1 = new AppPrivacyScorecardEngine.ConnectionRecord();
        r1.host = "api.kotsafe.org";
        r1.remoteIp = "104.21.5.1";
        r1.port = 443;
        r1.isPlainHttp = false;
        records.add(r1);

        AppPrivacyScorecardEngine.ScorecardResult res =
                AppPrivacyScorecardEngine.evaluate(null, "com.kotsafe.security", records);

        Assert.assertNotNull(res);
        Assert.assertEquals(100, res.score);
        Assert.assertEquals("EXCELLENT", res.grade);
        Assert.assertEquals(0, res.trackerDomainsFound);
        Assert.assertFalse(res.hasCleartextHttp);
    }

    @Test
    public void testAppPrivacyScorecard_HandlesUnknownPackageNameGracefully() {
        List<AppPrivacyScorecardEngine.ConnectionRecord> records = new ArrayList<>();

        AppPrivacyScorecardEngine.ConnectionRecord record = new AppPrivacyScorecardEngine.ConnectionRecord();
        record.host = "graph.facebook.com";
        record.remoteIp = "2.3.4.5";
        record.port = 443;
        record.isPlainHttp = false;
        records.add(record);

        AppPrivacyScorecardEngine.ScorecardResult res =
                AppPrivacyScorecardEngine.evaluate(
                        androidx.test.core.app.ApplicationProvider.getApplicationContext(),
                        null,
                        records);

        Assert.assertNotNull(res);
        Assert.assertEquals(95, res.score);
        Assert.assertEquals(1, res.trackerDomainsFound);
        Assert.assertFalse(res.hasCleartextHttp);
    }

    @Test
    public void testBeaconingDetector_DetectsFixedIntervalHeartbeat() throws Exception {
        final java.util.concurrent.CountDownLatch latch = new java.util.concurrent.CountDownLatch(1);
        final java.util.concurrent.atomic.AtomicReference<com.kotsafe.security.security.event.SecurityEvent> capturedEvent =
                new java.util.concurrent.atomic.AtomicReference<>();

        com.kotsafe.security.security.event.SecurityEventBus.SecurityEventListener listener = event -> {
            capturedEvent.set(event);
            latch.countDown();
        };

        com.kotsafe.security.security.event.SecurityEventBus.getInstance()
                .subscribeType(com.kotsafe.security.security.event.EventTypes.NETWORK_BEACON, listener);

        long baseTime = 1700000000000L;
        // Feed 10 connections spaced exactly 30 seconds apart (30,000 ms)
        for (int i = 0; i < 10; i++) {
            long ts = baseTime + (i * 30000L);
            BeaconingAnomalyDetector.getInstance().onConnection(
                    androidx.test.core.app.ApplicationProvider.getApplicationContext(),
                    10999,
                    "com.malicious.c2",
                    "c2.adversary.org",
                    ts,
                    128
            );
        }

        boolean received = latch.await(3, java.util.concurrent.TimeUnit.SECONDS);
        com.kotsafe.security.security.event.SecurityEventBus.getInstance().unsubscribe(listener);

        Assert.assertTrue("Expected C2 beacon alert was not received!", received);
        Assert.assertNotNull(capturedEvent.get());
        Assert.assertEquals(com.kotsafe.security.security.event.EventTypes.NETWORK_BEACON, capturedEvent.get().getEventType());
        Assert.assertEquals(com.kotsafe.security.security.event.SecurityEvent.Severity.HIGH, capturedEvent.get().getSeverity());
    }
}
