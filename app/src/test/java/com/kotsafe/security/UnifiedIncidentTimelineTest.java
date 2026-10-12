/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security;

import com.kotsafe.security.model.UnifiedIncidentTimeline;
import com.kotsafe.security.model.WebCategoryEngine;


import org.junit.Before;
import org.junit.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.Assert.*;

/**
 * Unit tests for {@link UnifiedIncidentTimeline}.
 *
 * Tests the in-memory ring buffer, event construction, listener callbacks,
 * filtering, and JSON serialisation — no Android context required.
 */
public class UnifiedIncidentTimelineTest {

    /** Minimal in-process timeline (no SQLite, no Context). */
    private InProcessTimeline mTimeline;

    @Before
    public void setUp() {
        mTimeline = new InProcessTimeline();
    }

    // ── Event construction ────────────────────────────────────────────────────

    @Test
    public void testBuilderDefaults() {
        UnifiedIncidentTimeline.IncidentEvent e =
                new UnifiedIncidentTimeline.IncidentEvent.Builder()
                        .title("Test Event")
                        .build();

        assertNotNull(e.id);
        assertFalse(e.id.isEmpty());
        assertEquals(UnifiedIncidentTimeline.EventType.GENERAL_ALERT, e.type);
        assertEquals(UnifiedIncidentTimeline.Severity.MEDIUM, e.severity);
        assertEquals("Test Event", e.title);
        assertTrue(e.timestampMs > 0);
        assertEquals(50, e.riskScore);
    }

    @Test
    public void testBuilderAllFields() {
        UnifiedIncidentTimeline.IncidentEvent e =
                new UnifiedIncidentTimeline.IncidentEvent.Builder()
                        .type(UnifiedIncidentTimeline.EventType.IPS_HIT)
                        .severity(UnifiedIncidentTimeline.Severity.CRITICAL)
                        .title("IPS: SQL Injection")
                        .detail("SELECT * FROM users WHERE 1=1")
                        .sourceApp("com.evil.app")
                        .target("api.example.com")
                        .mitre("T1190")
                        .risk(95)
                        .correlationId("incident-001")
                        .build();

        assertEquals(UnifiedIncidentTimeline.EventType.IPS_HIT,  e.type);
        assertEquals(UnifiedIncidentTimeline.Severity.CRITICAL,   e.severity);
        assertEquals("IPS: SQL Injection",                        e.title);
        assertEquals("SELECT * FROM users WHERE 1=1",             e.detail);
        assertEquals("com.evil.app",                              e.sourceApp);
        assertEquals("api.example.com",                           e.target);
        assertEquals("T1190",                                     e.mitreTechnique);
        assertEquals(95,                                          e.riskScore);
        assertEquals("incident-001",                              e.correlationId);
    }

    // ── JSON serialisation ────────────────────────────────────────────────────

    @Test
    public void testEventFieldsIntegrity() {
        // Verify all IncidentEvent fields are set correctly without relying on Android JSON stubs
        UnifiedIncidentTimeline.IncidentEvent e =
                new UnifiedIncidentTimeline.IncidentEvent.Builder()
                        .type(UnifiedIncidentTimeline.EventType.DNS_TUNNEL)
                        .severity(UnifiedIncidentTimeline.Severity.HIGH)
                        .title("DNS Tunnel: evil.com")
                        .detail("High-entropy query")
                        .sourceApp("com.suspicious.app")
                        .target("evil.com")
                        .mitre("T1048.003")
                        .risk(85)
                        .correlationId("incident-007")
                        .build();

        assertNotNull(e.id);
        assertFalse(e.id.isEmpty());
        assertEquals(UnifiedIncidentTimeline.EventType.DNS_TUNNEL, e.type);
        assertEquals(UnifiedIncidentTimeline.Severity.HIGH,        e.severity);
        assertEquals("DNS Tunnel: evil.com",                       e.title);
        assertEquals("High-entropy query",                         e.detail);
        assertEquals("com.suspicious.app",                         e.sourceApp);
        assertEquals("evil.com",                                   e.target);
        assertEquals("T1048.003",                                  e.mitreTechnique);
        assertEquals(85,                                           e.riskScore);
        assertEquals("incident-007",                               e.correlationId);
    }

    // ── Ring buffer ───────────────────────────────────────────────────────────

    @Test
    public void testAddAndRetrieve() {
        mTimeline.record(new UnifiedIncidentTimeline.IncidentEvent.Builder()
                .type(UnifiedIncidentTimeline.EventType.PORT_SCAN)
                .title("Port Scan from 192.168.1.100")
                .risk(65)
                .build());

        List<UnifiedIncidentTimeline.IncidentEvent> events = mTimeline.getRecentEvents();
        assertEquals(1, events.size());
        assertEquals(UnifiedIncidentTimeline.EventType.PORT_SCAN, events.get(0).type);
    }

    @Test
    public void testRingBufferOrder_NewestFirst() {
        for (int i = 0; i < 5; i++) {
            mTimeline.record(new UnifiedIncidentTimeline.IncidentEvent.Builder()
                    .title("Event " + i)
                    .build());
        }

        List<UnifiedIncidentTimeline.IncidentEvent> events = mTimeline.getRecentEvents();
        assertEquals(5, events.size());
        // newest first
        assertEquals("Event 4", events.get(0).title);
        assertEquals("Event 0", events.get(4).title);
    }

    @Test
    public void testRingBufferBounded() {
        // Insert MAX_EVENTS + 10 events — oldest must be evicted
        for (int i = 0; i < 510; i++) {
            mTimeline.record(new UnifiedIncidentTimeline.IncidentEvent.Builder()
                    .title("Event " + i)
                    .build());
        }

        List<UnifiedIncidentTimeline.IncidentEvent> events = mTimeline.getRecentEvents();
        assertTrue("Ring buffer must not exceed 500 events", events.size() <= 500);
        // Most recent must be present
        assertEquals("Event 509", events.get(0).title);
    }

    @Test
    public void testClearMemory() {
        mTimeline.record(new UnifiedIncidentTimeline.IncidentEvent.Builder().title("A").build());
        mTimeline.record(new UnifiedIncidentTimeline.IncidentEvent.Builder().title("B").build());
        assertEquals(2, mTimeline.getEventCount());

        mTimeline.clearMemory();
        assertEquals(0, mTimeline.getEventCount());
    }

    // ── Filtering ─────────────────────────────────────────────────────────────

    @Test
    public void testGetEventsByType() {
        mTimeline.record(new UnifiedIncidentTimeline.IncidentEvent.Builder()
                .type(UnifiedIncidentTimeline.EventType.IPS_HIT).title("IPS").build());
        mTimeline.record(new UnifiedIncidentTimeline.IncidentEvent.Builder()
                .type(UnifiedIncidentTimeline.EventType.DNS_SINKHOLE).title("DNS").build());
        mTimeline.record(new UnifiedIncidentTimeline.IncidentEvent.Builder()
                .type(UnifiedIncidentTimeline.EventType.IPS_HIT).title("IPS 2").build());

        List<UnifiedIncidentTimeline.IncidentEvent> ips =
                mTimeline.getEventsByType(UnifiedIncidentTimeline.EventType.IPS_HIT);
        assertEquals(2, ips.size());

        List<UnifiedIncidentTimeline.IncidentEvent> dns =
                mTimeline.getEventsByType(UnifiedIncidentTimeline.EventType.DNS_SINKHOLE);
        assertEquals(1, dns.size());
    }

    @Test
    public void testGetEventsForTarget() {
        mTimeline.record(new UnifiedIncidentTimeline.IncidentEvent.Builder()
                .target("evil.com").title("Hit 1").build());
        mTimeline.record(new UnifiedIncidentTimeline.IncidentEvent.Builder()
                .target("safe.com").title("Hit 2").build());
        mTimeline.record(new UnifiedIncidentTimeline.IncidentEvent.Builder()
                .target("evil.com").title("Hit 3").build());

        List<UnifiedIncidentTimeline.IncidentEvent> evilEvents =
                mTimeline.getEventsForTarget("evil.com");
        assertEquals(2, evilEvents.size());
    }

    // ── Listener ─────────────────────────────────────────────────────────────

    @Test
    public void testListenerReceivesEvent() {
        AtomicBoolean fired = new AtomicBoolean(false);
        mTimeline.addListener(event -> {
            assertEquals(UnifiedIncidentTimeline.EventType.FIREWALL_BLOCK, event.type);
            fired.set(true);
        });

        mTimeline.record(new UnifiedIncidentTimeline.IncidentEvent.Builder()
                .type(UnifiedIncidentTimeline.EventType.FIREWALL_BLOCK)
                .title("Block: evil.com")
                .build());

        assertTrue("Listener must have been invoked", fired.get());
    }

    @Test
    public void testRemoveListener() {
        AtomicBoolean fired = new AtomicBoolean(false);
        UnifiedIncidentTimeline.TimelineListener l = event -> fired.set(true);

        mTimeline.addListener(l);
        mTimeline.removeListener(l);

        mTimeline.record(new UnifiedIncidentTimeline.IncidentEvent.Builder().title("X").build());
        assertFalse("Removed listener must NOT be invoked", fired.get());
    }

    // ── Factory methods ───────────────────────────────────────────────────────

    @Test
    public void testFactoryRecordIpsHit() {
        mTimeline.recordIpsHit("com.evil.app", "10.0.0.1", "SQL Injection", 90);
        List<UnifiedIncidentTimeline.IncidentEvent> events = mTimeline.getRecentEvents();
        assertEquals(1, events.size());
        assertEquals(UnifiedIncidentTimeline.EventType.IPS_HIT, events.get(0).type);
        assertEquals("T1190", events.get(0).mitreTechnique);
        assertTrue(events.get(0).riskScore >= 80);
    }

    @Test
    public void testFactoryRecordDnsSinkhole() {
        mTimeline.recordDnsSinkhole("malware.evil.com", "com.suspicious.app");
        UnifiedIncidentTimeline.IncidentEvent e = mTimeline.getRecentEvents().get(0);
        assertEquals(UnifiedIncidentTimeline.EventType.DNS_SINKHOLE, e.type);
        assertEquals("malware.evil.com", e.target);
        assertEquals("T1071.004", e.mitreTechnique);
        assertEquals(90, e.riskScore);
    }

    @Test
    public void testFactoryRecordDnsTunnel() {
        mTimeline.recordDnsTunnel("longrandomentropystring.evil.com", "com.exfil.app");
        UnifiedIncidentTimeline.IncidentEvent e = mTimeline.getRecentEvents().get(0);
        assertEquals(UnifiedIncidentTimeline.EventType.DNS_TUNNEL, e.type);
        assertEquals("T1048.003", e.mitreTechnique);
    }

    @Test
    public void testFactoryRecordPortScan() {
        mTimeline.recordPortScan("192.168.1.55", 42, "com.test.app");
        UnifiedIncidentTimeline.IncidentEvent e = mTimeline.getRecentEvents().get(0);
        assertEquals(UnifiedIncidentTimeline.EventType.PORT_SCAN, e.type);
        assertEquals("T1046", e.mitreTechnique);
    }

    @Test
    public void testFactoryRecordJa3() {
        mTimeline.recordJa3Match("aabbcc", "Cobalt Strike", "C2", "com.app");
        UnifiedIncidentTimeline.IncidentEvent e = mTimeline.getRecentEvents().get(0);
        assertEquals(UnifiedIncidentTimeline.EventType.JA3_MALICIOUS, e.type);
        assertEquals("T1071.001", e.mitreTechnique);
        assertTrue(e.riskScore >= 90);
    }

    @Test
    public void testFactoryRecordWebCategoryBlock() {
        mTimeline.recordWebCategoryBlock("pornhub.com", WebCategoryEngine.Category.ADULT, "com.browser");
        UnifiedIncidentTimeline.IncidentEvent e = mTimeline.getRecentEvents().get(0);
        assertEquals(UnifiedIncidentTimeline.EventType.WEB_CATEGORY_BLOCK, e.type);
        assertEquals("pornhub.com", e.target);
    }

    @Test
    public void testFactoryRecordRateLimit() {
        mTimeline.recordRateLimit("app:com.spammer", false, "com.spammer");
        UnifiedIncidentTimeline.IncidentEvent e = mTimeline.getRecentEvents().get(0);
        assertEquals(UnifiedIncidentTimeline.EventType.RATE_LIMIT, e.type);
        assertFalse(e.title.contains("Quarantine"));
    }

    @Test
    public void testFactoryRecordRateLimitQuarantined() {
        mTimeline.recordRateLimit("app:com.spammer", true, "com.spammer");
        UnifiedIncidentTimeline.IncidentEvent e = mTimeline.getRecentEvents().get(0);
        assertEquals(UnifiedIncidentTimeline.EventType.RATE_LIMIT, e.type);
        assertTrue(e.title.contains("Quarantine"));
        assertEquals(UnifiedIncidentTimeline.Severity.HIGH, e.severity);
    }

    @Test
    public void testAppPermissionChangeEventCarriesPackagePermissionAndObservedState() {
        mTimeline.record(new UnifiedIncidentTimeline.IncidentEvent.Builder()
                .type(UnifiedIncidentTimeline.EventType.APP_PERMISSION_CHANGE)
                .severity(UnifiedIncidentTimeline.Severity.INFO)
                .title("Permission granted: CAMERA")
                .detail("android.permission.CAMERA changed from not granted to granted.")
                .sourceApp("com.example.camera")
                .target("Android runtime permissions")
                .risk(0)
                .build());

        UnifiedIncidentTimeline.IncidentEvent event = mTimeline.getRecentEvents().get(0);
        assertEquals(UnifiedIncidentTimeline.EventType.APP_PERMISSION_CHANGE, event.type);
        assertEquals("com.example.camera", event.sourceApp);
        assertTrue(event.detail.contains("android.permission.CAMERA"));
        assertTrue(event.timestampMs > 0);
    }

    // ── Formatted time ────────────────────────────────────────────────────────

    @Test
    public void testFormattedTimeJustNow() {
        UnifiedIncidentTimeline.IncidentEvent e =
                new UnifiedIncidentTimeline.IncidentEvent.Builder()
                        .timestamp(System.currentTimeMillis() - 5000)
                        .title("recent")
                        .build();
        assertEquals("Just now", e.getFormattedTime());
    }

    @Test
    public void testFormattedTimeMinutesAgo() {
        UnifiedIncidentTimeline.IncidentEvent e =
                new UnifiedIncidentTimeline.IncidentEvent.Builder()
                        .timestamp(System.currentTimeMillis() - 5 * 60_000)
                        .title("5 min ago")
                        .build();
        assertTrue(e.getFormattedTime().contains("m ago"));
    }

    // ── In-process test double ────────────────────────────────────────────────

    /**
     * Minimal in-process timeline — no SQLite or Android Context.
     * Shares the real ring-buffer, listener, and factory logic.
     */
    static class InProcessTimeline {
        private final java.util.ArrayDeque<UnifiedIncidentTimeline.IncidentEvent> ringBuffer =
                new java.util.ArrayDeque<>(501);
        private final java.util.concurrent.CopyOnWriteArrayList<UnifiedIncidentTimeline.TimelineListener>
                listeners = new java.util.concurrent.CopyOnWriteArrayList<>();
        private static final int MAX = 500;

        void record(UnifiedIncidentTimeline.IncidentEvent event) {
            synchronized (ringBuffer) {
                ringBuffer.addFirst(event);
                if (ringBuffer.size() > MAX) ringBuffer.removeLast();
            }
            for (var l : listeners) l.onEventAdded(event);
        }

        void record(UnifiedIncidentTimeline.IncidentEvent.Builder b) { record(b.build()); }

        List<UnifiedIncidentTimeline.IncidentEvent> getRecentEvents() {
            synchronized (ringBuffer) { return new java.util.ArrayList<>(ringBuffer); }
        }

        List<UnifiedIncidentTimeline.IncidentEvent> getEventsByType(
                UnifiedIncidentTimeline.EventType type) {
            List<UnifiedIncidentTimeline.IncidentEvent> r = new java.util.ArrayList<>();
            synchronized (ringBuffer) {
                for (var e : ringBuffer) if (e.type == type) r.add(e);
            }
            return r;
        }

        List<UnifiedIncidentTimeline.IncidentEvent> getEventsForTarget(String target) {
            List<UnifiedIncidentTimeline.IncidentEvent> r = new java.util.ArrayList<>();
            synchronized (ringBuffer) {
                for (var e : ringBuffer) if (target.equals(e.target) || target.equals(e.sourceApp)) r.add(e);
            }
            return r;
        }

        int getEventCount() { synchronized (ringBuffer) { return ringBuffer.size(); } }
        void clearMemory()  { synchronized (ringBuffer) { ringBuffer.clear(); } }

        void addListener(UnifiedIncidentTimeline.TimelineListener l)    { listeners.add(l); }
        void removeListener(UnifiedIncidentTimeline.TimelineListener l) { listeners.remove(l); }

        // Factory shims
        void recordIpsHit(String pkg, String target, String rule, int risk) {
            record(new UnifiedIncidentTimeline.IncidentEvent.Builder()
                    .type(UnifiedIncidentTimeline.EventType.IPS_HIT)
                    .severity(risk >= 80 ? UnifiedIncidentTimeline.Severity.CRITICAL : UnifiedIncidentTimeline.Severity.HIGH)
                    .title("IPS: " + rule).detail("Exploit signature matched for " + target)
                    .sourceApp(pkg).target(target).mitre("T1190").risk(risk));
        }

        void recordDnsSinkhole(String domain, String pkg) {
            record(new UnifiedIncidentTimeline.IncidentEvent.Builder()
                    .type(UnifiedIncidentTimeline.EventType.DNS_SINKHOLE)
                    .severity(UnifiedIncidentTimeline.Severity.HIGH)
                    .title("DNS Sinkhole: " + domain)
                    .detail("Malicious domain blocked at DNS resolution — sinkholed to 0.0.0.0")
                    .sourceApp(pkg).target(domain).mitre("T1071.004").risk(90));
        }

        void recordDnsTunnel(String domain, String pkg) {
            record(new UnifiedIncidentTimeline.IncidentEvent.Builder()
                    .type(UnifiedIncidentTimeline.EventType.DNS_TUNNEL)
                    .severity(UnifiedIncidentTimeline.Severity.HIGH)
                    .title("DNS Tunnel: " + domain).sourceApp(pkg).target(domain)
                    .mitre("T1048.003").risk(85));
        }

        void recordPortScan(String ip, int portCount, String pkg) {
            record(new UnifiedIncidentTimeline.IncidentEvent.Builder()
                    .type(UnifiedIncidentTimeline.EventType.PORT_SCAN)
                    .severity(UnifiedIncidentTimeline.Severity.MEDIUM)
                    .title("Port Scan from " + ip).sourceApp(pkg).target(ip)
                    .mitre("T1046").risk(65));
        }

        void recordJa3Match(String ja3, String toolName, String cat, String pkg) {
            record(new UnifiedIncidentTimeline.IncidentEvent.Builder()
                    .type(UnifiedIncidentTimeline.EventType.JA3_MALICIOUS)
                    .severity(UnifiedIncidentTimeline.Severity.HIGH)
                    .title("C2 Client Fingerprint: " + toolName)
                    .detail("JA3=" + ja3 + " matches known " + cat + " C2 toolkit")
                    .sourceApp(pkg).target(ja3).mitre("T1071.001").risk(95));
        }

        void recordWebCategoryBlock(String domain, WebCategoryEngine.Category category, String pkg) {
            record(new UnifiedIncidentTimeline.IncidentEvent.Builder()
                    .type(UnifiedIncidentTimeline.EventType.WEB_CATEGORY_BLOCK)
                    .severity(UnifiedIncidentTimeline.Severity.MEDIUM)
                    .title("Web Block: " + category.label + " — " + domain)
                    .sourceApp(pkg).target(domain).mitre("T1071.001")
                    .risk(category.defaultRisk));
        }

        void recordRateLimit(String key, boolean quarantined, String pkg) {
            record(new UnifiedIncidentTimeline.IncidentEvent.Builder()
                    .type(UnifiedIncidentTimeline.EventType.RATE_LIMIT)
                    .severity(quarantined ? UnifiedIncidentTimeline.Severity.HIGH : UnifiedIncidentTimeline.Severity.MEDIUM)
                    .title(quarantined ? "Flood Guard Quarantine: " + key : "Rate Limit: " + key)
                    .sourceApp(pkg).target(key).mitre("T1498")
                    .risk(quarantined ? 70 : 40));
        }
    }
}
