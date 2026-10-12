/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.content.Context;

import androidx.test.core.app.ApplicationProvider;

import com.kotsafe.security.model.SiemTelemetryForwarder;
import com.kotsafe.security.model.TelemetrySpoolDb;
import com.kotsafe.security.model.UnifiedIncidentTimeline;

import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

import java.util.Collections;
import java.util.List;

@RunWith(RobolectricTestRunner.class)
public class SiemTelemetryForwarderTest {

    private Context mContext;
    private TelemetrySpoolDb mSpoolDb;
    private SiemTelemetryForwarder mForwarder;

    @Before
    public void setUp() {
        mContext = ApplicationProvider.getApplicationContext();
        mSpoolDb = TelemetrySpoolDb.getInstance(mContext);
        mSpoolDb.clearAll();
        mForwarder = SiemTelemetryForwarder.getInstance(mContext);
    }

    @Test
    public void testTelemetrySpoolDbLifecycle() {
        assertEquals(0, mSpoolDb.getPendingCount());

        mSpoolDb.enqueue("evt-1", 1700000000000L, "IPS_HIT", "CRITICAL", "{\"test\":1}");
        mSpoolDb.enqueue("evt-2", 1700000001000L, "MALWARE", "HIGH", "{\"test\":2}");

        assertEquals(2, mSpoolDb.getPendingCount());

        List<TelemetrySpoolDb.SpooledEvent> batch = mSpoolDb.pollBatch(10);
        assertEquals(2, batch.size());
        assertEquals("evt-1", batch.get(0).eventId);
        assertEquals("IPS_HIT", batch.get(0).eventType);

        // Mark first delivered
        mSpoolDb.markDelivered(Collections.singletonList(batch.get(0).dbId));
        assertEquals(1, mSpoolDb.getPendingCount());

        // Attempt failure increments attempt count
        mSpoolDb.recordAttemptFailure(Collections.singletonList(batch.get(1).dbId));
        List<TelemetrySpoolDb.SpooledEvent> retryBatch = mSpoolDb.pollBatch(10);
        assertEquals(1, retryBatch.size());
        assertEquals(1, retryBatch.get(0).attempts);
    }

    @Test
    public void testFormatIncidentEcsJson() throws Exception {
        UnifiedIncidentTimeline.IncidentEvent event = new UnifiedIncidentTimeline.IncidentEvent.Builder()
                .type(UnifiedIncidentTimeline.EventType.IPS_HIT)
                .severity(UnifiedIncidentTimeline.Severity.CRITICAL)
                .title("Chrome V8 JIT Heap Corruption")
                .detail("Out-of-bounds pointer write detected")
                .sourceApp("com.android.chrome")
                .target("198.51.100.42:443")
                .mitre("T1190")
                .risk(95)
                .timestamp(1700000000000L)
                .build();

        String ecsJson = mForwarder.formatIncident(event, SiemTelemetryForwarder.FORMAT_ECS);
        assertNotNull(ecsJson);

        JSONObject root = new JSONObject(ecsJson);
        assertTrue(root.has("@timestamp"));
        assertTrue(root.has("event"));
        assertTrue(root.has("host"));
        assertTrue(root.has("threat"));

        JSONObject threat = root.getJSONObject("threat");
        assertEquals("Chrome V8 JIT Heap Corruption", threat.getString("rule_name"));
        assertEquals("T1190", threat.getString("technique_id"));

        JSONObject destination = root.getJSONObject("destination");
        // Anonymization active by default zeroes last octet: 198.51.100.0 or masks IP
        String address = destination.getString("address");
        assertNotNull(address);
    }

    @Test
    public void testFormatIncidentCef() {
        UnifiedIncidentTimeline.IncidentEvent event = new UnifiedIncidentTimeline.IncidentEvent.Builder()
                .type(UnifiedIncidentTimeline.EventType.BEHAVIORAL_CORRELATION)
                .severity(UnifiedIncidentTimeline.Severity.HIGH)
                .title("Low Jitter C2 Heartbeat")
                .detail("Periodic beaconing detected")
                .sourceApp("com.suspicious.app")
                .target("203.0.113.5")
                .mitre("T1071")
                .risk(85)
                .build();

        String cef = mForwarder.formatIncident(event, SiemTelemetryForwarder.FORMAT_CEF);
        assertNotNull(cef);
        assertTrue(cef.startsWith("CEF:0|KotSafe|NextGenEDR|3.0|BEHAVIORAL_CORRELATION|"));
        assertTrue(cef.contains("dproc=com.suspicious.app"));
        assertTrue(cef.contains("cs1=T1071"));
    }
}
