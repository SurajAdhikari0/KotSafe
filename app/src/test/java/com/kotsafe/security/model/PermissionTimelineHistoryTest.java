package com.kotsafe.security.model;

import androidx.test.core.app.ApplicationProvider;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

import java.util.List;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(RobolectricTestRunner.class)
public class PermissionTimelineHistoryTest {
    @Test
    public void permissionEventsArePersistedAndQueriedForTheOwningApp() {
        String appPackage = "test.permission.history." + UUID.randomUUID().toString().replace("-", "");
        UnifiedIncidentTimeline timeline = UnifiedIncidentTimeline.getInstance(
                ApplicationProvider.getApplicationContext());
        timeline.record(new UnifiedIncidentTimeline.IncidentEvent.Builder()
                .type(UnifiedIncidentTimeline.EventType.APP_PERMISSION_CHANGE)
                .severity(UnifiedIncidentTimeline.Severity.INFO)
                .title("Permission granted: CAMERA")
                .detail("android.permission.CAMERA changed from not granted to granted.")
                .sourceApp(appPackage)
                .target("Android runtime permissions")
                .risk(0)
                .build());

        List<UnifiedIncidentTimeline.IncidentEvent> events =
                timeline.getPermissionEventsForApp(appPackage, 20);

        assertEquals(1, events.size());
        assertEquals(UnifiedIncidentTimeline.EventType.APP_PERMISSION_CHANGE, events.get(0).type);
        assertEquals(appPackage, events.get(0).sourceApp);
        assertTrue(events.get(0).timestampMs > 0);
    }
}
