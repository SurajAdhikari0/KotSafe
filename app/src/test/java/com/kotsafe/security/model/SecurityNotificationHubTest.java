package com.kotsafe.security.model;
import static org.junit.Assert.*;
import android.app.Application;
import android.app.Notification;
import android.app.NotificationManager;
import android.content.Context;
import java.lang.reflect.Field;
import java.time.Duration;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.Shadows;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowSystemClock;

@RunWith(RobolectricTestRunner.class)
@Config(application = Application.class, sdk = 34, manifest = Config.NONE)
public class SecurityNotificationHubTest {
    private SecurityNotificationHub hub;
    private NotificationManager manager;
    @Before public void setup() throws Exception {
        Field singleton = SecurityNotificationHub.class.getDeclaredField("sInstance");
        singleton.setAccessible(true);
        singleton.set(null, null);
        Context context = RuntimeEnvironment.getApplication();
        hub = SecurityNotificationHub.getInstance(context);
        manager = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
    }
    private Notification summary() {
        return Shadows.shadowOf(manager).getNotification(SecurityNotificationHub.NOTIF_ID_THREAT_SUMMARY);
    }
    @Test public void repeatedObservationIsOneFindingAfterCooldown() {
        hub.postThreatAlert("Review", "example.test", "DNS", "SUSPICIOUS");
        for (int i = 0; i < 1000; i++) {
            ShadowSystemClock.advanceBy(Duration.ofSeconds(61));
            hub.postThreatAlert("Review", "example.test", "DNS", "SUSPICIOUS");
        }
        assertEquals(1, summary().extras.getCharSequenceArray(Notification.EXTRA_TEXT_LINES).length);
        assertEquals(SecurityNotificationHub.CHAN_REVIEW, summary().getChannelId());
        assertEquals(NotificationManager.IMPORTANCE_LOW,
                manager.getNotificationChannel(SecurityNotificationHub.CHAN_REVIEW).getImportance());
    }
    @Test public void escalationBypassesCooldownAndCanAlert() {
        hub.postThreatAlert("Review", "app", "APK", "SUSPICIOUS");
        hub.postThreatAlert("Known threat", "app", "APK", "MALICIOUS");
        assertEquals(SecurityNotificationHub.CHAN_THREATS, summary().getChannelId());
        assertEquals(0, summary().flags & Notification.FLAG_ONLY_ALERT_ONCE);
        assertEquals(1, summary().extras.getCharSequenceArray(Notification.EXTRA_TEXT_LINES).length);
        assertTrue(summary().extras.getCharSequence(Notification.EXTRA_TEXT).toString().contains("Known threat"));
    }
    @Test public void laterSuspicionDoesNotDowngradeThreat() {
        hub.postThreatAlert("Known threat", "app", "APK", "MALICIOUS");
        hub.postThreatAlert("Review", "app", "APK", "SUSPICIOUS");
        assertEquals(SecurityNotificationHub.CHAN_THREATS, summary().getChannelId());
        assertTrue(summary().extras.getCharSequence(Notification.EXTRA_TEXT).toString().contains("Known threat"));
    }
    @Test public void newCriticalIncidentCanAlertWhileSummaryExists() {
        hub.postThreatAlert("Known threat", "first", "APK", "MALICIOUS");
        hub.postThreatAlert("Known threat", "second", "APK", "MALICIOUS");
        assertEquals(2, summary().extras.getCharSequenceArray(Notification.EXTRA_TEXT_LINES).length);
        assertEquals(0, summary().flags & Notification.FLAG_ONLY_ALERT_ONCE);
    }
    @Test public void suspiciousScanDoesNotPublishSecureCompletion() {
        AntivirusScanEngine.ScanResult scan = new AntivirusScanEngine.ScanResult();
        hub.postScanCompleteNotification(scan);
        assertNotNull(Shadows.shadowOf(manager).getNotification(SecurityNotificationHub.NOTIF_ID_SCAN_REPORT));
        scan.suspiciousDetected = 2;
        hub.postScanCompleteNotification(scan);
        assertEquals(SecurityNotificationHub.CHAN_REVIEW, summary().getChannelId());
        assertNull(Shadows.shadowOf(manager).getNotification(SecurityNotificationHub.NOTIF_ID_SCAN_REPORT));
    }
    @Test public void escalatedOlderFindingBecomesVisibleInPreview() {
        hub.postThreatAlert("Review", "first", "APK", "SUSPICIOUS");
        for (int i = 0; i < 10; i++)
            hub.postThreatAlert("Review", "other" + i, "APK", "SUSPICIOUS");
        hub.postThreatAlert("Confirmed first", "first", "APK", "MALICIOUS");
        assertTrue(summary().extras.getCharSequence(Notification.EXTRA_TEXT).toString().contains("Confirmed first"));
    }
}
