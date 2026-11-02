package com.kotsafe.security.p2p;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.TimeZone;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class TimezoneSentinelTest {

    private TimeZone mOriginalTz;

    @Before
    public void setUp() {
        mOriginalTz = TimeZone.getDefault();
    }

    @After
    public void tearDown() {
        TimeZone.setDefault(mOriginalTz);
    }

    @Test
    public void testAlignedTimezoneMatches() {
        // Set device timezone to Asia/Kolkata (+5:30)
        TimeZone.setDefault(TimeZone.getTimeZone("Asia/Kolkata"));

        TimezoneSentinel.TimezoneAudit audit = TimezoneSentinel.auditTimezone("IN");
        assertNotNull(audit);
        assertFalse("Expected aligned timezone not to be flagged as mismatch", audit.isMismatch);
        assertEquals(0, audit.diffMinutes);
        assertEquals("IN", audit.exitCountry);
    }

    @Test
    public void testMismatchTimezoneDetected() {
        // Device is set to London (UTC+0) while exit node is in India (UTC+5:30)
        TimeZone.setDefault(TimeZone.getTimeZone("Europe/London"));

        TimezoneSentinel.TimezoneAudit audit = TimezoneSentinel.auditTimezone("IN");
        assertNotNull(audit);
        assertTrue("Expected 5.5 hour discrepancy to be flagged as mismatch", audit.isMismatch);
        assertEquals(330, audit.diffMinutes);
        assertTrue(audit.advisoryText.contains("Websites can detect your travel location"));
    }

    @Test
    public void testNullOrEmptyCountrySafe() {
        TimezoneSentinel.TimezoneAudit auditNull = TimezoneSentinel.auditTimezone(null);
        assertNotNull(auditNull);
        assertFalse(auditNull.isMismatch);

        TimezoneSentinel.TimezoneAudit auditEmpty = TimezoneSentinel.auditTimezone("  ");
        assertNotNull(auditEmpty);
        assertFalse(auditEmpty.isMismatch);
    }

    @Test
    public void testSupportedCountryMappings() {
        // France (UTC+1) vs Asia/Dubai (UTC+4) -> 3 hours diff
        TimeZone.setDefault(TimeZone.getTimeZone("Europe/Paris"));
        TimezoneSentinel.TimezoneAudit dubaiAudit = TimezoneSentinel.auditTimezone("AE");
        assertTrue(dubaiAudit.isMismatch);
        assertEquals(180, dubaiAudit.diffMinutes);

        // France vs France -> 0 diff
        TimezoneSentinel.TimezoneAudit frAudit = TimezoneSentinel.auditTimezone("FR");
        assertFalse(frAudit.isMismatch);
    }
}
