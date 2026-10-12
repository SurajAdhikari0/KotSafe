/*
 * This file is part of KotSafe.
 *
 * KotSafe is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * KotSafe is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with KotSafe.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2026 - KotSafe
 */

package com.kotsafe.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.kotsafe.security.model.BrowserActivityManager;
import com.kotsafe.security.model.BrowserActivityManager.BrowserLogEntry;

import org.junit.Test;

public class BrowserActivityManagerTest {

    @Test
    public void testKnownBrowsersList() {
        assertTrue(BrowserActivityManager.KNOWN_BROWSER_PACKAGES.contains("com.android.chrome"));
        assertTrue(BrowserActivityManager.KNOWN_BROWSER_PACKAGES.contains("org.mozilla.firefox"));
        assertTrue(BrowserActivityManager.KNOWN_BROWSER_PACKAGES.contains("com.brave.browser"));
        assertTrue(BrowserActivityManager.KNOWN_BROWSER_PACKAGES.contains("com.sec.android.app.sbrowser"));
        assertTrue(BrowserActivityManager.KNOWN_BROWSER_PACKAGES.contains("com.microsoft.emmx"));
        assertTrue(BrowserActivityManager.KNOWN_BROWSER_PACKAGES.contains("com.duckduckgo.mobile.android"));
    }

    @Test
    public void testFormatEncryptedTlsPreview() {
        byte[] sampleTlsBytes = new byte[] {
                0x17, 0x03, 0x03, 0x00, 0x20,
                (byte) 0xa1, (byte) 0xb2, (byte) 0xc3, (byte) 0xd4
        };

        String formatted = BrowserActivityManager.formatEncryptedTlsPreview(sampleTlsBytes);
        assertNotNull(formatted);
        assertTrue(formatted.contains("17 03 03 00 20 a1 b2 c3 d4"));
    }

    @Test
    public void testBrowserLogEntryDecryptedModel() {
        BrowserLogEntry entry = new BrowserLogEntry(
                1,
                1600000000000L,
                "Google Chrome",
                "com.android.chrome",
                10085,
                "www.google.com",
                "142.250.190.68",
                443,
                true, // isDecrypted
                false, // isCleartextHttp
                "GET",
                "https://www.google.com/search?q=kotsafe",
                200,
                "application/json",
                "{\"status\":\"ok\"}",
                true, // hasJwt
                false, // hasProtobuf
                false, // hasDoh
                "TLSv1.3",
                "TLS_AES_256_GCM_SHA384",
                "",
                1024,
                8192
        );

        assertTrue(entry.isDecrypted);
        assertEquals("GET", entry.httpMethod);
        assertEquals("https://www.google.com/search?q=kotsafe", entry.url);
        assertTrue(entry.hasJwt);
        assertFalse(entry.hasProtobuf);
        assertEquals(200, entry.statusCode);
        assertEquals("Google Chrome", entry.appName);
    }

    @Test
    public void testBrowserLogEntryEncryptedModel() {
        BrowserLogEntry entry = new BrowserLogEntry(
                2,
                1600000000000L,
                "Mozilla Firefox",
                "org.mozilla.firefox",
                10090,
                "mozilla.org",
                "104.16.249.249",
                443,
                false, // isDecrypted = false (encrypted TLS)
                false,
                "",
                "",
                0,
                "",
                "",
                false,
                false,
                false,
                "TLSv1.3",
                "TLS_AES_256_GCM_SHA384",
                "17 03 03 00 a0 [ENCRYPTED APPLICATION DATA STREAM]",
                2048,
                16384
        );

        assertFalse(entry.isDecrypted);
        assertEquals("TLSv1.3", entry.tlsVersion);
        assertEquals("mozilla.org", entry.hostOrDomain);
        assertTrue(entry.encryptedHexPreview.contains("ENCRYPTED"));
    }
}
