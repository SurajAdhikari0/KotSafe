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

import com.kotsafe.security.model.UnifiedTrafficEvent;

import org.junit.Test;

public class TrafficDeduplicationParserTest {

    @Test
    public void testVpnUnifiedEventConstruction() {
        UnifiedTrafficEvent event = new UnifiedTrafficEvent.Builder()
                .setSourceTag(UnifiedTrafficEvent.SOURCE_VPN)
                .setAppUid(10150)
                .setPackageName("com.example.app")
                .setAppName("Example App")
                .setDestination("api.malicious.com")
                .setIp("198.51.100.25")
                .setDomain("api.malicious.com")
                .setUrl("https://api.malicious.com/endpoint")
                .setPort(443)
                .setProtocol("TCP")
                .setBytesSent(1500)
                .setBytesRcvd(4500)
                .setEventCategory(UnifiedTrafficEvent.EventCategory.NETWORK_CONN)
                .build();

        assertTrue(event.isVpnSource());
        assertFalse(event.isApiSource());
        assertEquals("vpn", event.sourceTag);
        assertEquals(10150, event.appUid);
        assertEquals("com.example.app", event.packageName);
        assertEquals("api.malicious.com", event.domain);
        assertEquals(1500, event.bytesSent);
        assertEquals(4500, event.bytesRcvd);
        assertEquals(UnifiedTrafficEvent.EventCategory.NETWORK_CONN, event.eventCategory);
    }

    @Test
    public void testApiBrowserNavigationEventConstruction() {
        UnifiedTrafficEvent event = new UnifiedTrafficEvent.Builder()
                .setSourceTag(UnifiedTrafficEvent.SOURCE_API)
                .setPackageName("com.android.chrome")
                .setAppName("Chrome")
                .setDestination("login.phishing-target.net")
                .setDomain("login.phishing-target.net")
                .setUrl("https://login.phishing-target.net/auth/login")
                .setPort(443)
                .setProtocol("HTTPS")
                .setEventCategory(UnifiedTrafficEvent.EventCategory.BROWSER_NAV)
                .setDetails("Defender Browser Navigation")
                .build();

        assertFalse(event.isVpnSource());
        assertTrue(event.isApiSource());
        assertEquals("api", event.sourceTag);
        assertEquals("com.android.chrome", event.packageName);
        assertEquals("https://login.phishing-target.net/auth/login", event.url);
        assertEquals(UnifiedTrafficEvent.EventCategory.BROWSER_NAV, event.eventCategory);
        assertEquals("Defender Browser Navigation", event.details);
    }

    @Test
    public void testApiWifiSecurityEventConstruction() {
        UnifiedTrafficEvent event = new UnifiedTrafficEvent.Builder()
                .setSourceTag(UnifiedTrafficEvent.SOURCE_API)
                .setDestination("Free_Public_Wifi")
                .setDomain("00:11:22:33:44:55")
                .setProtocol("802.11 (OPEN / UNENCRYPTED)")
                .setEventCategory(UnifiedTrafficEvent.EventCategory.WIFI_SECURITY)
                .setDetails("Connected to open unencrypted network.")
                .build();

        assertTrue(event.isApiSource());
        assertEquals(UnifiedTrafficEvent.EventCategory.WIFI_SECURITY, event.eventCategory);
        assertEquals("Free_Public_Wifi", event.destination);
        assertEquals("00:11:22:33:44:55", event.domain);
    }
}
