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
import static org.junit.Assert.assertTrue;

import com.kotsafe.security.services.PhishingNotificationListener;

import org.junit.Test;

import java.util.List;

public class PhishingNotificationListenerTest {

    @Test
    public void testExtractStandardHttpUrl() {
        String msg = "Your bank account is locked! Please verify at http://secure-bank-update.xyz/login immediately.";
        List<String> urls = PhishingNotificationListener.extractUrls(msg);

        assertEquals(1, urls.size());
        assertEquals("http://secure-bank-update.xyz/login", urls.get(0));
    }

    @Test
    public void testExtractHttpsAndBareDomain() {
        String msg = "Check your package tracking: https://fedx-delivery.top/track?id=83829 and also visit evil-phish.ru/auth";
        List<String> urls = PhishingNotificationListener.extractUrls(msg);

        assertEquals(2, urls.size());
        assertTrue(urls.contains("https://fedx-delivery.top/track?id=83829"));
        assertTrue(urls.contains("https://evil-phish.ru/auth"));
    }

    @Test
    public void testNoUrlsInMessage() {
        String msg = "Hello, are we still meeting for lunch at 12:30 today?";
        List<String> urls = PhishingNotificationListener.extractUrls(msg);

        assertTrue(urls.isEmpty());
    }
}
