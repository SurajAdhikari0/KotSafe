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
 * Copyright 2026 KotSafe Cyber Security Project
 */

package com.kotsafe.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.kotsafe.security.model.AppBaselineDb;
import com.kotsafe.security.model.AppBehaviorProfileManager;

import org.junit.Test;

public class AppBehaviorProfileManagerTest {

    @Test
    public void testShannonEntropyLowNormalDomain() {
        double entropyGoogle = AppBehaviorProfileManager.calculateShannonEntropy("google.com");
        // "google.com" has repeated characters and is low entropy
        assertTrue("Entropy for google.com should be reasonable", entropyGoogle < 3.2);

        double entropyEmpty = AppBehaviorProfileManager.calculateShannonEntropy("");
        assertEquals(0.0, entropyEmpty, 0.001);
    }

    @Test
    public void testShannonEntropyHighDgaDomain() {
        // High entropy algorithmic domain: random alphanumeric string
        String dgaDomain = "x7k9p2m4q8z1w3v5b0.biz";
        double entropyDga = AppBehaviorProfileManager.calculateShannonEntropy(dgaDomain);
        assertTrue("DGA domain should have high entropy > 3.8", entropyDga > 3.8);
    }

    @Test
    public void testAppProfileBasics() {
        AppBaselineDb.AppProfile profile = new AppBaselineDb.AppProfile();
        profile.packageName = "com.test.calculator";
        profile.appName = "Calculator";
        profile.knownPorts.add(443);
        profile.knownPorts.add(80);
        profile.knownDomains.add("api.calculator.com");

        assertTrue(profile.isKnownPort(443));
        assertTrue(profile.isKnownPort(80));
        assertFalse("Port 4444 should not be known", profile.isKnownPort(4444));
        assertFalse("Port 1337 should not be known", profile.isKnownPort(1337));

        assertTrue(profile.isKnownDomain("api.calculator.com"));
        assertFalse(profile.isKnownDomain("c2-evil-server.top"));
    }
}
