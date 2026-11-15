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
 */

package com.kotsafe.security.model;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.List;

public class AccessibilityStalkerwareDetectorTest {

    @Test
    public void testKnownStalkerwareCatalogMatches() {
        assertTrue(AccessibilityStalkerwareDetector.isKnownStalkerwarePackage("com.cerberus.app"));
        assertEquals("Cerberus", AccessibilityStalkerwareDetector.getStalkerwareFamily("com.cerberus.app"));

        assertTrue(AccessibilityStalkerwareDetector.isKnownStalkerwarePackage("com.spyhide.monitor"));
        assertEquals("SpyHide", AccessibilityStalkerwareDetector.getStalkerwareFamily("com.spyhide.monitor"));

        assertTrue(AccessibilityStalkerwareDetector.isKnownStalkerwarePackage("com.mspy.service"));
        assertEquals("mSpy", AccessibilityStalkerwareDetector.getStalkerwareFamily("com.mspy.service"));

        assertTrue(AccessibilityStalkerwareDetector.isKnownStalkerwarePackage("com.trackview.cam"));
        assertEquals("TrackView", AccessibilityStalkerwareDetector.getStalkerwareFamily("com.trackview.cam"));

        assertTrue(AccessibilityStalkerwareDetector.isKnownStalkerwarePackage("com.chrysaor.surveillance"));
        assertEquals("Pegasus / Chrysaor", AccessibilityStalkerwareDetector.getStalkerwareFamily("com.chrysaor.surveillance"));

        assertTrue(AccessibilityStalkerwareDetector.isKnownStalkerwarePackage("com.flexispy.agent"));
        assertEquals("FlexiSPY", AccessibilityStalkerwareDetector.getStalkerwareFamily("com.flexispy.agent"));
    }

    @Test
    public void testCleanPackagesDoNotMatchStalkerware() {
        assertFalse(AccessibilityStalkerwareDetector.isKnownStalkerwarePackage("com.whatsapp"));
        assertNull(AccessibilityStalkerwareDetector.getStalkerwareFamily("com.whatsapp"));

        assertFalse(AccessibilityStalkerwareDetector.isKnownStalkerwarePackage("com.google.android.talkback"));
        assertNull(AccessibilityStalkerwareDetector.getStalkerwareFamily("com.google.android.talkback"));

        assertFalse(AccessibilityStalkerwareDetector.isKnownStalkerwarePackage("com.kotsafe.security"));
        assertNull(AccessibilityStalkerwareDetector.getStalkerwareFamily("com.kotsafe.security"));

        assertFalse(AccessibilityStalkerwareDetector.isKnownStalkerwarePackage(null));
        assertNull(AccessibilityStalkerwareDetector.getStalkerwareFamily(null));
    }

    @Test
    public void testSafeNullContextHandling() {
        List<AccessibilityStalkerwareDetector.StalkerwareThreat> threats =
                AccessibilityStalkerwareDetector.scanActiveServices(null);
        assertNotNull(threats);
        assertTrue(threats.isEmpty());

        assertNull(AccessibilityStalkerwareDetector.evaluateService(null, null));
    }

    @Test
    public void testThreatDataClass() {
        AccessibilityStalkerwareDetector.StalkerwareThreat threat = new AccessibilityStalkerwareDetector.StalkerwareThreat();
        threat.packageName = "com.spyhide.test";
        threat.severity = AntivirusEvidenceItem.SEVERITY_MALICIOUS;
        threat.riskScore = 100;
        threat.isKnownStalkerwareFamily = true;
        threat.stalkerwareFamily = "SpyHide";

        assertTrue(threat.isThreat());

        threat.severity = AntivirusEvidenceItem.SEVERITY_CLEAN;
        assertFalse(threat.isThreat());
    }
}

