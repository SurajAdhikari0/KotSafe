/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.kotsafe.security.model.DomainSuffixTree;

import org.junit.Before;
import org.junit.Test;

public class DomainSuffixTreeTest {

    private DomainSuffixTree mTree;

    @Before
    public void setUp() {
        mTree = new DomainSuffixTree();
    }

    @Test
    public void testExactMatch() {
        mTree.addDomain("ads.example.com", "AdList");
        assertTrue(mTree.isBlocked("ads.example.com"));
        assertEquals("AdList", mTree.matches("ads.example.com"));
        assertFalse(mTree.isBlocked("example.com"));
        assertFalse(mTree.isBlocked("other.com"));
    }

    @Test
    public void testSubdomainMatching() {
        mTree.addDomain("doubleclick.net", "GoogleAds");
        assertTrue(mTree.isBlocked("doubleclick.net"));
        assertTrue(mTree.isBlocked("ad.doubleclick.net"));
        assertTrue(mTree.isBlocked("sub.deep.ad.doubleclick.net"));
        assertEquals("GoogleAds", mTree.matches("sub.deep.ad.doubleclick.net"));
        assertFalse(mTree.isBlocked("notdoubleclick.net"));
    }

    @Test
    public void testWildcardPrefixStripping() {
        mTree.addDomain("*.analytics.track.org", "TrackerList");
        assertTrue(mTree.isBlocked("analytics.track.org"));
        assertTrue(mTree.isBlocked("client.analytics.track.org"));
        assertFalse(mTree.isBlocked("track.org"));
    }

    @Test
    public void testCleanDomain() {
        assertEquals("evil.com", DomainSuffixTree.cleanDomain("https://evil.com/path?query=1"));
        assertEquals("bad.org", DomainSuffixTree.cleanDomain("http://bad.org:8080/ad.js"));
        assertEquals("clean.net", DomainSuffixTree.cleanDomain("  clean.net.  "));
    }
}
