/*
 * This file is part of KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import android.content.Context;

import androidx.test.core.app.ApplicationProvider;

import com.kotsafe.security.model.KotSafeCloudProvider;
import com.kotsafe.security.model.ThreatIntelProvider;
import com.kotsafe.security.model.ThreatIntelRouter;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 33)
public class KotSafeCloudProviderTest {

    private Context mContext;
    private KotSafeCloudProvider mProvider;

    @Before
    public void setUp() {
        mContext = ApplicationProvider.getApplicationContext();
        mProvider = new KotSafeCloudProvider(mContext);
    }

    @Test
    public void testProviderIdentity() {
        assertEquals("KotSafe Cloud Intelligence", mProvider.getProviderName());
        assertEquals("KOTSAFE", mProvider.getProviderCode());
        assertTrue("KotSafe Cloud Provider should be available by default", mProvider.isAvailable());
        assertEquals("https://kotsafe.com/api/v1/threat-intel/lookup", mProvider.getEndpointUrl());
    }

    @Test
    public void testPrivateIpShortCircuit() {
        // Private / local IPs should resolve as clean without network call
        ThreatIntelProvider.ThreatReport rep = mProvider.queryIp("127.0.0.1");
        assertNotNull(rep);
        assertFalse(rep.isMalicious);
        assertEquals("SAFE", rep.verdict);

        ThreatIntelProvider.ThreatReport repLan = mProvider.queryIp("192.168.1.1:8080");
        assertNotNull(repLan);
        assertFalse(repLan.isMalicious);
        assertEquals("SAFE", repLan.verdict);
    }

    @Test
    public void testNullAndEmptyHandling() {
        assertNull(mProvider.queryHash(null));
        assertNull(mProvider.queryHash("   "));
        assertNull(mProvider.queryDomain(""));
        assertNull(mProvider.queryIp(""));
    }

    @Test
    public void testRouterIncludesKotSafeCloudAsPrimary() {
        ThreatIntelRouter router = ThreatIntelRouter.getInstance(mContext);
        assertTrue("Router must report active providers", router.hasAnyProvider());
        assertTrue("KotSafe Cloud must be in active providers",
                router.getActiveProviderNames().contains("KotSafe Cloud Intelligence"));
    }

    @Test
    public void testApiClientHasAnyApiKeyIsTrueByDefault() {
        ThreatIntelApiClient client = ThreatIntelApiClient.getInstance(mContext);
        assertTrue("ApiClient must consider protection active without personal keys", client.hasAnyApiKey());
    }
}
