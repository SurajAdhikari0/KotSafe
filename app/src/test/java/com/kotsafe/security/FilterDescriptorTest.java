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
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security;

import com.kotsafe.security.model.ConnectionDescriptor;
import com.kotsafe.security.model.ConnectionDescriptor.Status;
import com.kotsafe.security.model.ConnectionDescriptor.DecryptionStatus;
import com.kotsafe.security.model.ConnectionDescriptor.FilteringStatus;
import com.kotsafe.security.model.FilterDescriptor;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import androidx.preference.PreferenceManager;
import com.kotsafe.security.model.Prefs;

@RunWith(RobolectricTestRunner.class)
public class FilterDescriptorTest {
    FilterDescriptor filter;

    @Before
    public void setup() {
        Context ctx = KotSafe.getInstance();
        if (ctx != null) {
            PreferenceManager.getDefaultSharedPreferences(ctx)
                    .edit()
                    .putBoolean(Prefs.PREF_HIDE_SYSTEM_TRAFFIC, false)
                    .apply();
        }
        filter = new FilterDescriptor();
    }

    private ConnectionDescriptor makeConn() {
        // uid 10100 is a regular user-app UID (>= 10000), so "Hide System Traffic" (default=true)
        // does not filter it out during unit tests.
        ConnectionDescriptor conn = new ConnectionDescriptor(0, 4, 6,
                "1.1.1.1", "2.2.2.2", "", 51234, 80,
                0, 10100, 0, false, 0);
        conn.l7proto = "HTTP";
        conn.status = ConnectionDescriptor.CONN_STATUS_CONNECTED;
        return conn;
    }

    @Test
    public void testInitialState() {
        assertFalse(filter.isSet());
    }

    @Test
    public void testDefaultMatchesEverything() {
        ConnectionDescriptor conn = makeConn();
        assertTrue(filter.matches(conn));
    }

    @Test
    public void testAllCategoryIncludesSystemTrafficButExcludesDns() {
        Context ctx = KotSafe.getInstance();
        if (ctx != null) {
            PreferenceManager.getDefaultSharedPreferences(ctx)
                    .edit()
                    .putBoolean(Prefs.PREF_HIDE_SYSTEM_TRAFFIC, true)
                    .apply();
        }

        FilterDescriptor all = new FilterDescriptor();
        all.appCategory = FilterDescriptor.AppCategory.ALL;

        ConnectionDescriptor system = makeConn();
        system.uid = 1000;
        system.status = ConnectionDescriptor.CONN_STATUS_CONNECTED;
        assertTrue("All should include system traffic in the broad view", all.matches(system));

        ConnectionDescriptor dns = new ConnectionDescriptor(999, 4, 17,
                "10.0.0.2", "8.8.8.8", "", 50000, 53,
                0, 10100, 0, false, 0);
        dns.l7proto = "DNS";
        dns.info = "example.com";
        dns.status = ConnectionDescriptor.CONN_STATUS_CONNECTED;
        assertFalse("DNS traffic should remain separate from the generic All view", all.matches(dns));
    }

    @Test
    public void testStatusFilterActive() {
        filter.status = Status.STATUS_ACTIVE;
        assertTrue(filter.isSet());

        ConnectionDescriptor active = makeConn();
        active.status = ConnectionDescriptor.CONN_STATUS_CONNECTED;
        assertTrue(filter.matches(active));

        ConnectionDescriptor closed = makeConn();
        closed.status = ConnectionDescriptor.CONN_STATUS_CLOSED;
        assertFalse(filter.matches(closed));
    }

    @Test
    public void testStatusFilterClosed() {
        filter.status = Status.STATUS_CLOSED;

        ConnectionDescriptor closed = makeConn();
        closed.status = ConnectionDescriptor.CONN_STATUS_CLOSED;
        assertTrue(filter.matches(closed));

        ConnectionDescriptor active = makeConn();
        active.status = ConnectionDescriptor.CONN_STATUS_CONNECTED;
        assertFalse(filter.matches(active));
    }

    @Test
    public void testOnlyBlacklisted() {
        filter.onlyBlacklisted = true;
        assertTrue(filter.isSet());

        ConnectionDescriptor conn = makeConn();
        assertFalse(filter.matches(conn));

        // set blacklisted via Whitebox
        Whitebox.setInternalState(conn, "blacklisted_ip", true);
        assertTrue(filter.matches(conn));
    }

    @Test
    public void testOnlyCleartext() {
        filter.onlyCleartext = true;
        assertTrue(filter.isSet());

        ConnectionDescriptor cleartext = makeConn();
        assertTrue(filter.matches(cleartext));

        ConnectionDescriptor encrypted = makeConn();
        Whitebox.setInternalState(encrypted, "encrypted_l7", true);
        assertFalse(filter.matches(encrypted));
    }

    @Test
    public void testFilteringStatusBlocked() {
        filter.filteringStatus = FilteringStatus.BLOCKED;
        assertTrue(filter.isSet());

        ConnectionDescriptor blocked = makeConn();
        blocked.is_blocked = true;
        assertTrue(filter.matches(blocked));

        ConnectionDescriptor allowed = makeConn();
        allowed.is_blocked = false;
        assertFalse(filter.matches(allowed));
    }

    @Test
    public void testFilteringStatusAllowed() {
        filter.filteringStatus = FilteringStatus.ALLOWED;

        ConnectionDescriptor allowed = makeConn();
        allowed.is_blocked = false;
        assertTrue(filter.matches(allowed));

        ConnectionDescriptor blocked = makeConn();
        blocked.is_blocked = true;
        assertFalse(filter.matches(blocked));
    }

    @Test
    public void testUidFilter() {
        filter.uid = 10100;
        assertTrue(filter.isSet());

        ConnectionDescriptor match = makeConn(); // uid=10100
        assertTrue(filter.matches(match));

        ConnectionDescriptor noMatch = new ConnectionDescriptor(1, 4, 6,
                "1.1.1.1", "2.2.2.2", "", 51234, 80,
                0, 10200, 0, false, 0);
        noMatch.l7proto = "HTTP";
        noMatch.status = ConnectionDescriptor.CONN_STATUS_CONNECTED;
        assertFalse(filter.matches(noMatch));
    }

    @Test
    public void testMinSizeFilter() {
        filter.minSize = 100;
        assertTrue(filter.isSet());

        ConnectionDescriptor small = makeConn();
        small.sent_bytes = 10;
        small.rcvd_bytes = 10;
        assertFalse(filter.matches(small));

        ConnectionDescriptor big = makeConn();
        big.sent_bytes = 50;
        big.rcvd_bytes = 60;
        assertTrue(filter.matches(big));
    }

    @Test
    public void testCombinedFilters() {
        filter.status = Status.STATUS_ACTIVE;
        filter.onlyCleartext = true;

        ConnectionDescriptor match = makeConn();
        match.status = ConnectionDescriptor.CONN_STATUS_CONNECTED;
        assertTrue(filter.matches(match));

        ConnectionDescriptor wrongStatus = makeConn();
        wrongStatus.status = ConnectionDescriptor.CONN_STATUS_CLOSED;
        assertFalse(filter.matches(wrongStatus));

        ConnectionDescriptor wrongCleartext = makeConn();
        wrongCleartext.status = ConnectionDescriptor.CONN_STATUS_CONNECTED;
        Whitebox.setInternalState(wrongCleartext, "encrypted_l7", true);
        assertFalse(filter.matches(wrongCleartext));
    }

    @Test
    public void testClear() {
        filter.status = Status.STATUS_ACTIVE;
        filter.onlyBlacklisted = true;
        filter.onlyCleartext = true;
        filter.minSize = 100;
        filter.filteringStatus = FilteringStatus.BLOCKED;
        assertTrue(filter.isSet());

        filter.clear();
        assertFalse(filter.isSet());
    }

    @Test
    public void testClearById() {
        filter.onlyBlacklisted = true;
        filter.clear(R.id.blacklisted);
        assertFalse(filter.onlyBlacklisted);

        filter.onlyCleartext = true;
        filter.clear(R.id.only_cleartext);
        assertFalse(filter.onlyCleartext);

        filter.status = Status.STATUS_ACTIVE;
        filter.clear(R.id.status_ind);
        assertTrue(filter.status == Status.STATUS_INVALID);

        filter.filteringStatus = FilteringStatus.BLOCKED;
        filter.clear(R.id.firewall);
        assertTrue(filter.filteringStatus == FilteringStatus.INVALID);

        filter.iface = "wlan0";
        filter.clear(R.id.capture_interface);
        assertTrue(filter.iface == null);

        filter.showMasked = false;
        filter.clear(R.id.not_hidden);
        assertTrue(filter.showMasked);
    }
}
