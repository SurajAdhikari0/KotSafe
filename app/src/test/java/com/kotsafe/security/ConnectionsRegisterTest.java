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

import android.content.Context;

import androidx.test.core.app.ApplicationProvider;

import com.kotsafe.security.interfaces.ConnectionsListener;
import com.kotsafe.security.model.AppStats;
import com.kotsafe.security.model.ConnectionDescriptor;
import com.kotsafe.security.model.ConnectionUpdate;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

import java.util.ArrayList;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

@RunWith(RobolectricTestRunner.class)
public class ConnectionsRegisterTest {
    static final int MAX_CONNECTIONS = 8;
    ConnectionsRegister reg;
    CaptureService service;
    int incrId = 0;
    ArrayList<String> events = new ArrayList<>();

    @Before
    public void setup() {
        incrId = 0;
        events.clear();

        Context context = ApplicationProvider.getApplicationContext();
        reg = new ConnectionsRegister(context, MAX_CONNECTIONS);

        // Mock CaptureService (needed for processConnectionStatus)
        service = new CaptureService();
        Whitebox.setInternalState(service, "INSTANCE", service);
        Whitebox.setInternalState(service, "conn_reg", reg);
    }

    @After
    public void tearDown() {
        Whitebox.setInternalState(service, "INSTANCE", null);
    }

    private ConnectionDescriptor newConn(int uid) {
        ConnectionDescriptor conn = new ConnectionDescriptor(incrId++, 4, 6,
                "1.1.1.1", "2.2.2.2", "", 51234, 80,
                0, uid, 0, false, 0);
        conn.status = ConnectionDescriptor.CONN_STATUS_CONNECTED;
        conn.l7proto = "";
        return conn;
    }

    @Test
    public void testInsert() {
        reg.newConnections(new ConnectionDescriptor[]{newConn(1000), newConn(1000)});
        assertEquals(2, reg.getConnCount());
        assertEquals(0, reg.getUntrackedConnCount());
        assertNotNull(reg.getConn(0));
        assertNotNull(reg.getConn(1));
        assertEquals(0, reg.getConn(0).incr_id);
        assertEquals(1, reg.getConn(1).incr_id);
    }

    @Test
    public void testRollover() {
        // fill to capacity
        ConnectionDescriptor[] conns = new ConnectionDescriptor[MAX_CONNECTIONS];
        for (int i = 0; i < MAX_CONNECTIONS; i++)
            conns[i] = newConn(1000);
        reg.newConnections(conns);
        assertEquals(MAX_CONNECTIONS, reg.getConnCount());

        // add 2 more, causing rollover of first 2
        reg.newConnections(new ConnectionDescriptor[]{newConn(1000), newConn(1000)});
        assertEquals(MAX_CONNECTIONS, reg.getConnCount());
        assertEquals(2, reg.getUntrackedConnCount());

        // oldest should be id=2
        assertEquals(2, reg.getConn(0).incr_id);
        // newest should be id=9
        assertEquals(9, reg.getConn(MAX_CONNECTIONS - 1).incr_id);
    }

    @Test
    public void testGetConnById() {
        reg.newConnections(new ConnectionDescriptor[]{newConn(1000), newConn(1000), newConn(1000)});

        assertNotNull(reg.getConnById(0));
        assertNotNull(reg.getConnById(2));
        assertNull(reg.getConnById(3));
        assertNull(reg.getConnById(-1));
    }

    @Test
    public void testGetConnPositionById() {
        reg.newConnections(new ConnectionDescriptor[]{newConn(1000), newConn(1000), newConn(1000)});

        assertEquals(0, reg.getConnPositionById(0));
        assertEquals(1, reg.getConnPositionById(1));
        assertEquals(2, reg.getConnPositionById(2));
        assertEquals(-1, reg.getConnPositionById(3));
        assertEquals(-1, reg.getConnPositionById(-1));
    }

    @Test
    public void testGetConnPositionAfterRollover() {
        ConnectionDescriptor[] conns = new ConnectionDescriptor[MAX_CONNECTIONS];
        for (int i = 0; i < MAX_CONNECTIONS; i++)
            conns[i] = newConn(1000);
        reg.newConnections(conns);
        reg.newConnections(new ConnectionDescriptor[]{newConn(1000), newConn(1000)});

        // first connection is now id=2
        assertEquals(-1, reg.getConnPositionById(0));
        assertEquals(-1, reg.getConnPositionById(1));
        assertEquals(0, reg.getConnPositionById(2));
        assertEquals(7, reg.getConnPositionById(9));
    }

    @Test
    public void testGetConnOutOfBounds() {
        reg.newConnections(new ConnectionDescriptor[]{newConn(1000)});
        assertNull(reg.getConn(-1));
        assertNull(reg.getConn(1));
        assertNotNull(reg.getConn(0));
    }

    @Test
    public void testGetConnByIdWithGaps() {
        ConnectionDescriptor c0 = newConn(1000); // incr_id = 0
        incrId = 5; // create a gap in incrId
        ConnectionDescriptor c5 = newConn(1000); // incr_id = 5
        reg.newConnections(new ConnectionDescriptor[]{c0, c5});

        assertEquals(2, reg.getConnCount());
        assertEquals(0, reg.getConnPositionById(0));
        assertEquals(1, reg.getConnPositionById(5));
        assertEquals(-1, reg.getConnPositionById(1));
        assertEquals(-1, reg.getConnPositionById(6));

        assertNotNull(reg.getConnById(0));
        assertEquals(0, reg.getConnById(0).incr_id);
        assertNotNull(reg.getConnById(5));
        assertEquals(5, reg.getConnById(5).incr_id);
        assertNull(reg.getConnById(1));
        assertNull(reg.getConnById(6));
    }

    @Test
    public void testGetConnByIdWithDnsAggregationAndAlias() {
        // DNS query 1
        ConnectionDescriptor dns1 = new ConnectionDescriptor(incrId++, 4, 17,
                "1.1.1.1", "8.8.8.8", "", 51234, 53,
                0, 1000, 0, false, 0);
        dns1.l7proto = "DNS";
        dns1.info = "example.com";

        // DNS query 2 (same key, will be aggregated)
        ConnectionDescriptor dns2 = new ConnectionDescriptor(incrId++, 4, 17,
                "1.1.1.1", "8.8.8.8", "", 51235, 53,
                0, 1000, 0, false, 0);
        dns2.l7proto = "DNS";
        dns2.info = "example.com";

        // Single TCP connection (incr_id = 2)
        ConnectionDescriptor tcp = newConn(1000); // incr_id = 2

        reg.newConnections(new ConnectionDescriptor[]{dns1, dns2, tcp});

        // dns2 was aggregated into dns1, so reg only has 2 connections: dns1 (id=0) and tcp (id=2)
        assertEquals(2, reg.getConnCount());
        assertNotNull(reg.getConnById(0));
        assertNotNull(reg.getConnById(2));
        assertEquals(2, reg.getConnById(2).incr_id);

        // Alias resolution: querying the merged connection dns2 (id=1) should return the canonical dns1 connection (id=0)
        assertNotNull(reg.getConnById(1));
        assertEquals(0, reg.getConnById(1).incr_id);
    }

    @Test
    public void testReset() {
        reg.newConnections(new ConnectionDescriptor[]{newConn(1000), newConn(1000)});
        reg.reset();
        assertEquals(0, reg.getConnCount());
        assertEquals(0, reg.getUntrackedConnCount());
        assertNull(reg.getConn(0));
    }

    @Test
    public void testAppStats() {
        reg.newConnections(new ConnectionDescriptor[]{
                newConn(1000), newConn(1000), newConn(2000)
        });

        AppStats stats1000 = reg.getAppStats(1000);
        assertNotNull(stats1000);
        assertEquals(2, stats1000.numConnections);

        AppStats stats2000 = reg.getAppStats(2000);
        assertNotNull(stats2000);
        assertEquals(1, stats2000.numConnections);
    }

    @Test
    public void testAppStatsBytes() {
        ConnectionDescriptor conn = newConn(1000);
        conn.sent_bytes = 100;
        conn.rcvd_bytes = 200;
        reg.newConnections(new ConnectionDescriptor[]{conn});

        AppStats stats = reg.getAppStats(1000);
        assertNotNull(stats);
        assertEquals(100, stats.sentBytes);
        assertEquals(200, stats.rcvdBytes);
    }

    @Test
    public void testConnectionsUpdates() {
        reg.newConnections(new ConnectionDescriptor[]{newConn(1000), newConn(1000)});

        ConnectionUpdate update = new ConnectionUpdate(1);
        update.setStats(0, 0, 50, 100, 5, 10,
                0, 0, ConnectionDescriptor.CONN_STATUS_CONNECTED);
        reg.connectionsUpdates(new ConnectionUpdate[]{update});

        ConnectionDescriptor conn = reg.getConnById(1);
        assertNotNull(conn);
        assertEquals(50, conn.sent_bytes);
        assertEquals(100, conn.rcvd_bytes);
        assertEquals(5, conn.sent_pkts);
        assertEquals(10, conn.rcvd_pkts);
    }

    @Test
    public void testConnectionsUpdatesIgnoresUntracked() {
        reg.newConnections(new ConnectionDescriptor[]{newConn(1000)});

        // update for non-existent id should not crash
        ConnectionUpdate update = new ConnectionUpdate(999);
        update.setStats(0, 0, 50, 100, 5, 10,
                0, 0, ConnectionDescriptor.CONN_STATUS_CONNECTED);
        reg.connectionsUpdates(new ConnectionUpdate[]{update});

        // original unchanged
        assertEquals(0, reg.getConn(0).sent_bytes);
    }

    @Test
    public void testBlockedConnectionCounting() {
        ConnectionDescriptor conn = newConn(1000);
        conn.is_blocked = true;
        reg.newConnections(new ConnectionDescriptor[]{conn});

        assertEquals(1, reg.getNumBlockedConnections());
    }

    @Test
    public void testMaxBytes() {
        ConnectionDescriptor c1 = newConn(1000);
        c1.sent_bytes = 100;
        c1.rcvd_bytes = 200;

        ConnectionDescriptor c2 = newConn(1000);
        c2.sent_bytes = 50;
        c2.rcvd_bytes = 50;

        reg.newConnections(new ConnectionDescriptor[]{c1, c2});
        assertEquals(300, reg.getMaxBytes());
    }

    @Test
    public void testListenerNotifications() {
        ConnectionsListener listener = new ConnectionsListener() {
            @Override public void connectionsChanges(int num) { events.add("changes:" + num); }
            @Override public void connectionsAdded(int start, ConnectionDescriptor[] conns) { events.add("added:" + start + ":" + conns.length); }
            @Override public void connectionsRemoved(int start, ConnectionDescriptor[] conns) { events.add("removed:" + start + ":" + conns.length); }
            @Override public void connectionsUpdated(int[] positions) { events.add("updated:" + positions.length); }
        };

        reg.addListener(listener);
        // addListener sends initial sync
        assertEquals(1, events.size());
        assertEquals("changes:0", events.get(0));
        events.clear();

        // add connections
        reg.newConnections(new ConnectionDescriptor[]{newConn(1000), newConn(1000)});
        assertEquals(1, events.size());
        assertEquals("added:0:2", events.get(0));
        events.clear();

        // update
        ConnectionUpdate update = new ConnectionUpdate(0);
        update.setStats(0, 0, 10, 10, 1, 1,
                0, 0, ConnectionDescriptor.CONN_STATUS_CONNECTED);
        reg.connectionsUpdates(new ConnectionUpdate[]{update});
        assertEquals(1, events.size());
        assertEquals("updated:1", events.get(0));

        reg.removeListener(listener);
    }

    @Test
    public void testListenerNotificationsOnRollover() {
        ConnectionsListener listener = new ConnectionsListener() {
            @Override public void connectionsChanges(int num) { events.add("changes:" + num); }
            @Override public void connectionsAdded(int start, ConnectionDescriptor[] conns) { events.add("added:" + start + ":" + conns.length); }
            @Override public void connectionsRemoved(int start, ConnectionDescriptor[] conns) { events.add("removed:" + start + ":" + conns.length); }
            @Override public void connectionsUpdated(int[] positions) { events.add("updated:" + positions.length); }
        };

        // fill to capacity
        ConnectionDescriptor[] conns = new ConnectionDescriptor[MAX_CONNECTIONS];
        for (int i = 0; i < MAX_CONNECTIONS; i++)
            conns[i] = newConn(1000);
        reg.newConnections(conns);

        reg.addListener(listener);
        events.clear();

        // add 2 more, causing rollover
        reg.newConnections(new ConnectionDescriptor[]{newConn(1000), newConn(1000)});

        // should get removed then added
        assertTrue(events.size() >= 2);
        assertEquals("removed:0:2", events.get(0));
        assertEquals("added:6:2", events.get(1));

        reg.removeListener(listener);
    }

    @Test
    public void testSeenUids() {
        reg.newConnections(new ConnectionDescriptor[]{
                newConn(1000), newConn(2000), newConn(1000)
        });

        assertEquals(2, reg.getSeenUids().size());
        assertTrue(reg.getSeenUids().contains(1000));
        assertTrue(reg.getSeenUids().contains(2000));
    }

    @Test
    public void testKotEngineGroupsDnsByAppResolverAndDomain() {
        com.kotsafe.security.engine.ConnInfo first = new com.kotsafe.security.engine.ConnInfo(
                17, "10.0.0.2", 41000, "1.1.1.1", 53,
                10L, 20L, 12001, 2, "example.com.", "DNS", "",
                0.0, 0.0, "", 0.0f);
        reg.onKotEngineConnsUpdated(new com.kotsafe.security.engine.ConnInfo[]{first});

        assertEquals(1, reg.getConnCount());
        assertEquals("example.com", reg.getConn(0).info);
        assertEquals(1, reg.getConn(0).query_count);
        assertEquals(10L, reg.getConn(0).sent_bytes);
        assertEquals(20L, reg.getConn(0).rcvd_bytes);

        // The native engine reports cumulative counters for the same source tuple. Only the
        // delta must be added to the UI aggregate.
        com.kotsafe.security.engine.ConnInfo update = new com.kotsafe.security.engine.ConnInfo(
                17, "10.0.0.2", 41000, "1.1.1.1", 53,
                30L, 50L, 12001, 2, "example.com", "DNS", "",
                0.0, 0.0, "", 0.0f);
        reg.onKotEngineConnsUpdated(new com.kotsafe.security.engine.ConnInfo[]{update});
        assertEquals(1, reg.getConnCount());
        assertEquals(30L, reg.getConn(0).sent_bytes);
        assertEquals(50L, reg.getConn(0).rcvd_bytes);

        // A new ephemeral port is another DNS request, but belongs to the same app/resolver
        // group and should not create another "System DNS Resolver" row.
        com.kotsafe.security.engine.ConnInfo secondQuery = new com.kotsafe.security.engine.ConnInfo(
                17, "10.0.0.2", 41001, "1.1.1.1", 53,
                5L, 6L, 12001, 2, "example.com", "DNS", "",
                0.0, 0.0, "", 0.0f);
        reg.onKotEngineConnsUpdated(new com.kotsafe.security.engine.ConnInfo[]{secondQuery});
        assertEquals(1, reg.getConnCount());
        assertEquals(2, reg.getConn(0).query_count);
        assertEquals(35L, reg.getConn(0).sent_bytes);
        assertEquals(56L, reg.getConn(0).rcvd_bytes);

        // Identical host names from another app must remain separately attributable.
        com.kotsafe.security.engine.ConnInfo otherApp = new com.kotsafe.security.engine.ConnInfo(
                17, "10.0.0.2", 42000, "1.1.1.1", 53,
                1L, 1L, 12002, 2, "example.com", "DNS", "",
                0.0, 0.0, "", 0.0f);
        reg.onKotEngineConnsUpdated(new com.kotsafe.security.engine.ConnInfo[]{otherApp});
        assertEquals(2, reg.getConnCount());
    }

    @Test
    public void testSingleSocketDiagnosticsAggregatedSessions() {
        Context context = ApplicationProvider.getApplicationContext();
        com.kotsafe.security.model.Prefs.setSingleSocketDiagnostics(context, false);

        com.kotsafe.security.engine.ConnInfo sock1 = new com.kotsafe.security.engine.ConnInfo(
                6, "10.0.0.2", 54100, "93.184.216.34", 443,
                500L, 1500L, 10042, 2, "example.com", "TLS", "",
                0.0, 0.0, "t13d1516h2", 5.2f);
        com.kotsafe.security.engine.ConnInfo sock2 = new com.kotsafe.security.engine.ConnInfo(
                6, "10.0.0.2", 54101, "93.184.216.34", 443,
                300L, 800L, 10042, 4, "example.com", "TLS", "",
                0.0, 0.0, "t13d1516h2", 4.8f);

        reg.onKotEngineConnsUpdated(new com.kotsafe.security.engine.ConnInfo[]{sock1, sock2});

        // In Smart Aggregation mode, one UI row is exposed
        assertEquals(1, reg.getConnCount());
        ConnectionDescriptor conn = reg.getConn(0);
        assertEquals(800L, conn.sent_bytes);
        assertEquals(2300L, conn.rcvd_bytes);

        // Underlying Single-Socket Diagnostics contains both ephemeral sessions
        java.util.List<ConnectionDescriptor.SocketSession> sessions = conn.getSocketSessions();
        assertEquals(2, sessions.size());

        boolean found54100 = false;
        boolean found54101 = false;
        for (ConnectionDescriptor.SocketSession s : sessions) {
            if (s.src_port == 54100) {
                found54100 = true;
                assertEquals(500L, s.sent_bytes);
                assertEquals(1500L, s.rcvd_bytes);
                assertEquals("ESTABLISHED", s.getTcpStateString());
            } else if (s.src_port == 54101) {
                found54101 = true;
                assertEquals(300L, s.sent_bytes);
                assertEquals(800L, s.rcvd_bytes);
                assertEquals("CLOSED", s.getTcpStateString());
            }
        }
        assertTrue(found54100);
        assertTrue(found54101);
    }

    @Test
    public void testSingleSocketDiagnosticsRawMode() {
        Context context = ApplicationProvider.getApplicationContext();
        com.kotsafe.security.model.Prefs.setSingleSocketDiagnostics(context, true);

        try {
            com.kotsafe.security.engine.ConnInfo sock1 = new com.kotsafe.security.engine.ConnInfo(
                    6, "10.0.0.2", 55201, "1.1.1.1", 443,
                    100L, 200L, 10050, 2, "one.one.one.one", "TLS", "",
                    0.0, 0.0, "", 0.0f);
            com.kotsafe.security.engine.ConnInfo sock2 = new com.kotsafe.security.engine.ConnInfo(
                    6, "10.0.0.2", 55202, "1.1.1.1", 443,
                    300L, 400L, 10050, 2, "one.one.one.one", "TLS", "",
                    0.0, 0.0, "", 0.0f);

            reg.onKotEngineConnsUpdated(new com.kotsafe.security.engine.ConnInfo[]{sock1, sock2});

            // In Single Socket Diagnostics Raw Mode, each ephemeral socket is an individual row
            assertEquals(2, reg.getConnCount());
            assertEquals(55201, reg.getConn(0).src_port);
            assertEquals(55202, reg.getConn(1).src_port);
        } finally {
            com.kotsafe.security.model.Prefs.setSingleSocketDiagnostics(context, false);
        }
    }

    @Test
    public void testCorrelatedAppsForTimestamp() {
        long baseTime = 1000000000L;
        ConnectionDescriptor userAppConn = newConn(10042);
        userAppConn.first_seen = baseTime;
        userAppConn.last_seen = baseTime + 500;
        userAppConn.info = "api.example.com";

        ConnectionDescriptor systemDnsConn = newConn(1000);
        systemDnsConn.first_seen = baseTime + 100;
        systemDnsConn.last_seen = baseTime + 100;
        systemDnsConn.info = "adservice.google.com";
        systemDnsConn.is_blocked = true;

        reg.newConnections(new ConnectionDescriptor[]{userAppConn, systemDnsConn});

        java.util.List<ConnectionsRegister.CorrelatedApp> correlated =
                reg.getCorrelatedAppsForTimestamp(systemDnsConn.last_seen, 5000);
        assertNotNull(correlated);
        assertTrue(correlated.stream().allMatch(candidate -> candidate.app.getUid() >= 10000));
        assertTrue(correlated.stream().noneMatch(candidate -> candidate.app.getUid() == android.os.Process.myUid()));
    }
}
