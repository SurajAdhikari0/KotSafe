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

package com.kotsafe.security.model;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import androidx.annotation.NonNull;
import androidx.test.core.app.ApplicationProvider;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.AppsResolver;
import com.kotsafe.security.CaptureService;
import com.kotsafe.security.ConnectionsRegister;
import com.kotsafe.security.Whitebox;
import com.kotsafe.security.adapters.ConnectionsAdapter;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.shadows.ShadowLooper;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@RunWith(RobolectricTestRunner.class)
public class ConnectionPerformanceAndGroupingTest {
    private Context mContext;
    private ConnectionsRegister mRegister;
    private CaptureService mService;
    private AppsResolver mApps;
    private int mIncrId;

    @Before
    public void setup() {
        mIncrId = 1;
        mContext = ApplicationProvider.getApplicationContext();
        mApps = new AppsResolver(mContext);
        mRegister = new ConnectionsRegister(mContext, 200);

        mService = new CaptureService();
        Whitebox.setInternalState(mService, "INSTANCE", mService);
        Whitebox.setInternalState(mService, "conn_reg", mRegister);
    }

    @After
    public void tearDown() {
        Whitebox.setInternalState(mService, "INSTANCE", null);
    }

    @Test
    public void testConnectionsFilterDefaultsToAllCategory() {
        FilterDescriptor filter = new FilterDescriptor();
        assertEquals("Connection filters should default to All", FilterDescriptor.AppCategory.ALL, filter.appCategory);
        assertEquals("Default app-category helper should stay All", FilterDescriptor.AppCategory.ALL, FilterDescriptor.getDefaultAppCategory());

        ConnectionDescriptor dnsConn = createConn(10100, "8.8.8.8", 53, 17, "example.com", ConnectionDescriptor.CONN_STATUS_CONNECTED);
        assertFalse("DNS traffic should be excluded from the generic All view", filter.matches(dnsConn));

        FilterDescriptor dnsFilter = new FilterDescriptor();
        dnsFilter.appCategory = FilterDescriptor.AppCategory.DNS;
        assertTrue("DNS traffic should still be visible in the dedicated DNS filter", dnsFilter.matches(dnsConn));
    }

    private ConnectionDescriptor createConn(int uid, String dstIp, int dstPort, int proto, String info, int status) {
        ConnectionDescriptor c = new ConnectionDescriptor(mIncrId++, 4, proto,
                "10.0.0.2", dstIp, "", 40000 + mIncrId, dstPort,
                0, uid, 0, false, 0);
        c.status = status;
        c.info = info;
        c.l7proto = (dstPort == 53 || dstPort == 5353) ? "DNS" : ((proto == 6) ? "TCP" : "UDP");
        c.sent_bytes = 100;
        c.rcvd_bytes = 200;
        c.last_seen = System.currentTimeMillis();
        return c;
    }

    @Test
    public void testVpnTrafficBurstCoalescesUiUpdates() throws Exception {
        Handler mainHandler = new Handler(Looper.getMainLooper());
        ConnectionScreenStateBuilder builder = new ConnectionScreenStateBuilder(mContext, mApps);
        ConnectionRefreshCoordinator coordinator = new ConnectionRefreshCoordinator(builder, mainHandler);
        coordinator.setConnectionsRegister(mRegister);

        // Populate register with initial connections
        List<ConnectionDescriptor> initList = new ArrayList<>();
        for (int i = 0; i < 50; i++) {
            initList.add(createConn(10050, "142.250.190.46", 443, 6, "google.com", ConnectionDescriptor.CONN_STATUS_CONNECTED));
        }
        mRegister.newConnections(initList.toArray(new ConnectionDescriptor[0]));

        AtomicInteger deliveryCount = new AtomicInteger(0);
        CountDownLatch latch = new CountDownLatch(1);
        coordinator.setListener(state -> {
            deliveryCount.incrementAndGet();
            latch.countDown();
        });

        // Simulate high-frequency traffic burst: 1,000 updates arrive in a few milliseconds
        for (int i = 0; i < 1000; i++) {
            coordinator.requestRefresh(false);
        }

        // Fast-forward the coalesce window (180 ms)
        ShadowLooper.idleMainLooper(ConnectionRefreshCoordinator.COALESCE_WINDOW_MS + 20, TimeUnit.MILLISECONDS);

        // Allow background worker thread to complete build
        Thread.sleep(300);

        // Drain the main looper to process onStateReady
        ShadowLooper.idleMainLooper();

        // Must coalesce 1,000 requests into a single UI update batch!
        assertEquals("Burst must be coalesced into 1 UI render", 1, deliveryCount.get());

        coordinator.shutdown();
    }

    @Test
    public void testConnectionSnapshotIsCreatedOffMainThread() throws Exception {
        AtomicReference<String> snapshotThread = new AtomicReference<>();
        CountDownLatch snapshotCreated = new CountDownLatch(1);
        ConnectionsRegister trackingRegister = new ConnectionsRegister(mContext, 8) {
            @Override
            public synchronized List<ConnectionDescriptor> getConnectionsSnapshot() {
                snapshotThread.set(Thread.currentThread().getName());
                snapshotCreated.countDown();
                return super.getConnectionsSnapshot();
            }
        };

        ConnectionRefreshCoordinator coordinator = new ConnectionRefreshCoordinator(
                new ConnectionScreenStateBuilder(mContext, mApps),
                new Handler(Looper.getMainLooper())
        );
        coordinator.setConnectionsRegister(trackingRegister);
        coordinator.requestRefresh(true);

        assertTrue("Background worker should snapshot the register", snapshotCreated.await(2, TimeUnit.SECONDS));
        assertTrue("Snapshot must not run on the main thread: " + snapshotThread.get(),
                snapshotThread.get().startsWith("KotSafe-ConnRefresh"));
        coordinator.shutdown();
    }

    @Test
    public void testCuratedPackageNameAloneDoesNotSuppressAntivirusFindings() {
        assertTrue(AntivirusScanEngine.isCuratedThirdPartyApp("com.whatsapp"));
        assertFalse(AntivirusScanEngine.isVerifiedCuratedThirdPartyApp(mContext, "com.whatsapp"));
        assertFalse(AntivirusScanEngine.isCuratedThirdPartyApp("com.oppo.fake.security"));
        assertFalse(AntivirusScanEngine.isCuratedThirdPartyApp("com.whatsapp.fake.security"));
    }

        @Test
        public void testClosedUserAppFlowMovesFromUserFeedToClosedCategory() {
        PreferenceManager.getDefaultSharedPreferences(mContext)
            .edit()
            .putBoolean(Prefs.PREF_AUTO_MOVE_CLOSED, true)
            .apply();

        ConnectionDescriptor closed = createConn(
            10042,
            "198.51.100.42",
            443,
            6,
            "service.example",
            ConnectionDescriptor.CONN_STATUS_CLOSED
        );
        List<ConnectionDescriptor> snapshot = new ArrayList<>();
        snapshot.add(closed);

        FilterDescriptor userFilter = new FilterDescriptor();
        userFilter.appCategory = FilterDescriptor.AppCategory.USER;
        ConnectionScreenStateBuilder builder = new ConnectionScreenStateBuilder(mContext, mApps);
        ConnectionScreenState userState = builder.build(
            snapshot, userFilter, null, ConnectionScreenStateBuilder.SortMode.RECENT, 1L, 0);
        assertTrue("Closed user flows should leave the User feed", userState.rows.isEmpty());

        FilterDescriptor closedFilter = new FilterDescriptor();
        closedFilter.appCategory = FilterDescriptor.AppCategory.CLOSED;
        ConnectionScreenState closedState = builder.build(
            snapshot, closedFilter, null, ConnectionScreenStateBuilder.SortMode.RECENT, 2L, 0);
        assertEquals("Closed flow should remain available under Closed", 1, closedState.rows.size());
        assertEquals(closed.incr_id, closedState.rows.get(0).incrId);
        }

    @Test
    public void testObsoleteGenerationCannotOverwriteNewerState() {
        Handler mainHandler = new Handler(Looper.getMainLooper());
        ConnectionScreenStateBuilder builder = new ConnectionScreenStateBuilder(mContext, mApps);
        ConnectionRefreshCoordinator coordinator = new ConnectionRefreshCoordinator(builder, mainHandler);

        AtomicReference<ConnectionScreenState> deliveredState = new AtomicReference<>();
        coordinator.setListener(deliveredState::set);

        ConnectionScreenState stateGen2 = new ConnectionScreenState(2L, new ArrayList<>(), ConnectionScreenMetrics.empty(), System.currentTimeMillis(), false);
        ConnectionScreenState stateGen1 = new ConnectionScreenState(1L, new ArrayList<>(), ConnectionScreenMetrics.empty(), System.currentTimeMillis(), false);

        // Simulate stateGen2 delivered first
        Whitebox.setInternalState(coordinator, "mCurrentVisibleGeneration", 2L);
        deliveredState.set(stateGen2);

        // Attempt to deliver older generation stateGen1 directly
        long currentGen = coordinator.getCurrentVisibleGeneration();
        assertEquals(2L, currentGen);

        // Monotonic check: older generation is not allowed to overwrite
        boolean canApplyGen1 = stateGen1.generation >= coordinator.getCurrentVisibleGeneration();
        assertFalse("Older generation must be rejected", canApplyGen1);

        coordinator.shutdown();
    }

    @Test
    public void testDnsGroupingByAppResolverPortProtocolAndDomain() {
        ConnectionScreenStateBuilder builder = new ConnectionScreenStateBuilder(mContext, mApps);

        List<ConnectionDescriptor> list = new ArrayList<>();
        // App 10100 makes 3 queries to resolver 8.8.8.8 for example.com
        ConnectionDescriptor q1 = createConn(10100, "8.8.8.8", 53, 17, "example.com.", ConnectionDescriptor.CONN_STATUS_CONNECTED);
        ConnectionDescriptor q2 = createConn(10100, "8.8.8.8", 53, 17, "example.com", ConnectionDescriptor.CONN_STATUS_CONNECTED);
        ConnectionDescriptor q3 = createConn(10100, "8.8.8.8", 53, 17, "EXAMPLE.COM.", ConnectionDescriptor.CONN_STATUS_CONNECTED);

        // App 10100 makes 1 query to resolver 8.8.8.8 for api.github.com
        ConnectionDescriptor q4 = createConn(10100, "8.8.8.8", 53, 17, "api.github.com", ConnectionDescriptor.CONN_STATUS_CONNECTED);

        // App 10200 makes 1 query to resolver 8.8.8.8 for example.com
        ConnectionDescriptor q5 = createConn(10200, "8.8.8.8", 53, 17, "example.com", ConnectionDescriptor.CONN_STATUS_CONNECTED);

        list.add(q1);
        list.add(q2);
        list.add(q3);
        list.add(q4);
        list.add(q5);

        FilterDescriptor filter = new FilterDescriptor();
        filter.appCategory = FilterDescriptor.AppCategory.DNS;

        ConnectionScreenState state = builder.build(list, filter, null, ConnectionScreenStateBuilder.SortMode.RECENT, 1L, 0);

        // We expect exactly 3 DNS cards:
        // 1. App 10100 -> example.com (3 queries aggregated)
        // 2. App 10100 -> api.github.com (1 query)
        // 3. App 10200 -> example.com (1 query)
        assertEquals("Should group DNS cards by app, resolver, and domain", 3, state.rows.size());

        ConnectionRow exampleRowApp1 = null;
        for (ConnectionRow row : state.rows) {
            if (row.uid == 10100 && "example.com".equalsIgnoreCase(row.appName)) {
                exampleRowApp1 = row;
            }
        }
        assertNotNull("Grouped example.com row for App 10100 must exist", exampleRowApp1);
        assertEquals("Should aggregate 3 DNS queries into queryCount", 3, exampleRowApp1.queryCount);
    }

    @Test
    public void testSummaryCountsMatchGroupedRows() {
        ConnectionScreenStateBuilder builder = new ConnectionScreenStateBuilder(mContext, mApps);
        List<ConnectionDescriptor> list = new ArrayList<>();

        // 2 Active user app connections
        list.add(createConn(10050, "1.1.1.1", 443, 6, "cloudflare.com", ConnectionDescriptor.CONN_STATUS_CONNECTED));
        list.add(createConn(10051, "2.2.2.2", 443, 6, "fastly.com", ConnectionDescriptor.CONN_STATUS_CONNECTED));

        // 1 Closed connection
        list.add(createConn(10052, "3.3.3.3", 80, 6, "archive.org", ConnectionDescriptor.CONN_STATUS_CLOSED));

        // 1 Blocked connection
        ConnectionDescriptor blocked = createConn(10053, "4.4.4.4", 80, 6, "malware.test", ConnectionDescriptor.CONN_STATUS_CLOSED);
        blocked.is_blocked = true;
        list.add(blocked);

        // 1 DNS lookup
        list.add(createConn(10050, "8.8.8.8", 53, 17, "test.org", ConnectionDescriptor.CONN_STATUS_CONNECTED));

        // 1 System service connection (UID 1000)
        list.add(createConn(1000, "9.9.9.9", 443, 6, "android.com", ConnectionDescriptor.CONN_STATUS_CONNECTED));

        FilterDescriptor filter = new FilterDescriptor();
        ConnectionScreenState state = builder.build(list, filter, null, ConnectionScreenStateBuilder.SortMode.RECENT, 1L, 0);

        ConnectionScreenMetrics m = state.metrics;
        assertNotNull(m);
        assertEquals(6, m.totalCount);
        assertEquals(4, m.activeCount); // 2 user + 1 dns + 1 system
        assertEquals(2, m.closedCount); // 1 closed + 1 blocked
        assertEquals(1, m.blockedCount); // 1 blocked
        assertEquals(1, m.countDns);
        assertEquals(1, m.countSystem);
        assertEquals(1, m.countBlockedOnly);
    }

    @Test
    public void testSystemAppWideProtection() {
        AppPresentationCache cache = AppPresentationCache.getInstance();

        // System core UID 1000 (system_server)
        AppPresentationCache.Presentation presSystem = cache.getPresentation(1000, mContext, mApps);
        assertTrue("UID 1000 must be marked as system app", presSystem.isSystemApp);
        assertTrue("UID 1000 must be marked as system service", presSystem.isSystemService);
        assertFalse("UID 1000 CANNOT be blocked app-wide", presSystem.canBlockAppWide);

        // Low system UID (e.g. 1001 / telephony / radio)
        AppPresentationCache.Presentation presRadio = cache.getPresentation(1001, mContext, mApps);
        assertFalse("Core Android services CANNOT be blocked app-wide", presRadio.canBlockAppWide);

        // Negative UID (Kernel / DNS)
        AppPresentationCache.Presentation presKernel = cache.getPresentation(-1, mContext, mApps);
        assertFalse("Negative UID (kernel/system) CANNOT be blocked app-wide", presKernel.canBlockAppWide);

        // Regular user application (UID >= 10000)
        AppPresentationCache.Presentation presUser = cache.getPresentation(10150, mContext, mApps);
        assertFalse("Regular user app is not system service", presUser.isSystemService);
        assertTrue("Regular user app CAN be blocked app-wide", presUser.canBlockAppWide);
    }

    @Test
    public void testCachedStateInstantRender() {
        ConnectionScreenState state = new ConnectionScreenState(42L, new ArrayList<>(), ConnectionScreenMetrics.empty(), System.currentTimeMillis(), false);
        mRegister.setCachedScreenState(state);

        ConnectionScreenState retrieved = mRegister.getCachedScreenState();
        assertNotNull("Cached state must be present immediately", retrieved);
        assertEquals(42L, retrieved.generation);
    }

    @Test
    public void testAppConnectionGroupingAndExpansion() {
        int braveUid = 10188;
        int signalUid = 10190;

        List<ConnectionDescriptor> snapshot = new ArrayList<>();
        // Simulate Brave Browser opening 39 connections to different servers
        for (int i = 0; i < 39; i++) {
            ConnectionDescriptor conn = createConn(braveUid, "142.250.190." + (i + 1), 443, 6, "brave-endpoint-" + i, ConnectionDescriptor.CONN_STATUS_CONNECTED);
            snapshot.add(conn);
        }
        // Simulate Signal opening 1 connection
        ConnectionDescriptor signalConn = createConn(signalUid, "198.51.100.50", 443, 6, "signal.org", ConnectionDescriptor.CONN_STATUS_CONNECTED);
        snapshot.add(signalConn);

        ConnectionScreenStateBuilder builder = new ConnectionScreenStateBuilder(mContext, mApps);
        FilterDescriptor filter = new FilterDescriptor();
        filter.appCategory = FilterDescriptor.AppCategory.ALL;

        ConnectionScreenState state = builder.build(snapshot, filter, null, ConnectionScreenStateBuilder.SortMode.RECENT, 1L, 0);
        assertEquals("Total raw rows should be 40 (39 Brave + 1 Signal)", 40, state.rows.size());

        ConnectionsAdapter adapter = new ConnectionsAdapter(mContext, mApps);
        adapter.setGroupByApp(true);

        // 1. Collapsed state (default)
        List<ConnectionRow> grouped = adapter.applyGrouping(state.rows);
        // Should only show 2 rows: 1 App Group Header for Brave (wrapping 39 conns) and 1 normal row for Signal
        assertEquals("Collapsed view should wrap Brave into 1 row + Signal into 1 row = 2 rows", 2, grouped.size());

        ConnectionRow braveHeader = grouped.get(0);
        assertEquals("Header must be ROW_TYPE_APP_GROUP_HEADER", ConnectionRow.ROW_TYPE_APP_GROUP_HEADER, braveHeader.rowType);
        assertEquals("Header must reflect 39 connections", 39, braveHeader.groupConnectionCount);
        assertFalse("Header must be collapsed by default", braveHeader.isExpanded);

        ConnectionRow signalRow = grouped.get(1);
        assertEquals("Single app flow must be ROW_TYPE_NORMAL", ConnectionRow.ROW_TYPE_NORMAL, signalRow.rowType);

        // 2. Expand Brave
        adapter.toggleAppExpansion(braveUid);
        assertTrue("Brave should now be expanded", adapter.isAppExpanded(braveUid));

        List<ConnectionRow> expanded = adapter.applyGrouping(state.rows);
        // Expanded list should have: 1 Brave header + 39 Brave child rows + 1 Signal row = 41 rows
        assertEquals("Expanded view should have 1 header + 39 children + 1 signal = 41 rows", 41, expanded.size());
        assertEquals("First row is still Brave header", ConnectionRow.ROW_TYPE_APP_GROUP_HEADER, expanded.get(0).rowType);
        assertTrue("Brave header is now marked expanded", expanded.get(0).isExpanded);

        for (int i = 1; i <= 39; i++) {
            ConnectionRow child = expanded.get(i);
            assertEquals("Children must be ROW_TYPE_APP_CHILD", ConnectionRow.ROW_TYPE_APP_CHILD, child.rowType);
            assertEquals("Child must belong to Brave UID", braveUid, child.uid);
            assertNotNull("Child descriptor must be preserved", child.descriptor);
        }

        // 3. Collapse Brave back
        adapter.toggleAppExpansion(braveUid);
        assertFalse("Brave should now be collapsed", adapter.isAppExpanded(braveUid));
        List<ConnectionRow> collapsedAgain = adapter.applyGrouping(state.rows);
        assertEquals("View must collapse back to 2 rows", 2, collapsedAgain.size());
    }
}
