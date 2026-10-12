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
import android.os.SystemClock;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.AppsResolver;
import com.kotsafe.security.adapters.ConnectionsAdapter;
import com.kotsafe.security.util.ConnectionsTimingTrace;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Builds an immutable ConnectionScreenState from a safe connections snapshot.
 * Executes filtering, grouping, DNS normalization, sorting, and metrics calculations
 * completely off the main thread.
 */
public class ConnectionScreenStateBuilder {
    private static final String TAG = "StateBuilder";

    public enum SortMode {
        RECENT,
        ACTIVE,
        BYTES,
        NAME
    }

    private final Context mContext;
    private final AppsResolver mAppsResolver;
    private final AppPresentationCache mPresentationCache;

    public ConnectionScreenStateBuilder(@NonNull Context context, @Nullable AppsResolver appsResolver) {
        this.mContext = context.getApplicationContext();
        this.mAppsResolver = appsResolver;
        this.mPresentationCache = AppPresentationCache.getInstance();
    }

    @NonNull
    public ConnectionScreenState build(@NonNull List<ConnectionDescriptor> snapshot,
                                       @NonNull FilterDescriptor filter,
                                       @Nullable String searchQuery,
                                       @NonNull SortMode sortMode,
                                       long generation,
                                       int untrackedCount) {
        long startTime = ConnectionsTimingTrace.startTrace();

        boolean singleSocketMode = Prefs.isSingleSocketDiagnostics(PreferenceManager.getDefaultSharedPreferences(mContext));

        int totalCount = 0;
        int activeCount = 0;
        int closedCount = 0;
        int blockedCount = 0;
        long maxBytes = 0;

        FilterDescriptor.AppCategory[] cats = FilterDescriptor.AppCategory.values();
        int[] categoryCounts = new int[cats.length];

        @SuppressWarnings("unchecked")
        Set<String>[] seenKeys = new Set[cats.length];
        if (!singleSocketMode) {
            for (int k = 0; k < cats.length; k++) {
                seenKeys[k] = new HashSet<>();
            }
        }

        // 1. Single-pass calculation of visible metrics across all categories
        for (ConnectionDescriptor conn : snapshot) {
            if (conn == null) continue;
            maxBytes = Math.max(maxBytes, conn.sent_bytes + conn.rcvd_bytes);

            if (singleSocketMode) {
                totalCount++;
                if (conn.status < ConnectionDescriptor.CONN_STATUS_CLOSED) {
                    activeCount++;
                } else {
                    closedCount++;
                }
                if (conn.is_blocked || conn.isBlacklisted()) {
                    blockedCount++;
                }
                for (FilterDescriptor.AppCategory cat : cats) {
                    if (matchesCategory(conn, cat)) {
                        categoryCounts[cat.ordinal()]++;
                    }
                }
            } else {
                for (FilterDescriptor.AppCategory cat : cats) {
                    if (matchesCategory(conn, cat)) {
                        String key;
                        if (conn.isDns()) {
                            String resolver = (conn.dst_port == 53 || conn.dst_port == 5353) ? conn.dst_ip : conn.src_ip;
                            String domain = (conn.info != null && !conn.info.isEmpty()) ? conn.info : ((conn.url != null) ? conn.url : "");
                            while (domain.endsWith(".")) domain = domain.substring(0, domain.length() - 1);
                            key = "DNS:" + conn.uid + ":" + resolver + ":" + domain.toLowerCase(Locale.ROOT);
                        } else {
                            String target = ConnectionsAdapter.getCanonicalTarget(conn);
                            int dstPort = (conn.dst_port == 123 || conn.src_port == 123) ? 123
                                    : ((conn.ipproto == 1 || conn.ipproto == 58) ? 0 : conn.dst_port);

                            if (conn.is_blocked || conn.isBlacklisted()) {
                                key = "BLOCKED:" + conn.uid + ":" + conn.ipproto + ":" + target + ":" + dstPort;
                            } else if (cat == FilterDescriptor.AppCategory.ACTIVE_ONLY) {
                                key = "ACTIVE:" + conn.uid + ":" + conn.ipproto + ":" + target + ":" + dstPort;
                            } else if (cat == FilterDescriptor.AppCategory.CLOSED) {
                                key = "CLOSED:" + conn.uid + ":" + conn.ipproto + ":" + target + ":" + dstPort;
                            } else {
                                key = "FLOW:" + conn.uid + ":" + conn.ipproto + ":" + target + ":" + dstPort;
                            }
                        }
                        if (seenKeys[cat.ordinal()].add(key)) {
                            categoryCounts[cat.ordinal()]++;
                        }
                    }
                }
            }
        }

        if (!singleSocketMode) {
            activeCount = categoryCounts[FilterDescriptor.AppCategory.ACTIVE_ONLY.ordinal()];
            closedCount = categoryCounts[FilterDescriptor.AppCategory.CLOSED.ordinal()];
            blockedCount = categoryCounts[FilterDescriptor.AppCategory.BLOCKED_ONLY.ordinal()];
            totalCount = Math.max(activeCount + closedCount, categoryCounts[FilterDescriptor.AppCategory.ALL.ordinal()]);
        }

        ConnectionScreenMetrics metrics = new ConnectionScreenMetrics(
                totalCount,
                activeCount,
                closedCount,
                blockedCount,
                categoryCounts[FilterDescriptor.AppCategory.ALL.ordinal()],
                categoryCounts[FilterDescriptor.AppCategory.USER.ordinal()],
                categoryCounts[FilterDescriptor.AppCategory.SYSTEM.ordinal()],
                categoryCounts[FilterDescriptor.AppCategory.DNS.ordinal()],
                categoryCounts[FilterDescriptor.AppCategory.ACTIVE_ONLY.ordinal()],
                categoryCounts[FilterDescriptor.AppCategory.CLOSED.ordinal()],
                categoryCounts[FilterDescriptor.AppCategory.BLOCKED_ONLY.ordinal()],
                categoryCounts[FilterDescriptor.AppCategory.WEB_ONLY.ordinal()],
                maxBytes,
                untrackedCount
        );

        ConnectionsTimingTrace.logSummaryCalculation(startTime);

        // 2. Filter matching and Unified Flow Aggregation
        List<ConnectionDescriptor> matched = new ArrayList<>();
        Map<String, ConnectionDescriptor> aggregatedFlows = new LinkedHashMap<>();

        for (ConnectionDescriptor conn : snapshot) {
            if (conn == null) continue;

            if (matches(conn, filter, searchQuery)) {
                if (!singleSocketMode) {
                    String key = getAggregationKey(conn, filter);
                    if (key != null) {
                        ConnectionDescriptor existing = aggregatedFlows.get(key);
                        if (existing != null) {
                            mergeConnectionInto(existing, conn);
                            continue;
                        } else {
                            ConnectionDescriptor displayConn = new ConnectionDescriptor(conn);
                            if (conn.isDns() && displayConn.info != null) {
                                while (displayConn.info.endsWith(".")) {
                                    displayConn.info = displayConn.info.substring(0, displayConn.info.length() - 1);
                                }
                            }
                            aggregatedFlows.put(key, displayConn);
                            matched.add(displayConn);
                            continue;
                        }
                    }
                }
                matched.add(conn);
            }
        }

        // 3. Sorting
        if (sortMode == SortMode.RECENT) {
            matched.sort((ca, cb) -> Long.compare(cb.last_seen, ca.last_seen));
        } else if (sortMode == SortMode.ACTIVE) {
            matched.sort((ca, cb) -> {
                boolean aActive = ca.status < ConnectionDescriptor.CONN_STATUS_CLOSED;
                boolean bActive = cb.status < ConnectionDescriptor.CONN_STATUS_CLOSED;
                if (aActive != bActive) return aActive ? -1 : 1;
                return Long.compare(cb.last_seen, ca.last_seen);
            });
        } else if (sortMode == SortMode.BYTES) {
            matched.sort((ca, cb) ->
                    Long.compare(cb.sent_bytes + cb.rcvd_bytes, ca.sent_bytes + ca.rcvd_bytes));
        } else if (sortMode == SortMode.NAME) {
            matched.sort((ca, cb) -> {
                AppPresentationCache.Presentation presA = mPresentationCache.getPresentation(ca.uid, mContext, mAppsResolver);
                AppPresentationCache.Presentation presB = mPresentationCache.getPresentation(cb.uid, mContext, mAppsResolver);
                return presA.appLabel.compareToIgnoreCase(presB.appLabel);
            });
        }

        // 4. Construct immutable ConnectionRows with pre-resolved presentation
        List<ConnectionRow> rows = new ArrayList<>(matched.size());
        for (int i = 0; i < matched.size(); i++) {
            ConnectionDescriptor d = matched.get(i);
            AppPresentationCache.Presentation pres = mPresentationCache.getPresentation(d.uid, mContext, mAppsResolver);
            String target = ConnectionsAdapter.getCanonicalTarget(d);
            String proto = (d.l7proto != null && !d.l7proto.isEmpty()) ? d.l7proto : (d.ipproto == 6 ? "TCP" : (d.ipproto == 17 ? "UDP" : "IP"));
            String protoAndPort = proto + " • " + d.dst_port;
            long rowId = ((long) d.incr_id << 16) ^ (long) d.uid ^ (long) target.hashCode();
            rows.add(new ConnectionRow(rowId, d, pres, target, protoAndPort));
        }

        ConnectionsTimingTrace.logProcessing(startTime, snapshot.size(), rows.size());

        return new ConnectionScreenState(generation, rows, metrics, filter.appCategory, SystemClock.elapsedRealtime(), false);
    }

    private boolean matches(@NonNull ConnectionDescriptor conn, @NonNull FilterDescriptor filter, @Nullable String searchQuery) {
        if (!filter.matches(conn)) {
            return false;
        }
        if (searchQuery != null && !searchQuery.isEmpty()) {
            return matchesSearch(conn, searchQuery.toLowerCase(Locale.ROOT));
        }
        return true;
    }

    private boolean matchesSearch(@NonNull ConnectionDescriptor conn, @NonNull String query) {
        if (conn.info != null && conn.info.toLowerCase(Locale.ROOT).contains(query)) return true;
        if (conn.url != null && conn.url.toLowerCase(Locale.ROOT).contains(query)) return true;
        if (conn.dst_ip != null && conn.dst_ip.toLowerCase(Locale.ROOT).contains(query)) return true;
        AppPresentationCache.Presentation pres = mPresentationCache.getPresentation(conn.uid, mContext, mAppsResolver);
        if (pres.appLabel.toLowerCase(Locale.ROOT).contains(query)) return true;
        if (pres.packageName.toLowerCase(Locale.ROOT).contains(query)) return true;
        return false;
    }

    private boolean matchesCategory(@NonNull ConnectionDescriptor conn, @NonNull FilterDescriptor.AppCategory cat) {
        FilterDescriptor temp = new FilterDescriptor();
        temp.appCategory = cat;
        temp.showMasked = true;
        return temp.matches(conn);
    }

    @Nullable
    private String getAggregationKey(@NonNull ConnectionDescriptor conn, @NonNull FilterDescriptor filter) {
        int uid = conn.uid;
        if (conn.isDns()) {
            String resolver = (conn.dst_port == 53 || conn.dst_port == 5353) ? conn.dst_ip : conn.src_ip;
            String domain = (conn.info != null && !conn.info.isEmpty()) ? conn.info : ((conn.url != null) ? conn.url : "");
            while (domain.endsWith(".")) {
                domain = domain.substring(0, domain.length() - 1);
            }
            domain = domain.toLowerCase(Locale.ROOT);
            return "DNS:" + uid + ":" + resolver + ":" + domain;
        }

        String target = ConnectionsAdapter.getCanonicalTarget(conn);
        int dstPort = (conn.dst_port == 123 || conn.src_port == 123) ? 123
                : ((conn.ipproto == 1 || conn.ipproto == 58) ? 0 : conn.dst_port);

        if (conn.is_blocked || conn.isBlacklisted()) {
            return "BLOCKED:" + uid + ":" + conn.ipproto + ":" + target + ":" + dstPort;
        }

        return "FLOW:" + uid + ":" + conn.ipproto + ":" + target + ":" + dstPort;
    }

    private void mergeConnectionInto(@NonNull ConnectionDescriptor existing, @NonNull ConnectionDescriptor conn) {
        existing.aggregated_flows += Math.max(1, conn.aggregated_flows);
        existing.query_count += Math.max(1, conn.query_count);
        existing.blocked_pkts += conn.blocked_pkts;
        existing.sent_bytes += conn.sent_bytes;
        existing.rcvd_bytes += conn.rcvd_bytes;
        existing.sent_pkts += conn.sent_pkts;
        existing.rcvd_pkts += conn.rcvd_pkts;
        existing.first_seen = Math.min(existing.first_seen, conn.first_seen);
        existing.last_seen = Math.max(existing.last_seen, conn.last_seen);

        if (hasLetters(conn.url) && !hasLetters(existing.url)) {
            existing.url = conn.url;
        }
        if (hasLetters(conn.info) && !hasLetters(existing.info)) {
            existing.info = conn.info;
        }
        if ((existing.info == null || existing.info.isEmpty()) && (conn.info != null && !conn.info.isEmpty())) {
            existing.info = conn.info;
        }
        if ((existing.url == null || existing.url.isEmpty()) && (conn.url != null && !conn.url.isEmpty())) {
            existing.url = conn.url;
        }
        if (conn.is_blocked) {
            existing.is_blocked = true;
            if (conn.block_reason != null && !conn.block_reason.isEmpty()) {
                existing.block_reason = conn.block_reason;
            }
            if (conn.block_type != null && !conn.block_type.isEmpty()) {
                existing.block_type = conn.block_type;
            }
        }

        existing.getSocketSessions();
        existing.recordSocketSession(conn.ipproto, conn.src_port, conn.dst_port,
                conn.sent_bytes, conn.rcvd_bytes, conn.status, conn.l7proto, conn.last_seen, conn.is_blocked, conn.block_reason);
        for (ConnectionDescriptor.SocketSession s : conn.getSocketSessions()) {
            existing.recordSocketSession(s.proto, s.src_port, s.dst_port,
                    s.sent_bytes, s.rcvd_bytes, s.tcp_state, s.l7proto, s.last_seen, s.is_blocked, s.block_reason);
        }

        int activeState = -1;
        for (ConnectionDescriptor.SocketSession s : existing.getSocketSessions()) {
            if (s.tcp_state < ConnectionDescriptor.CONN_STATUS_CLOSED) {
                if (activeState == -1 || s.tcp_state > activeState) {
                    activeState = s.tcp_state;
                }
            }
        }
        if (activeState != -1) {
            existing.status = activeState;
        } else {
            existing.status = ConnectionDescriptor.CONN_STATUS_CLOSED;
        }
    }

    private static boolean hasLetters(@Nullable String str) {
        if (str == null || str.isEmpty()) return false;
        for (int i = 0; i < str.length(); i++) {
            if (Character.isLetter(str.charAt(i))) return true;
        }
        return false;
    }
}
