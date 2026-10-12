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
 * * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.activities;

import androidx.annotation.NonNull;
import androidx.core.content.ContextCompat;
import androidx.core.view.MenuProvider;

import android.app.ActivityManager;
import android.content.Context;
import android.graphics.Color;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.ProgressBar;
import android.widget.TextView;

import com.kotsafe.security.CaptureService;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.CaptureStats;
import com.kotsafe.security.model.Prefs;
import com.kotsafe.security.model.TrafficTimeSeriesCollector;
import com.kotsafe.security.views.GlassWireTrafficGraphView;

import java.util.Locale;

public class StatsActivity extends BaseActivity implements MenuProvider {
    private GlassWireTrafficGraphView mTrafficGraph;
    private TrafficTimeSeriesCollector.OnLiveTrafficListener mTrafficListener;

    private TextView mBytesSent;
    private TextView mBytesRcvd;
    private TextView mTvTotalTraffic;
    private TextView mIPv6BytesSentLabel;
    private TextView mIPv6BytesRcvdLabel;
    private TextView mIPv6BytesPercentage;
    private ProgressBar mProgressIpv6;
    private View mIpv6Container;

    private TextView mPacketsSent;
    private TextView mPacketsRcvd;
    private TextView mPacketsTotal;
    private TextView mDroppedPkts;
    private TextView mBadgePktsHealth;
    private View mRowPktsDropped;

    private TextView mActiveConns;
    private TextView mDroppedConns;
    private View mRowDroppedConns;
    private TextView mTotConns;
    private TextView mOpenSocks;
    private View mOpenSocksRow;

    private TextView mHeapUsage;
    private ProgressBar mProgressHeap;
    private TextView mMemUsage;
    private ProgressBar mProgressRam;
    private TextView mLowMem;

    private TextView mDnsServer;
    private TextView mDnsQueries;
    private TextView mBadgeDnsSec;
    private View mDnsServerRow;
    private View mDnsQueriesRow;
    private View mDnsCard;

    private View mCardAllocations;
    private TextView mAllocStats;

    private TextView mTvStatsMode;
    private TextView mBadgeStatusMode;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setTitle(R.string.stats);
        displayBackAction();
        setContentView(R.layout.activity_stats);
        addMenuProvider(this);

        mBytesSent = findViewById(R.id.bytes_sent);
        mBytesRcvd = findViewById(R.id.bytes_rcvd);
        mTvTotalTraffic = findViewById(R.id.tv_total_traffic);
        mIPv6BytesSentLabel = findViewById(R.id.ipv6_bytes_sent_label);
        mIPv6BytesRcvdLabel = findViewById(R.id.ipv6_bytes_rcvd_label);
        mIPv6BytesPercentage = findViewById(R.id.ipv6_bytes_percentage);
        mProgressIpv6 = findViewById(R.id.progress_ipv6);
        mIpv6Container = findViewById(R.id.ipv6_container);

        mPacketsSent = findViewById(R.id.packets_sent);
        mPacketsRcvd = findViewById(R.id.packets_rcvd);
        mPacketsTotal = findViewById(R.id.packets_total);
        mDroppedPkts = findViewById(R.id.pkts_dropped);
        mBadgePktsHealth = findViewById(R.id.badge_pkts_health);
        mRowPktsDropped = findViewById(R.id.row_pkts_dropped);

        mActiveConns = findViewById(R.id.active_connections);
        mDroppedConns = findViewById(R.id.dropped_connections);
        mRowDroppedConns = findViewById(R.id.row_dropped_connections);
        mTotConns = findViewById(R.id.tot_connections);
        mOpenSocks = findViewById(R.id.open_sockets);
        mOpenSocksRow = findViewById(R.id.open_sockets_row);

        mHeapUsage = findViewById(R.id.heap_usage);
        mProgressHeap = findViewById(R.id.progress_heap);
        mMemUsage = findViewById(R.id.mem_usage);
        mProgressRam = findViewById(R.id.progress_ram);
        mLowMem = findViewById(R.id.low_mem_detected);

        mDnsServer = findViewById(R.id.dns_server);
        mDnsQueries = findViewById(R.id.dns_queries);
        mBadgeDnsSec = findViewById(R.id.badge_dns_sec);
        mDnsServerRow = findViewById(R.id.dns_server_row);
        mDnsQueriesRow = findViewById(R.id.dns_queries_row);
        mDnsCard = findViewById(R.id.dns_card);

        mCardAllocations = findViewById(R.id.card_allocations);
        mAllocStats = findViewById(R.id.alloc_stats);

        mTvStatsMode = findViewById(R.id.tv_stats_mode);
        mBadgeStatusMode = findViewById(R.id.badge_status_mode);

        mTrafficGraph = findViewById(R.id.stats_traffic_graph);
        if (mTrafficGraph != null) {
            mTrafficGraph.setCompactMode(false);
        }
        setupLiveTrafficGraph();

        setupModeVisuals();

        // Listen for live stats updates
        CaptureService.observeStats(this, this::updateStats);

        CaptureService.askStatsDump();
    }

    private void setupLiveTrafficGraph() {
        if (mTrafficGraph == null) return;
        boolean enabled = Prefs.isTrafficGraphsEnabled(this);
        mTrafficGraph.setVisibility(enabled ? View.VISIBLE : View.GONE);
        if (enabled) {
            TrafficTimeSeriesCollector collector = TrafficTimeSeriesCollector.getInstance();
            mTrafficGraph.setDataPoints(collector.getRollingSnapshot());
            if (mTrafficListener == null) {
                mTrafficListener = (point, snapshot) -> runOnUiThread(() -> {
                    if (mTrafficGraph != null && !isFinishing() && !isDestroyed()) {
                        mTrafficGraph.setDataPoints(snapshot);
                    }
                });
                collector.addListener(mTrafficListener);
            }
        } else if (mTrafficListener != null) {
            TrafficTimeSeriesCollector.getInstance().removeListener(mTrafficListener);
            mTrafficListener = null;
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        setupLiveTrafficGraph();
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (mTrafficListener != null) {
            TrafficTimeSeriesCollector.getInstance().removeListener(mTrafficListener);
            mTrafficListener = null;
        }
    }

    private void setupModeVisuals() {
        boolean isServiceActive = CaptureService.isServiceActive();
        if (CaptureService.isCapturingAsRoot()) {
            mTvStatsMode.setText("Root Capture Mode Active");
            mOpenSocksRow.setVisibility(View.GONE);
            mRowDroppedConns.setVisibility(View.GONE);
            mRowPktsDropped.setVisibility(View.VISIBLE);
        } else if (CaptureService.isReadingFromPcapFile()) {
            mTvStatsMode.setText("PCAP Replay File Mode Active");
            mRowPktsDropped.setVisibility(View.GONE);
        } else {
            mTvStatsMode.setText(isServiceActive ? "VPN Service Engine Active" : "Engine Idle / Capture Stopped");
            if (!CaptureService.isIPv6Enabled()) {
                mIpv6Container.setVisibility(View.GONE);
            }
            mRowPktsDropped.setVisibility(View.GONE);
        }

        if (!isServiceActive) {
            mBadgeStatusMode.setText("IDLE");
            mBadgeStatusMode.setBackground(ContextCompat.getDrawable(this, R.drawable.badge_pill_closed));
            mBadgeStatusMode.setTextColor(ContextCompat.getColor(this, R.color.badgeClosedFg));
        } else {
            mBadgeStatusMode.setText("LIVE");
            mBadgeStatusMode.setBackground(ContextCompat.getDrawable(this, R.drawable.badge_pill_active));
            mBadgeStatusMode.setTextColor(ContextCompat.getColor(this, R.color.badgeActiveFg));
        }
    }

    private void updateStats(CaptureStats stats) {
        if (stats == null) return;

        // Traffic
        mBytesSent.setText(Utils.formatBytes(stats.bytes_sent));
        mBytesRcvd.setText(Utils.formatBytes(stats.bytes_rcvd));
        long tot_bytes = stats.bytes_sent + stats.bytes_rcvd;
        mTvTotalTraffic.setText("Tot: " + Utils.formatBytes(tot_bytes));

        // IPv6
        mIPv6BytesSentLabel.setText("Sent: " + Utils.formatBytes(stats.ipv6_bytes_sent));
        mIPv6BytesRcvdLabel.setText("Rcvd: " + Utils.formatBytes(stats.ipv6_bytes_rcvd));
        long percentage = (tot_bytes > 0) ?
                ((stats.ipv6_bytes_sent + stats.ipv6_bytes_rcvd) * 100 / tot_bytes) : 0;
        mIPv6BytesPercentage.setText(
                String.format(Utils.getPrimaryLocale(this), "%d%%", percentage));
        mProgressIpv6.setProgress((int) percentage);

        // Packets
        mPacketsSent.setText(Utils.formatIntShort(stats.pkts_sent));
        mPacketsRcvd.setText(Utils.formatIntShort(stats.pkts_rcvd));
        long totalPkts = (long) stats.pkts_sent + (long) stats.pkts_rcvd;
        mPacketsTotal.setText(Utils.formatIntShort(totalPkts));
        mDroppedPkts.setText(Utils.formatNumber(this, stats.pkts_dropped));

        if (stats.pkts_dropped > 0) {
            mBadgePktsHealth.setText(R.string.stat_warning);
            mBadgePktsHealth.setBackground(ContextCompat.getDrawable(this, R.drawable.badge_pill_blocked));
            mBadgePktsHealth.setTextColor(ContextCompat.getColor(this, R.color.badgeBlockedFg));
        } else {
            mBadgePktsHealth.setText(R.string.stat_healthy);
            mBadgePktsHealth.setBackground(ContextCompat.getDrawable(this, R.drawable.badge_pill_active));
            mBadgePktsHealth.setTextColor(ContextCompat.getColor(this, R.color.badgeActiveFg));
        }

        // Connections & Sockets
        mActiveConns.setText(Utils.formatNumber(this, stats.active_conns));
        mDroppedConns.setText(Utils.formatNumber(this, stats.num_dropped_conns));
        if (stats.num_dropped_conns > 0) {
            mDroppedConns.setTextColor(ContextCompat.getColor(this, R.color.statusError));
        } else {
            mDroppedConns.setTextColor(ContextCompat.getColor(this, R.color.metricTextPrimary));
        }
        mTotConns.setText(Utils.formatNumber(this, stats.tot_conns));
        mOpenSocks.setText(Utils.formatNumber(this, stats.num_open_sockets));

        // Memory
        updateMemoryStats();

        // DNS
        if (!CaptureService.isDNSEncrypted()) {
            mDnsCard.setVisibility(View.VISIBLE);
            mDnsServerRow.setVisibility(View.VISIBLE);
            mDnsQueriesRow.setVisibility(View.VISIBLE);
            mDnsServer.setText(CaptureService.getDNSServer());
            mDnsQueries.setText(Utils.formatNumber(this, stats.num_dns_queries));
            mBadgeDnsSec.setText(R.string.stat_standard_dns);
            mBadgeDnsSec.setBackground(ContextCompat.getDrawable(this, R.drawable.badge_pill_closed));
            mBadgeDnsSec.setTextColor(ContextCompat.getColor(this, R.color.badgeClosedFg));
        } else {
            mDnsCard.setVisibility(View.VISIBLE);
            mDnsServerRow.setVisibility(View.GONE);
            mDnsQueriesRow.setVisibility(View.GONE);
            mBadgeDnsSec.setText(R.string.stat_encrypted_dns);
            mBadgeDnsSec.setBackground(ContextCompat.getDrawable(this, R.drawable.badge_pill_proto));
            mBadgeDnsSec.setTextColor(ContextCompat.getColor(this, R.color.badgeProtoFg));
        }

        // Allocations
        if (stats.alloc_summary != null && !stats.alloc_summary.isEmpty()) {
            mCardAllocations.setVisibility(View.VISIBLE);
            mAllocStats.setText(stats.alloc_summary);
        } else {
            mCardAllocations.setVisibility(View.GONE);
        }
    }

    private void updateMemoryStats() {
        Locale locale = Utils.getPrimaryLocale(this);
        long heapAvailable = Utils.getAvailableHeap();
        long heapMax = Runtime.getRuntime().maxMemory();

        ActivityManager activityManager = (ActivityManager) getSystemService(Context.ACTIVITY_SERVICE);
        ActivityManager.MemoryInfo memoryInfo = new ActivityManager.MemoryInfo();
        if (activityManager != null) {
            activityManager.getMemoryInfo(memoryInfo);
        }

        long heapUsed = Math.max(0, heapMax - heapAvailable);
        int heapPercent = (heapMax > 0) ? (int) (heapUsed * 100 / heapMax) : 0;
        mHeapUsage.setText(String.format(locale, "%s / %s (%d%%)",
                Utils.formatBytes(heapUsed),
                Utils.formatBytes(heapMax),
                heapPercent));
        mProgressHeap.setProgress(heapPercent);

        if (memoryInfo.totalMem > 0) {
            long memUsed = Math.max(0, memoryInfo.totalMem - memoryInfo.availMem);
            int memPercent = (int) (memUsed * 100 / memoryInfo.totalMem);
            mMemUsage.setText(String.format(locale, "%s / %s (%d%%)",
                    Utils.formatBytes(memUsed),
                    Utils.formatBytes(memoryInfo.totalMem),
                    memPercent));
            mProgressRam.setProgress(memPercent);
        }

        boolean isLowMem = CaptureService.isLowMemory() || (memoryInfo != null && memoryInfo.lowMemory);
        if (isLowMem) {
            mLowMem.setText(R.string.stat_warning);
            mLowMem.setBackground(ContextCompat.getDrawable(this, R.drawable.badge_pill_blocked));
            mLowMem.setTextColor(ContextCompat.getColor(this, R.color.badgeBlockedFg));
        } else {
            mLowMem.setText(R.string.stat_healthy);
            mLowMem.setBackground(ContextCompat.getDrawable(this, R.drawable.badge_pill_active));
            mLowMem.setTextColor(ContextCompat.getColor(this, R.color.badgeActiveFg));
        }
    }

    @Override
    public void onCreateMenu(@NonNull Menu menu, MenuInflater inflater) {
        inflater.inflate(R.menu.copy_share_menu, menu);
    }

    private String getContents() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== KotSafe Live Telemetry Statistics ===\n");
        sb.append("Received (Rx): ").append(mBytesRcvd.getText()).append("\n");
        sb.append("Sent (Tx): ").append(mBytesSent.getText()).append("\n");
        sb.append("Total Traffic: ").append(mTvTotalTraffic.getText()).append("\n");
        sb.append("IPv6 Share: ").append(mIPv6BytesPercentage.getText()).append("\n");
        sb.append("Packets Received: ").append(mPacketsRcvd.getText()).append("\n");
        sb.append("Packets Sent: ").append(mPacketsSent.getText()).append("\n");
        sb.append("Packets Total: ").append(mPacketsTotal.getText()).append("\n");
        sb.append("Packets Dropped: ").append(mDroppedPkts.getText()).append("\n");
        sb.append("Active Connections: ").append(mActiveConns.getText()).append("\n");
        sb.append("Total Connections: ").append(mTotConns.getText()).append("\n");
        sb.append("Dropped Connections: ").append(mDroppedConns.getText()).append("\n");
        sb.append("Open Sockets: ").append(mOpenSocks.getText()).append("\n");
        sb.append("DNS Server: ").append(mDnsServer.getText()).append("\n");
        sb.append("DNS Queries: ").append(mDnsQueries.getText()).append("\n");
        sb.append("App Heap Usage: ").append(mHeapUsage.getText()).append("\n");
        sb.append("Device RAM Usage: ").append(mMemUsage.getText()).append("\n");
        sb.append("Memory Condition: ").append(mLowMem.getText()).append("\n");
        return sb.toString();
    }

    @Override
    public boolean onMenuItemSelected(@NonNull MenuItem item) {
        int id = item.getItemId();

        if (id == R.id.copy_to_clipboard) {
            Utils.copyToClipboard(this, getContents());
            return true;
        } else if (id == R.id.share) {
            Utils.shareText(this, getString(R.string.stats), getContents());
            return true;
        }

        return false;
    }
}