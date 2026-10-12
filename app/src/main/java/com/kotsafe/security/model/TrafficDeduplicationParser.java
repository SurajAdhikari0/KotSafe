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

package com.kotsafe.security.model;

import android.content.Context;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.kotsafe.security.AppsResolver;
import com.kotsafe.security.CaptureService;
import com.kotsafe.security.Log;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.ConnectionDescriptor;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Deduplication & Event Normalization Parser.
 * Sits between VPN Mode & API Mode traffic sources and the security detection engine.
 *
 * Rule:
 * 1. Normalize both sources into UnifiedTrafficEvent.
 * 2. When VPN is ON: match on (appUid + destination + 3500ms window), merge duplicates,
 *    preferring VPN-sourced packet records (has SNI/DNS/bytes) while attaching API full URLs.
 * 3. When VPN is OFF: pass API-mode events straight through to the detection pipeline.
 */
public class TrafficDeduplicationParser {
    private static final String TAG = "TrafficDedupParser";
    private static volatile TrafficDeduplicationParser sInstance;

    private static final long DEDUP_WINDOW_MS = 3500L;
    private static final int MAX_CACHE_SIZE = 500;

    private final Context mContext;
    private final AppsResolver mAppsResolver;
    private final ExecutorService mExecutor;
    private final Handler mMainHandler;
    private final List<OnUnifiedEventListener> mListeners;

    // Sliding window LRU cache for deduplicating concurrent events
    private final Map<String, UnifiedTrafficEvent> mEventWindow;

    public interface OnUnifiedEventListener {
        void onUnifiedEvent(UnifiedTrafficEvent event);
    }

    public static TrafficDeduplicationParser getInstance(Context context) {
        if (sInstance == null) {
            synchronized (TrafficDeduplicationParser.class) {
                if (sInstance == null) {
                    sInstance = new TrafficDeduplicationParser(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    private static class LruEventMap extends LinkedHashMap<String, UnifiedTrafficEvent> {
        LruEventMap(int initialCapacity, float loadFactor, boolean accessOrder) {
            super(initialCapacity, loadFactor, accessOrder);
        }

        @Override
        protected boolean removeEldestEntry(Map.Entry<String, UnifiedTrafficEvent> eldest) {
            return size() > MAX_CACHE_SIZE;
        }
    }

    private TrafficDeduplicationParser(Context context) {
        mContext = context;
        mAppsResolver = new AppsResolver(context);
        mExecutor = Executors.newSingleThreadExecutor();
        mMainHandler = new Handler(Looper.getMainLooper());
        mListeners = Collections.synchronizedList(new ArrayList<>());
        mEventWindow = Collections.synchronizedMap(new LruEventMap(128, 0.75f, true));
    }

    public void addListener(OnUnifiedEventListener listener) {
        if (listener != null && !mListeners.contains(listener)) {
            mListeners.add(listener);
        }
    }

    public void removeListener(OnUnifiedEventListener listener) {
        if (listener != null) {
            mListeners.remove(listener);
        }
    }

    /**
     * Ingests a VPN-mode connection event.
     */
    public void onVpnConnection(@NonNull ConnectionDescriptor conn) {
        mExecutor.execute(() -> {
            try {
                long now = conn.first_seen > 0 ? conn.first_seen : System.currentTimeMillis();
                int uid = conn.uid;
                String pkgName = "";
                String appName = "";

                AppDescriptor app = mAppsResolver.getAppByUid(uid, 0);
                if (app != null) {
                    pkgName = app.getPackageName();
                    appName = app.getName();
                } else {
                    appName = "App (" + uid + ")";
                    pkgName = "uid:" + uid;
                }

                String dest = conn.info != null && !conn.info.isEmpty() ? conn.info : conn.dst_ip;
                String domain = conn.info != null && !conn.info.isEmpty() ? conn.info : "";
                String url = conn.url != null ? conn.url : "";

                UnifiedTrafficEvent.Builder builder = new UnifiedTrafficEvent.Builder()
                        .setSourceTag(UnifiedTrafficEvent.SOURCE_VPN)
                        .setAppUid(uid)
                        .setPackageName(pkgName)
                        .setAppName(appName)
                        .setTimestamp(now)
                        .setDestination(dest)
                        .setIp(conn.dst_ip != null ? conn.dst_ip : "")
                        .setDomain(domain)
                        .setUrl(url)
                        .setPort(conn.dst_port)
                        .setProtocol(Utils.proto2str(conn.ipproto))
                        .setBytesSent(conn.sent_bytes)
                        .setBytesRcvd(conn.rcvd_bytes)
                        .setEventCategory(UnifiedTrafficEvent.EventCategory.NETWORK_CONN);

                UnifiedTrafficEvent vpnEvent = builder.build();
                processIncomingEvent(vpnEvent);
            } catch (Exception e) {
                Log.e(TAG, "Error ingesting VPN connection: " + e.getMessage());
            }
        });
    }

    /**
     * Ingests an API-mode browser navigation event (from BrowserAccessibilityService).
     */
    public void onApiBrowserNavigation(@NonNull String packageName, @NonNull String fullUrl, long timestamp) {
        mExecutor.execute(() -> {
            try {
                int uid = -1;
                String appName = packageName;
                AppDescriptor app = mAppsResolver.getAppByPackage(packageName, 0);
                if (app != null) {
                    uid = app.getUid();
                    appName = app.getName();
                }

                String host = "";
                try {
                    Uri uri = Uri.parse(fullUrl);
                    if (uri.getHost() != null) {
                        host = uri.getHost();
                    }
                } catch (Exception ignored) {}
                if (host.isEmpty()) host = fullUrl;

                UnifiedTrafficEvent event = new UnifiedTrafficEvent.Builder()
                        .setSourceTag(UnifiedTrafficEvent.SOURCE_API)
                        .setAppUid(uid)
                        .setPackageName(packageName)
                        .setAppName(appName)
                        .setTimestamp(timestamp > 0 ? timestamp : System.currentTimeMillis())
                        .setDestination(host)
                        .setDomain(host)
                        .setUrl(fullUrl)
                        .setPort(443)
                        .setProtocol("HTTPS")
                        .setEventCategory(UnifiedTrafficEvent.EventCategory.BROWSER_NAV)
                        .setDetails("KotSafe Browser Navigation")
                        .build();

                processIncomingEvent(event);
            } catch (Exception e) {
                Log.e(TAG, "Error ingesting API browser navigation: " + e.getMessage());
            }
        });
    }

    /**
     * Ingests an API-mode NetworkStats usage anomaly delta.
     */
    public void onApiUsageDelta(int uid, @NonNull String packageName, long bytesDelta, long timestamp) {
        mExecutor.execute(() -> {
            try {
                AppDescriptor app = mAppsResolver.getAppByPackage(packageName, 0);
                String appName = app != null ? app.getName() : packageName;

                UnifiedTrafficEvent event = new UnifiedTrafficEvent.Builder()
                        .setSourceTag(UnifiedTrafficEvent.SOURCE_API)
                        .setAppUid(uid)
                        .setPackageName(packageName)
                        .setAppName(appName)
                        .setTimestamp(timestamp > 0 ? timestamp : System.currentTimeMillis())
                        .setDestination("Aggregate Network Usage")
                        .setBytesSent(bytesDelta / 2)
                        .setBytesRcvd(bytesDelta / 2)
                        .setEventCategory(UnifiedTrafficEvent.EventCategory.USAGE_DELTA)
                        .setDetails("NetworkStatsManager Delta: " + Utils.formatBytes(bytesDelta))
                        .build();

                processIncomingEvent(event);
            } catch (Exception e) {
                Log.e(TAG, "Error ingesting API usage delta: " + e.getMessage());
            }
        });
    }

    /**
     * Ingests an API-mode Wi-Fi security alert event.
     */
    public void onApiWifiSecurityEvent(@NonNull String ssid, @NonNull String bssid, @NonNull String securityType, @NonNull String threatDetails) {
        mExecutor.execute(() -> {
            try {
                UnifiedTrafficEvent event = new UnifiedTrafficEvent.Builder()
                        .setSourceTag(UnifiedTrafficEvent.SOURCE_API)
                        .setDestination(ssid)
                        .setDomain(bssid)
                        .setProtocol("802.11 (" + securityType + ")")
                        .setEventCategory(UnifiedTrafficEvent.EventCategory.WIFI_SECURITY)
                        .setDetails(threatDetails)
                        .build();

                processIncomingEvent(event);
            } catch (Exception e) {
                Log.e(TAG, "Error ingesting Wi-Fi security event: " + e.getMessage());
            }
        });
    }

    /**
     * Ingests an API-mode static application package scan event.
     */
    public void onApiAppScanEvent(@NonNull String packageName, @NonNull String appName, @NonNull String hash, boolean isMalicious, @Nullable String threatName) {
        mExecutor.execute(() -> {
            try {
                UnifiedTrafficEvent event = new UnifiedTrafficEvent.Builder()
                        .setSourceTag(UnifiedTrafficEvent.SOURCE_API)
                        .setPackageName(packageName)
                        .setAppName(appName)
                        .setDestination(packageName)
                        .setDomain(hash)
                        .setEventCategory(UnifiedTrafficEvent.EventCategory.APP_SCAN)
                        .setDetails(isMalicious ? "Threat: " + threatName : "Clean APK Scan")
                        .build();

                processIncomingEvent(event);
            } catch (Exception e) {
                Log.e(TAG, "Error ingesting App Scan event: " + e.getMessage());
            }
        });
    }

    /**
     * Core Deduplication and Routing logic.
     */
    private void processIncomingEvent(UnifiedTrafficEvent incoming) {
        boolean isVpnActive = CaptureService.isServiceActive();
        UnifiedTrafficEvent finalEvent = incoming;

        if (isVpnActive) {
            String dedupKey = buildDedupKey(incoming);
            UnifiedTrafficEvent existing = mEventWindow.get(dedupKey);

            if (existing != null && (Math.abs(incoming.timestamp - existing.timestamp) < DEDUP_WINDOW_MS)) {
                // Deduplicate & Merge
                if (incoming.isVpnSource() && existing.isApiSource()) {
                    // Enrich VPN with API url/details
                    finalEvent = new UnifiedTrafficEvent.Builder()
                            .setSourceTag(UnifiedTrafficEvent.SOURCE_VPN)
                            .setAppUid(incoming.appUid)
                            .setPackageName(incoming.packageName)
                            .setAppName(incoming.appName)
                            .setTimestamp(incoming.timestamp)
                            .setDestination(incoming.destination)
                            .setIp(incoming.ip)
                            .setDomain(incoming.domain)
                            .setUrl((incoming.url != null && !incoming.url.isEmpty()) ? incoming.url : existing.url)
                            .setPort(incoming.port)
                            .setProtocol(incoming.protocol)
                            .setBytesSent(incoming.bytesSent)
                            .setBytesRcvd(incoming.bytesRcvd)
                            .setNetworkType(incoming.networkType)
                            .setBackground(incoming.isBackground)
                            .setEventCategory(incoming.eventCategory)
                            .setDetails(existing.details)
                            .build();
                } else if (incoming.isApiSource() && existing.isVpnSource()) {
                    // Already have VPN record, enrich existing without emitting duplicate
                    mEventWindow.put(dedupKey, new UnifiedTrafficEvent.Builder()
                            .setSourceTag(UnifiedTrafficEvent.SOURCE_VPN)
                            .setAppUid(existing.appUid)
                            .setPackageName(existing.packageName)
                            .setAppName(existing.appName)
                            .setTimestamp(existing.timestamp)
                            .setDestination(existing.destination)
                            .setIp(existing.ip)
                            .setDomain(existing.domain)
                            .setUrl((incoming.url != null && !incoming.url.isEmpty()) ? incoming.url : existing.url)
                            .setPort(existing.port)
                            .setProtocol(existing.protocol)
                            .setBytesSent(existing.bytesSent)
                            .setBytesRcvd(existing.bytesRcvd)
                            .setNetworkType(existing.networkType)
                            .setBackground(existing.isBackground)
                            .setEventCategory(existing.eventCategory)
                            .setDetails(incoming.details)
                            .build());
                    return; // Dropped as duplicate
                }
            }
            mEventWindow.put(dedupKey, finalEvent);
        }

        // Dispatch unified event to downstream security detection engines
        dispatchToSecurityEngines(finalEvent);

        // Notify UI subscribers only if listeners are registered
        if (!mListeners.isEmpty()) {
            final UnifiedTrafficEvent ev = finalEvent;
            mMainHandler.post(() -> {
                synchronized (mListeners) {
                    for (OnUnifiedEventListener l : mListeners) {
                        l.onUnifiedEvent(ev);
                    }
                }
            });
        }
    }

    private String buildDedupKey(UnifiedTrafficEvent e) {
        String destKey = e.domain != null && !e.domain.isEmpty() ? e.domain : (e.destination != null ? e.destination : "");
        if (destKey.startsWith("http://") || destKey.startsWith("https://")) {
            try {
                Uri u = Uri.parse(destKey);
                if (u.getHost() != null) destKey = u.getHost();
            } catch (Exception ignored) {}
        }
        return e.appUid + ":" + destKey.toLowerCase();
    }

    /**
     * Routes normalized event to NetworkSecurityMonitor, FirewallLogDbHelper, and SmartScreen.
     */
    private void dispatchToSecurityEngines(UnifiedTrafficEvent event) {
        try {
            if (event.eventCategory == UnifiedTrafficEvent.EventCategory.BROWSER_NAV ||
                event.eventCategory == UnifiedTrafficEvent.EventCategory.NETWORK_CONN) {

                // If VPN is OFF and API-mode captured navigation, log and check threats
                if (event.isApiSource() && !CaptureService.isServiceActive()) {
                    FirewallLogEntry entry = new FirewallLogEntry();
                    entry.timestamp = event.timestamp;
                    entry.uid = event.appUid;
                    entry.appName = event.appName;
                    entry.packageName = event.packageName;
                    entry.dstIp = event.ip;
                    entry.dstPort = event.port;
                    entry.protocol = event.protocol;
                    entry.domainOrUrl = (event.url != null && !event.url.isEmpty()) ? event.url : event.destination;
                    entry.bytesSent = event.bytesSent;
                    entry.bytesRcvd = event.bytesRcvd;
                    entry.threatSource = "API_MODE_KOTSAFE";

                    SecurityBlocklistManager blMgr = SecurityBlocklistManager.getInstance(mContext);
                    SecurityRulesDb.SecurityRule blockRule = (event.url != null && !event.url.isEmpty()) ? blMgr.findUrlBlockRule(event.url) : null;
                    if (blockRule == null && event.domain != null && !event.domain.isEmpty()) {
                        blockRule = blMgr.findBlockRule(event.domain);
                    }
                    boolean isBlocked = (blockRule != null && blockRule.enabled);

                    entry.action = isBlocked ? FirewallLogEntry.ACTION_BLOCKED : FirewallLogEntry.ACTION_ALLOWED;
                    if (isBlocked) {
                        entry.threatVerdict = FirewallLogEntry.VERDICT_MALICIOUS;
                        entry.blockReason = (blockRule.reason != null && !blockRule.reason.isEmpty()) ? blockRule.reason : "Firewall Rule Restriction";
                    }

                    FirewallLogDbHelper.getInstance(mContext).insertLog(entry);

                    // Inspect in NetworkSecurityMonitor
                    NetworkSecurityMonitor.getInstance(mContext).onConnection(
                            event.appName,
                            event.packageName,
                            event.ip,
                            event.port,
                            event.domain,
                            event.url,
                            "GET"
                    );
                }
            } else if (event.eventCategory == UnifiedTrafficEvent.EventCategory.WIFI_SECURITY) {
                AlertStore.getInstance(mContext).add(
                        AlertRecord.Severity.HIGH,
                        AlertRecord.AlertType.SMARTSCREEN,
                        "Insecure Wi-Fi: " + event.destination,
                        event.details,
                        "Wi-Fi Security Guard"
                );
            }
        } catch (Exception e) {
            Log.w(TAG, "Error dispatching to security engine: " + e.getMessage());
        }
    }
}
