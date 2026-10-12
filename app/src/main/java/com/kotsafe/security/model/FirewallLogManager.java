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

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import com.kotsafe.security.AppsResolver;
import com.kotsafe.security.CaptureService;
import com.kotsafe.security.ConnectionsRegister;
import com.kotsafe.security.Log;
import com.kotsafe.security.NetworkStateMonitor;
import com.kotsafe.security.ScreenStateMonitor;
import com.kotsafe.security.Utils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class FirewallLogManager {
    private static final String TAG = "FirewallLogManager";
    private static volatile FirewallLogManager sInstance;

    private final Context mContext;
    private final FirewallLogDbHelper mDbHelper;
    private final AppsResolver mAppsResolver;
    private final ExecutorService mExecutor;
    private final Handler mMainHandler;
    private final List<OnNewLogListener> mListeners;
    // LRU-capped set: tracks incr_ids that have been logged. When the cap is exceeded the
    // oldest entries are evicted so we never hold more than MAX_LOGGED_IDS IDs in memory.
    private static final int MAX_LOGGED_IDS = 10_000;
    private final java.util.LinkedHashSet<Integer> mLoggedConns;

    private long mLastPurgeTime = 0;
    private static final long PURGE_INTERVAL_MILLIS = 6L * 60L * 60L * 1000L; // 6 hours

    public interface OnNewLogListener {
        void onNewLog(FirewallLogEntry entry);
        void onLogsCleared();
    }

    public static FirewallLogManager getInstance(Context context) {
        if(sInstance == null) {
            synchronized (FirewallLogManager.class) {
                if(sInstance == null) {
                    sInstance = new FirewallLogManager(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    private final NetworkStateMonitor mNetMonitor;
    private final ScreenStateMonitor mScreenMonitor;

    private FirewallLogManager(Context context) {
        mContext = context;
        mDbHelper = FirewallLogDbHelper.getInstance(context);
        mAppsResolver = new AppsResolver(context);
        mNetMonitor = new NetworkStateMonitor(context, null);
        mScreenMonitor = new ScreenStateMonitor(context, null);
        mExecutor = Executors.newSingleThreadExecutor();
        mMainHandler = new Handler(Looper.getMainLooper());
        mListeners = Collections.synchronizedList(new ArrayList<>());
        // Thread-safe LRU-capped set backed by a LinkedHashSet
        mLoggedConns = new java.util.LinkedHashSet<Integer>() {
            @Override
            public boolean add(Integer id) {
                if (size() >= MAX_LOGGED_IDS) {
                    // evict the oldest entry
                    remove(iterator().next());
                }
                return super.add(id);
            }
        };

        // Perform initial 7-day auto-purge on startup
        mExecutor.execute(() -> {
            mDbHelper.purgeOldLogs();
            mLastPurgeTime = System.currentTimeMillis();
        });
    }

    public void addListener(OnNewLogListener listener) {
        if(listener != null && !mListeners.contains(listener)) {
            mListeners.add(listener);
        }
    }

    public void removeListener(OnNewLogListener listener) {
        if(listener != null) {
            mListeners.remove(listener);
        }
    }

    public void clearLogs() {
        mExecutor.execute(() -> {
            mDbHelper.clearAll();
            mLoggedConns.clear();
            mMainHandler.post(() -> {
                synchronized (mListeners) {
                    for(OnNewLogListener l : mListeners) l.onLogsCleared();
                }
            });
        });
    }

    public void logConnection(ConnectionDescriptor conn) {
        if(conn == null) return;

        // Ensure we don't duplicate logs for the same connection unless its action changed (e.g. was blocked)
        final int connId = conn.incr_id;
        boolean blockedFlag = conn.is_blocked;
        if (!blockedFlag) {
            try {
                SecurityBlocklistManager secBl = SecurityBlocklistManager.getInstance(mContext);
                if (secBl != null) {
                    if ((conn.info != null && !conn.info.isEmpty() && secBl.isFastBlocked(conn.info))
                            || (conn.url != null && !conn.url.isEmpty() && secBl.isFastBlocked(conn.url))
                            || (conn.dst_ip != null && !conn.dst_ip.isEmpty() && secBl.isFastBlocked(conn.dst_ip))) {
                        blockedFlag = true;
                    }
                }
            } catch (Exception ignored) {}
        }
        final boolean isBlocked = blockedFlag;
        final boolean isAlerted = conn.isBlacklisted();

        mExecutor.execute(() -> {
            try {
                // Auto-purge old logs periodically
                long now = System.currentTimeMillis();
                if(now - mLastPurgeTime > PURGE_INTERVAL_MILLIS) {
                    mDbHelper.purgeOldLogs();
                    mLastPurgeTime = now;
                }

                // If already logged and status hasn't become blocked/alerted, skip
                if(mLoggedConns.contains(connId) && !isBlocked && !isAlerted) {
                    return;
                }
                mLoggedConns.add(connId);

                FirewallLogEntry entry = new FirewallLogEntry();
                entry.timestamp = conn.first_seen > 0 ? conn.first_seen : now;
                entry.uid = conn.uid;

                AppDescriptor app = mAppsResolver.getAppByUid(conn.uid, 0);
                AppDescriptor correlatedApp = null;
                if (conn.uid == 1000 || conn.uid <= 0 || conn.isDns()) {
                    try {
                        ConnectionsRegister reg = CaptureService.getConnsRegister();
                        if (reg != null) {
                            long t = conn.last_seen > 0 ? conn.last_seen : (conn.first_seen > 0 ? conn.first_seen : now);
                            List<ConnectionsRegister.CorrelatedApp> list = reg.getCorrelatedAppsForTimestamp(t, 5000);
                            if (list != null && !list.isEmpty()) {
                                correlatedApp = list.get(0).app;
                            }
                        }
                    } catch (Throwable ignored) {}
                }

                if (correlatedApp != null) {
                    entry.appName = correlatedApp.getName() + " (via Android System)";
                    entry.packageName = correlatedApp.getPackageName();
                    entry.isServiceApp = false;
                } else if(app != null) {
                    entry.appName = app.getName();
                    entry.packageName = app.getPackageName();
                    entry.isServiceApp = app.isSystem() || (conn.uid < 10000 && conn.uid != Utils.UID_UNKNOWN);
                } else {
                    entry.appName = "App (" + conn.uid + ")";
                    entry.packageName = "uid:" + conn.uid;
                    entry.isServiceApp = (conn.uid < 10000 && conn.uid != Utils.UID_UNKNOWN);
                }

                entry.srcIp = conn.src_ip != null ? conn.src_ip : "";
                entry.srcPort = conn.src_port;
                entry.dstIp = conn.dst_ip != null ? conn.dst_ip : "";
                entry.dstPort = conn.dst_port;
                entry.protocol = Utils.proto2str(conn.ipproto);
                entry.l7proto = conn.l7proto != null ? conn.l7proto : "";
                String resolvedUrl = "";
                if(conn.url != null && !conn.url.isEmpty()) {
                    resolvedUrl = conn.url;
                } else if(conn.info != null && !conn.info.isEmpty()) {
                    String scheme = (conn.dst_port == 443 || !conn.isCleartext()) ? "https://" : "http://";
                    resolvedUrl = scheme + conn.info + ((conn.dst_port != 80 && conn.dst_port != 443) ? ":" + conn.dst_port : "");
                } else if(conn.dst_ip != null && !conn.dst_ip.isEmpty()) {
                    resolvedUrl = "http://" + conn.dst_ip + ":" + conn.dst_port;
                }
                entry.domainOrUrl = resolvedUrl;
                entry.country = conn.country != null ? conn.country : "";
                entry.asn = conn.asn != null ? conn.asn.toString() : "";
                entry.bytesSent = conn.sent_bytes;
                entry.bytesRcvd = conn.rcvd_bytes;
                entry.duration = conn.last_seen > conn.first_seen ? (conn.last_seen - conn.first_seen) : 0;

                // Determine Network Type
                NetworkType netType = mNetMonitor.getCurrentNetworkType();
                entry.networkType = netType != null ? netType.name() : "UNKNOWN";

                // Determine Background State
                entry.isBackground = !mScreenMonitor.isScreenOn();

                // Compute initial payload SHA-256 hash if data exists
                byte[] sampleData = null;
                if(conn.info != null && !conn.info.isEmpty()) {
                    sampleData = conn.info.getBytes();
                } else if(conn.url != null && !conn.url.isEmpty()) {
                    sampleData = conn.url.getBytes();
                }
                if(sampleData != null && sampleData.length > 0) {
                    entry.payloadHash = ThreatIntelManager.computeSha256(sampleData);
                }

                // Determine Firewall Action & Reason
                AppNetworkRulesManager rulesMgr = AppNetworkRulesManager.getInstance(mContext);
                AppNetworkRule rule = rulesMgr.getRule(conn.uid);

                if(isAlerted) {
                    entry.action = FirewallLogEntry.ACTION_ALERT;
                    entry.blockType = FirewallLogEntry.BLOCK_TYPE_MALWARE;
                    entry.threatVerdict = FirewallLogEntry.VERDICT_MALICIOUS;
                    entry.threatSource = "Blacklist/Maltrail";
                    entry.threatDetails = "Identified on malicious domain/IP threat list";
                    entry.blockReason = "Threat Detection Flagged";
                } else if(isBlocked) {
                    entry.action = FirewallLogEntry.ACTION_BLOCKED;

                    // 1. Detect if this is an Ad or Tracker domain/service
                    String domainToCheck = entry.domainOrUrl;
                    if ((domainToCheck == null || domainToCheck.isEmpty()) && conn.info != null) {
                        domainToCheck = conn.info;
                    }
                    boolean isAdOrTracker = false;
                    try {
                        AdBlockSubscriptionManager adBlockMgr = AdBlockSubscriptionManager.getInstance(mContext);
                        if (adBlockMgr != null && adBlockMgr.isAdBlockEnabled() && domainToCheck != null && !domainToCheck.isEmpty()) {
                            String adReason = adBlockMgr.checkDomain(domainToCheck);
                            if (adReason != null) {
                                isAdOrTracker = true;
                                entry.blockType = FirewallLogEntry.BLOCK_TYPE_ADS;
                                entry.blockReason = "Ads & Trackers Shield: " + adReason;
                            }
                        }
                    } catch (Exception ignored) {}

                    if (!isAdOrTracker) {
                        if(conn.block_reason != null && !conn.block_reason.isEmpty()) {
                            entry.blockReason = conn.block_reason;
                            if (conn.block_type != null && !conn.block_type.isEmpty()) {
                                entry.blockType = conn.block_type;
                            }
                        } else if(rule != null && netType == NetworkType.WIFI && rule.isWifiBlocked()) {
                            entry.blockType = FirewallLogEntry.BLOCK_TYPE_FIREWALL_RULE;
                            entry.blockReason = "Wi-Fi Access Blocked (Network Rule)";
                        } else if(rule != null && netType == NetworkType.MOBILE && rule.isMobileBlocked()) {
                            entry.blockType = FirewallLogEntry.BLOCK_TYPE_FIREWALL_RULE;
                            entry.blockReason = "Mobile Data Blocked (Network Rule)";
                        } else if(rule != null && netType == NetworkType.ROAMING && rule.isRoamingBlocked()) {
                            entry.blockType = FirewallLogEntry.BLOCK_TYPE_FIREWALL_RULE;
                            entry.blockReason = "Data Roaming Blocked (Network Rule)";
                        } else if(rule != null && entry.isBackground && !rule.isAllowInBackground()) {
                            entry.blockType = FirewallLogEntry.BLOCK_TYPE_FIREWALL_RULE;
                            entry.blockReason = "Background Access Blocked (Screen-Off Policy)";
                        } else if(rule != null && rule.isLanBlocked()) {
                            entry.blockType = FirewallLogEntry.BLOCK_TYPE_LAN_RULE;
                            entry.blockReason = "LAN Access Blocked (Local Isolation)";
                        } else if(conn.isBlacklistedHost() || conn.isBlacklistedIp()) {
                            entry.blockType = FirewallLogEntry.BLOCK_TYPE_MALWARE;
                            entry.blockReason = "Threat Intelligence: Malicious Host / IOC Blocked";
                        } else {
                            entry.blockType = FirewallLogEntry.BLOCK_TYPE_POLICY;
                            entry.blockReason = "Firewall Policy Blocked";
                        }
                    }

                    if (entry.blockType == null || entry.blockType.isEmpty()) {
                        entry.blockType = entry.getFormattedBlockType();
                    }
                    if(conn.block_reason == null || conn.block_reason.isEmpty()) {
                        conn.block_reason = entry.blockReason;
                    }
                    if(conn.block_type == null || conn.block_type.isEmpty()) {
                        conn.block_type = entry.blockType;
                    }
                    if(entry.blockReason.toLowerCase().contains("malicious") || entry.blockReason.toLowerCase().contains("c2")) {
                        entry.threatVerdict = FirewallLogEntry.VERDICT_MALICIOUS;
                    } else if(entry.blockReason.toLowerCase().contains("phish")) {
                        entry.threatVerdict = FirewallLogEntry.VERDICT_SUSPICIOUS;
                    }
                } else {
                    entry.action = FirewallLogEntry.ACTION_ALLOWED;
                    entry.blockType = "ALLOWED";
                    entry.blockReason = "Policy Allowed (" + entry.networkType + ")";
                    entry.threatVerdict = FirewallLogEntry.VERDICT_CLEAN;
                }

                mDbHelper.insertLog(entry);

                // Feed to TrafficDeduplicationParser for dual-mode correlation & deduplication
                try {
                    TrafficDeduplicationParser.getInstance(mContext).onVpnConnection(conn);
                } catch (Exception ignored) {}

                // Wire into NetworkSecurityMonitor for threat enrichment & SmartScreen alerts
                try {
                    SmartScreenManager ssm = SmartScreenManager.getInstance(mContext);
                    boolean isBrowser = entry.packageName != null && ssm.isBrowserPackage(entry.packageName);
                    if (isBrowser) {
                        SmartScreenManager.noteBrowserActivity(entry.packageName);
                    }



                    // Always run NetworkSecurityMonitor for threat enrichment (AI analysis, DB logging)
                    String domain = (conn.info != null && !conn.info.isEmpty()) ? conn.info : null;
                    NetworkSecurityMonitor.getInstance(mContext).onConnection(
                            entry.appName,
                            entry.packageName,
                            entry.dstIp,
                            entry.dstPort,
                            domain,
                            entry.domainOrUrl,
                            (entry.l7proto != null && !entry.l7proto.isEmpty()) ? entry.l7proto : "TCP"
                    );
                } catch (Exception e) {
                    Log.w(TAG, "NetworkSecurityMonitor dispatch: " + e.getMessage());
                }

                // Notify UI listeners
                mMainHandler.post(() -> {
                    synchronized (mListeners) {
                        for(OnNewLogListener l : mListeners) {
                            l.onNewLog(entry);
                        }
                    }
                });

            } catch (Exception e) {
                Log.e(TAG, "Error logging connection: " + e.getMessage());
            }
        });
    }
}
