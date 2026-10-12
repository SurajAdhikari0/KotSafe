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

package com.kotsafe.security;

import android.content.Context;
import android.os.Build;
import android.util.SparseArray;
import android.util.SparseIntArray;

import androidx.annotation.Nullable;
import androidx.collection.ArraySet;

import com.kotsafe.security.interfaces.ConnectionsListener;
import com.kotsafe.security.model.AppDescriptor;
import com.kotsafe.security.model.AppStats;
import com.kotsafe.security.model.ConnectionDescriptor;
import com.kotsafe.security.model.ConnectionUpdate;
import com.kotsafe.security.adapters.ConnectionsAdapter;
import com.kotsafe.security.model.AppPresentationCache;
import com.kotsafe.security.model.ConnectionScreenState;
import com.kotsafe.security.model.Prefs;
import com.kotsafe.security.util.ConnectionsTimingTrace;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/* A container for the connections. This is used to store active/closed connections until the capture
 * is stopped. Active connections are also kept in the native side.
 *
 * The ConnectionsRegister can store up to _size items, after which rollover occurs and older
 * connections are replaced with the new ones. Via the addListener method it's possible to listen
 * for connections changes (connections added/removed/updated). The usual listener for such events
 * is the ConnectionsFragment, which then forwards them to the ConnectionsAdapter.
 *
 * Connections are added/updated by the CaptureService in a separate thread. The getter methods are
 * instead called on the UI thread, usually by the ConnectionsAdapter. Methods are synchronized to
 * provide threads safety on this class. Concurrent access to the ConnectionDescriptors fields can
 * occur during connectionsUpdates but it's not protected, check out the ConnectionDescriptor class
 * for more details.
 */
public class ConnectionsRegister {
    private static final String TAG = "ConnectionsRegister";

    private ConnectionDescriptor[] mItemsRing;
    private int mTail;
    private int mSize;
    private int mCurItems;
    private int mUntrackedItems; // number of old connections which were discarded due to the rollover
    private int mNumMalicious;
    private int mNumBlocked;
    private long mLastFirewallBlock;
    private long mMaxBytes;
    private final SparseArray<AppStats> mAppsStats;
    private final SparseIntArray mConnsByIface;
    private final ArrayList<ConnectionsListener> mListeners;
    private final Geolocation mGeo;
    private final AppsResolver mAppsResolver;
    private final Context mContext;
    /*
     * Native telemetry is emitted as a snapshot for every 5-tuple.  Keep the per-5-tuple
     * counters separate from the row shown in the UI: several ephemeral source ports can
     * legitimately contribute to one app/service row.  Mapping every source tuple directly
     * to the display descriptor used to make later snapshots add their cumulative byte count
     * again, which was the source of duplicate-looking system and DNS entries.
     */
    private static final class KotEngineFlowState {
        final ConnectionDescriptor displayConnection;
        long sentBytes;
        long receivedBytes;

        KotEngineFlowState(ConnectionDescriptor displayConnection, long sentBytes, long receivedBytes) {
            this.displayConnection = displayConnection;
            this.sentBytes = sentBytes;
            this.receivedBytes = receivedBytes;
        }
    }

    private final java.util.Map<String, KotEngineFlowState> mKotEngineConns = new java.util.concurrent.ConcurrentHashMap<>();
    private final java.util.Map<String, ConnectionDescriptor> mSmartDnsMap = new java.util.concurrent.ConcurrentHashMap<>();
    private final java.util.Map<String, ConnectionDescriptor> mSmartMcastMap = new java.util.concurrent.ConcurrentHashMap<>();
    // Deduplicates repeated connections from same app to same dst_ip:dst_port (different ephemeral src ports)
    private final java.util.Map<String, ConnectionDescriptor> mSmartFlowMap = new java.util.concurrent.ConcurrentHashMap<>();
    private final java.util.Map<Integer, Integer> mDnsAliasToCanonicalId = new java.util.concurrent.ConcurrentHashMap<>();
    private int mTotalInspectedConnections = 0;
    private long mLastFirewallEvent = 0;
    private int mNextKotEngineIncrId = 0;

    private static boolean isDnsConnection(int srcPort, int dstPort, @Nullable String l7proto) {
        return dstPort == 53 || srcPort == 53 || dstPort == 5353 || srcPort == 5353
                || "DNS".equalsIgnoreCase(l7proto) || "MDNS".equalsIgnoreCase(l7proto);
    }

    private static String normalizedDomain(@Nullable String domain) {
        if (domain == null)
            return "";

        String normalized = domain.trim().toLowerCase(java.util.Locale.ROOT);
        while (normalized.endsWith("."))
            normalized = normalized.substring(0, normalized.length() - 1);
        return normalized;
    }

    private static String dnsResolverIp(String srcIp, String dstIp, int srcPort, int dstPort) {
        return (dstPort == 53 || dstPort == 5353) ? dstIp : srcIp;
    }

    private static int dnsResolverPort(int srcPort, int dstPort) {
        return (dstPort == 53 || dstPort == 5353) ? dstPort : srcPort;
    }

    /* A DNS name alone is not an identity: identical queries can originate from different
     * apps and resolvers.  Keeping that context prevents Android system DNS traffic from
     * swallowing a user's app traffic (and vice versa). */
    private static String dnsAggregationKey(int uid, int proto, String resolverIp, int resolverPort,
                                            String domain) {
        int owner = uid >= 0 ? uid : 1000;
        String resolver = resolverIp == null || resolverIp.isEmpty() ? "unknown" : resolverIp;
        String name = domain == null || domain.isEmpty() ? "<unresolved>" : domain;
        return "DNS:" + owner + ':' + proto + ':' + resolver + ':' + resolverPort + ':' + name;
    }

    private static String flowAggregationKey(int uid, int proto, String target, int port) {
        int owner = uid >= 0 ? uid : 1000;
        return "FLOW:" + owner + ':' + proto + ':' + (target == null ? "" : target) + ':' + port;
    }

    private static String multicastAggregationKey(int uid, int proto, String target, int srcPort, int dstPort) {
        int owner = uid >= 0 ? uid : 1000;
        if (dstPort == 123 || srcPort == 123)
            return "SYSTEM:" + owner + ":NTP";
        if (dstPort == 1900)
            return "SYSTEM:" + owner + ":SSDP";
        if (dstPort == 5355)
            return "SYSTEM:" + owner + ":LLMNR";
        if (proto == 1 || proto == 58)
            return "SYSTEM:" + owner + ":ICMP:" + proto;
        return "MCAST:" + owner + ':' + proto + ':' + (target == null ? "mcast" : target) + ':' + dstPort;
    }

    private static boolean isSystemBroadcast(int proto, String dstIp, int srcPort, int dstPort) {
        return dstPort == 1900 || dstPort == 5355 || dstPort == 123 || srcPort == 123
                || proto == 1 || proto == 58
                || (dstIp != null && (dstIp.startsWith("224.") || dstIp.startsWith("239.")
                || dstIp.startsWith("ff0") || dstIp.equals("255.255.255.255")));
    }

    private void forgetAggregation(ConnectionDescriptor conn) {
        if (conn == null)
            return;

        mKotEngineConns.entrySet().removeIf(entry -> entry.getValue().displayConnection == conn);
        mSmartDnsMap.entrySet().removeIf(entry -> entry.getValue() == conn);
        mSmartMcastMap.entrySet().removeIf(entry -> entry.getValue() == conn);
        mSmartFlowMap.entrySet().removeIf(entry -> entry.getValue() == conn);
        mDnsAliasToCanonicalId.entrySet().removeIf(entry -> entry.getValue() == conn.incr_id || entry.getKey() == conn.incr_id);
    }

    /** Resolve ownership before choosing a grouping key.  Grouping unknown traffic first can
     * otherwise incorrectly attach a later-resolved app to an Android-system DNS row. */
    private int resolveConnectionUid(ConnectionDescriptor conn) {
        int uid = conn.uid;
        if (uid < 0 && !conn.uid_checked && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            CaptureService service = CaptureService.getInstance();
            if (service != null) {
                int resolvedUid = service.getUidQ(conn.ipproto, conn.src_ip, conn.src_port,
                        conn.dst_ip, conn.dst_port);
                if (resolvedUid >= 0) {
                    conn.uid = resolvedUid;
                    uid = resolvedUid;
                }
            }
            conn.uid_checked = true;
        }
        if (uid < 0) {
            String destination = conn.dst_ip;
            if ((destination != null && (destination.startsWith("ff02:")
                    || destination.startsWith("ff0") || destination.startsWith("224.")
                    || destination.equals("255.255.255.255")))
                    || conn.ipproto == 1 || conn.ipproto == 58) {
                conn.uid = 1000;
                uid = 1000;
            }
        }
        return uid;
    }

    public ConnectionsRegister(Context ctx, int _size) {
        mContext = ctx.getApplicationContext();
        mTail = 0;
        mCurItems = 0;
        mUntrackedItems = 0;
        mMaxBytes = 0;
        mSize = _size;
        mGeo = new Geolocation(ctx);
        mItemsRing = new ConnectionDescriptor[mSize];
        mListeners = new ArrayList<>();
        mAppsStats = new SparseArray<>(); // uid -> AppStats
        mConnsByIface = new SparseIntArray();
        mAppsResolver = new AppsResolver(ctx);
    }

    // returns the position in mItemsRing of the oldest connection
    private synchronized int firstPos() {
        return (mCurItems < mSize) ? 0 : mTail;
    }

    // returns the position in mItemsRing of the newest connection
    private synchronized int lastPos() {
        return (mTail - 1 + mSize) % mSize;
    }

    private void processConnectionStatus(ConnectionDescriptor conn, AppStats stats) {
        if(!conn.is_blocked) {
            try {
                com.kotsafe.security.model.SecurityBlocklistManager secMgr =
                        com.kotsafe.security.model.SecurityBlocklistManager.getInstance(mContext);
                if(secMgr != null) {
                    boolean isDstWhitelisted = secMgr.isSystemWhitelisted(conn.dst_ip)
                            || secMgr.isSystemWhitelisted(conn.info)
                            || com.kotsafe.security.model.SecurityBlocklistManager.isGoogleIp(conn.dst_ip)
                            || com.kotsafe.security.model.SecurityBlocklistManager.isMetaWhatsAppIp(conn.dst_ip)
                            || com.kotsafe.security.model.SecurityBlocklistManager.isCloudflareCdnIp(conn.dst_ip)
                            || com.kotsafe.security.model.SecurityBlocklistManager.isLocalOrConnectedDeviceIp(conn.dst_ip);
                    if (!isDstWhitelisted) {
                        if((conn.info != null && !conn.info.isEmpty() && secMgr.isFastBlocked(conn.info))
                                || (conn.url != null && !conn.url.isEmpty() && secMgr.isFastBlocked(conn.url))
                                || (conn.dst_ip != null && !conn.dst_ip.isEmpty() && secMgr.isFastBlocked(conn.dst_ip))) {
                            conn.is_blocked = true;
                            conn.block_reason = "Malicious Host (Threat Blocklist)";
                        }
                    }
                }
            } catch (Exception ignored) {}
        }


        // Privacy & Ad Tracker Shield Evaluation and DNS Activity Logging
        if (!conn.dns_accounted && (conn.info != null && !conn.info.isEmpty())) {
            try {
                com.kotsafe.security.model.AdBlockSubscriptionManager adBlockMgr =
                        com.kotsafe.security.model.AdBlockSubscriptionManager.getInstance(mContext);
                boolean isDns = "DNS".equalsIgnoreCase(conn.l7proto) || conn.dst_port == 53;
                String domain = conn.info;
                AppDescriptor appDesc = (mAppsResolver != null) ? mAppsResolver.getAppByUid(conn.uid, 0) : null;
                String clientApp = (appDesc != null) ? appDesc.getPackageName() : (conn.uid > 0 ? "UID " + conn.uid : "system");

                if (conn.uid == 1000 || conn.uid <= 0) {
                    List<CorrelatedApp> correlated = getCorrelatedAppsForTimestamp(conn.first_seen > 0 ? conn.first_seen : System.currentTimeMillis(), 5000);
                    if (correlated != null && !correlated.isEmpty()) {
                        clientApp = correlated.get(0).app.getPackageName();
                    }
                }

                // Google Trusted Services (Play Store, Play Protect, Services) accessing official infrastructure are trusted unless malicious
                boolean isGoogleTrustedFlow = Utils.isVerifiedGoogleTrustedService(mContext, clientApp)
                        && com.kotsafe.security.model.SecurityBlocklistManager.isOfficialDomain(domain)
                        && !conn.isBlacklisted();

                if (!isGoogleTrustedFlow && adBlockMgr != null && adBlockMgr.isAdBlockEnabled()) {
                    String blockReason = adBlockMgr.checkDomain(domain);
                    if (blockReason != null) {
                        conn.is_blocked = true;
                        conn.block_reason = blockReason;
                        conn.dns_accounted = true;
                        com.kotsafe.security.model.DnsActivityDbHelper.getInstance(mContext).logDnsQuery(
                                domain,
                                com.kotsafe.security.model.DnsActivityEntry.STATUS_BLOCKED,
                                blockReason,
                                clientApp,
                                (conn.l7proto != null && !conn.l7proto.isEmpty()) ? conn.l7proto : "DNS"
                        );
                    } else if (isDns) {
                        conn.dns_accounted = true;
                        com.kotsafe.security.model.DnsActivityDbHelper.getInstance(mContext).logDnsQuery(
                                domain,
                                com.kotsafe.security.model.DnsActivityEntry.STATUS_ALLOWED,
                                "Allowed",
                                clientApp,
                                "DNS"
                        );
                    }
                } else if (isDns) {
                    conn.dns_accounted = true;
                    com.kotsafe.security.model.DnsActivityDbHelper.getInstance(mContext).logDnsQuery(
                            domain,
                            com.kotsafe.security.model.DnsActivityEntry.STATUS_ALLOWED,
                            isGoogleTrustedFlow ? "Trusted Google Service" : "Allowed",
                            clientApp,
                            "DNS"
                    );
                }
            } catch (Exception ignored) {}
        }

        boolean is_blacklisted = conn.isBlacklisted();

        if(!conn.alerted && is_blacklisted) {
            CaptureService.requireInstance().notifyBlacklistedConnection(conn);
            conn.alerted = true;
            mNumMalicious++;
        } else if(conn.alerted && !is_blacklisted) {
            // the connection was whitelisted
            conn.alerted = false;
            mNumMalicious--;
        }

        if(!conn.block_accounted && conn.is_blocked) {
            mNumBlocked++;
            stats.numBlockedConnections++;
            conn.block_accounted = true;
        } else if(conn.block_accounted && !conn.is_blocked) {
            mNumBlocked--;
            stats.numBlockedConnections--;
            conn.block_accounted = false;
        }

        if(conn.is_blocked)
            mLastFirewallBlock = Math.max(conn.last_seen, mLastFirewallBlock);

        // Record into persistent Firewall Logs (only on first seen or if block status changed)
        if (!conn.logged_to_firewall || conn.is_blocked) {
            try {
                com.kotsafe.security.model.FirewallLogManager.getInstance(mContext).logConnection(conn);
                conn.logged_to_firewall = true;
            } catch (Exception ignored) {}
        }

        // Mercenary Spyware (Pegasus, Predator) & Micro-Beacon Detection
        if (!conn.spyware_inspected || conn.entropy > 7.5f || (conn.ja4 != null && !conn.ja4.isEmpty())) {
            try {
                com.kotsafe.security.model.MercenarySpywareDetector.getInstance(mContext)
                        .inspectNetworkFlow(conn.uid, conn.dst_ip, conn.dst_port, conn.info,
                                (int)conn.sent_bytes, (int)conn.rcvd_bytes, conn.entropy, conn.ja4 != null ? conn.ja4 : "");
                conn.spyware_inspected = true;
            } catch (Exception ignored) {}
        }

        // Phase 2: TinyML Beaconing Anomaly Detection — C2 / RAT heartbeat pattern classifier
        // Feeds connection timestamps per {uid, host} into sliding-window statistical detector.
        try {
            String host = (conn.info != null && !conn.info.isEmpty()) ? conn.info : conn.dst_ip;
            if (host != null && !host.isEmpty()) {
                AppDescriptor beaconAppDesc = (mAppsResolver != null)
                        ? mAppsResolver.getAppByUid(conn.uid, 0) : null;
                String beaconPkg = (beaconAppDesc != null) ? beaconAppDesc.getPackageName() : null;
                com.kotsafe.security.model.BeaconingAnomalyDetector.getInstance()
                        .onConnection(mContext, conn.uid, beaconPkg, host,
                                conn.first_seen > 0 ? conn.first_seen : System.currentTimeMillis(),
                                conn.sent_bytes);
            }
        } catch (Exception ignored) {}

        processHttpLogging(conn);
    }


    private void processHttpLogging(ConnectionDescriptor conn) {
        HttpLog httpLog = CaptureService.getHttpLog();
        if (httpLog == null)
            return;

        boolean isHttp = (conn.l7proto != null && conn.l7proto.equalsIgnoreCase("HTTP"))
                || conn.dst_port == 80 || conn.dst_port == 8080;
        boolean isHttps = (conn.l7proto != null && (conn.l7proto.equalsIgnoreCase("HTTPS") || conn.l7proto.equalsIgnoreCase("TLS")))
                || conn.dst_port == 443 || conn.dst_port == 8443;
        boolean hasUrl = (conn.url != null && !conn.url.isEmpty());

        if ((isHttp || isHttps || hasUrl) && conn.http_log_pos < 0) {
            HttpLog.HttpRequest req = new HttpLog.HttpRequest(conn, 0);
            req.timestamp = (conn.first_seen > 0) ? conn.first_seen : System.currentTimeMillis();
            req.host = (conn.info != null && !conn.info.isEmpty()) ? conn.info : conn.dst_ip;
            req.method = isHttps ? "CONNECT" : "GET";

            if (hasUrl) {
                if (conn.url.startsWith("http://") || conn.url.startsWith("https://")) {
                    int schemeEnd = conn.url.indexOf("://");
                    int pathStart = conn.url.indexOf('/', schemeEnd + 3);
                    if (pathStart >= 0) {
                        int queryStart = conn.url.indexOf('?', pathStart);
                        if (queryStart >= 0) {
                            req.path = conn.url.substring(pathStart, queryStart);
                            req.query = conn.url.substring(queryStart);
                        } else {
                            req.path = conn.url.substring(pathStart);
                        }
                    } else {
                        req.path = "/";
                    }
                } else if (conn.url.startsWith("/")) {
                    req.path = conn.url;
                } else {
                    req.path = "/" + conn.url;
                }
            } else {
                req.path = "/";
            }

            conn.http_log_pos = httpLog.getSize();
            httpLog.addHttpRequest(req);
        }

        if (conn.http_log_pos >= 0) {
            HttpLog.HttpRequest req = httpLog.getRequest(conn.http_log_pos);
            if (req != null && req.reply == null && conn.rcvd_bytes > 0) {
                HttpLog.HttpReply reply = new HttpLog.HttpReply(req, 0);
                reply.responseCode = 200;
                reply.responseStatus = "OK";
                reply.bodyLength = (int) Math.min(conn.rcvd_bytes, Integer.MAX_VALUE);
                reply.contentType = isHttps ? "application/octet-stream" : "text/html";
                req.reply = reply;
                httpLog.addHttpReply(reply);
            }
        }
    }

    // called by the CaptureService in a separate thread when new connections should be added to the register
    public synchronized void newConnections(ConnectionDescriptor[] conns) {
        ArrayList<ConnectionDescriptor> newConnsToAdd = new ArrayList<>(conns.length);
        ArrayList<Integer> updatedPositions = new ArrayList<>();
        long now = System.currentTimeMillis();

        for (ConnectionDescriptor conn : conns) {
            if (conn == null) continue;

            int uid = resolveConnectionUid(conn);
            AppPresentationCache.getInstance().getPresentation(uid, mContext, mAppsResolver);

            boolean isDns = isDnsConnection(conn.src_port, conn.dst_port, conn.l7proto);
            String domain = normalizedDomain(conn.info);
            String srvIp = dnsResolverIp(conn.src_ip, conn.dst_ip, conn.src_port, conn.dst_port);
            int srvPort = dnsResolverPort(conn.src_port, conn.dst_port);
            String smartDnsKey = isDns ? dnsAggregationKey(uid, conn.ipproto, srvIp, srvPort, domain) : null;

            if (isDns && smartDnsKey != null) {
                ConnectionDescriptor existingDns = mSmartDnsMap.get(smartDnsKey);
                if (existingDns != null && existingDns != conn) {
                    mDnsAliasToCanonicalId.put(conn.incr_id, existingDns.incr_id);
                    existingDns.query_count += Math.max(1, conn.query_count);
                    existingDns.sent_bytes += conn.sent_bytes;
                    existingDns.rcvd_bytes += conn.rcvd_bytes;
                    existingDns.last_seen = now;
                    existingDns.status = ConnectionDescriptor.CONN_STATUS_CONNECTED;
                    if ((existingDns.info == null || existingDns.info.isEmpty()) && !domain.isEmpty()) {
                        existingDns.info = domain;
                    }
                    AppStats stats = getAppsStatsOrCreate(existingDns.uid);
                    stats.sentBytes += conn.sent_bytes;
                    stats.rcvdBytes += conn.rcvd_bytes;
                    processConnectionStatus(existingDns, stats);
                    existingDns.getSocketSessions();
                    existingDns.recordSocketSession(conn.ipproto, conn.src_port, conn.dst_port,
                            conn.sent_bytes, conn.rcvd_bytes, conn.status, conn.l7proto, now, conn.is_blocked, conn.block_reason);
                    for (ConnectionDescriptor.SocketSession s : conn.getSocketSessions()) {
                        existingDns.recordSocketSession(s.proto, s.src_port, s.dst_port,
                                s.sent_bytes, s.rcvd_bytes, s.tcp_state, s.l7proto, s.last_seen, s.is_blocked, s.block_reason);
                    }

                    int regPos = getConnPositionById(existingDns.incr_id);
                    if (regPos >= 0 && !updatedPositions.contains(regPos)) {
                        updatedPositions.add(regPos);
                    }
                    continue;
                } else if (existingDns == null) {
                    conn.query_count = Math.max(1, conn.query_count);
                    mSmartDnsMap.put(smartDnsKey, conn);
                }
            }

            newConnsToAdd.add(conn);
        }

        if (newConnsToAdd.isEmpty()) {
            if (!updatedPositions.isEmpty()) {
                int[] changed = new int[updatedPositions.size()];
                for (int i = 0; i < updatedPositions.size(); i++) changed[i] = updatedPositions.get(i);
                for (ConnectionsListener listener : mListeners) {
                    listener.connectionsUpdated(changed);
                }
            }
            return;
        }

        ConnectionDescriptor[] connsToAdd = newConnsToAdd.toArray(new ConnectionDescriptor[0]);

        if(connsToAdd.length > mSize) {
            // this should only occur while testing with small register sizes
            // take the most recent connections
            mUntrackedItems += connsToAdd.length - mSize;
            connsToAdd = Arrays.copyOfRange(connsToAdd, connsToAdd.length - mSize, connsToAdd.length);
        }

        int out_items = connsToAdd.length - Math.min((mSize - mCurItems), connsToAdd.length);
        int insert_pos = mCurItems;
        boolean recalcMaxBytes = false;
        ConnectionDescriptor[] removedItems = null;

        // Remove old connections
        if(out_items > 0) {
            int pos = firstPos();
            removedItems = new ConnectionDescriptor[out_items];

            for(int i=0; i<out_items; i++) {
                ConnectionDescriptor conn = mItemsRing[pos];

                if(conn != null) {
                    if(conn.ifidx > 0) {
                        int num_conn = mConnsByIface.get(conn.ifidx);
                        if(--num_conn <= 0)
                            mConnsByIface.delete(conn.ifidx);
                        else
                            mConnsByIface.put(conn.ifidx, num_conn);
                    }

                    if(conn.isBlacklisted())
                        mNumMalicious--;

                    if ((conn.sent_bytes + conn.rcvd_bytes) == mMaxBytes)
                        recalcMaxBytes = true;

                    forgetAggregation(conn);
                }

                removedItems[i] = conn;
                pos = (pos + 1) % mSize;
            }
        }

        mTotalInspectedConnections += connsToAdd.length;
        mLastFirewallEvent = Math.max(mLastFirewallEvent, System.currentTimeMillis());

        // Add new connections
        for(ConnectionDescriptor conn: connsToAdd) {
            mItemsRing[mTail] = conn;
            mTail = (mTail + 1) % mSize;
            mCurItems = Math.min(mCurItems + 1, mSize);

            boolean isDns = isDnsConnection(conn.src_port, conn.dst_port, conn.l7proto);
            if (isDns) {
                String domain = normalizedDomain(conn.info);
                String srvIp = dnsResolverIp(conn.src_ip, conn.dst_ip, conn.src_port, conn.dst_port);
                int srvPort = dnsResolverPort(conn.src_port, conn.dst_port);
                String smartDnsKey = dnsAggregationKey(conn.uid, conn.ipproto, srvIp, srvPort, domain);
                conn.query_count = Math.max(1, conn.query_count);
                mSmartDnsMap.put(smartDnsKey, conn);
            }

            // update the apps stats
            int uid = resolveConnectionUid(conn);
            AppStats stats = getAppsStatsOrCreate(uid);

            if(conn.ifidx > 0) {
                int num_conn = mConnsByIface.get(conn.ifidx);
                mConnsByIface.put(conn.ifidx, num_conn + 1);
            }

            // Geolocation
            conn.asn = mGeo.getASN(conn.getDstAddr());
            if (conn.country == null || conn.country.isEmpty() || conn.country.equals("ZZ")) {
                String dstGeoCountry = mGeo.getCountryCode(conn.getDstAddr());
                if (dstGeoCountry != null && !dstGeoCountry.isEmpty())
                    conn.country = dstGeoCountry;
                else
                    conn.country = Utils.getIpCountryCode(KotSafe.getInstance(), conn.dst_ip);
            }

            String srcGeoCountry = mGeo.getCountryCode(conn.getSrcAddr());
            if (srcGeoCountry != null && !srcGeoCountry.isEmpty())
                conn.src_country = srcGeoCountry;
            else
                conn.src_country = Utils.getIpCountryCode(KotSafe.getInstance(), conn.src_ip);

            AppDescriptor app = mAppsResolver.getAppByUid(conn.uid, 0);
            if(app != null)
                conn.encrypted_payload = Utils.hasEncryptedPayload(app, conn);

            processConnectionStatus(conn, stats);

            stats.numConnections++;
            stats.rcvdBytes += conn.rcvd_bytes;
            stats.sentBytes += conn.sent_bytes;

            long totBytes = conn.sent_bytes + conn.rcvd_bytes;
            if (totBytes > mMaxBytes) {
                mMaxBytes = totBytes;
                recalcMaxBytes = false;
            }
        }

        mUntrackedItems += out_items;

        if (recalcMaxBytes)
            calculateMaxBytes();

        for(ConnectionsListener listener: mListeners) {
            if(out_items > 0)
                listener.connectionsRemoved(0, removedItems);

            if(connsToAdd.length > 0)
                listener.connectionsAdded(insert_pos - out_items, connsToAdd);
        }

        if (!updatedPositions.isEmpty()) {
            int[] changed = new int[updatedPositions.size()];
            for (int i = 0; i < updatedPositions.size(); i++) changed[i] = updatedPositions.get(i);
            for (ConnectionsListener listener : mListeners) {
                listener.connectionsUpdated(changed);
            }
        }
    }

    private synchronized void calculateMaxBytes() {
        long maxBytes = 0;

        for(int i = 0; i < mCurItems; i++) {
            ConnectionDescriptor conn = mItemsRing[i];
            maxBytes = Math.max(maxBytes, conn.sent_bytes + conn.rcvd_bytes);
        }

        mMaxBytes = maxBytes;
    }

    // called by the CaptureService in a separate thread when connections should be updated
    public synchronized void connectionsUpdates(ConnectionUpdate[] updates) {
        if(mCurItems == 0)
            return;

        int first_pos = firstPos();
        int last_pos = lastPos();
        int first_id = mItemsRing[first_pos].incr_id;
        int last_id = mItemsRing[last_pos].incr_id;
        int []changed_pos = new int[updates.length];
        int k = 0;

        Log.d(TAG, "connectionsUpdates: items=" + mCurItems + ", first_id=" + first_id + ", last_id=" + last_id);

        for(ConnectionUpdate update: updates) {
            int id = update.incr_id;
            int relPos = getConnPositionById(id);
            if(relPos < 0) {
                Integer canonId = mDnsAliasToCanonicalId.get(id);
                if(canonId != null) {
                    relPos = getConnPositionById(canonId);
                }
            }

            // ignore updates for untracked items
            if(relPos >= 0) {
                int pos = (first_pos + relPos) % mSize;
                ConnectionDescriptor conn = mItemsRing[pos];
                if(conn == null)
                    continue;

                // update the app stats
                AppStats stats = getAppsStatsOrCreate(conn.uid);
                stats.sentBytes += update.sent_bytes - conn.sent_bytes;
                stats.rcvdBytes += update.rcvd_bytes - conn.rcvd_bytes;
                mMaxBytes = Math.max(mMaxBytes, update.sent_bytes + update.rcvd_bytes);

                //Log.d(TAG, "update " + update.incr_id + " -> " + update.update_type);
                conn.processUpdate(update);
                processConnectionStatus(conn, stats);

                changed_pos[k++] = relPos;
            }
        }

        if(k == 0)
            // no updates for items in the ring
            return;

        if(k != updates.length)
            // some untracked items where skipped, shrink the array
            changed_pos = Arrays.copyOf(changed_pos, k);

        for(ConnectionsListener listener: mListeners)
            listener.connectionsUpdated(changed_pos);
    }

    public synchronized void reset() {
        for(int i = 0; i< mSize; i++)
            mItemsRing[i] = null;

        mCurItems = 0;
        mUntrackedItems = 0;
        mTail = 0;
        mNumMalicious = 0;
        mNumBlocked = 0;
        mLastFirewallBlock = 0;
        mMaxBytes = 0;
        mAppsStats.clear();
        mConnsByIface.clear();
        mKotEngineConns.clear();
        mSmartDnsMap.clear();
        mSmartMcastMap.clear();
        mSmartFlowMap.clear();
        mDnsAliasToCanonicalId.clear();
        mTotalInspectedConnections = 0;
        mLastFirewallEvent = 0;
        mNextKotEngineIncrId = 0;
        mCachedScreenState = null;

        for(ConnectionsListener listener: mListeners)
            listener.connectionsChanges(mCurItems);
    }

    public synchronized void addListener(ConnectionsListener listener) {
        mListeners.add(listener);

        // Send the first update to sync it
        listener.connectionsChanges(mCurItems);

        Log.d(TAG, "(add) new connections listeners size: " + mListeners.size());
    }

    public synchronized void removeListener(ConnectionsListener listener) {
        mListeners.remove(listener);

        Log.d(TAG, "(remove) new connections listeners size: " + mListeners.size());
    }

    public int getConnCount() {
        return mCurItems;
    }

    public int getUntrackedConnCount() {
        return mUntrackedItems;
    }

    private volatile ConnectionScreenState mCachedScreenState;

    @androidx.annotation.NonNull
    public synchronized List<ConnectionDescriptor> getConnectionsSnapshot() {
        long startTime = ConnectionsTimingTrace.startTrace();
        List<ConnectionDescriptor> list = new ArrayList<>(mCurItems);
        for (int i = 0; i < mCurItems; i++) {
            ConnectionDescriptor conn = getConn(i);
            if (conn != null) {
                list.add(conn);
            }
        }
        ConnectionsTimingTrace.logSnapshotCreation(startTime, list.size());
        return list;
    }

    @Nullable
    public ConnectionScreenState getCachedScreenState() {
        return mCachedScreenState;
    }

    public void setCachedScreenState(@Nullable ConnectionScreenState state) {
        this.mCachedScreenState = state;
    }

    public synchronized int getSize() {
        return mSize;
    }

    public synchronized void setSize(int newSize) {
        if(newSize == mSize || newSize <= 0)
            return;

        ConnectionDescriptor[] newRing = new ConnectionDescriptor[newSize];
        int countToCopy = Math.min(mCurItems, newSize);
        int dropped = mCurItems - countToCopy;

        // If shrinking, discard oldest connections and clean up interface counts
        if(dropped > 0) {
            int oldStart = firstPos();
            for(int i = 0; i < dropped; i++) {
                int pos = (oldStart + i) % mSize;
                ConnectionDescriptor conn = mItemsRing[pos];
                if(conn != null && conn.ifidx > 0) {
                    int num_conn = mConnsByIface.get(conn.ifidx);
                    if(--num_conn <= 0)
                        mConnsByIface.delete(conn.ifidx);
                    else
                        mConnsByIface.put(conn.ifidx, num_conn);
                }
                forgetAggregation(conn);
            }
            mUntrackedItems += dropped;
        }

        // Copy surviving items in chronological order into newRing[0 ... countToCopy-1]
        int oldFirst = firstPos();
        for(int i = 0; i < countToCopy; i++) {
            int oldPos = (oldFirst + dropped + i) % mSize;
            newRing[i] = mItemsRing[oldPos];
        }

        mItemsRing = newRing;
        mSize = newSize;
        mCurItems = countToCopy;
        mTail = (countToCopy == newSize) ? 0 : countToCopy;

        calculateMaxBytes();

        for(ConnectionsListener listener: mListeners)
            listener.connectionsChanges(mCurItems);
    }

    // get the i-th oldest connection
    public synchronized @Nullable ConnectionDescriptor getConn(int i) {
        if((i < 0) || (i >= mCurItems))
            return null;

        int pos = (firstPos() + i) % mSize;
        return mItemsRing[pos];
    }

    public synchronized int getConnPositionById(int incr_id) {
        if(mCurItems <= 0)
            return -1;

        int first_pos = firstPos();
        int last_pos = lastPos();
        ConnectionDescriptor first = mItemsRing[first_pos];
        ConnectionDescriptor last = mItemsRing[last_pos];

        if(first == null || last == null || incr_id < first.incr_id || incr_id > last.incr_id)
            return -1;

        // Fast path: if there are no gaps between first.incr_id and incr_id
        int offset = incr_id - first.incr_id;
        if(offset >= 0 && offset < mCurItems) {
            int candidatePos = (first_pos + offset) % mSize;
            ConnectionDescriptor candidate = mItemsRing[candidatePos];
            if(candidate != null && candidate.incr_id == incr_id)
                return offset;
        }

        // Monotonic binary search over the ring buffer [0, mCurItems - 1]
        int low = 0;
        int high = mCurItems - 1;
        while(low <= high) {
            int mid = (low + high) >>> 1;
            int ringPos = (first_pos + mid) % mSize;
            ConnectionDescriptor midConn = mItemsRing[ringPos];
            if(midConn == null)
                break;

            if(midConn.incr_id < incr_id) {
                low = mid + 1;
            } else if(midConn.incr_id > incr_id) {
                high = mid - 1;
            } else {
                return mid;
            }
        }

        return -1;
    }

    public synchronized @Nullable ConnectionDescriptor getConnById(int incr_id) {
        int pos = getConnPositionById(incr_id);
        if(pos >= 0)
            return getConn(pos);

        Integer canonicalId = mDnsAliasToCanonicalId.get(incr_id);
        if(canonicalId != null) {
            int canonPos = getConnPositionById(canonicalId);
            if(canonPos >= 0)
                return getConn(canonPos);
        }

        return null;
    }

    public static class CorrelatedApp {
        public final AppDescriptor app;
        public final long timeDeltaMs;
        public final String sampleTarget;

        public CorrelatedApp(AppDescriptor app, long timeDeltaMs, String sampleTarget) {
            this.app = app;
            this.timeDeltaMs = timeDeltaMs;
            this.sampleTarget = sampleTarget;
        }
    }

    /**
     * Resolves the user application(s) that were actively communicating around a given timestamp.
     * Used when an ad query or system DNS request is attributed to Android System (UID 1000)
     * because the Android DNS resolver processed the query on behalf of a user app.
     *
     * @param timestampMillis Timestamp in milliseconds to correlate around
     * @param windowMillis Window in milliseconds (e.g. 5000ms = +/- 5 seconds)
     * @return List of CorrelatedApp candidates sorted by temporal proximity
     */
    public synchronized List<CorrelatedApp> getCorrelatedAppsForTimestamp(long timestampMillis, long windowMillis) {
        List<CorrelatedApp> results = new ArrayList<>();
        if (mCurItems == 0) return results;

        if (timestampMillis <= 0) {
            timestampMillis = System.currentTimeMillis();
        }
        if (windowMillis <= 0) {
            windowMillis = 5000;
        }

        int myUid = android.os.Process.myUid();
        Map<Integer, ConnectionDescriptor> candidateMap = new HashMap<>();
        Map<Integer, Long> bestDeltaMap = new HashMap<>();

        for (int i = 0; i < mCurItems; i++) {
            ConnectionDescriptor conn = mItemsRing[i];
            if (conn == null) continue;

            // Only non-system user applications, excluding KotSafe itself. OEM
            // system apps can have UIDs >= 10000, so the UID range alone is not enough.
            if (conn.uid < 10000 || conn.uid == myUid
                || Utils.isSystemApp(mContext, conn.uid)) continue;

            long connTime = conn.last_seen > 0 ? conn.last_seen : conn.first_seen;
            if (connTime <= 0) continue;

            long delta = Math.abs(connTime - timestampMillis);
            if (delta <= windowMillis) {
                Long existingBest = bestDeltaMap.get(conn.uid);
                if (existingBest == null || delta < existingBest) {
                    bestDeltaMap.put(conn.uid, delta);
                    candidateMap.put(conn.uid, conn);
                }
            }
        }

        // If no app was active in the tight window, expand up to 30 seconds to catch slower background apps
        if (candidateMap.isEmpty()) {
            long relaxedWindow = Math.max(windowMillis * 4, 30000);
            for (int i = 0; i < mCurItems; i++) {
                ConnectionDescriptor conn = mItemsRing[i];
                if (conn == null || conn.uid < 10000 || conn.uid == myUid
                    || Utils.isSystemApp(mContext, conn.uid)) continue;

                long connTime = conn.last_seen > 0 ? conn.last_seen : conn.first_seen;
                if (connTime <= 0) continue;

                long delta = Math.abs(connTime - timestampMillis);
                if (delta <= relaxedWindow) {
                    Long existingBest = bestDeltaMap.get(conn.uid);
                    if (existingBest == null || delta < existingBest) {
                        bestDeltaMap.put(conn.uid, delta);
                        candidateMap.put(conn.uid, conn);
                    }
                }
            }
        }

        for (Map.Entry<Integer, Long> entry : bestDeltaMap.entrySet()) {
            int uid = entry.getKey();
            long delta = entry.getValue();
            ConnectionDescriptor conn = candidateMap.get(uid);
            AppDescriptor app = (mAppsResolver != null) ? mAppsResolver.getAppByUid(uid, 0) : null;
            if (app != null) {
                String target = (conn != null && conn.info != null && !conn.info.isEmpty())
                        ? conn.info
                        : (conn != null ? conn.dst_ip : "");
                results.add(new CorrelatedApp(app, delta, target));
            }
        }

        Collections.sort(results, (a, b) -> Long.compare(a.timeDeltaMs, b.timeDeltaMs));
        return results;
    }

    public synchronized AppStats getAppStats(int uid) {
        return mAppsStats.get(uid);
    }

    public synchronized List<AppStats> getAppsStats() {
        ArrayList<AppStats> rv = new ArrayList<>(mAppsStats.size());

        for(int i=0; i<mAppsStats.size(); i++) {
            // Create a clone to avoid concurrency issues
            AppStats stats = mAppsStats.valueAt(i).clone();

            rv.add(stats);
        }

        return rv;
    }

    private synchronized AppStats getAppsStatsOrCreate(int uid) {
        AppStats stats = mAppsStats.get(uid);
        if(stats == null) {
            stats = new AppStats(uid);
            mAppsStats.put(uid, stats);
        }

        return stats;
    }

    public synchronized void resetAppsStats() {
        mAppsStats.clear();
    }

    public synchronized Set<Integer> getSeenUids() {
        ArraySet<Integer> rv = new ArraySet<>();

        for(int i=0; i<mAppsStats.size(); i++)
            rv.add(mAppsStats.keyAt(i));

        return rv;
    }

    public int getNumMaliciousConnections() {
        return mNumMalicious;
    }

    public int getNumBlockedConnections() {
        return mNumBlocked;
    }

    public long getLastFirewallBlock() {
        return mLastFirewallBlock;
    }

    public synchronized int getTotalInspectedConnections() {
        return mTotalInspectedConnections;
    }

    public synchronized long getLastFirewallEvent() {
        return mLastFirewallEvent;
    }

    public synchronized boolean hasSeenMultipleInterfaces() {
        return(mConnsByIface.size() > 1);
    }

    // Returns a sorted list of seen network interfaces
    public synchronized List<String> getSeenInterfaces() {
        List<String> rv = new ArrayList<>();

        for(int i=0; i<mConnsByIface.size(); i++) {
            int ifidx = mConnsByIface.keyAt(i);
            String ifname = CaptureService.getInterfaceName(ifidx);

            if(!ifname.isEmpty())
                rv.add(ifname);
        }

        Collections.sort(rv);
        return rv;
    }

    public synchronized void releasePayloadMemory() {
        Log.i(TAG, "releaseFullPayloadMemory called");

        for(int i=0; i<mCurItems; i++) {
            ConnectionDescriptor conn = mItemsRing[i];
            conn.dropPayload();
        }
    }

    public synchronized long getMaxBytes() {
        return mMaxBytes;
    }

    /**
     * Snapshot of observed connections for a specific UID, mapped for AppPrivacyScorecardEngine.
     */
    public synchronized java.util.List<com.kotsafe.security.model.AppPrivacyScorecardEngine.ConnectionRecord> getPrivacyRecordsForUid(int uid) {
        java.util.List<com.kotsafe.security.model.AppPrivacyScorecardEngine.ConnectionRecord> records = new java.util.ArrayList<>();
        for (int i = 0; i < mCurItems; i++) {
            ConnectionDescriptor conn = mItemsRing[i];
            if (conn != null && conn.uid == uid) {
                com.kotsafe.security.model.AppPrivacyScorecardEngine.ConnectionRecord rec =
                        new com.kotsafe.security.model.AppPrivacyScorecardEngine.ConnectionRecord();
                rec.remoteIp = conn.dst_ip;
                rec.port = conn.dst_port;
                rec.host = (conn.info != null && !conn.info.isEmpty()) ? conn.info : conn.dst_ip;
                rec.isPlainHttp = (conn.l7proto != null && conn.l7proto.equalsIgnoreCase("HTTP")) || conn.dst_port == 80;
                rec.madeWhileScreenOff = false;
                records.add(rec);
            }
        }
        return records;
    }

    private int resolveKotEngineUid(com.kotsafe.security.engine.ConnInfo info, boolean isDns) {
        int uid = info.getUid();
        if (uid >= 0)
            return uid;

        if (isDns || info.getProto() == 1 || info.getProto() == 58)
            return 1000;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            CaptureService service = CaptureService.getInstance();
            if (service != null) {
                int resolved = service.getUidQ(info.getProto(), info.getSrcIp(), info.getSrcPort(),
                        info.getDstIp(), info.getDstPort());
                if (resolved >= 0)
                    return resolved;
            }
        }
        return uid;
    }

    private ConnectionDescriptor newKotEngineConnection(com.kotsafe.security.engine.ConnInfo info, int uid, long now) {
        int ipver = info.getSrcIp().contains(":") ? 6 : 4;
        ConnectionDescriptor conn = new ConnectionDescriptor(
                mNextKotEngineIncrId++, ipver, info.getProto(), info.getSrcIp(), info.getDstIp(),
                info.getCountryCode(), info.getSrcPort(), info.getDstPort(), info.getSrcPort(),
                uid, 0, false, now);
        conn.sent_bytes = Math.max(0, info.getBytesSent());
        conn.rcvd_bytes = Math.max(0, info.getBytesRcvd());
        String dom = normalizedDomain(info.getDomain());
        if (dom.isEmpty() && info.getDstIp() != null) {
            dom = ConnectionsAdapter.getDomainForIp(info.getDstIp());
        } else if (!dom.isEmpty() && info.getDstIp() != null) {
            ConnectionsAdapter.recordIpDomain(info.getDstIp(), dom);
        }
        conn.info = dom;
        conn.l7proto = info.getL7Proto();
        conn.ja4 = info.getJa4();
        conn.entropy = info.getEntropy();
        conn.tx_speed_bps = info.getTxSpeedBps();
        conn.rx_speed_bps = info.getRxSpeedBps();
        conn.status = (info.getTcpState() == 4 || info.getTcpState() == 5)
                ? ConnectionDescriptor.CONN_STATUS_CLOSED
                : ConnectionDescriptor.CONN_STATUS_CONNECTED;
        conn.recordSocketSession(info.getProto(), info.getSrcPort(), info.getDstPort(),
                conn.sent_bytes, conn.rcvd_bytes, info.getTcpState(), info.getL7Proto(), now);
        return conn;
    }

    private void updateKotEngineMetadata(ConnectionDescriptor conn,
                                         com.kotsafe.security.engine.ConnInfo info,
                                         boolean isDns, int uid) {
        String domain = normalizedDomain(info.getDomain());
        if (domain.isEmpty() && info.getDstIp() != null) {
            domain = ConnectionsAdapter.getDomainForIp(info.getDstIp());
        }
        if (!domain.isEmpty()) {
            conn.info = domain;
            if (info.getDstIp() != null) {
                ConnectionsAdapter.recordIpDomain(info.getDstIp(), domain);
            }
            if (isDns) {
                String resolver = dnsResolverIp(info.getSrcIp(), info.getDstIp(), info.getSrcPort(), info.getDstPort());
                int resolverPort = dnsResolverPort(info.getSrcPort(), info.getDstPort());
                String domainKey = dnsAggregationKey(uid, info.getProto(), resolver, resolverPort, domain);
                ConnectionDescriptor existing = mSmartDnsMap.get(domainKey);
                if (existing == null || existing == conn) {
                    mSmartDnsMap.entrySet().removeIf(entry -> entry.getValue() == conn);
                    mSmartDnsMap.put(domainKey, conn);
                }
            }
        }
        if (info.getL7Proto() != null && !info.getL7Proto().isEmpty())
            conn.l7proto = info.getL7Proto();
        if (info.getJa4() != null && !info.getJa4().isEmpty())
            conn.ja4 = info.getJa4();
        if (info.getEntropy() > 0.0f)
            conn.entropy = info.getEntropy();
        conn.tx_speed_bps = info.getTxSpeedBps();
        conn.rx_speed_bps = info.getRxSpeedBps();
        conn.status = (info.getTcpState() == 4 || info.getTcpState() == 5)
                ? ConnectionDescriptor.CONN_STATUS_CLOSED
                : ConnectionDescriptor.CONN_STATUS_CONNECTED;
    }

    /**
     * Ingest batched native telemetry. A 5-tuple remains the source-of-truth for byte
     * deltas, while the UI shows one canonical row per app/service target.
     */
    public synchronized void onKotEngineConnsUpdated(com.kotsafe.security.engine.ConnInfo[] conns) {
        if (conns == null || conns.length == 0)
            return;

        ArrayList<ConnectionDescriptor> newConns = new ArrayList<>(conns.length);
        ArrayList<Integer> updatedPositions = new ArrayList<>(conns.length);
        long now = System.currentTimeMillis();
        mLastFirewallEvent = Math.max(mLastFirewallEvent, now);

        for (com.kotsafe.security.engine.ConnInfo info : conns) {
            if (info == null)
                continue;

            boolean isDns = isDnsConnection(info.getSrcPort(), info.getDstPort(), info.getL7Proto());
            boolean isSystemService = isSystemBroadcast(info.getProto(), info.getDstIp(),
                    info.getSrcPort(), info.getDstPort());
            int uid = resolveKotEngineUid(info, isDns);
            String sourceKey = uid + ":" + info.getProto() + ":" + info.getSrcIp() + ':' + info.getSrcPort()
                    + ':' + info.getDstIp() + ':' + info.getDstPort();
            String domain = normalizedDomain(info.getDomain());

            KotEngineFlowState source = mKotEngineConns.get(sourceKey);
            if (source == null) {
                ConnectionDescriptor display;
                boolean newDisplay = false;
                boolean singleSocketMode = Prefs.isSingleSocketDiagnostics(mContext);

                if (singleSocketMode) {
                    display = newKotEngineConnection(info, uid, now);
                    newDisplay = true;
                } else if (isDns) {
                    String resolver = dnsResolverIp(info.getSrcIp(), info.getDstIp(), info.getSrcPort(), info.getDstPort());
                    String groupKey = dnsAggregationKey(uid, info.getProto(), resolver,
                            dnsResolverPort(info.getSrcPort(), info.getDstPort()), domain);
                    display = mSmartDnsMap.get(groupKey);
                    if (display == null) {
                        display = newKotEngineConnection(info, uid, now);
                        mSmartDnsMap.put(groupKey, display);
                        newDisplay = true;
                    } else
                        display.query_count++;
                } else if (isSystemService) {
                    String groupKey = multicastAggregationKey(uid, info.getProto(), info.getDstIp(),
                            info.getSrcPort(), info.getDstPort());
                    display = mSmartMcastMap.get(groupKey);
                    if (display == null) {
                        display = newKotEngineConnection(info, uid, now);
                        if (info.getDstPort() == 123 || info.getSrcPort() == 123)
                            display.info = "Network Time Service";
                        else if (info.getProto() == 1 || info.getProto() == 58)
                            display.info = "Network Diagnostic (ICMP)";
                        mSmartMcastMap.put(groupKey, display);
                        newDisplay = true;
                    } else {
                        display.aggregated_flows++;
                    }
                } else {
                    String target = !domain.isEmpty() ? domain : info.getDstIp();
                    String groupKey = flowAggregationKey(uid, info.getProto(), target, info.getDstPort());
                    display = mSmartFlowMap.get(groupKey);
                    if (display == null) {
                        display = newKotEngineConnection(info, uid, now);
                        mSmartFlowMap.put(groupKey, display);
                        newDisplay = true;
                    } else {
                        display.aggregated_flows++;
                    }
                }

                source = new KotEngineFlowState(display, Math.max(0, info.getBytesSent()),
                        Math.max(0, info.getBytesRcvd()));
                mKotEngineConns.put(sourceKey, source);
                display.recordSocketSession(info.getProto(), info.getSrcPort(), info.getDstPort(),
                        Math.max(0, info.getBytesSent()), Math.max(0, info.getBytesRcvd()),
                        info.getTcpState(), info.getL7Proto(), now);

                if (newDisplay) {
                    newConns.add(display);
                } else {
                    display.sent_bytes += source.sentBytes;
                    display.rcvd_bytes += source.receivedBytes;
                    display.last_seen = now;
                    updateKotEngineMetadata(display, info, isDns, uid);
                    // The canonical row may have been created earlier in this same native
                    // batch. Let newConnections account for its complete initial byte total
                    // once, instead of counting the second source tuple twice.
                    if (!newConns.contains(display)) {
                        AppStats stats = getAppsStatsOrCreate(display.uid);
                        stats.sentBytes += source.sentBytes;
                        stats.rcvdBytes += source.receivedBytes;
                        processConnectionStatus(display, stats);
                        int position = getConnPositionById(display.incr_id);
                        if (position >= 0 && !updatedPositions.contains(position))
                            updatedPositions.add(position);
                    }
                }
            } else {
                ConnectionDescriptor display = source.displayConnection;
                long sentDelta = Math.max(0, info.getBytesSent() - source.sentBytes);
                long receivedDelta = Math.max(0, info.getBytesRcvd() - source.receivedBytes);
                // Keep the most recent counters, rather than their high-water marks. Native
                // counters can reset when a socket is recycled; the following snapshot must
                // then be able to contribute fresh traffic again.
                source.sentBytes = Math.max(0, info.getBytesSent());
                source.receivedBytes = Math.max(0, info.getBytesRcvd());

                display.sent_bytes += sentDelta;
                display.rcvd_bytes += receivedDelta;
                display.last_seen = now;
                display.recordSocketSession(info.getProto(), info.getSrcPort(), info.getDstPort(),
                        Math.max(0, info.getBytesSent()), Math.max(0, info.getBytesRcvd()),
                        info.getTcpState(), info.getL7Proto(), now);
                updateKotEngineMetadata(display, info, isDns, uid);
                AppStats stats = getAppsStatsOrCreate(display.uid);
                stats.sentBytes += sentDelta;
                stats.rcvdBytes += receivedDelta;
                mMaxBytes = Math.max(mMaxBytes, display.sent_bytes + display.rcvd_bytes);
                processConnectionStatus(display, stats);
                int position = getConnPositionById(display.incr_id);
                if (position >= 0 && !updatedPositions.contains(position))
                    updatedPositions.add(position);
            }
        }

        if (!newConns.isEmpty())
            newConnections(newConns.toArray(new ConnectionDescriptor[0]));
        if (!updatedPositions.isEmpty()) {
            int[] positions = new int[updatedPositions.size()];
            for (int i = 0; i < positions.length; i++)
                positions[i] = updatedPositions.get(i);
            for (ConnectionsListener listener : mListeners)
                listener.connectionsUpdated(positions);
        }
    }
}
