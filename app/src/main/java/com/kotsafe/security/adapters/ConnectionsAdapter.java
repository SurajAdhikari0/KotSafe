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

package com.kotsafe.security.adapters;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.res.TypedArray;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import java.util.List;
import android.util.SparseIntArray;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.collection.ArraySet;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.AsyncListDiffer;
import androidx.recyclerview.widget.RecyclerView;

import com.kotsafe.security.AppIconLoader;
import com.kotsafe.security.Log;
import com.kotsafe.security.KotSafe;
import com.kotsafe.security.interfaces.ConnectionsListener;
import com.kotsafe.security.model.AppDescriptor;
import com.kotsafe.security.CaptureService;
import com.kotsafe.security.AppsResolver;
import com.kotsafe.security.model.ConnectionDescriptor;
import com.kotsafe.security.model.ConnectionRow;
import com.kotsafe.security.util.ConnectionsTimingTrace;
import com.kotsafe.security.ConnectionsRegister;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.ConnectionTrustEvaluator;
import com.kotsafe.security.model.FilterDescriptor;
import com.kotsafe.security.model.MatchList;
import com.kotsafe.security.model.AppNetworkRule;
import com.kotsafe.security.model.AppNetworkRulesManager;
import com.kotsafe.security.model.Prefs;
import androidx.preference.PreferenceManager;
import com.haipq.android.flagkit.FlagImageView;

import android.os.Build;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class ConnectionsAdapter extends RecyclerView.Adapter<ConnectionsAdapter.ViewHolder>
        implements ConnectionsListener {
    private static final String TAG = "ConnectionsAdapter";
    private final LayoutInflater mLayoutInflater;
    private final Drawable mUnknownIcon;
    private int mUnfilteredItemsCount;
    private View.OnClickListener mListener;
    private View.OnLongClickListener mSelectionLongClickListener;
    private final AppsResolver mAppsResolver;
    private final Context mContext;
    private ConnectionDescriptor mSelectedItem;
    private final ArraySet<Integer> mSelectedItems = new ArraySet<>();
    private final int mSelectedColor;
    private final int mSelectableBackground;

    // Maps a connection ID to its current position in mFilteredConn. SparseIntArray is
    // less efficient than a HashMap on large collections, but takes much less memory.
    private final SparseIntArray mIdToFilteredPos;

    private ArrayList<ConnectionDescriptor> mFilteredConn;
    private String mSearch;
    public final MatchList mMask;
    public FilterDescriptor mFilter = new FilterDescriptor(); // must call refreshFilteredConnections to apply changes
    private final ConnectionTrustEvaluator mTrustEvaluator = new ConnectionTrustEvaluator();
    private final AppNetworkRulesManager mRulesManager;
    private boolean mFwEnabled;
    private final Map<String, ConnectionDescriptor> mAggregatedFlows = new LinkedHashMap<>();
    private final Map<Integer, Integer> mAliasToCanonicalId = new HashMap<>();

    private final AsyncListDiffer<ConnectionRow> mDiffer = new AsyncListDiffer<>(this, ConnectionRow.DIFF_CALLBACK);
    private boolean mUseDiffer = false;
    private boolean mGroupByApp = true;
    private final Set<Integer> mExpandedAppUids = new HashSet<>();
    private List<ConnectionRow> mRawRows = new ArrayList<>();

    public void setGroupByApp(boolean groupByApp) {
        if (mGroupByApp != groupByApp) {
            mGroupByApp = groupByApp;
            if (mRawRows != null && !mRawRows.isEmpty()) {
                mDiffer.submitList(applyGrouping(mRawRows));
            }
        }
    }

    public boolean isGroupByApp() {
        return mGroupByApp;
    }

    public void toggleAppExpansion(int uid) {
        if (mExpandedAppUids.contains(uid)) {
            mExpandedAppUids.remove(uid);
        } else {
            mExpandedAppUids.add(uid);
        }
        if (mRawRows != null && !mRawRows.isEmpty()) {
            mDiffer.submitList(applyGrouping(mRawRows));
        }
    }

    public boolean isAppExpanded(int uid) {
        return mExpandedAppUids.contains(uid);
    }

    public void setConnectionRows(@NonNull java.util.List<ConnectionRow> rows) {
        mUseDiffer = true;
        mRawRows = rows;
        mDiffer.submitList(applyGrouping(rows));
    }

    @NonNull
    public List<ConnectionRow> applyGrouping(@Nullable List<ConnectionRow> rawRows) {
        if (!mGroupByApp || rawRows == null || rawRows.isEmpty()) {
            return rawRows != null ? rawRows : Collections.emptyList();
        }

        Map<Integer, List<ConnectionRow>> appGroups = new LinkedHashMap<>();
        for (ConnectionRow row : rawRows) {
            if (row == null) continue;
            List<ConnectionRow> list = appGroups.get(row.uid);
            if (list == null) {
                list = new ArrayList<>();
                appGroups.put(row.uid, list);
            }
            list.add(row);
        }

        // Helper structure to sort apps by latest activity
        class AppGroupHolder {
            final int uid;
            final List<ConnectionRow> rows;
            final long maxLastSeen;

            AppGroupHolder(int uid, List<ConnectionRow> rows) {
                this.uid = uid;
                this.rows = rows;
                // Sort child connections within each app by newest activity first
                rows.sort((ra, rb) -> Long.compare(rb.lastSeen, ra.lastSeen));
                long maxTs = 0;
                for (ConnectionRow r : rows) {
                    if (r.lastSeen > maxTs) {
                        maxTs = r.lastSeen;
                    }
                }
                this.maxLastSeen = maxTs;
            }
        }

        List<AppGroupHolder> holders = new ArrayList<>(appGroups.size());
        for (Map.Entry<Integer, List<ConnectionRow>> entry : appGroups.entrySet()) {
            if (!entry.getValue().isEmpty()) {
                holders.add(new AppGroupHolder(entry.getKey(), entry.getValue()));
            }
        }

        // Sort apps so that the app with the most recent activity appears FIRST!
        holders.sort((ha, hb) -> Long.compare(hb.maxLastSeen, ha.maxLastSeen));

        List<ConnectionRow> result = new ArrayList<>();
        for (AppGroupHolder holder : holders) {
            int uid = holder.uid;
            List<ConnectionRow> group = holder.rows;

            if (group.size() == 1) {
                result.add(group.get(0));
            } else {
                boolean isExpanded = mExpandedAppUids.contains(uid);
                long totalSent = 0;
                long totalRcvd = 0;
                int activeCount = 0;
                int blockedCount = 0;
                long latestSeen = holder.maxLastSeen;
                long earliestSeen = Long.MAX_VALUE;
                ConnectionRow representative = group.get(0);

                for (ConnectionRow r : group) {
                    totalSent += r.sentBytes;
                    totalRcvd += r.rcvdBytes;
                    if (r.status < ConnectionDescriptor.CONN_STATUS_CLOSED) {
                        activeCount++;
                    }
                    if (r.isBlocked) {
                        blockedCount++;
                    }
                    earliestSeen = Math.min(earliestSeen, r.firstSeen);
                    if (r.status < ConnectionDescriptor.CONN_STATUS_CLOSED && representative.status >= ConnectionDescriptor.CONN_STATUS_CLOSED) {
                        representative = r;
                    }
                }

                ConnectionRow header = ConnectionRow.createAppGroupHeader(
                        uid,
                        group.size(),
                        activeCount,
                        isExpanded,
                        totalSent,
                        totalRcvd,
                        latestSeen,
                        earliestSeen,
                        (activeCount > 0) ? ConnectionDescriptor.CONN_STATUS_CONNECTED : ConnectionDescriptor.CONN_STATUS_CLOSED,
                        (blockedCount > 0),
                        representative
                );
                result.add(header);

                if (isExpanded) {
                    for (ConnectionRow child : group) {
                        result.add(child.asChildRow());
                    }
                }
            }
        }
        return result;
    }

    @NonNull
    public java.util.List<ConnectionRow> getConnectionRows() {
        return mDiffer.getCurrentList();
    }

    @androidx.annotation.Nullable
    public ConnectionRow getRow(int pos) {
        if (mUseDiffer) {
            java.util.List<ConnectionRow> list = mDiffer.getCurrentList();
            if (pos >= 0 && pos < list.size()) {
                return list.get(pos);
            }
        }
        return null;
    }

    public static String getPreferredAppName(@Nullable AppDescriptor systemApp,
                                            @Nullable AppDescriptor likelyApp,
                                            int uid) {
        if (uid == 1000 || uid <= 0) {
            if (systemApp != null && systemApp.getName() != null && !systemApp.getName().isEmpty()) {
                return systemApp.getName();
            }
            return "Android System";
        }
        if (likelyApp != null && likelyApp.getName() != null && !likelyApp.getName().isEmpty()) {
            return likelyApp.getName();
        }
        if (systemApp != null && systemApp.getName() != null && !systemApp.getName().isEmpty()) {
            return systemApp.getName();
        }
        return "Unknown";
    }

    public static class ViewHolder extends RecyclerView.ViewHolder {
        ImageView icon;
        ImageView jsInjectorInd;
        ImageView blacklistedInd;
        ImageView blockedInd;
        ImageView wifiBlockedInd;
        ImageView mobileBlockedInd;
        ImageView roamingBlockedInd;
        ImageView redirectedInd;
        ImageView decryptionInd;
        TextView statusInd;
        TextView remote;
        TextView l7proto;
        TextView riskBadge;
        TextView flowCountBadge;
        TextView blockedReasonTag;
        TextView traffic;
        TextView appName;
        TextView appPkg;
        TextView lastSeen;
        FlagImageView countryFlag;
        final String mProtoAndPort;
        final TextView groupCountBadge;
        final ImageView groupExpandIcon;

        ViewHolder(View itemView) {
            super(itemView);

            icon = itemView.findViewById(R.id.icon);
            remote = itemView.findViewById(R.id.remote);
            l7proto = itemView.findViewById(R.id.l7proto);
            traffic = itemView.findViewById(R.id.traffic);
            statusInd = itemView.findViewById(R.id.status_ind);
            decryptionInd = itemView.findViewById(R.id.decryption_status);
            appName = itemView.findViewById(R.id.app_name);
            appPkg = itemView.findViewById(R.id.app_pkg);
            lastSeen = itemView.findViewById(R.id.last_seen);
            jsInjectorInd = itemView.findViewById(R.id.js_injector);
            blacklistedInd = itemView.findViewById(R.id.blacklisted);
            blockedInd = itemView.findViewById(R.id.blocked);
            wifiBlockedInd = itemView.findViewById(R.id.wifi_blocked);
            mobileBlockedInd = itemView.findViewById(R.id.mobile_blocked);
            roamingBlockedInd = itemView.findViewById(R.id.roaming_blocked);
            redirectedInd = itemView.findViewById(R.id.redirected);
            countryFlag = itemView.findViewById(R.id.country_flag);
            riskBadge = itemView.findViewById(R.id.risk_badge);
            flowCountBadge = itemView.findViewById(R.id.flow_count_badge);
            blockedReasonTag = itemView.findViewById(R.id.tv_blocked_reason_tag);
            groupCountBadge = itemView.findViewById(R.id.group_count_badge);
            groupExpandIcon = itemView.findViewById(R.id.group_expand_icon);

            Context context = itemView.getContext();
            mProtoAndPort = context.getString(R.string.proto_and_port);
        }

        @SuppressWarnings("deprecation")
        public void bindConn(Context context, ConnectionDescriptor conn, AppsResolver apps, Drawable unknownIcon,
                             AppNetworkRulesManager rulesManager, boolean fwEnabled,
                             @androidx.annotation.Nullable FilterDescriptor filter) {
            AppDescriptor app = (conn.uid >= 0) ? apps.getAppByUid(conn.uid, 0) : null;
            if (app == null && conn.uid < 0) {
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
                    CaptureService service = CaptureService.getInstance();
                    if (service != null) {
                        int resolvedUid = service.getUidQ(conn.ipproto, conn.src_ip, conn.src_port, conn.dst_ip, conn.dst_port);
                        if (resolvedUid >= 0) {
                            conn.uid = resolvedUid;
                            app = apps.getAppByUid(conn.uid, 0);
                        }
                    }
                }
                if (app == null) {
                    String dst = conn.dst_ip;
                    if ((dst != null && (dst.startsWith("ff02:") || dst.startsWith("ff0") || dst.startsWith("224.") || dst.equals("255.255.255.255")))
                            || conn.ipproto == 1 || conn.ipproto == 58
                            || conn.dst_port == 53 || conn.dst_port == 5353 || conn.src_port == 53 || conn.src_port == 5353) {
                        conn.uid = 1000;
                        app = apps.getAppByUid(1000, 0);
                    }
                }
            }

            AppDescriptor likelyApp = null;
            boolean isDns = conn.isDns();
            if (isDns && conn.uid != 1000 && conn.uid > 0) {
                try {
                    ConnectionsRegister reg = CaptureService.requireConnsRegister();
                    if (reg != null) {
                        long t = conn.last_seen > 0 ? conn.last_seen : conn.first_seen;
                        List<ConnectionsRegister.CorrelatedApp> list = reg.getCorrelatedAppsForTimestamp(t, 5000);
                        if (list != null && !list.isEmpty()) {
                            likelyApp = list.get(0).app;
                        }
                    }
                } catch (Exception ignored) {}
            }
            String l7Text;

            if (isDns) {
                int dnsPort = (conn.dst_port == 53 || conn.dst_port == 5353) ? conn.dst_port : conn.src_port;
                int totalQueries = (conn.query_count > 1 ? conn.query_count : 1);
                String resolverIp = (conn.dst_port == 53 || conn.dst_port == 5353) ? conn.dst_ip : conn.src_ip;
                String owner;
                if (likelyApp != null) {
                    owner = likelyApp.getName() + " (via Android System)";
                    AppIconLoader.setIcon(icon, likelyApp, unknownIcon);
                    icon.setImageTintList(null);
                } else {
                    owner = (app != null && app.getName() != null && !app.getName().isEmpty())
                            ? app.getName()
                            : (conn.uid == 1000 ? "Android system service" : "UID " + conn.uid);
                    icon.setImageDrawable(ContextCompat.getDrawable(context, R.drawable.ic_dns));
                    icon.setImageTintList(android.content.res.ColorStateList.valueOf(
                            ContextCompat.getColor(context, R.color.badgeProtoFg)));
                }

                String queryDomain = (conn.info != null && !conn.info.isEmpty()) ? conn.info
                        : ((conn.url != null && !conn.url.isEmpty()) ? conn.url : "");
                while (queryDomain.endsWith(".")) {
                    queryDomain = queryDomain.substring(0, queryDomain.length() - 1);
                }
                if (queryDomain.isEmpty()) {
                    appName.setText("DNS lookup");
                    String sub = owner + " • Query name unavailable";
                    if (totalQueries > 1) sub += " • " + totalQueries + " queries";
                    if (appPkg != null) {
                        appPkg.setText(sub);
                        appPkg.setVisibility(View.VISIBLE);
                    }
                } else {
                    appName.setText(queryDomain);
                    String sub = owner + " • DNS lookup";
                    if (appPkg != null) {
                        appPkg.setText(sub);
                        appPkg.setVisibility(View.VISIBLE);
                    }
                }
                remote.setText("Resolver • " + resolverIp);
                l7Text = "DNS • " + dnsPort;
                updateFlowCountBadge(conn, true, totalQueries);
            } else {
                // App traffic: normal app icon and app name
                if (likelyApp != null) {
                    AppIconLoader.setIcon(icon, likelyApp, unknownIcon);
                } else {
                    AppIconLoader.setIcon(icon, app, unknownIcon);
                }
                icon.setImageTintList(null);

                // Remote host display
                String canonicalTarget = getCanonicalTarget(conn);
                if (!canonicalTarget.isEmpty() && !canonicalTarget.equals("ntp") && !canonicalTarget.equals("icmp")) {
                    remote.setText(canonicalTarget);
                } else if (conn.url != null && !conn.url.isEmpty()) {
                    remote.setText(cleanHost(conn.url));
                } else if ((conn.info != null) && (conn.info.length() > 0)) {
                    remote.setText(cleanHost(conn.info));
                } else {
                    remote.setText(conn.dst_ip != null ? conn.dst_ip : "");
                }

                if(conn.dst_port != 0) {
                    if(conn.l7proto != null && !conn.l7proto.isEmpty())
                        l7Text = String.format(mProtoAndPort, conn.l7proto, conn.dst_port);
                    else
                        l7Text = String.valueOf(conn.dst_port);
                } else {
                    l7Text = (conn.l7proto != null) ? conn.l7proto : "";
                }

                if(conn.ipver == 6) {
                    if(l7Text.isEmpty())
                        l7Text = "IPv6";
                    else
                        l7Text = l7Text + ", IPv6";
                }

                updateFlowCountBadge(conn, false, conn.aggregated_flows);

                String info_txt;
                String pkg_txt = null;
                if (conn.uid == android.os.Process.myUid()) {
                    info_txt = "KotSafe";
                    pkg_txt = "🛡️ Security Engine (Local Traffic)";
                } else if (likelyApp != null) {
                    info_txt = getPreferredAppName(app, likelyApp, conn.uid);
                    pkg_txt = "via Android System • " + (likelyApp.getPackageName() != null ? likelyApp.getPackageName() : ("UID " + likelyApp.getUid()));
                } else if (app != null && app.getName() != null && !app.getName().isEmpty()) {
                    if (conn.uid == 1000) {
                        if (conn.dst_port == 123 || conn.src_port == 123) {
                            info_txt = "Network Time Service";
                        } else if (conn.ipproto == 1 || conn.ipproto == 58) {
                            info_txt = "Network Diagnostic";
                        } else {
                            info_txt = "Android System";
                        }
                        pkg_txt = "Android OS • System Service";
                        if (conn.info != null && !conn.info.isEmpty()
                                && conn.dst_port != 123 && conn.src_port != 123
                                && conn.ipproto != 1 && conn.ipproto != 58) {
                            pkg_txt += " • " + conn.info;
                        }
                    } else {
                        info_txt = app.getName();
                        pkg_txt = (app.getPackageName() != null && !app.getPackageName().isEmpty()
                                && !app.getPackageName().equals("android")
                                && !app.getPackageName().equals("root")
                                && !app.getPackageName().equals("unknown"))
                                ? (app.getPackageName() + " • UID " + conn.uid)
                                : (conn.uid == 0 ? "Kernel Network Stack" : ("UID " + conn.uid));
                    }
                } else if (conn.uid == 1000) {
                    if (conn.dst_port == 123 || conn.src_port == 123) {
                        info_txt = "Network Time Service";
                    } else if (conn.ipproto == 1 || conn.ipproto == 58) {
                        info_txt = "Network Diagnostic";
                    } else {
                        info_txt = "Android System";
                    }
                    pkg_txt = "System OS Service • UID 1000";
                    if (conn.info != null && !conn.info.isEmpty()
                            && conn.dst_port != 123 && conn.src_port != 123
                            && conn.ipproto != 1 && conn.ipproto != 58) {
                        pkg_txt += " • " + conn.info;
                    }
                    if (conn.aggregated_flows > 1) {
                        pkg_txt += " • " + conn.aggregated_flows + " flows";
                    }
                } else if (conn.uid == 0) {
                    info_txt = "Root / Kernel";
                    pkg_txt = "Kernel Network Stack • UID 0";
                    if (conn.aggregated_flows > 1) {
                        pkg_txt += " • " + conn.aggregated_flows + " flows";
                    }
                } else if (conn.uid > 10000) {
                    info_txt = "App (UID " + conn.uid + ")";
                    pkg_txt = "Application • UID " + conn.uid;
                    if (conn.aggregated_flows > 1) {
                        pkg_txt += " • " + conn.aggregated_flows + " flows";
                    }
                } else if (conn.uid > 0) {
                    info_txt = "System Service (UID " + conn.uid + ")";
                    pkg_txt = "Android OS Daemon • UID " + conn.uid;
                    if (conn.aggregated_flows > 1) {
                        pkg_txt += " • " + conn.aggregated_flows + " flows";
                    }
                } else {
                    if (conn.dst_port == 123 || conn.src_port == 123) {
                        info_txt = "Network Time (NTP)";
                        pkg_txt = "System Clock Synchronization • Port 123";
                    } else if (conn.ipproto == 1 || conn.ipproto == 58) {
                        info_txt = "Android System (ICMP / Ping)";
                        pkg_txt = "Kernel Diagnostic Service";
                    } else if (conn.dst_port == 80 || conn.dst_port == 443 || conn.dst_port == 8080 || conn.dst_port == 8443) {
                        if (conn.info != null && !conn.info.isEmpty()) {
                            info_txt = conn.info;
                            pkg_txt = "HTTPS/Web Traffic • Port " + conn.dst_port;
                        } else {
                            info_txt = "Web Traffic";
                            pkg_txt = "Remote Web Service • Port " + conn.dst_port;
                        }
                    } else {
                        info_txt = (conn.info != null && !conn.info.isEmpty()) ? conn.info : ("Network Service (" + conn.dst_port + ")");
                        pkg_txt = "Kernel Network Service";
                    }
                    if (conn.aggregated_flows > 1 && pkg_txt != null) {
                        pkg_txt += " • " + conn.aggregated_flows + " flows";
                    }
                }

                appName.setText(info_txt);

                if (appPkg != null) {
                    if (pkg_txt != null) {
                        appPkg.setText(pkg_txt);
                        appPkg.setVisibility(View.VISIBLE);
                    } else {
                        appPkg.setVisibility(View.GONE);
                    }
                }
            }

            l7proto.setText(l7Text);

            long totalBytes = conn.sent_bytes + conn.rcvd_bytes;
            traffic.setText(Utils.formatBytes(totalBytes));
            long lastSeenTs = conn.last_seen;
            lastSeen.setText(Utils.formatEpochShort(context, lastSeenTs / 1000));

            // If this is an aggregated card, show Active if ANY socket session is still alive.
            // This prevents "Closed" appearing on a merged card that still has live sessions.
            int effectiveStatus = conn.status;
            if (conn.aggregated_flows > 1 && effectiveStatus >= ConnectionDescriptor.CONN_STATUS_CLOSED) {
                for (ConnectionDescriptor.SocketSession s : conn.getSocketSessions()) {
                    if (s.tcp_state < ConnectionDescriptor.CONN_STATUS_CLOSED) {
                        effectiveStatus = s.tcp_state;
                        break;
                    }
                }
            }
            statusInd.setText(effectiveStatus < ConnectionDescriptor.CONN_STATUS_CLOSED
                    ? context.getString(R.string.conn_status_active)
                    : conn.getStatusLabel(context));

            int color;
            int bgRes;
            if(effectiveStatus < ConnectionDescriptor.CONN_STATUS_CLOSED) {
                color = R.color.badgeActiveFg;
                bgRes = R.drawable.badge_pill_active;
            } else if((effectiveStatus == ConnectionDescriptor.CONN_STATUS_CLOSED)
                    || (effectiveStatus == ConnectionDescriptor.CONN_STATUS_RESET)) {
                color = R.color.badgeClosedFg;
                bgRes = R.drawable.badge_pill_closed;
            } else if ((effectiveStatus == ConnectionDescriptor.CONN_STATUS_ERROR)
                    || ((effectiveStatus == ConnectionDescriptor.CONN_STATUS_SOCKET_ERROR))
                    || (effectiveStatus == ConnectionDescriptor.CONN_STATUS_UNREACHABLE)) {
                color = R.color.warning;
                bgRes = R.drawable.badge_pill_blocked;
            } else {
                color = R.color.statusError;
                bgRes = R.drawable.badge_pill_blocked;
            }

            statusInd.setTextColor(ContextCompat.getColor(context, color));
            statusInd.setBackgroundResource(bgRes);

            if (countryFlag != null) {
                if (conn.country == null || conn.country.isEmpty() || conn.country.equals("ZZ")) {
                    countryFlag.setVisibility(View.GONE);
                } else {
                    countryFlag.setVisibility(View.VISIBLE);
                    countryFlag.setCountryCode(conn.country);
                }
            }

            jsInjectorInd.setVisibility(((conn.js_injected_scripts != null) && !conn.js_injected_scripts.isEmpty()) ? View.VISIBLE : View.GONE);
            blacklistedInd.setVisibility(conn.isBlacklisted() ? View.VISIBLE : View.GONE);
            blockedInd.setVisibility(conn.is_blocked ? View.VISIBLE : View.GONE);

            if (blockedReasonTag != null) {
                if (conn.is_blocked || conn.isBlacklisted()) {
                    blockedReasonTag.setVisibility(View.VISIBLE);
                    String cat = conn.getBlockCategory();
                    int tagColor;
                    String tagText;
                    switch (cat) {
                        case "MALICIOUS":
                        case "MALWARE":
                            tagText = "MALWARE";
                            tagColor = android.graphics.Color.parseColor("#EF4444");
                            break;
                        case "PHISHING":
                            tagText = "PHISH";
                            tagColor = android.graphics.Color.parseColor("#A855F7");
                            break;
                        case "ADS":
                        case "ADS_TRACKER":
                            tagText = "ADS";
                            tagColor = android.graphics.Color.parseColor("#EC4899");
                            break;
                        case "RATE_LIMIT":
                            tagText = "LIMIT";
                            tagColor = android.graphics.Color.parseColor("#F97316");
                            break;
                        case "LAN_RULE":
                            tagText = "LAN";
                            tagColor = android.graphics.Color.parseColor("#6366F1");
                            break;
                        case "FIREWALL":
                        case "FIREWALL_RULE":
                            tagText = "FIREWALL";
                            tagColor = android.graphics.Color.parseColor("#F59E0B");
                            break;
                        default:
                            tagText = "BLOCKED";
                            tagColor = android.graphics.Color.parseColor("#EF4444");
                            break;
                    }
                    blockedReasonTag.setText(tagText);
                    blockedReasonTag.setBackgroundTintList(android.content.res.ColorStateList.valueOf(tagColor));
                    final String fCat = cat;
                    blockedReasonTag.setOnClickListener(v -> {
                        com.kotsafe.security.dialogs.TagExplanationDialog.showForBlockedReason(
                                v.getContext(),
                                fCat,
                                conn,
                                itemView::performClick
                        );
                    });
                } else {
                    blockedReasonTag.setVisibility(View.GONE);
                    blockedReasonTag.setOnClickListener(null);
                }
            }

            if (fwEnabled && rulesManager != null && conn.uid > 0) {
                AppNetworkRule netRule = rulesManager.getRule(conn.uid);
                if (netRule != null) {
                    wifiBlockedInd.setVisibility(netRule.isWifiBlocked() ? View.VISIBLE : View.GONE);
                    mobileBlockedInd.setVisibility(netRule.isMobileBlocked() ? View.VISIBLE : View.GONE);
                    roamingBlockedInd.setVisibility(netRule.isRoamingBlocked() ? View.VISIBLE : View.GONE);
                } else {
                    wifiBlockedInd.setVisibility(View.GONE);
                    mobileBlockedInd.setVisibility(View.GONE);
                    roamingBlockedInd.setVisibility(View.GONE);
                }
            } else {
                wifiBlockedInd.setVisibility(View.GONE);
                mobileBlockedInd.setVisibility(View.GONE);
                roamingBlockedInd.setVisibility(View.GONE);
            }

            redirectedInd.setVisibility((conn.isPortMappingApplied() && !conn.is_blocked) ? View.VISIBLE : View.GONE);

            if(CaptureService.isDecryptingTLS() || KotSafe.getInstance().isDecryptingPcap()) {
                decryptionInd.setVisibility(View.VISIBLE);
                Utils.setDecryptionIcon(decryptionInd, conn);
            } else
                decryptionInd.setVisibility(View.GONE);
        }

        public void bindRow(@NonNull Context context,
                            @NonNull ConnectionRow row,
                            @Nullable AppsResolver apps,
                            @Nullable Drawable unknownIcon,
                            @Nullable AppNetworkRulesManager rulesManager,
                            boolean fwEnabled,
                            @Nullable FilterDescriptor filter) {
            if (row.rowType == ConnectionRow.ROW_TYPE_APP_GROUP_HEADER) {
                bindGroupHeader(context, row, apps, unknownIcon);
                return;
            }
            if (row.rowType == ConnectionRow.ROW_TYPE_APP_CHILD) {
                bindChildRow(context, row);
                return;
            }

            if (groupCountBadge != null) groupCountBadge.setVisibility(View.GONE);
            if (groupExpandIcon != null) groupExpandIcon.setVisibility(View.GONE);

            bindConn(context, row.descriptor, apps, unknownIcon, rulesManager, fwEnabled, filter);
            appName.setText(row.appName);
            if (appPkg != null) {
                if (!row.appPackage.isEmpty()) {
                    appPkg.setText(row.appPackage);
                    appPkg.setVisibility(View.VISIBLE);
                } else if (!row.isDns) {
                    appPkg.setVisibility(View.GONE);
                }
            }
            if (!row.isDns && !row.targetDisplay.isEmpty() && !row.targetDisplay.equals("ntp") && !row.targetDisplay.equals("icmp")) {
                remote.setText(row.targetDisplay);
            }
        }

        private void bindGroupHeader(Context context, ConnectionRow row, AppsResolver apps, Drawable unknownIcon) {
            AppDescriptor app = (row.uid >= 0 && apps != null) ? apps.getAppByUid(row.uid, 0) : null;
            AppIconLoader.setIcon(icon, app, unknownIcon);
            icon.setImageTintList(null);

            appName.setText(row.appName);
            if (appPkg != null) {
                appPkg.setText(row.appPackage);
                appPkg.setVisibility(View.VISIBLE);
            }

            if (groupCountBadge != null) {
                groupCountBadge.setVisibility(View.VISIBLE);
                groupCountBadge.setText(row.groupConnectionCount + " connections");
            }

            if (groupExpandIcon != null) {
                groupExpandIcon.setVisibility(View.VISIBLE);
                groupExpandIcon.setRotation(row.isExpanded ? 180f : 0f);
            }

            boolean isActive = row.status < ConnectionDescriptor.CONN_STATUS_CLOSED;
            statusInd.setVisibility(View.VISIBLE);
            statusInd.setText(isActive ? context.getString(R.string.conn_status_active) : context.getString(R.string.conn_status_closed));
            statusInd.setTextColor(ContextCompat.getColor(context, isActive ? R.color.badgeActiveFg : R.color.badgeClosedFg));
            statusInd.setBackgroundResource(isActive ? R.drawable.badge_pill_active : R.drawable.badge_pill_closed);

            l7proto.setVisibility(View.VISIBLE);
            l7proto.setText(row.protoAndPort);

            remote.setVisibility(View.VISIBLE);
            remote.setText(row.targetDisplay);

            traffic.setVisibility(View.VISIBLE);
            traffic.setText(Utils.formatBytes(row.totalBytes));

            lastSeen.setVisibility(View.VISIBLE);
            lastSeen.setText(Utils.formatEpochShort(context, row.lastSeen / 1000));

            if (flowCountBadge != null) flowCountBadge.setVisibility(View.GONE);
            if (countryFlag != null) countryFlag.setVisibility(View.GONE);
            if (decryptionInd != null) decryptionInd.setVisibility(View.GONE);
            if (jsInjectorInd != null) jsInjectorInd.setVisibility(View.GONE);
            if (redirectedInd != null) redirectedInd.setVisibility(View.GONE);
            if (blacklistedInd != null) blacklistedInd.setVisibility(row.isBlacklisted ? View.VISIBLE : View.GONE);
            if (blockedInd != null) blockedInd.setVisibility(row.isBlocked ? View.VISIBLE : View.GONE);
            if (wifiBlockedInd != null) wifiBlockedInd.setVisibility(View.GONE);
            if (mobileBlockedInd != null) mobileBlockedInd.setVisibility(View.GONE);
            if (roamingBlockedInd != null) roamingBlockedInd.setVisibility(View.GONE);
            if (blockedReasonTag != null) blockedReasonTag.setVisibility(row.isBlocked ? View.VISIBLE : View.GONE);
        }

        private void bindChildRow(Context context, ConnectionRow row) {
            icon.setImageResource(R.drawable.ic_chevron_right);
            icon.setImageTintList(ColorStateList.valueOf(Color.parseColor("#94A3B8")));

            appName.setText(row.targetDisplay);

            if (appPkg != null) {
                appPkg.setText(row.protoAndPort + " • Port " + row.dstPort);
                appPkg.setVisibility(View.VISIBLE);
            }

            if (remote != null) {
                String remoteIp = row.descriptor.dst_ip != null ? row.descriptor.dst_ip : "";
                remote.setText(remoteIp);
                remote.setVisibility(remoteIp.isEmpty() ? View.GONE : View.VISIBLE);
            }

            if (groupCountBadge != null) groupCountBadge.setVisibility(View.GONE);
            if (groupExpandIcon != null) groupExpandIcon.setVisibility(View.GONE);

            boolean isActive = row.status < ConnectionDescriptor.CONN_STATUS_CLOSED;
            statusInd.setVisibility(View.VISIBLE);
            statusInd.setText(isActive ? context.getString(R.string.conn_status_active) : row.descriptor.getStatusLabel(context));
            statusInd.setTextColor(ContextCompat.getColor(context, isActive ? R.color.badgeActiveFg : R.color.badgeClosedFg));
            statusInd.setBackgroundResource(isActive ? R.drawable.badge_pill_active : R.drawable.badge_pill_closed);

            l7proto.setVisibility(View.VISIBLE);
            l7proto.setText(row.l7proto != null && !row.l7proto.isEmpty() ? row.l7proto : (row.ipproto == 6 ? "TCP" : "UDP"));

            traffic.setVisibility(View.VISIBLE);
            traffic.setText(Utils.formatBytes(row.totalBytes));

            lastSeen.setVisibility(View.VISIBLE);
            lastSeen.setText(Utils.formatEpochShort(context, row.lastSeen / 1000));

            if (countryFlag != null) {
                if (row.country == null || row.country.isEmpty() || row.country.equals("ZZ")) {
                    countryFlag.setVisibility(View.GONE);
                } else {
                    countryFlag.setVisibility(View.VISIBLE);
                    countryFlag.setCountryCode(row.country);
                }
            }

            updateFlowCountBadge(row.descriptor, row.isDns, row.aggregatedFlows);

            blockedInd.setVisibility(row.isBlocked ? View.VISIBLE : View.GONE);
            blacklistedInd.setVisibility(row.isBlacklisted ? View.VISIBLE : View.GONE);
            if (blockedReasonTag != null) {
                blockedReasonTag.setVisibility((row.isBlocked || row.isBlacklisted) ? View.VISIBLE : View.GONE);
            }
            if (decryptionInd != null) decryptionInd.setVisibility(View.GONE);
            if (jsInjectorInd != null) jsInjectorInd.setVisibility(View.GONE);
            if (redirectedInd != null) redirectedInd.setVisibility(View.GONE);
            if (wifiBlockedInd != null) wifiBlockedInd.setVisibility(View.GONE);
            if (mobileBlockedInd != null) mobileBlockedInd.setVisibility(View.GONE);
            if (roamingBlockedInd != null) roamingBlockedInd.setVisibility(View.GONE);
        }

        public void bindPayload(@NonNull ConnectionRow row, @NonNull Object payload) {
            traffic.setText(Utils.formatBytes(row.totalBytes));
            lastSeen.setText(Utils.formatEpochShort(itemView.getContext(), row.lastSeen / 1000));

            int effectiveStatus = row.status;
            statusInd.setText(effectiveStatus < ConnectionDescriptor.CONN_STATUS_CLOSED
                    ? itemView.getContext().getString(R.string.conn_status_active)
                    : row.descriptor.getStatusLabel(itemView.getContext()));

            int color;
            int bgRes;
            if(effectiveStatus < ConnectionDescriptor.CONN_STATUS_CLOSED) {
                color = R.color.badgeActiveFg;
                bgRes = R.drawable.badge_pill_active;
            } else if((effectiveStatus == ConnectionDescriptor.CONN_STATUS_CLOSED)
                    || (effectiveStatus == ConnectionDescriptor.CONN_STATUS_RESET)) {
                color = R.color.badgeClosedFg;
                bgRes = R.drawable.badge_pill_closed;
            } else if ((effectiveStatus == ConnectionDescriptor.CONN_STATUS_ERROR)
                    || ((effectiveStatus == ConnectionDescriptor.CONN_STATUS_SOCKET_ERROR))
                    || (effectiveStatus == ConnectionDescriptor.CONN_STATUS_UNREACHABLE)) {
                color = R.color.warning;
                bgRes = R.drawable.badge_pill_blocked;
            } else {
                color = R.color.statusError;
                bgRes = R.drawable.badge_pill_blocked;
            }

            statusInd.setTextColor(ContextCompat.getColor(itemView.getContext(), color));
            statusInd.setBackgroundResource(bgRes);

            blockedInd.setVisibility(row.isBlocked ? View.VISIBLE : View.GONE);
            if (blockedReasonTag != null) {
                if (row.isBlocked || row.isBlacklisted) {
                    blockedReasonTag.setVisibility(View.VISIBLE);
                    String cat = row.descriptor.getBlockCategory();
                    int tagColor;
                    String tagText;
                    switch (cat) {
                        case "MALICIOUS":
                        case "MALWARE":
                            tagText = "MALWARE";
                            tagColor = android.graphics.Color.parseColor("#EF4444");
                            break;
                        case "PHISHING":
                            tagText = "PHISH";
                            tagColor = android.graphics.Color.parseColor("#A855F7");
                            break;
                        case "ADS":
                        case "ADS_TRACKER":
                            tagText = "ADS";
                            tagColor = android.graphics.Color.parseColor("#EC4899");
                            break;
                        case "RATE_LIMIT":
                            tagText = "LIMIT";
                            tagColor = android.graphics.Color.parseColor("#F97316");
                            break;
                        case "LAN_RULE":
                            tagText = "LAN";
                            tagColor = android.graphics.Color.parseColor("#6366F1");
                            break;
                        case "FIREWALL":
                        case "FIREWALL_RULE":
                            tagText = "FIREWALL";
                            tagColor = android.graphics.Color.parseColor("#F59E0B");
                            break;
                        default:
                            tagText = "BLOCKED";
                            tagColor = android.graphics.Color.parseColor("#EF4444");
                            break;
                    }
                    blockedReasonTag.setText(tagText);
                    blockedReasonTag.setBackgroundTintList(android.content.res.ColorStateList.valueOf(tagColor));
                    final String fCat = cat;
                    blockedReasonTag.setOnClickListener(v -> {
                        com.kotsafe.security.dialogs.TagExplanationDialog.showForBlockedReason(
                                v.getContext(),
                                fCat,
                                row.descriptor,
                                itemView::performClick
                        );
                    });
                } else {
                    blockedReasonTag.setVisibility(View.GONE);
                    blockedReasonTag.setOnClickListener(null);
                }
            }

            updateFlowCountBadge(row.descriptor, row.isDns, row.isDns ? row.queryCount : row.aggregatedFlows);

            if (row.rowType == ConnectionRow.ROW_TYPE_APP_GROUP_HEADER) {
                if (groupExpandIcon != null) {
                    groupExpandIcon.setVisibility(View.VISIBLE);
                    groupExpandIcon.setRotation(row.isExpanded ? 180f : 0f);
                }
                if (groupCountBadge != null) {
                    groupCountBadge.setVisibility(View.VISIBLE);
                    groupCountBadge.setText(row.groupConnectionCount + " connections");
                }
                remote.setText(row.targetDisplay);
                l7proto.setText(row.protoAndPort);
            }
        }

        void bindRiskBadge(ConnectionTrustEvaluator evaluator, ConnectionDescriptor conn) {
            if (riskBadge == null) return;
            ConnectionTrustEvaluator.RiskLevel level = evaluator.evaluate(conn);
            if (level.isBadgeVisible()) {
                riskBadge.setVisibility(View.VISIBLE);
                riskBadge.setText(level.label());
                switch (level) {
                    case MALICIOUS:
                        riskBadge.setBackgroundTintList(
                                android.content.res.ColorStateList.valueOf(0xFFEF4444));
                        break;
                    case HIGH_RISK:
                        riskBadge.setBackgroundTintList(
                                android.content.res.ColorStateList.valueOf(0xFFD97706));
                        break;
                    default: // SUSPICIOUS
                        riskBadge.setBackgroundTintList(
                                android.content.res.ColorStateList.valueOf(0xFF7C3AED));
                        break;
                }
                riskBadge.setOnClickListener(v -> {
                    com.kotsafe.security.dialogs.TagExplanationDialog.showForRiskBadge(
                            v.getContext(),
                            level.label(),
                            conn,
                            itemView::performClick
                    );
                });
            } else {
                riskBadge.setVisibility(View.GONE);
                riskBadge.setOnClickListener(null);
            }
        }

        void updateFlowCountBadge(ConnectionDescriptor conn, boolean isDns, int totalCount) {
            if (flowCountBadge == null) return;
            if (totalCount > 1) {
                boolean isBlocked = conn.is_blocked || conn.isBlacklisted();
                if (isBlocked) {
                    flowCountBadge.setText("🔁 " + totalCount + " blocked");
                    flowCountBadge.setTextColor(Color.parseColor("#F85149"));
                    flowCountBadge.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor("#3B1219")));
                } else if (isDns) {
                    flowCountBadge.setText("🔁 " + totalCount + " queries");
                    flowCountBadge.setTextColor(Color.parseColor("#38BDF8"));
                    flowCountBadge.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor("#1E293B")));
                } else {
                    flowCountBadge.setText("🔁 " + totalCount + " flows");
                    flowCountBadge.setTextColor(Color.parseColor("#38BDF8"));
                    flowCountBadge.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor("#1E293B")));
                }
                flowCountBadge.setVisibility(View.VISIBLE);
                flowCountBadge.setOnClickListener(v -> {
                    com.kotsafe.security.dialogs.TagExplanationDialog.showForFlowBadge(
                            v.getContext(),
                            conn,
                            isDns,
                            totalCount,
                            itemView::performClick
                    );
                });
            } else {
                flowCountBadge.setVisibility(View.GONE);
                flowCountBadge.setOnClickListener(null);
            }
        }
    }

    public ConnectionsAdapter(Context context, AppsResolver resolver) {
        mContext = context;
        mAppsResolver = resolver;
        mLayoutInflater = (LayoutInflater) context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
        mUnknownIcon = ContextCompat.getDrawable(context, R.drawable.ic_apps);
        mListener = null;
        mFilteredConn = null;
        mUnfilteredItemsCount = 0;
        mIdToFilteredPos = new SparseIntArray();
        mMask = KotSafe.getInstance().getVisualizationMask();
        mSearch = null;
        TypedArray a = context.obtainStyledAttributes(new int[]{android.R.attr.colorControlHighlight});
        mSelectedColor = a.getColor(0, 0x40808080);
        a.recycle();
        TypedValue tv = new TypedValue();
        context.getTheme().resolveAttribute(android.R.attr.selectableItemBackground, tv, true);
        mSelectableBackground = tv.resourceId;
        setHasStableIds(true);

        mRulesManager = AppNetworkRulesManager.getInstance(context);
        mFwEnabled = Prefs.isFirewallEnabled(context, PreferenceManager.getDefaultSharedPreferences(context));
        mGroupByApp = Prefs.isGroupByApp(PreferenceManager.getDefaultSharedPreferences(context));
        mRulesManager.addListener(() -> {
            mFwEnabled = Prefs.isFirewallEnabled(mContext, PreferenceManager.getDefaultSharedPreferences(mContext));
            new android.os.Handler(android.os.Looper.getMainLooper()).post(this::notifyDataSetChanged);
        });
    }

    @Override
    public int getItemCount() {
        if (mUseDiffer) {
            return mDiffer.getCurrentList().size();
        }
        return((mFilteredConn != null) ? mFilteredConn.size() : mUnfilteredItemsCount);
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = mLayoutInflater.inflate(R.layout.connection_item, parent, false);

        // Enable the ability to show the context menu
        view.setLongClickable(true);

        view.setOnClickListener(v -> {
            if(mListener != null)
                mListener.onClick(v);
        });

        ViewHolder holder = new ViewHolder(view);

        view.setOnLongClickListener(v -> {
            if((mSelectionLongClickListener != null) && mSelectionLongClickListener.onLongClick(v))
                return true;

            // see registerForContextMenu
            mSelectedItem = getItem(holder.getAbsoluteAdapterPosition());
            return false;
        });

        return holder;
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position, @NonNull java.util.List<Object> payloads) {
        if (!payloads.isEmpty()) {
            if (mUseDiffer) {
                ConnectionRow row = getRow(position);
                if (row != null) {
                    holder.bindPayload(row, payloads.get(0));
                    return;
                }
            }
        }
        onBindViewHolder(holder, position);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        long startBind = ConnectionsTimingTrace.startTrace();
        if (mUseDiffer) {
            ConnectionRow row = getRow(position);
            if (row == null) {
                Log.w(TAG, "bad position: " + position);
                return;
            }

            holder.bindRow(mContext, row, mAppsResolver, mUnknownIcon, mRulesManager, mFwEnabled, mFilter);
            holder.bindRiskBadge(mTrustEvaluator, row.descriptor);

            if (mSelectedItems.contains(row.incrId))
                holder.itemView.setBackgroundColor(mSelectedColor);
            else
                holder.itemView.setBackgroundResource(R.drawable.connection_card_bg);

            ConnectionsTimingTrace.logRowBinding(startBind, position);
            return;
        }

        ConnectionDescriptor conn = getItem(position);
        if(conn == null) {
            Log.w(TAG, "bad position: " + position);
            return;
        }

        holder.bindConn(mContext, conn, mAppsResolver, mUnknownIcon, mRulesManager, mFwEnabled, mFilter);
        holder.bindRiskBadge(mTrustEvaluator, conn);

        if(mSelectedItems.contains(conn.incr_id))
            holder.itemView.setBackgroundColor(mSelectedColor);
        else
            holder.itemView.setBackgroundResource(R.drawable.connection_card_bg);

        ConnectionsTimingTrace.logRowBinding(startBind, position);
    }

    @Override
    public long getItemId(int pos) {
        if (mUseDiffer) {
            ConnectionRow row = getRow(pos);
            return row != null ? row.rowId : RecyclerView.NO_ID;
        }
        ConnectionDescriptor conn = getItem(pos);

        return ((conn != null) ? conn.incr_id : -1);
    }

    private boolean matches(ConnectionDescriptor conn) {
        return((conn != null)
                && mFilter.matches(conn)
                && ((mSearch == null) || conn.matches(mAppsResolver, mSearch)));
    }

    public enum SortMode {
        RECENT,      // Most Recent (Newest first) - DEFAULT
        ACTIVE,      // Active connections first
        BYTES,       // Highest data usage first
        NAME         // App name (A to Z)
    }

    private SortMode mSortMode = SortMode.RECENT;

    public void setSortMode(SortMode mode) {
        setSortMode(mode, true);
    }

    public void setSortMode(SortMode mode, boolean refreshLegacyList) {
        if (mSortMode != mode) {
            mSortMode = mode;
            if (refreshLegacyList && !mUseDiffer) {
                refreshFilteredConnections();
            }
        }
    }

    public SortMode getSortMode() {
        return mSortMode;
    }

    // Given an incrId, return the position of the connection into the mFilteredConn array
    private int getFilteredItemPos(int incrId) {
        int pos = mIdToFilteredPos.get(incrId, -1);
        if(pos == -1) {
            Integer canonicalId = mAliasToCanonicalId.get(incrId);
            if (canonicalId != null) {
                pos = mIdToFilteredPos.get(canonicalId, -1);
            }
        }
        if(pos == -1)
            return -1;
        return pos;
    }

    private void removeFilteredItemAt(int pos) {
        // get the previous item which was now removed
        ConnectionDescriptor item = getItem(pos);
        if(item == null)
            return;

        String key = getAggregationKey(item);
        if (key != null) {
            mAggregatedFlows.remove(key);
        }

        mFilteredConn.remove(pos);
        mIdToFilteredPos.delete(item.incr_id);
        notifyItemRemoved(pos);
    }

    /* Fixes the mappings in mIdToFilteredPos, starting from the provided position */
    private void fixFilteredPositions(int startPos) {
        for(int i=startPos; i<mFilteredConn.size(); i++)
            mIdToFilteredPos.put(mFilteredConn.get(i).incr_id, i);
    }

    @Override
    public void connectionsChanges(int num_connetions) {
        mUnfilteredItemsCount = num_connetions;
        refreshFilteredConnections();
    }

    @Override
    public void connectionsAdded(int start, ConnectionDescriptor []conns) {
        mUnfilteredItemsCount += conns.length;

        if(mFilteredConn == null) {
            notifyItemRangeInserted(start, conns.length);
            return;
        }

        if (Prefs.isSingleSocketDiagnostics(mContext)) {
            // Raw 1-to-1 mode for socket-level diagnostics
            int numNew = 0;
            int pos = mFilteredConn.size();

            for(ConnectionDescriptor conn : conns) {
                if(matches(conn)) {
                    mIdToFilteredPos.put(conn.incr_id, pos++);
                    mFilteredConn.add(conn);
                    numNew++;
                }
            }

            if(numNew > 0)
                notifyItemRangeInserted(mFilteredConn.size() - numNew, numNew);
            return;
        }

        // Smart aggregation mode: deduplicate incoming connections
        int initialSize = mFilteredConn.size();
        int numNew = 0;
        for(ConnectionDescriptor conn : conns) {
            if(!matches(conn)) continue;

            String key = getAggregationKey(conn);
            ConnectionDescriptor existing = (key != null) ? mAggregatedFlows.get(key) : null;
            if(existing != null) {
                mergeConnectionInto(existing, conn);
                int pos = getFilteredItemPos(existing.incr_id);
                if(pos != -1) {
                    mIdToFilteredPos.put(conn.incr_id, pos);
                    mAliasToCanonicalId.put(conn.incr_id, existing.incr_id);
                    notifyItemChanged(pos);
                }
            } else {
                ConnectionDescriptor displayConn = new ConnectionDescriptor(conn);
                if (conn.isDns() && displayConn.info != null) {
                    while (displayConn.info.endsWith(".")) {
                        displayConn.info = displayConn.info.substring(0, displayConn.info.length() - 1);
                    }
                }
                if(key != null) {
                    mAggregatedFlows.put(key, displayConn);
                }
                int pos = mFilteredConn.size();
                mIdToFilteredPos.put(conn.incr_id, pos);
                mFilteredConn.add(displayConn);
                numNew++;
            }
        }
        if(numNew > 0) {
            notifyItemRangeInserted(initialSize, numNew);
        }
    }

    @Override
    public void connectionsRemoved(int start, ConnectionDescriptor []conns) {
        mUnfilteredItemsCount -= conns.length;

        if(mFilteredConn == null) {
            notifyItemRangeRemoved(start, conns.length);
            return;
        }

        // Here dealing with filtered connections
        for(ConnectionDescriptor conn: conns) {
            if(conn == null)
                continue;

            mSelectedItems.remove(conn.incr_id);
        }

        // A rollover can evict either a canonical socket or an alias in a merged
        // display row. Rebuild once from surviving raw connections to preserve the
        // correct byte totals, socket sessions, and canonical IDs.
        if (!mAliasToCanonicalId.isEmpty()) {
            refreshFilteredConnections();
            return;
        }

        for(ConnectionDescriptor conn: conns) {
            if(conn == null) continue;
            int pos = getFilteredItemPos(conn.incr_id);
            if(pos != -1) {
                removeFilteredItemAt(pos);
                fixFilteredPositions(pos);
            }
        }
    }

    @Override
    public void connectionsUpdated(int[] positions) {
        if(mFilteredConn == null) {
            for(int pos : positions)
                notifyItemChanged(pos);
            return;
        }

        // Here dealing with filtered connections
        ConnectionsRegister reg = CaptureService.requireConnsRegister();
        int first_removed_pos = -1;
        int num_just_removed = 0;

        // Sort order necessary to properly use num_just_removed
        Arrays.sort(positions);

        for(int reg_pos : positions) {
            ConnectionDescriptor conn = reg.getConn(reg_pos);
            if(conn != null) {
                int pos = getFilteredItemPos(conn.incr_id);
                if(pos != -1) {
                    pos -= num_just_removed;

                    if(matches(conn)) {
                        ConnectionDescriptor displayed = (pos >= 0 && pos < mFilteredConn.size()) ? mFilteredConn.get(pos) : null;
                        if(displayed != null && displayed != conn) {
                            displayed.last_seen = Math.max(displayed.last_seen, conn.last_seen);
                            displayed.sent_bytes = Math.max(displayed.sent_bytes, conn.sent_bytes);
                            displayed.rcvd_bytes = Math.max(displayed.rcvd_bytes, conn.rcvd_bytes);
                            displayed.sent_pkts = Math.max(displayed.sent_pkts, conn.sent_pkts);
                            displayed.rcvd_pkts = Math.max(displayed.rcvd_pkts, conn.rcvd_pkts);
                            if (hasLetters(conn.url) && !hasLetters(displayed.url)) {
                                displayed.url = conn.url;
                            }
                            if (hasLetters(conn.info) && !hasLetters(displayed.info)) {
                                displayed.info = conn.info;
                            }
                            if ((displayed.info == null || displayed.info.isEmpty()) && (conn.info != null && !conn.info.isEmpty())) {
                                displayed.info = conn.info;
                            }
                            if ((displayed.url == null || displayed.url.isEmpty()) && (conn.url != null && !conn.url.isEmpty())) {
                                displayed.url = conn.url;
                            }
                            if (conn.is_blocked) {
                                displayed.is_blocked = true;
                                if (conn.block_reason != null && !conn.block_reason.isEmpty()) {
                                    displayed.block_reason = conn.block_reason;
                                }
                                if (conn.block_type != null && !conn.block_type.isEmpty()) {
                                    displayed.block_type = conn.block_type;
                                }
                            }
                            if (conn.status < ConnectionDescriptor.CONN_STATUS_CLOSED) {
                                displayed.status = conn.status;
                            }
                            displayed.recordSocketSession(conn.ipproto, conn.src_port, conn.dst_port,
                                    conn.sent_bytes, conn.rcvd_bytes, conn.status, conn.l7proto, conn.last_seen, conn.is_blocked, conn.block_reason);
                        }
                        notifyItemChanged(pos);
                    } else {
                        Log.d(TAG, "Unmatch item " + pos + ": " + conn.toString());

                        removeFilteredItemAt(pos);
                        num_just_removed++;

                        if(first_removed_pos == -1)
                            first_removed_pos = pos;
                    }
                }
            }
        }

        // Need to recalculate the mappings starting at the first removed item
        if(first_removed_pos != -1)
            fixFilteredPositions(first_removed_pos);
    }

    private static final Map<String, String> sIpToDomainCache = new ConcurrentHashMap<>();

    public static void recordIpDomain(String ip, String domain) {
        if (ip == null || ip.isEmpty() || domain == null || domain.isEmpty()) return;
        if (ip.equals("127.0.0.1") || ip.equals("::1") || ip.startsWith("255.") || ip.startsWith("ff02:")) return;
        if (hasLetters(domain)) {
            while (domain.endsWith(".")) {
                domain = domain.substring(0, domain.length() - 1);
            }
            sIpToDomainCache.put(ip.trim(), domain.toLowerCase(Locale.ROOT));
        }
    }

    public static String getDomainForIp(String ip) {
        if (ip == null || ip.isEmpty()) return "";
        String domain = sIpToDomainCache.get(ip.trim());
        return (domain != null) ? domain : "";
    }

    public static String getCanonicalTarget(ConnectionDescriptor conn) {
        if (conn == null) return "";
        if (conn.dst_port == 123 || conn.src_port == 123) return "ntp";
        if (conn.ipproto == 1 || conn.ipproto == 58) return "icmp";

        String urlHost = cleanHost(conn.url);
        String infoHost = cleanHost(conn.info);

        String target;
        if (hasLetters(urlHost)) {
            target = urlHost;
        } else if (hasLetters(infoHost)) {
            target = infoHost;
        } else if (!urlHost.isEmpty()) {
            target = urlHost;
        } else if (!infoHost.isEmpty()) {
            target = infoHost;
        } else {
            String ip = (conn.dst_ip != null) ? conn.dst_ip.trim() : "";
            String cachedDomain = !ip.isEmpty() ? sIpToDomainCache.get(ip) : null;
            if (cachedDomain != null && !cachedDomain.isEmpty()) {
                target = cachedDomain;
                if (conn.info == null || conn.info.isEmpty()) {
                    conn.info = cachedDomain;
                }
            } else {
                target = ip;
            }
        }

        while (target.endsWith(".")) {
            target = target.substring(0, target.length() - 1);
        }
        target = target.toLowerCase(Locale.ROOT);

        // Learn IP-to-domain mapping if target is a domain name
        if (conn.dst_ip != null && !conn.dst_ip.isEmpty() && hasLetters(target)) {
            recordIpDomain(conn.dst_ip, target);
        }

        return target;
    }

    public static String cleanHost(String raw) {
        if (raw == null || raw.isEmpty()) return "";
        String s = raw.trim();
        if (s.contains("://")) {
            int schemeEnd = s.indexOf("://") + 3;
            int pathStart = s.indexOf('/', schemeEnd);
            if (pathStart != -1) {
                s = s.substring(schemeEnd, pathStart);
            } else {
                s = s.substring(schemeEnd);
            }
            int colon = s.indexOf(':');
            if (colon != -1) {
                s = s.substring(0, colon);
            }
        }
        while (s.endsWith(".")) {
            s = s.substring(0, s.length() - 1);
        }
        return s;
    }

    public static boolean hasLetters(String s) {
        if (s == null || s.isEmpty()) return false;
        for (int i = 0; i < s.length(); i++) {
            if (Character.isLetter(s.charAt(i))) return true;
        }
        return false;
    }

    private String getAggregationKey(ConnectionDescriptor conn) {
        if (Prefs.isSingleSocketDiagnostics(mContext)) {
            return null;
        }

        int uid = conn.uid;
        if (uid < 0) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && !conn.uid_checked) {
                CaptureService service = CaptureService.getInstance();
                if (service != null) {
                    int resolvedUid = service.getUidQ(conn.ipproto, conn.src_ip, conn.src_port, conn.dst_ip, conn.dst_port);
                    if (resolvedUid >= 0) {
                        conn.uid = resolvedUid;
                        uid = resolvedUid;
                    }
                }
                conn.uid_checked = true;
            }
            if (uid < 0) {
                String dst = conn.dst_ip;
                if ((dst != null && (dst.startsWith("ff02:") || dst.startsWith("ff0") || dst.startsWith("224.") || dst.equals("255.255.255.255")))
                        || conn.ipproto == 1 || conn.ipproto == 58
                        || conn.dst_port == 53 || conn.dst_port == 5353 || conn.src_port == 53 || conn.src_port == 5353) {
                    conn.uid = 1000;
                    uid = 1000;
                }
            }
        }

        if (conn.isDns()) {
            String resolver = (conn.dst_port == 53 || conn.dst_port == 5353) ? conn.dst_ip : conn.src_ip;
            String domain = (conn.info != null && !conn.info.isEmpty()) ? conn.info : ((conn.url != null) ? conn.url : "");
            while (domain.endsWith(".")) {
                domain = domain.substring(0, domain.length() - 1);
            }
            domain = domain.toLowerCase(Locale.ROOT);
            return "DNS:" + uid + ":" + resolver + ":" + domain;
        }

        String target = getCanonicalTarget(conn);
        int dstPort = (conn.dst_port == 123 || conn.src_port == 123) ? 123
                : ((conn.ipproto == 1 || conn.ipproto == 58) ? 0 : conn.dst_port);

        if (conn.is_blocked || conn.isBlacklisted()) {
            return "BLOCKED:" + uid + ":" + conn.ipproto + ":" + target + ":" + dstPort;
        }

        // Unified Flow aggregation: ALL tabs (Active, Closed, All, User, System, Web) use the same
        // canonical key so that duplicate connections to the same service are always merged,
        // regardless of whether individual sessions are active or closed.
        return "FLOW:" + uid + ":" + conn.ipproto + ":" + target + ":" + dstPort;
    }

    private void mergeConnectionInto(ConnectionDescriptor existing, ConnectionDescriptor conn) {
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
        mAliasToCanonicalId.put(conn.incr_id, existing.incr_id);
    }

    @SuppressLint("NotifyDataSetChanged")
    public void refreshFilteredConnections() {
        final ConnectionsRegister reg = CaptureService.getConnsRegister();
        if(reg == null)
            return;

        Log.d(TAG, "refreshFilteredConn (" + mUnfilteredItemsCount + ") unfiltered");
        mFwEnabled = Prefs.isFirewallEnabled(mContext, PreferenceManager.getDefaultSharedPreferences(mContext));
        mIdToFilteredPos.clear();

        if(hasFilter() || mSortMode != SortMode.RECENT) {
            mFilteredConn = new ArrayList<>();
            mAggregatedFlows.clear();
            mAliasToCanonicalId.clear();

            // Synchronize to improve performance of getConn
            synchronized(reg) {
                for(int i = 0; i < mUnfilteredItemsCount; i++) {
                    ConnectionDescriptor conn = reg.getConn(i);
                    if(conn == null) continue;

                    if(matches(conn)) {
                        String key = getAggregationKey(conn);
                        if (key != null) {
                            ConnectionDescriptor existing = mAggregatedFlows.get(key);
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
                                mAggregatedFlows.put(key, displayConn);
                                mFilteredConn.add(displayConn);
                                continue;
                            }
                        }

                        mFilteredConn.add(conn);
                    }
                }
            }

            if (mSortMode != SortMode.RECENT) {
                if (mSortMode == SortMode.ACTIVE) {
                    mFilteredConn.sort((ca, cb) -> {
                        boolean aActive = ca.status < ConnectionDescriptor.CONN_STATUS_CLOSED;
                        boolean bActive = cb.status < ConnectionDescriptor.CONN_STATUS_CLOSED;
                        if (aActive != bActive) return aActive ? -1 : 1;
                        return Long.compare(cb.last_seen, ca.last_seen);
                    });
                } else if (mSortMode == SortMode.BYTES) {
                    mFilteredConn.sort((ca, cb) ->
                            Long.compare(cb.sent_bytes + cb.rcvd_bytes, ca.sent_bytes + ca.rcvd_bytes));
                } else if (mSortMode == SortMode.NAME) {
                    mFilteredConn.sort((ca, cb) -> {
                        AppDescriptor appA = (mAppsResolver != null) ? mAppsResolver.getAppByUid(ca.uid, 0) : null;
                        AppDescriptor appB = (mAppsResolver != null) ? mAppsResolver.getAppByUid(cb.uid, 0) : null;
                        String nameA = (appA != null && appA.getName() != null) ? appA.getName() : "";
                        String nameB = (appB != null && appB.getName() != null) ? appB.getName() : "";
                        return nameA.compareToIgnoreCase(nameB);
                    });
                }
            }

            for (int i = 0; i < mFilteredConn.size(); i++) {
                mIdToFilteredPos.put(mFilteredConn.get(i).incr_id, i);
            }
            for (Map.Entry<Integer, Integer> entry : mAliasToCanonicalId.entrySet()) {
                int canonicalId = entry.getValue();
                int pos = mIdToFilteredPos.get(canonicalId, -1);
                if (pos != -1) {
                    mIdToFilteredPos.put(entry.getKey(), pos);
                }
            }

            Log.d(TAG, "refreshFilteredConn: " + mFilteredConn.size() + " connections matched");
        } else {
            mFilteredConn = null;
            mAggregatedFlows.clear();
            mAliasToCanonicalId.clear();
        }

        notifyDataSetChanged();
    }

    public ConnectionDescriptor getItem(int pos) {
        if (mUseDiffer) {
            ConnectionRow row = getRow(pos);
            return (row != null) ? row.descriptor : null;
        }
        if(mFilteredConn != null) {
            if((pos < 0) || (pos >= mFilteredConn.size())) {
                Log.w(TAG, "getItem(filtered): bad position: " + pos);
                return null;
            }
            return mFilteredConn.get(pos);
        }

        ConnectionsRegister reg = CaptureService.getConnsRegister();
        if((pos < 0) || (pos >= mUnfilteredItemsCount) || (reg == null)) {
            Log.w(TAG, "getItem: bad position: " + pos);
            return null;
        }

        return reg.getConn(pos);
    }

    public void setSearch(String text) {
        setSearch(text, true);
    }

    public void setSearch(String text, boolean refreshLegacyList) {
        mSearch = text;
        if (refreshLegacyList && !mUseDiffer) {
            refreshFilteredConnections();
        }
    }

    public void setClickListener(View.OnClickListener listener) {
        mListener = listener;
    }

    public ConnectionDescriptor getSelectedItem() {
        return mSelectedItem;
    }

    public boolean hasFilter() {
        return (mSearch != null) || mFilter.isSet()
                || ((FilterDescriptor.isHideSystemTrafficEnabled() || FilterDescriptor.isAutoMoveClosedEnabled())
                && mFilter.appCategory == FilterDescriptor.AppCategory.ALL)
                || (KotSafe.getInstance() != null && !Prefs.isSingleSocketDiagnostics(mContext));
    }

    public String dumpConnectionsCsv(boolean selectedOnly) {
        StringBuilder builder = new StringBuilder();
        AppsResolver resolver = new AppsResolver(mContext);
        boolean malwareDetection = CaptureService.isMalwareDetectionEnabled();

        String header = mContext.getString(R.string.connections_csv_fields);
        builder.append(header);
        if(malwareDetection)
            builder.append(",Malicious");
        builder.append("\n");

        for(int i = 0; i < getItemCount(); i++) {
            ConnectionDescriptor conn = getItem(i);

            if((conn != null) && (!selectedOnly || mSelectedItems.contains(conn.incr_id))) {
                AppDescriptor app = resolver.getAppByUid(conn.uid, 0);

                builder.append(conn.ipproto);                               builder.append(",");
                builder.append(conn.src_ip);                                builder.append(",");
                builder.append(conn.src_port);                              builder.append(",");
                builder.append(conn.dst_ip);                                builder.append(",");
                builder.append(conn.dst_port);                              builder.append(",");
                builder.append(conn.uid);                                   builder.append(",");
                builder.append((app != null) ? app.getName() : "");         builder.append(",");
                builder.append((app != null) ? app.getPackageName() : "");  builder.append(",");
                builder.append(conn.l7proto);                               builder.append(",");
                builder.append(conn.getStatusLabel(mContext));              builder.append(",");
                builder.append((conn.info != null) ? conn.info : "");       builder.append(",");
                builder.append(conn.sent_bytes);                            builder.append(",");
                builder.append(conn.rcvd_bytes);                            builder.append(",");
                builder.append(conn.sent_pkts);                             builder.append(",");
                builder.append(conn.rcvd_pkts);                             builder.append(",");
                builder.append(Utils.formatMillisIso8601(mContext, conn.first_seen));                            builder.append(",");
                builder.append(Utils.formatMillisIso8601(mContext, conn.last_seen));

                if(malwareDetection) {
                    builder.append(",");

                    if(conn.isBlacklisted())
                        builder.append("yes");
                }

                builder.append("\n");
            }
        }

        return builder.toString();
    }

    public void toggleSelection(int position) {
        ConnectionDescriptor conn = getItem(position);
        if(conn == null)
            return;

        if(!mSelectedItems.remove(conn.incr_id))
            mSelectedItems.add(conn.incr_id);
        notifyItemChanged(position);
    }

    public void selectItem(int position) {
        ConnectionDescriptor conn = getItem(position);
        if(conn == null)
            return;

        mSelectedItems.add(conn.incr_id);
        notifyItemChanged(position);
    }

    @SuppressLint("NotifyDataSetChanged")
    public void clearSelection() {
        mSelectedItems.clear();
        notifyDataSetChanged();
    }

    public int getSelectedCount() {
        return mSelectedItems.size();
    }

    @SuppressLint("NotifyDataSetChanged")
    public void selectAll() {
        for(int i = 0; i < getItemCount(); i++) {
            ConnectionDescriptor conn = getItem(i);
            if(conn != null)
                mSelectedItems.add(conn.incr_id);
        }
        notifyDataSetChanged();
    }

    public void setSelectionLongClickListener(View.OnLongClickListener listener) {
        mSelectionLongClickListener = listener;
    }

    public ArrayList<Integer> getFilteredConnectionIds() {
        if (mUseDiffer) {
            List<ConnectionRow> list = mDiffer.getCurrentList();
            ArrayList<Integer> ids = new ArrayList<>(list.size());
            for (ConnectionRow r : list) {
                if (r != null && r.incrId > 0) {
                    ids.add(r.incrId);
                }
            }
            return ids;
        }
        if (mFilteredConn == null)
            return null;

        ArrayList<Integer> ids = new ArrayList<>(mFilteredConn.size());
        for (ConnectionDescriptor conn : mFilteredConn) {
            ids.add(conn.incr_id);
        }
        return ids;
    }
}
