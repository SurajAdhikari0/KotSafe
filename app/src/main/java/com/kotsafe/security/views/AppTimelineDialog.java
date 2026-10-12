/*
 * This file is part of KotSafe / KotSafe Cyber Security Project.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.views;

import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.GridLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;

import com.google.android.material.bottomsheet.BottomSheetDialogFragment;
import com.kotsafe.security.AppsResolver;
import com.kotsafe.security.CaptureService;
import com.kotsafe.security.ConnectionsRegister;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.AppDescriptor;
import com.kotsafe.security.model.ConnectionDescriptor;
import com.kotsafe.security.model.PermissionTimelineMonitor;
import com.kotsafe.security.model.UnifiedIncidentTimeline;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Microsoft Defender style "activity timeline" for one app.
 *
 * Every remote endpoint the app talked to becomes a node of the tree (like a process node in the
 * Defender alert story), with the service/API that was used, the moment it connected, how much data
 * moved, when it closed and the reasons it was flagged (threat intel, odd port, cleartext, exfil).
 */
public class AppTimelineDialog extends BottomSheetDialogFragment {

    private static final String ARG_UID = "uid";
    private static final String ARG_FOCUS_CONN = "focus_conn_id";
    private static final int MAX_GROUPS = 80;
    private static final long REFRESH_MS = 3000;

    private static final int SEV_OK = 0, SEV_SUSPICIOUS = 1, SEV_THREAT = 2;

    private int mUid;
    private int mFocusConnId = -1;
    private String mPackageName;
    private volatile List<UnifiedIncidentTimeline.IncidentEvent> mPermissionEvents = Collections.emptyList();
    private boolean mPermissionHistoryRequested;
    private String mTimelineFilter = "ALL";
    private final Map<String, TextView> mTimelineFilterChips = new LinkedHashMap<>();

    private LinearLayout mTimeline;
    private TextView mSummary;
    private TextView mServices;
    private TextView mVerdict;
    private ScrollView mScroll;
    private boolean mFullScreen;
    private final Handler mHandler = new Handler(Looper.getMainLooper());
    private final SimpleDateFormat mTime = new SimpleDateFormat("HH:mm:ss", Locale.getDefault());
    private boolean mFirstBuild = true;

    private final Runnable mRefresh = new Runnable() {
        @Override
        public void run() {
            if (!isAdded()) return;
            build();
            mHandler.postDelayed(this, REFRESH_MS);
        }
    };

    public static AppTimelineDialog newInstance(int uid, int focusConnId) {
        AppTimelineDialog d = new AppTimelineDialog();
        Bundle b = new Bundle();
        b.putInt(ARG_UID, uid);
        b.putInt(ARG_FOCUS_CONN, focusConnId);
        d.setArguments(b);
        return d;
    }

    // ---- model ------------------------------------------------------------------------------

    private static class Ev {
        long t;
        String title;
        String detail;
        int color;
    }

    private static class Group {
        String key;
        String title;
        long first = Long.MAX_VALUE;
        long last;
        boolean active;
        boolean focus;
        boolean permissionHistory;
        int severity = SEV_OK;
        int flows;
        long sent, rcvd;
        final Set<String> services = new LinkedHashSet<>();
        final Set<String> reasons = new LinkedHashSet<>();
        final List<Ev> events = new ArrayList<>();
    }

    // ---- UI ---------------------------------------------------------------------------------

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        Bundle a = getArguments();
        mUid = (a != null) ? a.getInt(ARG_UID, -1) : -1;
        mFocusConnId = (a != null) ? a.getInt(ARG_FOCUS_CONN, -1) : -1;

        LinearLayout root = new LinearLayout(requireContext());
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundResource(R.drawable.profile_dialog_bg);
        root.setPadding(0, 0, 0, dp(12));

        // handle bar
        View handle = new View(requireContext());
        LinearLayout.LayoutParams hp = new LinearLayout.LayoutParams(dp(40), dp(4));
        hp.gravity = Gravity.CENTER_HORIZONTAL;
        hp.topMargin = dp(10);
        hp.bottomMargin = dp(8);
        handle.setLayoutParams(hp);
        handle.setBackgroundColor(withAlpha(timelineTextPrimary(), 0x44));
        root.addView(handle);

        // header
        LinearLayout header = new LinearLayout(requireContext());
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);
        header.setPadding(dp(20), dp(4), dp(20), dp(8));

        ImageView icon = new ImageView(requireContext());
        icon.setLayoutParams(new LinearLayout.LayoutParams(dp(40), dp(40)));
        icon.setBackground(round(withAlpha(ContextCompat.getColor(requireContext(), R.color.colorAccent), 0x20),
                withAlpha(ContextCompat.getColor(requireContext(), R.color.colorAccent), 0x6A), 12));
        icon.setPadding(dp(8), dp(8), dp(8), dp(8));
        icon.setImageResource(R.drawable.ic_apps);
        header.addView(icon);

        LinearLayout names = new LinearLayout(requireContext());
        names.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams np = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        np.leftMargin = dp(12);
        names.setLayoutParams(np);

        TextView title = text("Activity Timeline", 18, true, timelineTextPrimary());
        TextView appName = text("", 13, false, timelineTextSecondary());
        names.addView(title);
        names.addView(appName);
        header.addView(names);

        TextView incidentBadge = text("INCIDENT CENTER", 9, true, ContextCompat.getColor(requireContext(), R.color.colorAccent));
        incidentBadge.setBackground(round(withAlpha(ContextCompat.getColor(requireContext(), R.color.colorAccent), 0x20),
                withAlpha(ContextCompat.getColor(requireContext(), R.color.colorAccent), 0x65), 999));
        incidentBadge.setPadding(dp(8), dp(5), dp(8), dp(5));
        incidentBadge.setAllCaps(true);
        LinearLayout.LayoutParams ibp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        ibp.leftMargin = dp(12);
        incidentBadge.setLayoutParams(ibp);
        header.addView(incidentBadge);
        root.addView(header);

        AppDescriptor app = null;
        try {
            app = new AppsResolver(requireContext()).getAppByUid(mUid, 0);
        } catch (Exception ignored) { }
        if (app != null) {
            mPackageName = app.getPackageName();
            appName.setText(app.getName() + "  •  " + app.getPackageName() + "  •  UID " + mUid);
            if (app.getIcon() != null) icon.setImageDrawable(app.getIcon());
            loadPermissionHistory(mPackageName);
        } else {
            appName.setText("UID " + mUid);
            icon.setImageResource(R.drawable.ic_apps);
        }

        mSummary = text("", 12, true, ContextCompat.getColor(requireContext(), R.color.colorAccent));
        mSummary.setPadding(dp(14), dp(8), dp(14), dp(8));
        mSummary.setBackground(round(withAlpha(ContextCompat.getColor(requireContext(), R.color.colorAccent), 0x1A),
                withAlpha(ContextCompat.getColor(requireContext(), R.color.colorAccent), 0x55), 12));
        LinearLayout.LayoutParams mp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        mp.leftMargin = dp(20);
        mp.rightMargin = dp(20);
        mp.bottomMargin = dp(10);
        mSummary.setLayoutParams(mp);
        root.addView(mSummary);

        mVerdict = text("", 12, false, timelineTextPrimary());
        mVerdict.setPadding(dp(14), dp(10), dp(14), dp(10));
        LinearLayout.LayoutParams vp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        vp.leftMargin = dp(20);
        vp.rightMargin = dp(20);
        vp.bottomMargin = dp(10);
        mVerdict.setLayoutParams(vp);
        mVerdict.setBackground(round(withAlpha(timelinePanelBg(), 0xC0), withAlpha(timelineBorder(), 0xAA), 12));
        mVerdict.setVisibility(View.GONE);
        root.addView(mVerdict);

        mServices = text("", 12, false, timelineTextSecondary());
        mServices.setPadding(dp(20), 0, dp(20), dp(10));
        mServices.setBackground(round(withAlpha(timelinePanelBg(), 0x96), withAlpha(timelineBorder(), 0xA0), 10));
        LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        sp.leftMargin = dp(20);
        sp.rightMargin = dp(20);
        sp.bottomMargin = dp(12);
        mServices.setLayoutParams(sp);
        root.addView(mServices);

        GridLayout filterBar = new GridLayout(requireContext());
        filterBar.setColumnCount(2);
        filterBar.setRowCount(3);
        filterBar.setPadding(dp(20), 0, dp(20), dp(10));
        GridLayout.LayoutParams filterBarParams = new GridLayout.LayoutParams(
                new ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        filterBar.setLayoutParams(filterBarParams);
        root.addView(filterBar);

        String[] filterModes = {"ALL", "ACTIVE", "THREAT", "SUSPICIOUS", "CLOSED"};
        for (String mode : filterModes) {
            TextView chip = text(mode, 10, true, timelineTextSecondary());
            chip.setAllCaps(true);
            chip.setPadding(dp(10), dp(6), dp(10), dp(6));
            chip.setBackground(round(timelinePanelBg(), timelineBorder(), 999));
            GridLayout.LayoutParams lp = new GridLayout.LayoutParams(
                    new ViewGroup.MarginLayoutParams(
                            ViewGroup.LayoutParams.WRAP_CONTENT,
                            ViewGroup.LayoutParams.WRAP_CONTENT));
            lp.leftMargin = dp(4);
            lp.rightMargin = dp(4);
            lp.topMargin = dp(4);
            lp.bottomMargin = dp(4);
            chip.setLayoutParams(lp);
            chip.setOnClickListener(v -> {
                mTimelineFilter = mode;
                updateFilterChipSelection();
                if (isAdded()) build();
            });
            filterBar.addView(chip);
            mTimelineFilterChips.put(mode, chip);
        }
        updateFilterChipSelection();

        mScroll = new ScrollView(requireContext());
        mScroll.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        mTimeline = new LinearLayout(requireContext());
        mTimeline.setOrientation(LinearLayout.VERTICAL);
        mTimeline.setPadding(dp(12), dp(6), dp(16), dp(12));
        mTimeline.setBackgroundColor(timelineSurface());
        mScroll.addView(mTimeline);
        root.addView(mScroll);

        // actions
        LinearLayout actions = new LinearLayout(requireContext());
        actions.setOrientation(LinearLayout.HORIZONTAL);
        actions.setGravity(Gravity.END);
        actions.setPadding(dp(20), dp(4), dp(20), 0);

        if (mFocusConnId >= 0) {
            TextView audit = action("Run AI Audit");
            audit.setOnClickListener(v -> {
                ConnectionAiFlowDialog.newInstance(mFocusConnId)
                        .show(getParentFragmentManager(), "ConnectionAiFlowDialog");
                dismiss();
            });
            actions.addView(audit);
        }
        TextView fullScreen = action(mFullScreen ? "Exit Full Screen" : "Full Screen");
        fullScreen.setOnClickListener(v -> {
            mFullScreen = !mFullScreen;
            fullScreen.setText(mFullScreen ? "Exit Full Screen" : "Full Screen");
            applyTimelineHeight(root);
        });
        actions.addView(fullScreen);
        TextView close = action("Close");
        close.setOnClickListener(v -> dismiss());
        actions.addView(close);
        root.addView(actions);

        return root;
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        applyTimelineHeight(view);
    }

    private void applyTimelineHeight(View view) {
        ViewGroup.LayoutParams lp = view.getLayoutParams();
        if (lp == null) return;

        int height = mFullScreen
                ? requireContext().getResources().getDisplayMetrics().heightPixels
                : (int) (requireContext().getResources().getDisplayMetrics().heightPixels * 0.85f);
        lp.height = height;
        view.setLayoutParams(lp);
    }

    @Override
    public void onResume() {
        super.onResume();
        mHandler.post(mRefresh);
    }

    @Override
    public void onPause() {
        super.onPause();
        mHandler.removeCallbacks(mRefresh);
    }

    @Override
    public void onDestroy() {
        mHandler.removeCallbacksAndMessages(null);
        super.onDestroy();
    }

    private void loadPermissionHistory(String packageName) {
        if (mPermissionHistoryRequested || packageName == null || packageName.isEmpty()) return;
        mPermissionHistoryRequested = true;
        android.content.Context appContext = requireContext().getApplicationContext();
        PermissionTimelineMonitor.getInstance(appContext).loadPermissionHistory(packageName, events -> {
            mPermissionEvents = events;
            mHandler.post(() -> {
                if (isAdded()) build();
            });
        });
    }

    // ---- data -------------------------------------------------------------------------------

    private void build() {
        ConnectionsRegister reg = CaptureService.getConnsRegister();
        if (mTimeline == null) return;

        Map<String, Group> groups = new LinkedHashMap<>();
        Map<String, Integer> serviceCount = new LinkedHashMap<>();
        int total = 0, active = 0, closed = 0;

        int n = reg != null ? reg.getConnCount() : 0;
        if (reg != null && mUid <= 0 && mFocusConnId != -1) {
            for (int i = 0; i < n; i++) {
                ConnectionDescriptor c = reg.getConn(i);
                if (c != null && c.incr_id == mFocusConnId) {
                    mUid = c.uid;
                    break;
                }
            }
        }

        for (int i = 0; i < n; i++) {
            ConnectionDescriptor c = reg.getConn(i);
            if (c == null || (mUid > 0 && c.uid != mUid)) continue;
            total++;
            boolean isActive = c.status < ConnectionDescriptor.CONN_STATUS_CLOSED;
            if (isActive) active++; else closed++;

            String host = (c.info != null && !c.info.isEmpty()) ? c.info.toLowerCase(Locale.ROOT) : c.dst_ip;
            String key = (host != null) ? host : "unknown";
            Group g = groups.get(key);
            if (g == null) {
                g = new Group();
                g.key = key;
                g.title = key;
                groups.put(key, g);
            }
            g.flows += Math.max(1, c.aggregated_flows);
            g.first = Math.min(g.first, c.first_seen);
            g.last = Math.max(g.last, Math.max(c.last_seen, c.first_seen));
            g.active |= isActive;
            g.sent += c.sent_bytes;
            g.rcvd += c.rcvd_bytes;
            if (c.incr_id == mFocusConnId) g.focus = true;

            if (c.isDns()) {
                String dnsProto = (c.dst_port == 5353) ? "mDNS" : "DNS";
                int qCount = Math.max(c.query_count, Math.max(1, c.aggregated_flows));
                List<ConnectionDescriptor.SocketSession> sessions = c.getSocketSessions();
                if (sessions.size() > 1) {
                    for (ConnectionDescriptor.SocketSession s : sessions) {
                        Ev e = new Ev();
                        e.t = s.first_seen;
                        e.title = dnsProto + " lookup";
                        e.detail = "Resolver port " + s.dst_port + "  •  " + Utils.formatBytes(s.sent_bytes + s.rcvd_bytes);
                        e.color = Color.GRAY;
                        g.events.add(e);
                    }
                } else {
                    Ev e = new Ev();
                    e.t = c.first_seen;
                    e.title = dnsProto + " lookup";
                    e.detail = "Resolved via " + c.dst_ip + ":" + c.dst_port + (qCount > 1 ? "  (×" + qCount + " queries)" : "");
                    e.color = Color.GRAY;
                    g.events.add(e);
                }
                g.services.add("DNS");
                bump(serviceCount, "DNS");
                continue;
            }

            String service = serviceOf(c);
            g.services.add(service);
            bump(serviceCount, service);

            // flags
            int sev = SEV_OK;
            if (c.isBlacklisted()) {
                sev = SEV_THREAT;
                g.reasons.add("Threat intelligence match (" + (c.isBlacklistedHost() ? "malicious domain" : "malicious IP") + ")");
            }
            if (isSuspiciousPort(c)) {
                sev = Math.max(sev, SEV_SUSPICIOUS);
                g.reasons.add("Unusual port " + c.dst_port);
            }
            if (c.dst_port == 80 && c.sent_bytes + c.rcvd_bytes > 0) {
                sev = Math.max(sev, SEV_SUSPICIOUS);
                g.reasons.add("Cleartext HTTP traffic");
            }
            if (c.entropy > 7.5f && c.sent_bytes > 100 * 1024 && !isWellKnownTls(c)) {
                sev = Math.max(sev, SEV_SUSPICIOUS);
                g.reasons.add("High-entropy outbound payload");
            }
            if (c.sent_bytes > 5L * 1024 * 1024 && c.sent_bytes > 8 * Math.max(1, c.rcvd_bytes)) {
                sev = Math.max(sev, SEV_SUSPICIOUS);
                g.reasons.add("Large upload (possible exfiltration)");
            }
            g.severity = Math.max(g.severity, sev);

            List<ConnectionDescriptor.SocketSession> sessions = c.getSocketSessions();
            if (sessions.size() > 1) {
                for (ConnectionDescriptor.SocketSession s : sessions) {
                    Ev se = new Ev();
                    se.t = s.first_seen;
                    if (s.is_blocked) {
                        se.title = "Blocked Attempt";
                        se.detail = (s.block_reason != null ? s.block_reason : c.getBlockReasonLabel(requireContext())) + "  •  Port " + s.dst_port;
                        se.color = ContextCompat.getColor(requireContext(), R.color.statusError);
                    } else {
                        se.title = "Socket Session (:" + s.src_port + " \u2192 :" + s.dst_port + ")";
                        String protoStr = (s.l7proto != null && !s.l7proto.isEmpty()) ? s.l7proto : protoName(c);
                        se.detail = protoStr + "  •  " + s.getTcpStateString() + "  •  \u2191 " + Utils.formatBytes(s.sent_bytes) + "  \u2193 " + Utils.formatBytes(s.rcvd_bytes);
                        se.color = (s.tcp_state == 4 || s.tcp_state == 5) ? Color.GRAY : ContextCompat.getColor(requireContext(), R.color.ok);
                    }
                    g.events.add(se);
                }
            } else {
                // connect event
                Ev open = new Ev();
                open.t = c.first_seen;
                open.title = "Connected";
                StringBuilder d = new StringBuilder(service);
                d.append("  •  ").append(protoName(c)).append("  •  ").append(c.dst_ip).append(':').append(c.dst_port);
                if (c.country != null && !c.country.isEmpty()) d.append("  •  ").append(c.country);
                if (c.aggregated_flows > 1) d.append("  •  ").append(c.aggregated_flows).append(" flows");
                open.detail = d.toString();
                open.color = ContextCompat.getColor(requireContext(), R.color.ok);
                g.events.add(open);

                if (c.is_blocked) {
                    Ev b = new Ev();
                    b.t = c.first_seen + 1;
                    b.title = "Blocked";
                    b.detail = c.getBlockReasonLabel(requireContext());
                    b.color = ContextCompat.getColor(requireContext(), R.color.statusError);
                    g.events.add(b);
                }

                Ev end = new Ev();
                end.t = Math.max(c.last_seen, c.first_seen + 2);
                String bytes = "\u2191 " + Utils.formatBytes(c.sent_bytes) + "  \u2193 " + Utils.formatBytes(c.rcvd_bytes);
                if (isActive) {
                    end.title = "Still active";
                    end.detail = bytes + " so far";
                    end.color = ContextCompat.getColor(requireContext(), R.color.ok);
                } else {
                    end.title = "Closed after " + Utils.formatDuration(requireContext(),
                            Math.max(0, (c.last_seen - c.first_seen) / 1000));
                    end.detail = bytes + "  •  " + c.getStatusLabel(requireContext());
                    end.color = Color.GRAY;
                }
                g.events.add(end);
            }
        }

        List<UnifiedIncidentTimeline.IncidentEvent> permissionEvents = mPermissionEvents;
        if (!permissionEvents.isEmpty()) {
            Group permissionGroup = new Group();
            permissionGroup.key = "__permissions__";
            permissionGroup.title = "Permissions & access";
            permissionGroup.permissionHistory = true;
            permissionGroup.services.add("Permissions");
            for (UnifiedIncidentTimeline.IncidentEvent permissionEvent : permissionEvents) {
                Ev event = new Ev();
                event.t = permissionEvent.timestampMs;
                event.title = permissionEvent.title;
                event.detail = permissionEvent.detail;
                event.color = ContextCompat.getColor(requireContext(), R.color.colorAccent);
                permissionGroup.events.add(event);
                permissionGroup.first = Math.min(permissionGroup.first, event.t);
                permissionGroup.last = Math.max(permissionGroup.last, event.t);
            }
            groups.put(permissionGroup.key, permissionGroup);
        }

        List<Group> list = new ArrayList<>(groups.values());
        Collections.sort(list, (a, b) -> Long.compare(a.first, b.first));
        if (list.size() > MAX_GROUPS) list = list.subList(list.size() - MAX_GROUPS, list.size());
        List<Group> visibleGroups = filterGroups(list);

        // ---- header info
        int threats = 0, suspicious = 0;
        Set<String> allReasons = new LinkedHashSet<>();
        for (Group g : list) {
            if (g.severity == SEV_THREAT) threats++;
            else if (g.severity == SEV_SUSPICIOUS) suspicious++;
            allReasons.addAll(g.reasons);
        }
        int endpointCount = groups.size() - (groups.containsKey("__permissions__") ? 1 : 0);
        mSummary.setText(endpointCount + " endpoints  •  " + total + " connections  •  "
                + active + " active  •  " + closed + " closed");

        if (threats > 0 || suspicious > 0) {
            boolean threat = threats > 0;
            int color = ContextCompat.getColor(requireContext(), threat ? R.color.statusError : R.color.warning);
            StringBuilder v = new StringBuilder(threat ? "\u26A0 Malicious activity detected" : "\u26A0 Suspicious behavior detected");
            v.append(" (").append(threats).append(" threat, ").append(suspicious).append(" suspicious)");
            for (String r : allReasons) v.append("\n\u2022 ").append(r);
            mVerdict.setText(v.toString());
            mVerdict.setBackground(round(withAlpha(color, 0x22), withAlpha(color, 0x99), 10));
            mVerdict.setVisibility(View.VISIBLE);
        } else {
            mVerdict.setVisibility(View.GONE);
        }

        StringBuilder sv = new StringBuilder();
        if (!serviceCount.isEmpty()) {
            sv.append("Services & APIs used: ");
            int k = 0;
            for (Map.Entry<String, Integer> e : serviceCount.entrySet()) {
                if (k++ > 0) sv.append(", ");
                sv.append(e.getKey()).append(" \u00D7").append(e.getValue());
            }
        }
        mServices.setText(sv.toString());
        mServices.setVisibility(sv.length() > 0 ? View.VISIBLE : View.GONE);

        // ---- timeline
        mTimeline.removeAllViews();

        if (visibleGroups.isEmpty()) {
            String emptyText = "No matching activity in this view.\nTry another filter to see more events.";
            if (list.isEmpty()) {
                emptyText = "No network activity recorded for this app yet.\nStart the capture and use the app.";
            }
            TextView empty = text(emptyText, 13, false, timelineTextSecondary());
            empty.setPadding(dp(12), dp(24), dp(12), dp(24));
            mTimeline.addView(empty);
            return;
        }

        View focusView = null;
        for (Group g : visibleGroups) {
            int color = groupColor(g);
            String title = g.title + (g.flows > 1 ? "   (" + g.flows + " flows)" : "");
            StringBuilder sub = new StringBuilder();
            sub.append(g.permissionHistory ? "Observed permission requests and grant-state changes" : (g.active ? "Active" : "Closed"));
            if (!g.services.isEmpty()) sub.append("  •  ").append(joinLimit(g.services, 3));
            if (g.sent + g.rcvd > 0) sub.append("  •  \u2191 ").append(Utils.formatBytes(g.sent))
                    .append(" \u2193 ").append(Utils.formatBytes(g.rcvd));
            if (!g.reasons.isEmpty()) sub.append("\n\u26A0 ").append(joinLimit(g.reasons, 3));

            String groupBadge = groupBadge(g);
            View node = node(mTime.format(new Date(g.first)), color, title, sub.toString(), groupBadge, 0, true, g.focus);
            mTimeline.addView(node);
            if (g.focus) focusView = node;

            Collections.sort(g.events, (a, b) -> Long.compare(a.t, b.t));
            int shown = 0;
            for (Ev e : g.events) {
                if (shown++ >= 24) {
                    mTimeline.addView(node("", Color.GRAY, "\u2026 " + (g.events.size() - 24) + " more events", "", "More", 1, false, false));
                    break;
                }
                mTimeline.addView(node(mTime.format(new Date(e.t)), e.color, e.title, e.detail,
                        eventBadgeLabel(e.title), 1, false, false));
            }
        }

        if (mFirstBuild) {
            mFirstBuild = false;
            final View fv = focusView;
            mScroll.post(() -> {
                if (fv != null) mScroll.scrollTo(0, Math.max(0, fv.getTop() - dp(40)));
                else mScroll.fullScroll(View.FOCUS_DOWN);
            });
        }
    }

    // ---- classification helpers ---------------------------------------------------------------

    private static void bump(Map<String, Integer> m, String k) {
        Integer v = m.get(k);
        m.put(k, v == null ? 1 : v + 1);
    }

    private static String protoName(ConnectionDescriptor c) {
        switch (c.ipproto) {
            case 6: return "TCP";
            case 17: return "UDP";
            case 1: return "ICMP";
            case 58: return "ICMPv6";
            default: return "IP/" + c.ipproto;
        }
    }

    static String serviceOf(ConnectionDescriptor c) {
        String l7 = (c.l7proto != null) ? c.l7proto.trim() : "";
        String byPort;
        switch (c.dst_port) {
            case 443: byPort = "HTTPS/TLS"; break;
            case 80: byPort = "HTTP"; break;
            case 53: byPort = "DNS"; break;
            case 853: byPort = "DNS-over-TLS"; break;
            case 123: byPort = "NTP"; break;
            case 5222: case 5223: byPort = "XMPP / WhatsApp"; break;
            case 5228: case 5229: case 5230: byPort = "Google Push (FCM)"; break;
            case 993: byPort = "IMAPS"; break;
            case 995: byPort = "POP3S"; break;
            case 587: case 465: case 25: byPort = "SMTP"; break;
            case 22: byPort = "SSH"; break;
            case 3389: byPort = "RDP"; break;
            case 3478: case 3479: byPort = "STUN/WebRTC"; break;
            case 8080: byPort = "HTTP (alt)"; break;
            case 8443: byPort = "HTTPS (alt)"; break;
            case 1883: case 8883: byPort = "MQTT"; break;
            default: byPort = "port " + c.dst_port;
        }
        if (!l7.isEmpty() && !l7.equalsIgnoreCase("unknown")) {
            return l7.equalsIgnoreCase(byPort) ? l7 : l7 + " (" + byPort + ")";
        }
        return byPort;
    }

    private static boolean isWellKnownTls(ConnectionDescriptor c) {
        return c.dst_port == 443 || c.dst_port == 853 || c.dst_port == 993 || c.dst_port == 5222
                || c.dst_port == 5228 || c.dst_port == 8443;
    }

    private static boolean isSuspiciousPort(ConnectionDescriptor c) {
        if (c.ipproto != 6 && c.ipproto != 17) return false;
        switch (c.dst_port) {
            case 80: case 443: case 53: case 853: case 123: case 5222: case 5223: case 5228: case 5229:
            case 5230: case 8080: case 8443: case 993: case 995: case 587: case 465: case 25: case 143:
            case 110: case 3478: case 3479: case 4244: case 5242: case 5243: case 9785: case 1883:
            case 8883: case 22:
                return false;
            default:
                // ephemeral/high ports are normal for P2P/QUIC style traffic; only flag the
                // classic backdoor / IRC / RAT ports
                return c.dst_port == 4444 || c.dst_port == 6667 || c.dst_port == 31337
                        || c.dst_port == 1337 || c.dst_port == 5555 || c.dst_port == 9001
                        || c.dst_port == 3389;
        }
    }

    private int groupColor(Group g) {
        if (g.severity == SEV_THREAT) return ContextCompat.getColor(requireContext(), R.color.statusError);
        if (g.severity == SEV_SUSPICIOUS) return ContextCompat.getColor(requireContext(), R.color.warning);
        if (g.active) return ContextCompat.getColor(requireContext(), R.color.ok);
        return Color.GRAY;
    }

    private static String joinLimit(Set<String> items, int max) {
        StringBuilder sb = new StringBuilder();
        int i = 0;
        for (String s : items) {
            if (i++ >= max) {
                sb.append(" +").append(items.size() - max);
                break;
            }
            if (sb.length() > 0) sb.append(", ");
            sb.append(s);
        }
        return sb.toString();
    }

    // ---- view helpers -------------------------------------------------------------------------

    /** One timeline row: time | rail with dot | title + detail. */
    private View node(String time, int color, String title, String detail, String badge, int indent, boolean big, boolean highlight) {
        LinearLayout row = new LinearLayout(requireContext());
        row.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams rp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        if (big) rp.topMargin = dp(8);
        row.setLayoutParams(rp);
        row.setPadding(dp(2), dp(2), dp(2), dp(2));
        row.setElevation(dp(1));
        if (highlight) {
            row.setBackground(round(withAlpha(color, 0x14), withAlpha(color, 0x6A), 12));
        } else {
            row.setBackground(round(withAlpha(timelineCardBg(), 0xA0), withAlpha(color, 0x25), 12));
        }

        TextView t = text(time, 10, false, timelineTextSecondary());
        t.setTypeface(Typeface.MONOSPACE);
        t.setLayoutParams(new LinearLayout.LayoutParams(dp(64), ViewGroup.LayoutParams.WRAP_CONTENT));
        t.setPadding(dp(4), dp(8), 0, dp(4));
        row.addView(t);

        FrameLayout rail = new FrameLayout(requireContext());
        int railW = dp(24) + dp(18) * indent;
        rail.setLayoutParams(new LinearLayout.LayoutParams(railW, ViewGroup.LayoutParams.MATCH_PARENT));
        View line = new View(requireContext());
        FrameLayout.LayoutParams lp = new FrameLayout.LayoutParams(dp(2), ViewGroup.LayoutParams.MATCH_PARENT);
        lp.leftMargin = railW - dp(12);
        line.setLayoutParams(lp);
        line.setBackgroundColor(withAlpha(timelineTextPrimary(), 0x2A));
        rail.addView(line);
        int d = big ? dp(15) : dp(10);
        View dot = new View(requireContext());
        FrameLayout.LayoutParams dp1 = new FrameLayout.LayoutParams(d, d);
        dp1.leftMargin = railW - dp(12) + dp(1) - d / 2;
        dp1.topMargin = dp(big ? 8 : 10);
        dot.setLayoutParams(dp1);
        GradientDrawable gd = new GradientDrawable();
        gd.setShape(GradientDrawable.OVAL);
        gd.setColor(color);
        gd.setStroke(dp(2), withAlpha(Color.WHITE, 0x55));
        dot.setBackground(gd);
        rail.addView(dot);
        row.addView(rail);

        LinearLayout content = new LinearLayout(requireContext());
        content.setOrientation(LinearLayout.VERTICAL);
        content.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        content.setPadding(dp(10), dp(8), dp(10), dp(8));
        content.setBackground(round(withAlpha(timelineCardBg(), 0xF0), withAlpha(color, 0x3D), 10));

        if (badge != null && !badge.isEmpty()) {
            LinearLayout badgeRow = new LinearLayout(requireContext());
            badgeRow.setOrientation(LinearLayout.HORIZONTAL);
            badgeRow.setGravity(Gravity.CENTER_VERTICAL);
            badgeRow.setPadding(dp(8), dp(4), dp(8), dp(4));
            badgeRow.setBackground(round(withAlpha(color, 0x20), withAlpha(color, 0x80), 999));
            badgeRow.setLayoutParams(new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));

            ImageView statusIcon = new ImageView(requireContext());
            statusIcon.setLayoutParams(new LinearLayout.LayoutParams(dp(14), dp(14)));
            statusIcon.setImageResource(statusIconResource(color));
            statusIcon.setImageTintList(ColorStateList.valueOf(color));
            badgeRow.addView(statusIcon);

            TextView badgeView = text(badge, 9, true, Color.WHITE);
            badgeView.setAllCaps(true);
            badgeView.setPadding(0, 0, 0, 0);
            LinearLayout.LayoutParams bLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            bLp.leftMargin = dp(6);
            badgeView.setLayoutParams(bLp);
            badgeRow.addView(badgeView);
            content.addView(badgeRow);
        }

        TextView tt = text(title, big ? 14 : 12, big, timelineTextPrimary());
        tt.setLineSpacing(0f, 1.1f);
        content.addView(tt);
        if (detail != null && !detail.isEmpty()) {
            TextView dd = text(detail, 11, false, timelineTextSecondary());
            dd.setLineSpacing(0f, 1.2f);
            content.addView(dd);
        }
        row.addView(content);
        return row;
    }

    private static String groupBadge(Group g) {
        if (g.permissionHistory) return "Permissions";
        if (g.severity == SEV_THREAT) return "Threat";
        if (g.severity == SEV_SUSPICIOUS) return "Suspicious";
        if (g.active) return "Active";
        return "Closed";
    }

    private static String eventBadgeLabel(String title) {
        if (title == null) return "Event";
        String t = title.trim();
        if (t.startsWith("Blocked") || t.startsWith("Block")) return "Blocked";
        if (t.contains("Still active") || t.contains("Connected")) return "Active";
        if (t.contains("Closed") || t.contains("Closed after")) return "Closed";
        if (t.contains("Threat") || t.contains("Malware") || t.contains("Attack")) return "Threat";
        return "Event";
    }

    private int statusIconResource(int color) {
        int error = ContextCompat.getColor(requireContext(), R.color.statusError);
        int warning = ContextCompat.getColor(requireContext(), R.color.warning);
        int ok = ContextCompat.getColor(requireContext(), R.color.ok);
        if (color == error) return R.drawable.ic_status_dot_red;
        if (color == warning) return R.drawable.ic_status_dot_yellow;
        if (color == ok) return R.drawable.ic_status_dot_green;
        return R.drawable.ic_status_dot_yellow;
    }

    private List<Group> filterGroups(List<Group> source) {
        if ("ALL".equals(mTimelineFilter)) return source;
        List<Group> filtered = new ArrayList<>();
        for (Group g : source) {
            boolean include = false;
            switch (mTimelineFilter) {
                case "ACTIVE":
                    include = g.active || g.permissionHistory;
                    break;
                case "THREAT":
                    include = g.severity == SEV_THREAT;
                    break;
                case "SUSPICIOUS":
                    include = g.severity == SEV_SUSPICIOUS;
                    break;
                case "CLOSED":
                    include = !g.active && !g.permissionHistory;
                    break;
                default:
                    include = true;
                    break;
            }
            if (include) filtered.add(g);
        }
        return filtered;
    }

    private void updateFilterChipSelection() {
        int selectedFill = ContextCompat.getColor(requireContext(), R.color.colorAccent);
        int selectedText = Color.WHITE;
        int neutralText = timelineTextSecondary();
        for (Map.Entry<String, TextView> entry : mTimelineFilterChips.entrySet()) {
            TextView chip = entry.getValue();
            boolean selected = entry.getKey().equals(mTimelineFilter);
            chip.setTextColor(selected ? selectedText : neutralText);
            chip.setBackground(round(selected ? withAlpha(selectedFill, 0x30) : timelinePanelBg(),
                    selected ? withAlpha(selectedFill, 0x7A) : timelineBorder(), 999));
            chip.setTypeface(null, selected ? Typeface.BOLD : Typeface.NORMAL);
        }
    }

    private TextView action(String label) {
        TextView tv = text(label, 14, true, ContextCompat.getColor(requireContext(), R.color.colorAccent));
        tv.setPadding(dp(16), dp(12), dp(16), dp(12));
        TypedValue out = new TypedValue();
        requireContext().getTheme().resolveAttribute(android.R.attr.selectableItemBackground, out, true);
        tv.setBackgroundResource(out.resourceId);
        return tv;
    }

    private int timelineSurface() {
        return ContextCompat.getColor(requireContext(), R.color.timelineSurface);
    }

    private int timelinePanelBg() {
        return ContextCompat.getColor(requireContext(), R.color.timelinePanelBg);
    }

    private int timelineCardBg() {
        return ContextCompat.getColor(requireContext(), R.color.timelineCardBg);
    }

    private int timelineBorder() {
        return ContextCompat.getColor(requireContext(), R.color.timelineBorder);
    }

    private int timelineTextPrimary() {
        return ContextCompat.getColor(requireContext(), R.color.timelineTextPrimary);
    }

    private int timelineTextSecondary() {
        return ContextCompat.getColor(requireContext(), R.color.timelineTextSecondary);
    }

    private TextView text(String s, int sp, boolean bold, int color) {
        TextView tv = new TextView(requireContext());
        tv.setText(s);
        tv.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        tv.setTextColor(color);
        if (bold) tv.setTypeface(tv.getTypeface(), Typeface.BOLD);
        return tv;
    }

    private GradientDrawable round(int fill, int stroke, int radiusDp) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(fill);
        g.setStroke(dp(1), stroke);
        g.setCornerRadius(dp(radiusDp));
        return g;
    }

    private static int withAlpha(int color, int alpha) {
        return (color & 0x00FFFFFF) | (alpha << 24);
    }

    private int dp(int v) {
        return (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v,
                requireContext().getResources().getDisplayMetrics());
    }
}
