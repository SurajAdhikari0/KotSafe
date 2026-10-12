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
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.graphics.drawable.Drawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.core.content.ContextCompat;
import androidx.preference.PreferenceManager;
import androidx.recyclerview.widget.RecyclerView;

import com.kotsafe.security.AppIconLoader;
import com.kotsafe.security.Billing;
import com.kotsafe.security.KotSafe;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.AppDescriptor;
import com.kotsafe.security.model.AppNetworkRule;
import com.kotsafe.security.model.AppNetworkRulesManager;
import com.kotsafe.security.model.AppStats;
import com.kotsafe.security.model.Blocklist;
import com.kotsafe.security.model.MatchList;
import com.kotsafe.security.model.Prefs;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class AppsManagerAdapter extends RecyclerView.Adapter<AppsManagerAdapter.ViewHolder> {
    public static final int FILTER_USER_APPS = 0;
    public static final int FILTER_SYSTEM_APPS = 1;
    public static final int FILTER_ALL_PACKAGES = 2;

    private final Context mContext;
    private final LayoutInflater mLayoutInflater;
    private final Drawable mUnknownIcon;
    private final SharedPreferences mPrefs;
    private final Blocklist mBlocklist;
    private final MatchList mWhitelist;
    private final boolean mFirewallAvailable;

    private List<AppDescriptor> mAllApps = new ArrayList<>();
    private List<AppDescriptor> mFilteredApps = new ArrayList<>();
    private final Map<Integer, AppStats> mAppStatsMap = new HashMap<>();

    private int mCurrentFilter = FILTER_USER_APPS;
    private String mSearchQuery = "";
    private OnAppClickListener mClickListener;
    private AppDescriptor mSelectedApp;

    private int mUserAppsCount = 0;
    private int mSystemAppsCount = 0;

    public interface OnAppClickListener {
        void onAppClick(AppDescriptor app);
    }

    public class ViewHolder extends RecyclerView.ViewHolder {
        final ImageView appIcon;
        final TextView appName;
        final TextView appPackage;
        final TextView badgeCategory;
        final TextView badgeUid;
        final TextView tvVersion;
        final TextView badgeTraffic;
        final ImageView blockedFlag;
        final ImageView wifiBlockedFlag;
        final ImageView mobileBlockedFlag;
        final ImageView whitelistedFlag;

        ViewHolder(@NonNull View itemView) {
            super(itemView);
            appIcon = itemView.findViewById(R.id.app_icon);
            appName = itemView.findViewById(R.id.app_name);
            appPackage = itemView.findViewById(R.id.app_package);
            badgeCategory = itemView.findViewById(R.id.badge_category);
            badgeUid = itemView.findViewById(R.id.badge_uid);
            tvVersion = itemView.findViewById(R.id.tv_version);
            badgeTraffic = itemView.findViewById(R.id.badge_traffic);
            blockedFlag = itemView.findViewById(R.id.blocked);
            wifiBlockedFlag = itemView.findViewById(R.id.wifi_blocked);
            mobileBlockedFlag = itemView.findViewById(R.id.mobile_blocked);
            whitelistedFlag = itemView.findViewById(R.id.whitelisted);
        }

        void bind(@NonNull AppDescriptor app) {
            AppIconLoader.setIcon(appIcon, app, mUnknownIcon);

            String displayName = app.getName();
            String pkg = app.getPackageName();
            if (pkg != null && !pkg.isEmpty()) {
                String lower = displayName.toLowerCase(Locale.ROOT).trim();
                if (lower.equals("services") || lower.equals("service") || lower.equals("settings") || lower.equals("android system") || lower.equals("system")) {
                    int lastDot = pkg.lastIndexOf('.');
                    String suffix = (lastDot >= 0 && lastDot < pkg.length() - 1) ? pkg.substring(lastDot + 1) : pkg;
                    displayName = displayName + " (" + suffix + ")";
                }
            }
            appName.setText(displayName);
            appPackage.setText(pkg);

            if (Utils.isVerifiedGoogleTrustedService(mContext, pkg)) {
                badgeCategory.setText("TRUSTED GOOGLE");
                badgeCategory.setBackground(ContextCompat.getDrawable(mContext, R.drawable.badge_pill_active));
                badgeCategory.setTextColor(ContextCompat.getColor(mContext, R.color.badgeActiveFg));
            } else if (app.isSystem()) {
                badgeCategory.setText("SYSTEM");
                badgeCategory.setBackground(ContextCompat.getDrawable(mContext, R.drawable.badge_pill_proto));
                badgeCategory.setTextColor(ContextCompat.getColor(mContext, R.color.badgeProtoFg));
            } else {
                badgeCategory.setText("USER");
                badgeCategory.setBackground(ContextCompat.getDrawable(mContext, R.drawable.badge_pill_active));
                badgeCategory.setTextColor(ContextCompat.getColor(mContext, R.color.badgeActiveFg));
            }

            badgeUid.setText("UID " + app.getUid());

            PackageInfo pInfo = app.getPackageInfo();
            if (pInfo != null && pInfo.versionName != null && !pInfo.versionName.isEmpty()) {
                tvVersion.setText("v" + pInfo.versionName);
                tvVersion.setVisibility(View.VISIBLE);
            } else {
                tvVersion.setVisibility(View.GONE);
            }

            // Network traffic if captured
            AppStats stats = mAppStatsMap.get(app.getUid());
            if (stats != null && (stats.sentBytes > 0 || stats.rcvdBytes > 0)) {
                badgeTraffic.setVisibility(View.VISIBLE);
                badgeTraffic.setText("⬇ " + Utils.formatBytes(stats.rcvdBytes) + "  ⬆ " + Utils.formatBytes(stats.sentBytes));
            } else {
                badgeTraffic.setVisibility(View.GONE);
            }

            // Firewall status
            int uid = app.getUid();
            boolean isBlocked = mBlocklist.matchesApp(uid);
            boolean isWhitelisted = mWhitelist.matchesApp(uid);
            boolean whitelistEnabled = Prefs.isFirewallEnabled(mContext, mPrefs) && Prefs.isFirewallWhitelistMode(mPrefs);

            blockedFlag.setVisibility(isBlocked ? View.VISIBLE : View.GONE);
            whitelistedFlag.setVisibility(whitelistEnabled && isWhitelisted ? View.VISIBLE : View.GONE);

            AppNetworkRule netRule = AppNetworkRulesManager.getInstance(mContext).getRule(uid);
            boolean fwEnabled = Prefs.isFirewallEnabled(mContext, mPrefs);
            if (netRule != null && fwEnabled) {
                wifiBlockedFlag.setVisibility(netRule.isWifiBlocked() ? View.VISIBLE : View.GONE);
                mobileBlockedFlag.setVisibility(netRule.isMobileBlocked() ? View.VISIBLE : View.GONE);
            } else {
                wifiBlockedFlag.setVisibility(View.GONE);
                mobileBlockedFlag.setVisibility(View.GONE);
            }
        }
    }

    public AppsManagerAdapter(Context context) {
        mContext = context;
        mLayoutInflater = LayoutInflater.from(context);
        mUnknownIcon = ContextCompat.getDrawable(context, R.drawable.ic_apps);
        mPrefs = PreferenceManager.getDefaultSharedPreferences(context);
        mBlocklist = KotSafe.getInstance().getBlocklist();
        mWhitelist = KotSafe.getInstance().getFirewallWhitelist();
        mFirewallAvailable = Billing.newInstance(context).isFirewallVisible();
        setHasStableIds(false);

        AppNetworkRulesManager.getInstance(context).addListener(() -> {
            new android.os.Handler(android.os.Looper.getMainLooper()).post(this::notifyDataSetChanged);
        });
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = mLayoutInflater.inflate(R.layout.item_app_card, parent, false);
        ViewHolder holder = new ViewHolder(view);

        view.setOnClickListener(v -> {
            int pos = holder.getBindingAdapterPosition();
            if (pos != RecyclerView.NO_POSITION && pos < mFilteredApps.size() && mClickListener != null) {
                mClickListener.onAppClick(mFilteredApps.get(pos));
            }
        });

        if (mFirewallAvailable) {
            view.setLongClickable(true);
            view.setOnLongClickListener(v -> {
                int pos = holder.getBindingAdapterPosition();
                if (pos != RecyclerView.NO_POSITION && pos < mFilteredApps.size()) {
                    mSelectedApp = mFilteredApps.get(pos);
                }
                return false;
            });
        }

        return holder;
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        AppDescriptor app = mFilteredApps.get(position);
        holder.bind(app);
    }

    @Override
    public int getItemCount() {
        return mFilteredApps.size();
    }

    public void setOnAppClickListener(OnAppClickListener listener) {
        mClickListener = listener;
    }

    public AppDescriptor getSelectedApp() {
        return mSelectedApp;
    }

    @SuppressLint("NotifyDataSetChanged")
    public void setApps(@NonNull List<AppDescriptor> apps) {
        mAllApps = new ArrayList<>(apps);

        int userCount = 0;
        int systemCount = 0;
        for (AppDescriptor a : mAllApps) {
            if (a.isSystem()) {
                systemCount++;
            } else {
                userCount++;
            }
        }
        mUserAppsCount = userCount;
        mSystemAppsCount = systemCount;

        applyFilters();
    }

    @SuppressLint("NotifyDataSetChanged")
    public void setAppStats(List<AppStats> statsList) {
        mAppStatsMap.clear();
        if (statsList != null) {
            for (AppStats s : statsList) {
                mAppStatsMap.put(s.getUid(), s);
            }
        }
        applyFilters();
    }

    public void setFilterMode(int filterMode) {
        if (mCurrentFilter != filterMode) {
            mCurrentFilter = filterMode;
            applyFilters();
        }
    }

    public void setSearchQuery(String query) {
        String trimmed = (query == null) ? "" : query.trim();
        if (!mSearchQuery.equals(trimmed)) {
            mSearchQuery = trimmed;
            applyFilters();
        }
    }

    public int getUserAppsCount() {
        return mUserAppsCount;
    }

    public int getSystemAppsCount() {
        return mSystemAppsCount;
    }

    public int getAllPackagesCount() {
        return mAllApps.size();
    }

    public int getFilterMode() {
        return mCurrentFilter;
    }

    @SuppressLint("NotifyDataSetChanged")
    private void applyFilters() {
        List<AppDescriptor> filtered = new ArrayList<>();
        String query = mSearchQuery.toLowerCase(Locale.ROOT);

        for (AppDescriptor app : mAllApps) {
            // Category check
            if (mCurrentFilter == FILTER_USER_APPS && app.isSystem()) {
                continue;
            } else if (mCurrentFilter == FILTER_SYSTEM_APPS && !app.isSystem()) {
                continue;
            }

            // Search query check
            if (!query.isEmpty()) {
                String name = app.getName().toLowerCase(Locale.ROOT);
                String pkg = app.getPackageName().toLowerCase(Locale.ROOT);
                String uidStr = String.valueOf(app.getUid());

                if (!name.contains(query) && !pkg.contains(query) && !uidStr.contains(query)) {
                    continue;
                }
            }

            filtered.add(app);
        }

        // Sort: Apps with traffic first (if any), then alphabetical
        Collections.sort(filtered, (o1, o2) -> {
            AppStats s1 = mAppStatsMap.get(o1.getUid());
            AppStats s2 = mAppStatsMap.get(o2.getUid());

            long b1 = (s1 != null) ? (s1.sentBytes + s1.rcvdBytes) : 0;
            long b2 = (s2 != null) ? (s2.sentBytes + s2.rcvdBytes) : 0;

            if (b1 > 0 || b2 > 0) {
                int cmp = -Long.compare(b1, b2);
                if (cmp != 0) return cmp;
            }

            return o1.compareTo(o2);
        });

        mFilteredApps = filtered;
        notifyDataSetChanged();
    }
}
