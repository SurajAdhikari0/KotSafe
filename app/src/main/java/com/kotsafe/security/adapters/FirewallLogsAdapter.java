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

package com.kotsafe.security.adapters;

import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.RecyclerView;

import com.kotsafe.security.AppsResolver;
import com.kotsafe.security.CaptureService;
import com.kotsafe.security.ConnectionsRegister;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.AppDescriptor;
import com.kotsafe.security.model.FirewallLogEntry;
import com.kotsafe.security.model.ThreatIntelManager;

import java.util.ArrayList;
import java.util.List;

public class FirewallLogsAdapter extends RecyclerView.Adapter<FirewallLogsAdapter.ViewHolder> {
    private final Context mContext;
    private final List<FirewallLogEntry> mLogs;
    private final AppsResolver mAppsResolver;
    private final OnLogItemClickListener mListener;

    public interface OnLogItemClickListener {
        void onLogItemClick(FirewallLogEntry entry);
        void onQuickThreatAnalyze(FirewallLogEntry entry);
    }

    public FirewallLogsAdapter(Context context, OnLogItemClickListener listener) {
        mContext = context;
        mLogs = new ArrayList<>();
        mAppsResolver = new AppsResolver(context);
        mListener = listener;
    }

    public void setLogs(List<FirewallLogEntry> logs) {
        mLogs.clear();
        if(logs != null) {
            mLogs.addAll(logs);
        }
        notifyDataSetChanged();
    }

    public void addLogAtTop(FirewallLogEntry entry) {
        mLogs.add(0, entry);
        notifyItemInserted(0);
    }

    public void clear() {
        int count = mLogs.size();
        mLogs.clear();
        notifyItemRangeRemoved(0, count);
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View v = LayoutInflater.from(mContext).inflate(R.layout.firewall_log_item, parent, false);
        return new ViewHolder(v);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        FirewallLogEntry log = mLogs.get(position);

        // App info
        AppDescriptor app = (log.uid >= 0) ? mAppsResolver.getAppByUid(log.uid, 0) : null;
        if (app == null && log.packageName != null && !log.packageName.isEmpty() && !log.packageName.startsWith("uid:")) {
            app = mAppsResolver.getAppByPackage(log.packageName, 0);
        }

        AppDescriptor correlatedApp = null;
        if (log.uid == 1000 || log.uid <= 0 || (log.appName != null && log.appName.toLowerCase().contains("android system"))) {
            try {
                ConnectionsRegister reg = CaptureService.requireConnsRegister();
                if (reg != null) {
                    List<ConnectionsRegister.CorrelatedApp> list = reg.getCorrelatedAppsForTimestamp(log.timestamp, 5000);
                    if (list != null && !list.isEmpty()) {
                        correlatedApp = list.get(0).app;
                    }
                }
            } catch (Exception ignored) {}
        }

        if (correlatedApp != null) {
            holder.appName.setText(correlatedApp.getName() + " (via Android System)");
            Drawable icon = correlatedApp.getIcon();
            if (icon != null) {
                holder.appIcon.setImageDrawable(icon);
            } else {
                holder.appIcon.setImageResource(android.R.drawable.sym_def_app_icon);
            }
            holder.serviceBadge.setVisibility(View.GONE);
        } else if (app != null) {
            holder.appName.setText(app.getName());
            Drawable icon = app.getIcon();
            if (icon != null) {
                holder.appIcon.setImageDrawable(icon);
            } else {
                holder.appIcon.setImageResource(android.R.drawable.sym_def_app_icon);
            }
            holder.serviceBadge.setVisibility(log.isServiceApp ? View.VISIBLE : View.GONE);
        } else {
            holder.appName.setText(log.appName != null && !log.appName.isEmpty() ? log.appName : ("App (" + log.uid + ")"));
            holder.appIcon.setImageResource(android.R.drawable.sym_def_app_icon);
            holder.serviceBadge.setVisibility(log.isServiceApp ? View.VISIBLE : View.GONE);
        }

        // Timestamp
        java.text.DateFormat timeFmt = new java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault());
        holder.timestamp.setText(timeFmt.format(new java.util.Date(log.timestamp)));

        // Action badge & reason
        String blockType = log.getFormattedBlockType();
        if(FirewallLogEntry.ACTION_BLOCKED.equalsIgnoreCase(log.action)) {
            if(FirewallLogEntry.BLOCK_TYPE_ADS.equalsIgnoreCase(blockType)) {
                holder.actionBadge.setText("ADS");
                holder.actionBadge.setBackgroundResource(R.drawable.bg_badge_ad);
                holder.actionBadge.setTextColor(Color.parseColor("#FF9800"));
            } else if(FirewallLogEntry.BLOCK_TYPE_RATE_LIMIT.equalsIgnoreCase(blockType)) {
                holder.actionBadge.setText("LIMIT");
                holder.actionBadge.setBackgroundResource(R.drawable.bg_badge_warn);
                holder.actionBadge.setTextColor(Color.parseColor("#FF5722"));
            } else if(FirewallLogEntry.BLOCK_TYPE_MALWARE.equalsIgnoreCase(blockType) || FirewallLogEntry.BLOCK_TYPE_PHISHING.equalsIgnoreCase(blockType)) {
                holder.actionBadge.setText("THREAT");
                holder.actionBadge.setBackgroundResource(R.drawable.bg_badge_threat);
                holder.actionBadge.setTextColor(Color.parseColor("#E91E63"));
            } else {
                holder.actionBadge.setText("BLOCKED");
                holder.actionBadge.setBackgroundResource(R.drawable.bg_nac_status_blocked);
                holder.actionBadge.setTextColor(ContextCompat.getColor(mContext, R.color.danger));
            }
        } else if(FirewallLogEntry.ACTION_ALERT.equalsIgnoreCase(log.action) || log.isMalicious()) {
            holder.actionBadge.setText("ALERT");
            holder.actionBadge.setBackgroundResource(R.drawable.bg_badge_threat);
            holder.actionBadge.setTextColor(Color.parseColor("#E91E63"));
        } else {
            holder.actionBadge.setText("ALLOWED");
            holder.actionBadge.setBackgroundResource(R.drawable.bg_nac_status_allowed);
            holder.actionBadge.setTextColor(ContextCompat.getColor(mContext, R.color.ok));
        }

        if (log.blockReason != null && !log.blockReason.isEmpty()) {
            String r = log.blockReason.toLowerCase();
            String prefix = "";
            if (r.contains("malware") || r.contains("malicious") || r.contains("threat") || r.contains("c2")) {
                prefix = "☣️ [Malicious] ";
            } else if (r.contains("phish")) {
                prefix = "🎣 [Phishing] ";
            } else if (r.contains("ad") || r.contains("track") || r.contains("telemetry") || r.contains("stevenblack") || r.contains("oisd")) {
                prefix = "🛑 [Ads & Trackers] ";
            } else if (r.contains("rate limit") || r.contains("flood guard")) {
                prefix = "⚡ [Rate Limit] ";
            } else if (r.contains("lan")) {
                prefix = "🏠 [LAN Isolation] ";
            } else if (r.contains("wi-fi") || r.contains("mobile") || r.contains("roaming") || r.contains("firewall")) {
                prefix = "🛡️ [Firewall Rule] ";
            } else if (r.contains("screen-off") || r.contains("background")) {
                prefix = "🌙 [Background Policy] ";
            }
            holder.reason.setText(prefix + log.blockReason);
        } else {
            holder.reason.setText(FirewallLogEntry.ACTION_BLOCKED.equalsIgnoreCase(log.action) ? "🛑 Blocked by Policy" : "Policy Allowed");
        }

        // Background indicator
        holder.backgroundIcon.setVisibility(log.isBackground ? View.VISIBLE : View.GONE);

        // Destination & protocols
        holder.destination.setText(log.getDisplayDestination());
        holder.protoBadge.setText(log.protocol != null ? log.protocol : "TCP");
        holder.networkBadge.setText(log.networkType != null ? log.networkType : "NET");

        // Hash row
        if(log.payloadHash != null && !log.payloadHash.isEmpty()) {
            holder.hashRow.setVisibility(View.VISIBLE);
            holder.payloadHash.setText(log.payloadHash);
        } else {
            holder.hashRow.setVisibility(View.GONE);
        }

        // Click listeners
        holder.itemView.setOnClickListener(v -> {
            if(mListener != null) mListener.onLogItemClick(log);
        });

        holder.btnQuickVt.setOnClickListener(v -> {
            if(mListener != null) mListener.onQuickThreatAnalyze(log);
        });
    }

    @Override
    public int getItemCount() {
        return mLogs.size();
    }

    public static class ViewHolder extends RecyclerView.ViewHolder {
        ImageView appIcon;
        TextView appName;
        TextView serviceBadge;
        TextView timestamp;
        TextView actionBadge;
        TextView reason;
        ImageView backgroundIcon;
        TextView destination;
        TextView protoBadge;
        TextView networkBadge;
        LinearLayout hashRow;
        TextView payloadHash;
        TextView btnQuickVt;

        public ViewHolder(@NonNull View itemView) {
            super(itemView);
            appIcon = itemView.findViewById(R.id.log_app_icon);
            appName = itemView.findViewById(R.id.log_app_name);
            serviceBadge = itemView.findViewById(R.id.log_service_badge);
            timestamp = itemView.findViewById(R.id.log_timestamp);
            actionBadge = itemView.findViewById(R.id.log_action_badge);
            reason = itemView.findViewById(R.id.log_reason);
            backgroundIcon = itemView.findViewById(R.id.log_background_icon);
            destination = itemView.findViewById(R.id.log_destination);
            protoBadge = itemView.findViewById(R.id.log_proto_badge);
            networkBadge = itemView.findViewById(R.id.log_network_badge);
            hashRow = itemView.findViewById(R.id.log_hash_row);
            payloadHash = itemView.findViewById(R.id.log_payload_hash);
            btnQuickVt = itemView.findViewById(R.id.btn_quick_vt);
        }
    }
}
