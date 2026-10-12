/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.adapters;

import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.kotsafe.security.AppsResolver;
import com.kotsafe.security.CaptureService;
import com.kotsafe.security.ConnectionsRegister;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.AppDescriptor;
import com.kotsafe.security.model.DnsActivityEntry;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class DnsActivityLogsAdapter extends RecyclerView.Adapter<DnsActivityLogsAdapter.ViewHolder> {

    public interface OnDnsItemClickListener {
        void onDnsItemClick(DnsActivityEntry entry);
    }

    private final Context mContext;
    private final List<DnsActivityEntry> mLogs;
    private final AppsResolver mAppsResolver;
    private final OnDnsItemClickListener mListener;
    private final SimpleDateFormat mTimeFmt = new SimpleDateFormat("HH:mm:ss", Locale.getDefault());

    public DnsActivityLogsAdapter(Context context, OnDnsItemClickListener listener) {
        mContext = context;
        mLogs = new ArrayList<>();
        mAppsResolver = new AppsResolver(context);
        mListener = listener;
    }

    public void setLogs(List<DnsActivityEntry> logs) {
        mLogs.clear();
        if (logs != null) {
            mLogs.addAll(logs);
        }
        notifyDataSetChanged();
    }

    public void addLogAtTop(DnsActivityEntry entry) {
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
        View v = LayoutInflater.from(mContext).inflate(R.layout.item_dns_activity, parent, false);
        return new ViewHolder(v);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        DnsActivityEntry log = mLogs.get(position);

        holder.tvDomain.setText(log.domain);
        holder.tvQueryType.setText(log.queryType != null ? log.queryType : "A");
        holder.tvTimestamp.setText(mTimeFmt.format(new Date(log.timestamp)));

        // Resolve App info if package available
        String appName = log.callerApp != null && !log.callerApp.isEmpty() ? log.callerApp : "System / Network";
        Drawable icon = null;
        if (log.callerPkg != null && !log.callerPkg.isEmpty()) {
            AppDescriptor ad = mAppsResolver.getAppByPackage(log.callerPkg, 0);
            if (ad != null) {
                appName = ad.getName();
                icon = ad.getIcon();
            }
        }
        if (icon == null || appName.contains("System")) {
            try {
                ConnectionsRegister reg = CaptureService.requireConnsRegister();
                if (reg != null) {
                    List<ConnectionsRegister.CorrelatedApp> list = reg.getCorrelatedAppsForTimestamp(log.timestamp, 5000);
                    if (list != null && !list.isEmpty()) {
                        AppDescriptor cApp = list.get(0).app;
                        appName = cApp.getName() + " (via Android System)";
                        icon = cApp.getIcon();
                    }
                }
            } catch (Exception ignored) {}
        }
        holder.tvCallerApp.setText(appName);
        if (icon != null) {
            holder.ivAppIcon.setImageDrawable(icon);
        } else {
            holder.ivAppIcon.setImageResource(android.R.drawable.sym_def_app_icon);
        }

        // Status Badge & Block Reason
        if (log.isBlocked()) {
            holder.tvStatusBadge.setText("BLOCKED");
            holder.tvStatusBadge.setBackgroundColor(Color.parseColor("#E53935"));
            String r = (log.blockReason != null && !log.blockReason.isEmpty()) ? log.blockReason : "Ad / Tracker Blocklist";
            holder.tvBlockReason.setText("Blocked by " + r);
            holder.tvBlockReason.setVisibility(View.VISIBLE);
        } else {
            holder.tvStatusBadge.setText("ALLOWED");
            holder.tvStatusBadge.setBackgroundColor(Color.parseColor("#43A047"));
            holder.tvBlockReason.setVisibility(View.GONE);
        }

        holder.itemView.setOnClickListener(v -> {
            if (mListener != null) {
                mListener.onDnsItemClick(log);
            }
        });
    }

    @Override
    public int getItemCount() {
        return mLogs.size();
    }

    public static class ViewHolder extends RecyclerView.ViewHolder {
        final ImageView ivAppIcon;
        final TextView tvCallerApp;
        final TextView tvQueryType;
        final TextView tvTimestamp;
        final TextView tvDomain;
        final TextView tvStatusBadge;
        final TextView tvBlockReason;

        public ViewHolder(@NonNull View itemView) {
            super(itemView);
            ivAppIcon = itemView.findViewById(R.id.dns_app_icon);
            tvCallerApp = itemView.findViewById(R.id.dns_caller_app);
            tvQueryType = itemView.findViewById(R.id.dns_query_type);
            tvTimestamp = itemView.findViewById(R.id.dns_timestamp);
            tvDomain = itemView.findViewById(R.id.dns_domain);
            tvStatusBadge = itemView.findViewById(R.id.dns_status_badge);
            tvBlockReason = itemView.findViewById(R.id.dns_block_reason);
        }
    }
}
