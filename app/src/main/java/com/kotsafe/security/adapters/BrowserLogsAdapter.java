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

package com.kotsafe.security.adapters;

import android.content.Context;
import android.graphics.drawable.Drawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.RecyclerView;

import com.kotsafe.security.AppsResolver;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.AppDescriptor;
import com.kotsafe.security.model.BrowserActivityManager.BrowserLogEntry;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class BrowserLogsAdapter extends RecyclerView.Adapter<BrowserLogsAdapter.LogViewHolder> {
    private final Context mContext;
    private final LayoutInflater mInflater;
    private final AppsResolver mAppsResolver;
    private final SimpleDateFormat mTimeFormat;
    private final List<BrowserLogEntry> mEntries = new ArrayList<>();
    private OnLogItemClickListener mListener;

    public interface OnLogItemClickListener {
        void onLogItemClick(BrowserLogEntry entry);
    }

    public BrowserLogsAdapter(@NonNull Context context) {
        mContext = context;
        mInflater = LayoutInflater.from(context);
        mAppsResolver = new AppsResolver(context);
        mTimeFormat = new SimpleDateFormat("HH:mm:ss", Locale.getDefault());
    }

    public void setOnLogItemClickListener(OnLogItemClickListener listener) {
        mListener = listener;
    }

    public void setEntries(List<BrowserLogEntry> entries) {
        mEntries.clear();
        if (entries != null) {
            mEntries.addAll(entries);
        }
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public LogViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = mInflater.inflate(R.layout.browser_log_item, parent, false);
        return new LogViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull LogViewHolder holder, int position) {
        BrowserLogEntry entry = mEntries.get(position);

        // App Icon & Name
        holder.tvAppName.setText(entry.appName);
        holder.tvTime.setText(mTimeFormat.format(new Date(entry.timestamp)));

        AppDescriptor app = mAppsResolver.getAppByUid(entry.uid, 0);
        if (app != null) {
            Drawable icon = app.getIcon();
            if (icon != null) {
                holder.ivAppIcon.setImageDrawable(icon);
                holder.ivAppIcon.setImageTintList(null);
            } else {
                holder.ivAppIcon.setImageResource(R.drawable.ic_language);
                holder.ivAppIcon.setColorFilter(ContextCompat.getColor(mContext, R.color.colorPrimary));
            }
        } else {
            holder.ivAppIcon.setImageResource(R.drawable.ic_language);
            holder.ivAppIcon.setColorFilter(ContextCompat.getColor(mContext, R.color.colorPrimary));
        }

        // Bytes transferred
        holder.tvBytes.setText(String.format("Tx: %s  Rx: %s",
                Utils.formatBytes(entry.sentBytes),
                Utils.formatBytes(entry.rcvdBytes)));

        if (entry.isDecrypted) {
            // DECRYPTED FORMAT
            holder.tvStatusBadge.setText("DECRYPTED");
            holder.tvStatusBadge.setBackgroundResource(R.drawable.badge_pill_active);
            holder.tvStatusBadge.setTextColor(ContextCompat.getColor(mContext, R.color.badgeActiveFg));

            holder.layoutDecrypted.setVisibility(View.VISIBLE);
            holder.layoutEncrypted.setVisibility(View.GONE);

            holder.tvHttpMethod.setText(entry.httpMethod);
            holder.tvHttpUrl.setText(entry.url);

            // HTTP status
            if (entry.statusCode > 0) {
                holder.tvHttpStatus.setVisibility(View.VISIBLE);
                com.kotsafe.security.model.parser.AdvancedLogParser.ParsedHttpStatus parsedStatus =
                        com.kotsafe.security.model.parser.AdvancedLogParser.parseHttpStatus(entry.statusCode);
                holder.tvHttpStatus.setText(parsedStatus.getFormatted());
                holder.tvHttpStatus.setTextColor(parsedStatus.badgeColor);
            } else {
                holder.tvHttpStatus.setVisibility(View.GONE);
            }

            // Tracking and Risk Chips
            if (entry.parsedUrl != null && entry.parsedUrl.hasTrackingParams()) {
                holder.chipTrackers.setVisibility(View.VISIBLE);
                holder.chipTrackers.setText("TRACKERS (" + entry.parsedUrl.trackingParameters.size() + ")");
            } else {
                holder.chipTrackers.setVisibility(View.GONE);
            }

            if (entry.parsedUrl != null && entry.parsedUrl.riskAssessment != null &&
                    (entry.parsedUrl.riskAssessment.riskLevel == com.kotsafe.security.model.parser.AdvancedLogParser.RiskLevel.SUSPICIOUS ||
                     entry.parsedUrl.riskAssessment.riskLevel == com.kotsafe.security.model.parser.AdvancedLogParser.RiskLevel.HIGH_RISK)) {
                holder.chipRisk.setVisibility(View.VISIBLE);
                holder.chipRisk.setText(entry.parsedUrl.riskAssessment.riskLevel.label);
                holder.chipRisk.setTextColor(entry.parsedUrl.riskAssessment.riskLevel.color);
            } else {
                holder.chipRisk.setVisibility(View.GONE);
            }

            // Decoder chips
            holder.chipHttps.setVisibility(entry.hasHttps ? View.VISIBLE : View.GONE);
            holder.chipDoh.setVisibility(entry.hasDoh ? View.VISIBLE : View.GONE);
            holder.chipProto.setVisibility(entry.hasProtobuf ? View.VISIBLE : View.GONE);
            holder.chipJwt.setVisibility(entry.hasJwt ? View.VISIBLE : View.GONE);
        } else {
            // ENCRYPTED FORMAT
            holder.tvStatusBadge.setText("ENCRYPTED (TLS)");
            holder.tvStatusBadge.setBackgroundResource(R.drawable.badge_pill_closed);
            holder.tvStatusBadge.setTextColor(ContextCompat.getColor(mContext, R.color.badgeClosedFg));

            holder.layoutDecrypted.setVisibility(View.GONE);
            holder.layoutEncrypted.setVisibility(View.VISIBLE);

            holder.tvEncryptedProto.setText(entry.tlsVersion);
            holder.tvSniDomain.setText("SNI: " + entry.hostOrDomain);
            holder.tvEncryptedHex.setText(entry.encryptedHexPreview);
        }

        holder.itemView.setOnClickListener(v -> {
            if (mListener != null) {
                mListener.onLogItemClick(entry);
            }
        });
    }

    @Override
    public int getItemCount() {
        return mEntries.size();
    }

    static class LogViewHolder extends RecyclerView.ViewHolder {
        ImageView ivAppIcon;
        TextView tvAppName;
        TextView tvTime;
        TextView tvStatusBadge;
        TextView tvBytes;

        // Decrypted
        View layoutDecrypted;
        TextView tvHttpMethod;
        TextView tvHttpStatus;
        TextView tvHttpUrl;
        TextView chipTrackers;
        TextView chipRisk;
        TextView chipHttps;
        TextView chipDoh;
        TextView chipProto;
        TextView chipJwt;

        // Encrypted
        View layoutEncrypted;
        TextView tvEncryptedProto;
        TextView tvSniDomain;
        TextView tvEncryptedHex;

        LogViewHolder(@NonNull View itemView) {
            super(itemView);
            ivAppIcon = itemView.findViewById(R.id.iv_browser_icon);
            tvAppName = itemView.findViewById(R.id.tv_browser_app_name);
            tvTime = itemView.findViewById(R.id.tv_log_time);
            tvStatusBadge = itemView.findViewById(R.id.tv_status_badge);
            tvBytes = itemView.findViewById(R.id.tv_bytes_transferred);

            layoutDecrypted = itemView.findViewById(R.id.layout_decrypted_view);
            tvHttpMethod = itemView.findViewById(R.id.tv_http_method);
            tvHttpStatus = itemView.findViewById(R.id.tv_http_status);
            tvHttpUrl = itemView.findViewById(R.id.tv_http_url);
            chipTrackers = itemView.findViewById(R.id.chip_trackers);
            chipRisk = itemView.findViewById(R.id.chip_risk);
            chipHttps = itemView.findViewById(R.id.chip_https);
            chipDoh = itemView.findViewById(R.id.chip_doh);
            chipProto = itemView.findViewById(R.id.chip_proto);
            chipJwt = itemView.findViewById(R.id.chip_jwt);

            layoutEncrypted = itemView.findViewById(R.id.layout_encrypted_view);
            tvEncryptedProto = itemView.findViewById(R.id.tv_encrypted_proto);
            tvSniDomain = itemView.findViewById(R.id.tv_sni_domain);
            tvEncryptedHex = itemView.findViewById(R.id.tv_encrypted_hex);
        }
    }
}
