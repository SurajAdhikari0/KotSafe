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
import android.content.Intent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.activities.AppDetailsActivity;
import com.kotsafe.security.model.AntivirusEvidenceItem;
import com.kotsafe.security.model.MitreCorrelator;
import com.kotsafe.security.model.ThreatIntelManager;
import com.google.android.material.button.MaterialButton;

import java.util.ArrayList;
import java.util.List;

public class AntivirusEvidenceAdapter extends RecyclerView.Adapter<AntivirusEvidenceAdapter.ViewHolder> {
    private final Context mContext;
    private final List<AntivirusEvidenceItem> mItems = new ArrayList<>();

    public AntivirusEvidenceAdapter(Context context) {
        mContext = context;
    }

    public void setItems(List<AntivirusEvidenceItem> items) {
        int oldSize = mItems.size();
        mItems.clear();
        if (items != null) {
            mItems.addAll(items);
        }
        int newSize = mItems.size();
        if (newSize == 0) {
            notifyDataSetChanged();
        } else if (newSize >= oldSize) {
            // Items appended — only notify new range, don't rebind existing cards
            if (oldSize > 0) notifyItemRangeChanged(0, oldSize);
            if (newSize > oldSize) notifyItemRangeInserted(oldSize, newSize - oldSize);
        } else {
            // Filter shrunk the list — full rebind needed
            notifyDataSetChanged();
        }
    }


    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(mContext).inflate(R.layout.antivirus_evidence_item, parent, false);
        return new ViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        AntivirusEvidenceItem item = mItems.get(position);

        // Smart title formatting — raw URLs with query params are completely unreadable
        // at full length (fills the entire card). Strip query/fragment, show domain+path only.
        String displayTitle = item.title;
        if (AntivirusEvidenceItem.TYPE_URL.equals(item.type) && item.title != null) {
            try {
                android.net.Uri uri = android.net.Uri.parse(item.title);
                String host = uri.getHost();
                String path = uri.getPath();
                if (host != null) {
                    String scheme = uri.getScheme();
                    displayTitle = (scheme != null ? scheme + "://" : "") + host
                            + (path != null && !path.isEmpty() && !path.equals("/") ? path : "");
                }
            } catch (Exception ignored) {}
        }
        // Cap at 72 chars with ellipsis to prevent any overflow
        if (displayTitle != null && displayTitle.length() > 72) {
            displayTitle = displayTitle.substring(0, 69) + "…";
        }
        holder.title.setText(displayTitle);
        holder.title.setMaxLines(2);
        holder.title.setEllipsize(android.text.TextUtils.TruncateAt.END);

        holder.subtitle.setText(item.subtitle);
        holder.details.setText(item.details);

        // Icon based on evidence type
        if (AntivirusEvidenceItem.TYPE_URL.equals(item.type)) {
            holder.icon.setImageResource(R.drawable.ic_search);
        } else if (AntivirusEvidenceItem.TYPE_IP.equals(item.type)) {
            holder.icon.setImageResource(R.drawable.ic_lan);
        } else if (AntivirusEvidenceItem.TYPE_SERVICE_HASH.equals(item.type) || AntivirusEvidenceItem.TYPE_YARA_MATCH.equals(item.type)) {
            holder.icon.setImageResource(R.drawable.ic_shield);
        } else {
            holder.icon.setImageResource(R.drawable.ic_apps);
        }

        boolean isThreat = AntivirusEvidenceItem.SEVERITY_MALICIOUS.equals(item.severity)
                || AntivirusEvidenceItem.SEVERITY_SUSPICIOUS.equals(item.severity);

        // Forensic Path — only shown for real threats, not for clean/low-risk noise
        if (isThreat) {
            String dispPath = item.getDisplayPath();
            if (dispPath != null && !dispPath.isEmpty()) {
                holder.pathContainer.setVisibility(View.VISIBLE);
                holder.tvPath.setText(dispPath);
                holder.pathContainer.setOnClickListener(v -> {
                    android.content.ClipboardManager cm = (android.content.ClipboardManager)
                            mContext.getSystemService(Context.CLIPBOARD_SERVICE);
                    if (cm != null) {
                        cm.setPrimaryClip(android.content.ClipData.newPlainText("File Path", dispPath));
                        Toast.makeText(mContext, "Copied path to clipboard", Toast.LENGTH_SHORT).show();
                    }
                });
            } else {
                holder.pathContainer.setVisibility(View.GONE);
            }

            // Forensic SHA-256 Hash — only for real threats
            String dispHash = item.getDisplaySha256();
            if (dispHash != null && !dispHash.isEmpty()) {
                holder.hashContainer.setVisibility(View.VISIBLE);
                holder.tvHash.setText("SHA-256: " + dispHash);
                holder.hashContainer.setOnClickListener(v -> {
                    android.content.ClipboardManager cm = (android.content.ClipboardManager)
                            mContext.getSystemService(Context.CLIPBOARD_SERVICE);
                    if (cm != null) {
                        cm.setPrimaryClip(android.content.ClipData.newPlainText("SHA-256 Hash", dispHash));
                        Toast.makeText(mContext, "Copied SHA-256 to clipboard", Toast.LENGTH_SHORT).show();
                    }
                });
            } else {
                holder.hashContainer.setVisibility(View.GONE);
            }

            // MITRE ATT&CK — only for real threats
            List<MitreCorrelator.MitreTtp> ttps = MitreCorrelator.correlate(item);
            String mitreBadges = MitreCorrelator.formatShortBadges(ttps);
            if (mitreBadges != null && !mitreBadges.isEmpty()) {
                holder.mitreContainer.setVisibility(View.VISIBLE);
                holder.tvMitre.setText("🎯 MITRE ATT&CK: " + mitreBadges);
            } else {
                holder.mitreContainer.setVisibility(View.GONE);
            }

            // VT / OTX lookup buttons — only useful for actual threats
            holder.btnVt.setVisibility(View.VISIBLE);
            holder.btnOtx.setVisibility(View.VISIBLE);
            holder.btnVt.setOnClickListener(v -> {
                if (item.iocValue == null || item.iocValue.isEmpty()) return;
                ThreatIntelManager.openVirusTotalAuto(mContext, item.iocValue, item.type);
            });
            holder.btnOtx.setOnClickListener(v -> {
                if (item.iocValue == null || item.iocValue.isEmpty()) return;
                ThreatIntelManager.openOtxAuto(mContext, item.iocValue, item.type);
            });

        } else {
            // Clean / Low-risk item: hide all forensic technical noise
            holder.pathContainer.setVisibility(View.GONE);
            holder.hashContainer.setVisibility(View.GONE);
            holder.mitreContainer.setVisibility(View.GONE);
            holder.btnVt.setVisibility(View.GONE);
            holder.btnOtx.setVisibility(View.GONE);
        }



        // Severity badge
        if (item.isQuarantined || AntivirusEvidenceItem.SEVERITY_RESOLVED.equals(item.severity)) {
            holder.severityBadge.setText("🔒 QUARANTINED");
            holder.severityBadge.setBackgroundResource(R.drawable.bg_badge_service);
            holder.severityBadge.setTextColor(0xFF3FB950);
        } else if (item.isSystemApp) {
            if (AntivirusEvidenceItem.SEVERITY_LOW.equals(item.severity)) {
                holder.severityBadge.setText("SYSTEM OS (MONITORED)");
                holder.severityBadge.setBackgroundResource(R.drawable.bg_badge_low_risk);
                holder.severityBadge.setTextColor(0xFFFFA000);
            } else {
                holder.severityBadge.setText("SYSTEM (SAFE)");
                holder.severityBadge.setBackgroundResource(R.drawable.bg_badge_service);
                holder.severityBadge.setTextColor(0xFF2196F3);
            }
        } else if (AntivirusEvidenceItem.SEVERITY_MALICIOUS.equals(item.severity)) {
            holder.severityBadge.setText(AntivirusEvidenceItem.TYPE_YARA_MATCH.equals(item.type) ? "YARA THREAT" : "MALICIOUS");
            holder.severityBadge.setBackgroundResource(R.drawable.bg_badge_threat);
            holder.severityBadge.setTextColor(0xFFE91E63);
        } else if (AntivirusEvidenceItem.SEVERITY_SUSPICIOUS.equals(item.severity)) {
            holder.severityBadge.setText("SUSPICIOUS");
            holder.severityBadge.setBackgroundResource(R.drawable.bg_badge_threat);
            holder.severityBadge.setTextColor(0xFFE91E63);
        } else if (AntivirusEvidenceItem.SEVERITY_LOW.equals(item.severity)) {
            holder.severityBadge.setText("LOW RISK");
            holder.severityBadge.setBackgroundResource(R.drawable.bg_badge_low_risk);
            holder.severityBadge.setTextColor(0xFFFFA000);
        } else {
            holder.severityBadge.setText("CLEAN");
            holder.severityBadge.setBackgroundResource(R.drawable.bg_badge_service);
            holder.severityBadge.setTextColor(0xFF2196F3);
        }

        holder.itemView.setOnClickListener(v -> {
            if (AntivirusEvidenceItem.SEVERITY_MALICIOUS.equals(item.severity)
                    || AntivirusEvidenceItem.SEVERITY_SUSPICIOUS.equals(item.severity)
                    || AntivirusEvidenceItem.TYPE_STORAGE_FILE.equals(item.type)) {
                com.kotsafe.security.views.ThreatRemediationDialog.show(mContext, item, () -> {
                    // Refresh or update item status if needed
                    notifyItemChanged(holder.getBindingAdapterPosition());
                });
            } else {
                Intent intent = new Intent(mContext, com.kotsafe.security.activities.EvidenceDetailActivity.class);
                intent.putExtra(com.kotsafe.security.activities.EvidenceDetailActivity.EXTRA_TITLE, item.title);
                intent.putExtra(com.kotsafe.security.activities.EvidenceDetailActivity.EXTRA_SUBTITLE, item.subtitle);
                intent.putExtra(com.kotsafe.security.activities.EvidenceDetailActivity.EXTRA_IOC_VALUE, item.iocValue);
                intent.putExtra(com.kotsafe.security.activities.EvidenceDetailActivity.EXTRA_IOC_TYPE, item.type);
                intent.putExtra(com.kotsafe.security.activities.EvidenceDetailActivity.EXTRA_SEVERITY, item.severity);
                intent.putExtra(com.kotsafe.security.activities.EvidenceDetailActivity.EXTRA_DETAILS, item.details);
                intent.putExtra(com.kotsafe.security.activities.EvidenceDetailActivity.EXTRA_PACKAGE_NAME, item.packageName);
                intent.putExtra(com.kotsafe.security.activities.EvidenceDetailActivity.EXTRA_FILE_PATH, item.filePath);
                intent.putExtra(com.kotsafe.security.activities.EvidenceDetailActivity.EXTRA_SHA256, item.sha256);
                intent.putExtra(com.kotsafe.security.activities.EvidenceDetailActivity.EXTRA_FILE_SIZE, item.fileSizeFormatted);
                intent.putExtra(com.kotsafe.security.activities.EvidenceDetailActivity.EXTRA_MALWARE_FAMILY, item.malwareFamily);
                intent.putExtra(com.kotsafe.security.activities.EvidenceDetailActivity.EXTRA_IS_SYSTEM_APP, item.isSystemApp);
                intent.putExtra(com.kotsafe.security.activities.EvidenceDetailActivity.EXTRA_IS_WHITELISTED, item.isWhitelisted);
                intent.putExtra(com.kotsafe.security.activities.EvidenceDetailActivity.EXTRA_SYSTEM_REASON, item.systemReason);
                intent.putExtra(com.kotsafe.security.activities.EvidenceDetailActivity.EXTRA_AI_EXPLANATION, item.aiExplanation);
                intent.putExtra(com.kotsafe.security.activities.EvidenceDetailActivity.EXTRA_AI_ACTION_PLAN, item.aiActionPlan);
                intent.putExtra(com.kotsafe.security.activities.EvidenceDetailActivity.EXTRA_AI_PROMPT, item.aiConversationalPrompt);
                intent.putStringArrayListExtra(com.kotsafe.security.activities.EvidenceDetailActivity.EXTRA_MITRE_TECHNIQUES, new java.util.ArrayList<>(item.mitreTechniques));
                intent.putExtra(com.kotsafe.security.activities.EvidenceDetailActivity.EXTRA_RISK_SCORE, item.mlRiskScore > 0 ? item.mlRiskScore : 0);
                mContext.startActivity(intent);
            }
        });

        // Long click always opens the Action Center
        holder.itemView.setOnLongClickListener(v -> {
            com.kotsafe.security.views.ThreatRemediationDialog.show(mContext, item, () -> {
                notifyItemChanged(holder.getBindingAdapterPosition());
            });
            return true;
        });


        if (item.packageName != null && !item.packageName.isEmpty() && !item.packageName.startsWith("uid:")) {
            holder.btnManage.setVisibility(View.VISIBLE);
            holder.btnManage.setOnClickListener(v -> {
                try {
                    android.content.pm.PackageManager pm = mContext.getPackageManager();
                    int uid = Utils.getPackageUid(pm, item.packageName, 0);
                    Intent intent = new Intent(mContext, AppDetailsActivity.class);
                    intent.putExtra(AppDetailsActivity.APP_UID_EXTRA, uid);
                    mContext.startActivity(intent);
                } catch (Exception e) {
                    Toast.makeText(mContext, "Could not open app details", Toast.LENGTH_SHORT).show();
                }
            });
        } else {
            holder.btnManage.setVisibility(View.GONE);
        }
    }

    @Override
    public int getItemCount() {
        return mItems.size();
    }

    static class ViewHolder extends RecyclerView.ViewHolder {
        ImageView icon;
        TextView title, subtitle, details, severityBadge;
        View pathContainer, hashContainer, mitreContainer;
        TextView tvPath, tvHash, tvMitre;
        MaterialButton btnVt, btnOtx, btnManage;

        ViewHolder(@NonNull View itemView) {
            super(itemView);
            icon = itemView.findViewById(R.id.evidence_icon);
            title = itemView.findViewById(R.id.evidence_title);
            subtitle = itemView.findViewById(R.id.evidence_subtitle);
            details = itemView.findViewById(R.id.evidence_details);
            severityBadge = itemView.findViewById(R.id.evidence_severity_badge);
            pathContainer = itemView.findViewById(R.id.evidence_path_container);
            hashContainer = itemView.findViewById(R.id.evidence_hash_container);
            mitreContainer = itemView.findViewById(R.id.evidence_mitre_container);
            tvPath = itemView.findViewById(R.id.evidence_path);
            tvHash = itemView.findViewById(R.id.evidence_hash);
            tvMitre = itemView.findViewById(R.id.evidence_mitre_text);
            btnVt = itemView.findViewById(R.id.btn_action_vt);
            btnOtx = itemView.findViewById(R.id.btn_action_otx);
            btnManage = itemView.findViewById(R.id.btn_action_manage);
        }
    }
}
