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

package com.kotsafe.security.views;

import android.content.Intent;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import java.util.List;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;

import com.kotsafe.security.AppsResolver;
import com.kotsafe.security.CaptureService;
import com.kotsafe.security.ConnectionsRegister;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.activities.AppDetailsActivity;
import com.kotsafe.security.model.AlertRecord;
import com.kotsafe.security.model.AppDescriptor;
import com.kotsafe.security.model.FirewallLogEntry;
import com.kotsafe.security.model.ThreatIntelManager;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;
import com.google.android.material.button.MaterialButton;

public class FirewallLogDetailsDialog extends BottomSheetDialogFragment {
    private static final String ARG_LOG_ENTRY = "log_entry";
    private FirewallLogEntry mLog;

    public static FirewallLogDetailsDialog newInstance(FirewallLogEntry entry) {
        FirewallLogDetailsDialog dialog = new FirewallLogDetailsDialog();
        Bundle args = new Bundle();
        args.putSerializable(ARG_LOG_ENTRY, entry);
        dialog.setArguments(args);
        return dialog;
    }

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if(getArguments() != null) {
            mLog = (FirewallLogEntry) getArguments().getSerializable(ARG_LOG_ENTRY);
        }
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        View root = inflater.inflate(R.layout.dialog_firewall_log_details, container, false);
        if(mLog == null) return root;

        ImageView appIcon = root.findViewById(R.id.dialog_app_icon);
        TextView appName = root.findViewById(R.id.dialog_app_name);
        TextView pkgName = root.findViewById(R.id.dialog_pkg_name);
        TextView serviceBadge = root.findViewById(R.id.dialog_service_badge);

        TextView actionBadge = root.findViewById(R.id.dialog_action_badge);
        TextView reason = root.findViewById(R.id.dialog_reason);
        TextView timestampFull = root.findViewById(R.id.dialog_timestamp_full);

        TextView destHost = root.findViewById(R.id.dialog_dest_host);
        TextView destIpPort = root.findViewById(R.id.dialog_dest_ip_port);
        TextView trafficMetrics = root.findViewById(R.id.dialog_traffic_metrics);
        TextView geoInfo = root.findViewById(R.id.dialog_geo_info);

        TextView hashValue = root.findViewById(R.id.dialog_hash_value);
        ImageView btnCopyHash = root.findViewById(R.id.btn_copy_hash);

        MaterialButton btnVirusTotal = root.findViewById(R.id.btn_virustotal_lookup);
        MaterialButton btnOtx = root.findViewById(R.id.btn_otx_lookup);
        MaterialButton btnManageNac = root.findViewById(R.id.btn_manage_nac);

        // App info
        AppsResolver appsResolver = new AppsResolver(requireContext());
        AppDescriptor app = (mLog.uid >= 0) ? appsResolver.getAppByUid(mLog.uid, 0) : null;
        if (app == null && mLog.packageName != null && !mLog.packageName.isEmpty() && !mLog.packageName.startsWith("uid:")) {
            app = appsResolver.getAppByPackage(mLog.packageName, 0);
        }

        AppDescriptor correlatedApp = null;
        if (mLog.uid == 1000 || mLog.uid <= 0 || (mLog.appName != null && mLog.appName.toLowerCase().contains("android system"))) {
            try {
                ConnectionsRegister reg = CaptureService.requireConnsRegister();
                if (reg != null) {
                    List<ConnectionsRegister.CorrelatedApp> list = reg.getCorrelatedAppsForTimestamp(mLog.timestamp, 5000);
                    if (list != null && !list.isEmpty()) {
                        correlatedApp = list.get(0).app;
                    }
                }
            } catch (Exception ignored) {}
        }

        final AppDescriptor resolvedApp = correlatedApp != null ? correlatedApp : app;

        if (correlatedApp != null) {
            appName.setText(correlatedApp.getName());
            pkgName.setText(correlatedApp.getPackageName() + " • UID " + correlatedApp.getUid() + " (via Android System Resolver)");
            Drawable icon = correlatedApp.getIcon();
            if (icon != null) appIcon.setImageDrawable(icon);
            else appIcon.setImageResource(android.R.drawable.sym_def_app_icon);
            serviceBadge.setText("CORRELATED CALLER");
            serviceBadge.setVisibility(View.VISIBLE);
        } else if (app != null) {
            appName.setText(app.getName());
            pkgName.setText(app.getPackageName() + " (UID: " + mLog.uid + ")");
            Drawable icon = app.getIcon();
            if (icon != null) appIcon.setImageDrawable(icon);
            else appIcon.setImageResource(android.R.drawable.sym_def_app_icon);
            serviceBadge.setVisibility(mLog.isServiceApp ? View.VISIBLE : View.GONE);
        } else {
            appName.setText(mLog.appName != null && !mLog.appName.isEmpty() ? mLog.appName : ("App (" + mLog.uid + ")"));
            pkgName.setText((mLog.packageName != null ? mLog.packageName : "") + " (UID: " + mLog.uid + ")");
            appIcon.setImageResource(android.R.drawable.sym_def_app_icon);
            serviceBadge.setVisibility(mLog.isServiceApp ? View.VISIBLE : View.GONE);
        }

        // Action badge
        String blockType = mLog.getFormattedBlockType();
        if(FirewallLogEntry.ACTION_BLOCKED.equalsIgnoreCase(mLog.action)) {
            if(FirewallLogEntry.BLOCK_TYPE_ADS.equalsIgnoreCase(blockType)) {
                actionBadge.setText("ADS");
                actionBadge.setBackgroundResource(R.drawable.bg_badge_ad);
                actionBadge.setTextColor(Color.parseColor("#FF9800"));
            } else if(FirewallLogEntry.BLOCK_TYPE_RATE_LIMIT.equalsIgnoreCase(blockType)) {
                actionBadge.setText("LIMIT");
                actionBadge.setBackgroundResource(R.drawable.bg_badge_warn);
                actionBadge.setTextColor(Color.parseColor("#FF5722"));
            } else if(FirewallLogEntry.BLOCK_TYPE_MALWARE.equalsIgnoreCase(blockType) || FirewallLogEntry.BLOCK_TYPE_PHISHING.equalsIgnoreCase(blockType)) {
                actionBadge.setText("THREAT");
                actionBadge.setBackgroundResource(R.drawable.bg_badge_threat);
                actionBadge.setTextColor(Color.parseColor("#E91E63"));
            } else {
                actionBadge.setText("BLOCKED");
                actionBadge.setBackgroundResource(R.drawable.bg_nac_status_blocked);
                actionBadge.setTextColor(ContextCompat.getColor(requireContext(), R.color.danger));
            }
        } else if(FirewallLogEntry.ACTION_ALERT.equalsIgnoreCase(mLog.action) || mLog.isMalicious()) {
            actionBadge.setText("ALERT");
            actionBadge.setBackgroundResource(R.drawable.bg_badge_threat);
            actionBadge.setTextColor(Color.parseColor("#E91E63"));
        } else {
            actionBadge.setText("ALLOWED");
            actionBadge.setBackgroundResource(R.drawable.bg_nac_status_allowed);
            actionBadge.setTextColor(ContextCompat.getColor(requireContext(), R.color.ok));
        }

        reason.setText(mLog.blockReason != null && !mLog.blockReason.isEmpty() ? mLog.blockReason : "Allowed");
        java.text.DateFormat dateTimeFmt = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.getDefault());
        String timeStr = dateTimeFmt.format(new java.util.Date(mLog.timestamp));
        String stateStr = mLog.isBackground ? "Background" : "Foreground";
        timestampFull.setText("Logged on: " + timeStr + " • Network: " + mLog.networkType + " • " + stateStr);

        // Forensics
        if(mLog.domainOrUrl != null && !mLog.domainOrUrl.isEmpty()) {
            destHost.setText("Host / URL: " + mLog.domainOrUrl);
            destHost.setVisibility(View.VISIBLE);
        } else {
            destHost.setVisibility(View.GONE);
        }

        String protoStr = (mLog.protocol != null ? mLog.protocol : "TCP") + (mLog.l7proto != null && !mLog.l7proto.isEmpty() ? "/" + mLog.l7proto : "");
        destIpPort.setText("Destination: " + mLog.dstIp + ":" + mLog.dstPort + " (" + protoStr + ")");

        trafficMetrics.setText("Traffic: " + Utils.formatBytes(mLog.bytesSent) + " sent • " + Utils.formatBytes(mLog.bytesRcvd) + " received");

        String geo = "";
        if(mLog.country != null && !mLog.country.isEmpty()) geo += "Country: " + mLog.country;
        if(mLog.asn != null && !mLog.asn.isEmpty()) geo += (geo.isEmpty() ? "" : " • ") + mLog.asn;
        if(!geo.isEmpty()) {
            geoInfo.setText(geo);
            geoInfo.setVisibility(View.VISIBLE);
        } else {
            geoInfo.setVisibility(View.GONE);
        }

        // Hash
        if(mLog.payloadHash != null && !mLog.payloadHash.isEmpty()) {
            hashValue.setText(mLog.payloadHash);
            btnCopyHash.setOnClickListener(v -> {
                Utils.copyToClipboard(requireContext(), mLog.payloadHash);
                Toast.makeText(requireContext(), "Hash copied to clipboard", Toast.LENGTH_SHORT).show();
            });
        } else {
            hashValue.setText("No payload hash available");
            btnCopyHash.setVisibility(View.GONE);
        }

        // Threat Intelligence Lookups
        btnVirusTotal.setOnClickListener(v -> {
            if(mLog.domainOrUrl != null && !mLog.domainOrUrl.isEmpty()) {
                ThreatIntelManager.openVirusTotalAuto(requireContext(), mLog.domainOrUrl, "DOMAIN");
            } else if(mLog.payloadHash != null && !mLog.payloadHash.isEmpty()) {
                ThreatIntelManager.openVirusTotalAuto(requireContext(), mLog.payloadHash, "HASH");
            } else if(mLog.dstIp != null && !mLog.dstIp.isEmpty()) {
                ThreatIntelManager.openVirusTotalAuto(requireContext(), mLog.dstIp, "IP");
            } else {
                Toast.makeText(requireContext(), "No indicator available for lookup", Toast.LENGTH_SHORT).show();
            }
        });

        btnOtx.setOnClickListener(v -> {
            if(mLog.domainOrUrl != null && !mLog.domainOrUrl.isEmpty()) {
                ThreatIntelManager.openOtxAuto(requireContext(), mLog.domainOrUrl, "DOMAIN");
            } else if(mLog.payloadHash != null && !mLog.payloadHash.isEmpty()) {
                ThreatIntelManager.openOtxAuto(requireContext(), mLog.payloadHash, "HASH");
            } else if(mLog.dstIp != null && !mLog.dstIp.isEmpty()) {
                ThreatIntelManager.openOtxAuto(requireContext(), mLog.dstIp, "IP");
            } else {
                Toast.makeText(requireContext(), "No indicator available for lookup", Toast.LENGTH_SHORT).show();
            }
        });

        MaterialButton btnAiTriage = root.findViewById(R.id.btn_ai_triage_flow);
        if (btnAiTriage != null) {
            btnAiTriage.setOnClickListener(v -> {
                com.kotsafe.security.ai.AiConfig aiConfig = new com.kotsafe.security.ai.AiConfig(requireContext());
                if (!aiConfig.isAiEnabled()) {
                    Toast.makeText(requireContext(), "Please enable AI Protection in Settings first", Toast.LENGTH_SHORT).show();
                    return;
                }
                if (!aiConfig.canAccessFirewall()) {
                    Toast.makeText(requireContext(), "Enable 'Allow Access to Firewall & MITRE Alerts' in AI Protection Settings", Toast.LENGTH_SHORT).show();
                    return;
                }
                btnAiTriage.setEnabled(false);
                btnAiTriage.setText("🤖 Analyzing with AI...");
                AlertRecord dummy = new AlertRecord(
                        "fw_" + System.currentTimeMillis(),
                        System.currentTimeMillis(),
                        AlertRecord.Severity.MEDIUM,
                        AlertRecord.AlertType.FIREWALL_BLOCK,
                        "Firewall Event: " + (mLog.domainOrUrl != null ? mLog.domainOrUrl : mLog.dstIp),
                        "Action=" + mLog.action + ", Destination=" + mLog.dstIp + ":" + mLog.dstPort
                                + ", Protocol=" + mLog.protocol + ", PayloadHash=" + mLog.payloadHash,
                        mLog.appName != null ? mLog.appName : "UID " + mLog.uid
                );
                com.kotsafe.security.ai.AiClientEngine.getInstance(requireContext()).analyzeAlert(dummy, new com.kotsafe.security.ai.AiClientEngine.AlertTriageCallback() {
                    @Override
                    public void onResult(com.kotsafe.security.ai.AiClientEngine.AlertTriageResult result) {
                        if (!isAdded() || getContext() == null) return;
                        btnAiTriage.setEnabled(true);
                        btnAiTriage.setText("🤖 AI Analysis Result");
                        new androidx.appcompat.app.AlertDialog.Builder(requireContext())
                                .setTitle("🤖 AI Threat Assessment")
                                .setMessage("• Verdict: " + result.verdict
                                        + "\n• Malicious Probability: " + result.maliciousProbability + "%"
                                        + " (False Positive: " + (100 - result.maliciousProbability) + "%)"
                                        + "\n\n• Analysis:\n" + result.reasoning
                                        + "\n\n• Recommendation:\n" + result.recommendation)
                                .setPositiveButton("OK", null)
                                .show();
                    }

                    @Override
                    public void onError(String error) {
                        if (!isAdded() || getContext() == null) return;
                        btnAiTriage.setEnabled(true);
                        btnAiTriage.setText("🤖 AI Threat Analysis (Retry)");
                        Toast.makeText(requireContext(), "AI Error: " + error, Toast.LENGTH_LONG).show();
                    }
                });
            });
        }

        btnManageNac.setOnClickListener(v -> {
            dismiss();
            int targetUid = (resolvedApp != null && resolvedApp.getUid() > 0) ? resolvedApp.getUid() : mLog.uid;
            if(targetUid > 0) {
                Intent intent = new Intent(requireContext(), AppDetailsActivity.class);
                intent.putExtra(AppDetailsActivity.APP_UID_EXTRA, targetUid);
                startActivity(intent);
            }
        });

        return root;
    }
}
