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
 * Copyright 2026 KotSafe Cyber Security Project
 */

package com.kotsafe.security.views;

import android.app.Dialog;
import android.content.Context;
import android.graphics.Color;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;

import com.kotsafe.security.R;
import com.kotsafe.security.model.DetectionRule;
import com.kotsafe.security.model.DetectionRulesManager;
import com.kotsafe.security.model.Prefs;
import com.google.android.material.bottomsheet.BottomSheetDialog;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;

import java.text.DateFormat;
import java.util.Date;
import java.util.List;

public class DetectionRulesDialog {

    public interface OnRulesUpdatedListener {
        void onRulesUpdated(int count);
    }

    public static void show(@NonNull Context context, OnRulesUpdatedListener listener) {
        BottomSheetDialog dialog = new BottomSheetDialog(context);
        View view = LayoutInflater.from(context).inflate(R.layout.dialog_detection_rules, null);
        dialog.setContentView(view);

        TextView tvHeaderSubtitle = view.findViewById(R.id.tv_rules_header_subtitle);
        TextView tvSourceUrl = view.findViewById(R.id.tv_rules_source_url);
        TextView tvSyncStatus = view.findViewById(R.id.tv_rules_sync_status);
        MaterialButton btnSyncGithub = view.findViewById(R.id.btn_dialog_sync_github);
        LinearLayout containerRules = view.findViewById(R.id.container_detection_rules_list);
        MaterialButton btnClose = view.findViewById(R.id.btn_close_rules_dialog);

        DetectionRulesManager manager = DetectionRulesManager.getInstance(context);

        String repoUrl = Prefs.getDetectionRulesGithubUrl(context);
        tvSourceUrl.setText("Source: " + repoUrl);

        Runnable refreshUI = () -> {
            List<DetectionRule> rules = manager.getRules();
            tvHeaderSubtitle.setText(rules.size() + " active threat detection & IOC rules");

            long lastSync = Prefs.getDetectionRulesLastSyncTime(context);
            if (lastSync > 0) {
                String timeStr = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(new Date(lastSync));
                tvSyncStatus.setText("Status: Synced with GitHub on " + timeStr);
                tvSyncStatus.setTextColor(Color.parseColor("#3FB950"));
            } else {
                tvSyncStatus.setText("Status: Active • Bundled default rules loaded");
                tvSyncStatus.setTextColor(Color.parseColor("#38BDF8"));
            }

            containerRules.removeAllViews();
            for (DetectionRule rule : rules) {
                View item = LayoutInflater.from(context).inflate(R.layout.item_detection_rule_card, containerRules, false);

                TextView tvRuleId = item.findViewById(R.id.tv_rule_id);
                TextView tvRuleSeverity = item.findViewById(R.id.tv_rule_severity);
                TextView tvRuleName = item.findViewById(R.id.tv_rule_name);
                TextView tvRuleSchedule = item.findViewById(R.id.tv_rule_schedule);
                TextView tvRuleDesc = item.findViewById(R.id.tv_rule_desc);
                TextView tvRuleMitre = item.findViewById(R.id.tv_rule_mitre);
                TextView tvRuleRemediation = item.findViewById(R.id.tv_rule_remediation);

                tvRuleId.setText(rule.id);
                tvRuleSeverity.setText(rule.severity);
                if (DetectionRule.SEVERITY_CRITICAL.equalsIgnoreCase(rule.severity)) {
                    tvRuleSeverity.setTextColor(Color.parseColor("#F85149"));
                } else if (DetectionRule.SEVERITY_HIGH.equalsIgnoreCase(rule.severity)) {
                    tvRuleSeverity.setTextColor(Color.parseColor("#F0883E"));
                } else {
                    tvRuleSeverity.setTextColor(Color.parseColor("#D29922"));
                }

                tvRuleName.setText(rule.name);
                tvRuleSchedule.setText("TRIGGER: " + rule.triggerSchedule + " (" + rule.target.toUpperCase() + ")");
                tvRuleDesc.setText(rule.description);

                TextView tvRuleIocs = item.findViewById(R.id.tv_rule_iocs);

                if (!rule.mitreTechniques.isEmpty()) {
                    tvRuleMitre.setVisibility(View.VISIBLE);
                    tvRuleMitre.setText("MITRE ATT&CK: " + android.text.TextUtils.join(", ", rule.mitreTechniques));
                } else {
                    tvRuleMitre.setVisibility(View.GONE);
                }

                if (rule.hasIocs()) {
                    tvRuleIocs.setVisibility(View.VISIBLE);
                    tvRuleIocs.setText("🎯 Active IOCs: " + rule.getIocsSummary());
                } else {
                    tvRuleIocs.setVisibility(View.GONE);
                }

                if (rule.remediation != null && !rule.remediation.isEmpty()) {
                    tvRuleRemediation.setVisibility(View.VISIBLE);
                    tvRuleRemediation.setText("Remediation: " + rule.remediation);
                } else {
                    tvRuleRemediation.setVisibility(View.GONE);
                }

                containerRules.addView(item);
            }
        };

        refreshUI.run();

        btnSyncGithub.setOnClickListener(v -> {
            btnSyncGithub.setEnabled(false);
            btnSyncGithub.setText("Syncing with GitHub...");
            manager.syncRulesFromGitHub(new DetectionRulesManager.SyncCallback() {
                @Override
                public void onSuccess(int rulesCount) {
                    btnSyncGithub.setEnabled(true);
                    btnSyncGithub.setText("Sync Rules From GitHub Now");
                    Toast.makeText(context, "Successfully updated " + rulesCount + " detection rules from GitHub", Toast.LENGTH_LONG).show();
                    refreshUI.run();
                    if (listener != null) {
                        listener.onRulesUpdated(rulesCount);
                    }
                }

                @Override
                public void onError(String errorMessage) {
                    btnSyncGithub.setEnabled(true);
                    btnSyncGithub.setText("Sync Rules From GitHub Now");
                    Toast.makeText(context, "GitHub Sync failed (" + errorMessage + "). Preserving local rules.", Toast.LENGTH_SHORT).show();
                    refreshUI.run();
                }
            });
        });

        btnClose.setOnClickListener(v -> dialog.dismiss());
        dialog.show();
    }
}
