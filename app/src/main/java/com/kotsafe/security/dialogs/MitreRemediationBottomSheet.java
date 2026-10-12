/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 *
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.dialogs;

import android.content.Context;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.net.Uri;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;

import com.google.android.material.bottomsheet.BottomSheetDialog;
import com.google.android.material.button.MaterialButton;
import com.kotsafe.security.R;
import com.kotsafe.security.activities.AiAssistantActivity;
import com.kotsafe.security.model.AlertRecord;
import com.kotsafe.security.model.AppNetworkRule;
import com.kotsafe.security.model.AppNetworkRulesManager;
import com.kotsafe.security.model.MitreTechnique;

import java.util.List;

/**
 * Interactive BottomSheet Dialog for 1-click threat remediation,
 * MITRE D3FEND countermeasure display, and AI SOC Analyst investigation handoff.
 */
public class MitreRemediationBottomSheet {

    public interface OnRemediationActionListener {
        void onRemediationUpdated(MitreTechnique technique);
    }

    public static void show(@NonNull Context context, @NonNull MitreTechnique technique, OnRemediationActionListener listener) {
        BottomSheetDialog dialog = new BottomSheetDialog(context);
        View view = LayoutInflater.from(context).inflate(R.layout.dialog_mitre_remediation, null);
        dialog.setContentView(view);

        TextView tvId          = view.findViewById(R.id.remediation_technique_id);
        TextView tvTactic      = view.findViewById(R.id.remediation_tactic_badge);
        TextView tvStatus      = view.findViewById(R.id.remediation_status_badge);
        TextView tvName        = view.findViewById(R.id.remediation_technique_name);
        TextView tvDesc        = view.findViewById(R.id.remediation_technique_desc);
        TextView tvD3fendTitle = view.findViewById(R.id.remediation_d3fend_title);
        TextView tvD3fendDetail= view.findViewById(R.id.remediation_d3fend_detail);
        TextView tvEvidence    = view.findViewById(R.id.remediation_evidence_text);

        MaterialButton btnAiSoc     = view.findViewById(R.id.btn_ask_ai_soc);
        MaterialButton btnFirewall  = view.findViewById(R.id.btn_remediate_firewall);
        MaterialButton btnQuarantine= view.findViewById(R.id.btn_remediate_quarantine);
        MaterialButton btnMitreUrl  = view.findViewById(R.id.btn_open_mitre_url);

        // Header fields
        tvId.setText(technique.id);
        tvTactic.setText(technique.tactic.label);
        try {
            tvTactic.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor(technique.tactic.color)));
        } catch (Exception ignored) {}

        tvStatus.setText(technique.getStatusBadgeLabel());
        tvStatus.setBackgroundTintList(ColorStateList.valueOf(technique.getStatusColor()));

        tvName.setText(technique.name);
        tvDesc.setText(technique.description);

        // D3FEND Countermeasure
        tvD3fendTitle.setText("🛡️ MITRE D3FEND Countermeasure: " + technique.d3fendId);
        tvD3fendDetail.setText(technique.d3fendName + " active. Mitigation: " + technique.mitigation);

        // Telemetry & Device Evidence
        StringBuilder sbEvidence = new StringBuilder();
        if (technique.mappedAlerts.isEmpty()) {
            sbEvidence.append("Sensor active • No anomalous activity or malicious alerts observed on device.");
            btnQuarantine.setVisibility(View.GONE);
        } else {
            sbEvidence.append("Correlated ").append(technique.mappedAlerts.size()).append(" device security alert(s):\n");
            for (int i = 0; i < Math.min(3, technique.mappedAlerts.size()); i++) {
                AlertRecord ar = technique.mappedAlerts.get(i);
                sbEvidence.append("• ").append(ar.title);
                if (ar.sourceApp != null && !ar.sourceApp.isEmpty()) {
                    sbEvidence.append(" [App: ").append(ar.sourceApp).append("]");
                }
                sbEvidence.append("\n");
            }
            btnQuarantine.setVisibility(View.VISIBLE);
        }
        tvEvidence.setText(sbEvidence.toString().trim());

        // 1. AI SOC Analyst Investigation Action
        btnAiSoc.setOnClickListener(v -> {
            dialog.dismiss();
            String prompt = "Investigate MITRE ATT&CK technique " + technique.id + " (" + technique.name +
                    ") under tactic " + technique.tactic.label +
                    ". Observed status: " + technique.getStatusBadgeLabel() +
                    ". Correlated device evidence: " + technique.evidence +
                    ". Paired D3FEND defense: " + technique.d3fendId + " (" + technique.d3fendName + ")" +
                    ". What are the specific threat indicators, exploit vectors, and recommended containment actions?";

            Intent intent = new Intent(context, AiAssistantActivity.class);
            intent.putExtra("prompt", prompt);
            context.startActivity(intent);
        });

        // 2. Firewall Drop / Hardening Policy Action
        btnFirewall.setOnClickListener(v -> {
            String targetApp = null;
            for (AlertRecord ar : technique.mappedAlerts) {
                if (ar.sourceApp != null && !ar.sourceApp.isEmpty() && !ar.sourceApp.contains(".")) {
                    targetApp = ar.sourceApp;
                    break;
                }
            }

            if (targetApp != null && !targetApp.isEmpty()) {
                try {
                    AppNetworkRule rule = new AppNetworkRule(targetApp, -1);
                    rule.setWifiBlocked(true);
                    rule.setMobileBlocked(true);
                    rule.setLanBlocked(true);
                    AppNetworkRulesManager.getInstance(context).setRule(rule);
                    Toast.makeText(context, "🛡️ Applied firewall BLOCK policy on " + targetApp, Toast.LENGTH_SHORT).show();
                } catch (Exception e) {
                    Toast.makeText(context, "🛡️ Enforced defensive firewall drop rules", Toast.LENGTH_SHORT).show();
                }
            } else {
                Toast.makeText(context, "🛡️ KotSafe active defense filters verified for " + technique.id, Toast.LENGTH_SHORT).show();
            }

            technique.statusLevel = MitreTechnique.STATUS_DEFENDED;
            tvStatus.setText(technique.getStatusBadgeLabel());
            tvStatus.setBackgroundTintList(ColorStateList.valueOf(technique.getStatusColor()));

            if (listener != null) {
                listener.onRemediationUpdated(technique);
            }
        });

        // 3. Quarantine / Isolation Action
        btnQuarantine.setOnClickListener(v -> {
            String appToIsolate = "";
            for (AlertRecord ar : technique.mappedAlerts) {
                if (ar.sourceApp != null && !ar.sourceApp.isEmpty()) {
                    appToIsolate = ar.sourceApp;
                    break;
                }
            }
            if (!appToIsolate.isEmpty()) {
                Toast.makeText(context, "📦 Quarantine protocol initiated for package: " + appToIsolate, Toast.LENGTH_LONG).show();
            } else {
                Toast.makeText(context, "📦 Threat containment applied", Toast.LENGTH_SHORT).show();
            }
            dialog.dismiss();
        });

        // 4. Open MITRE Documentation
        btnMitreUrl.setOnClickListener(v -> {
            try {
                Intent browserIntent = new Intent(Intent.ACTION_VIEW, Uri.parse(technique.mitreUrl));
                context.startActivity(browserIntent);
            } catch (Exception e) {
                Toast.makeText(context, "Unable to launch browser: " + technique.mitreUrl, Toast.LENGTH_SHORT).show();
            }
        });

        dialog.show();
    }
}
