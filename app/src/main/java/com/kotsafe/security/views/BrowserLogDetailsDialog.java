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

package com.kotsafe.security.views;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;

import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.AdBlockSubscriptionManager;
import com.kotsafe.security.model.BrowserActivityManager.BrowserLogEntry;
import com.kotsafe.security.model.ThreatIntelManager;
import com.kotsafe.security.model.parser.AdvancedLogParser;
import com.kotsafe.security.model.parser.AdvancedLogParser.ParsedPayload;
import com.kotsafe.security.model.parser.AdvancedLogParser.ParsedUrl;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;
import com.google.android.material.button.MaterialButton;

import java.util.Map;

/**
 * Advanced BottomSheet dialog for inspecting detailed browser traffic logs, parsed URLs,
 * query parameters, threat assessments, and payload structures.
 */
public class BrowserLogDetailsDialog extends BottomSheetDialogFragment {
    public static final String TAG = "BrowserLogDetailsDialog";

    private static final String ARG_APP_NAME = "app_name";
    private static final String ARG_HOST = "host";
    private static final String ARG_REMOTE_IP = "remote_ip";
    private static final String ARG_REMOTE_PORT = "remote_port";
    private static final String ARG_IS_DECRYPTED = "is_decrypted";
    private static final String ARG_URL = "url";
    private static final String ARG_PAYLOAD = "payload";
    private static final String ARG_TLS_VERSION = "tls_version";
    private static final String ARG_CIPHER = "cipher";
    private static final String ARG_ENCRYPTED_HEX = "encrypted_hex";
    private static final String ARG_SENT_BYTES = "sent_bytes";
    private static final String ARG_RCVD_BYTES = "rcvd_bytes";
    private static final String ARG_RAW_PAYLOAD = "raw_payload";

    public static BrowserLogDetailsDialog newInstance(@NonNull BrowserLogEntry entry) {
        BrowserLogDetailsDialog dialog = new BrowserLogDetailsDialog();
        Bundle args = new Bundle();
        args.putString(ARG_APP_NAME, entry.appName);
        args.putString(ARG_HOST, entry.hostOrDomain);
        args.putString(ARG_REMOTE_IP, entry.remoteIp);
        args.putInt(ARG_REMOTE_PORT, entry.remotePort);
        args.putBoolean(ARG_IS_DECRYPTED, entry.isDecrypted);
        args.putString(ARG_URL, entry.url);
        args.putString(ARG_PAYLOAD, entry.decryptedPayloadPreview);
        args.putString(ARG_TLS_VERSION, entry.tlsVersion);
        args.putString(ARG_CIPHER, entry.cipherSuite);
        args.putString(ARG_ENCRYPTED_HEX, entry.encryptedHexPreview);
        args.putLong(ARG_SENT_BYTES, entry.sentBytes);
        args.putLong(ARG_RCVD_BYTES, entry.rcvdBytes);
        if (entry.rawPayloadBytes != null) {
            args.putByteArray(ARG_RAW_PAYLOAD, entry.rawPayloadBytes);
        }
        dialog.setArguments(args);
        return dialog;
    }

    @Override
    public int getTheme() {
        return com.google.android.material.R.style.Theme_MaterialComponents_DayNight_BottomSheetDialog;
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.dialog_browser_log_details, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        Bundle args = getArguments();
        if (args == null) {
            dismiss();
            return;
        }

        String appName = args.getString(ARG_APP_NAME, "Browser");
        String host = args.getString(ARG_HOST, "");
        String remoteIp = args.getString(ARG_REMOTE_IP, "");
        int remotePort = args.getInt(ARG_REMOTE_PORT, 443);
        boolean isDecrypted = args.getBoolean(ARG_IS_DECRYPTED, false);
        String url = args.getString(ARG_URL, "");
        String payload = args.getString(ARG_PAYLOAD, "");
        String tlsVersion = args.getString(ARG_TLS_VERSION, "TLSv1.3");
        String cipher = args.getString(ARG_CIPHER, "TLS_AES_256_GCM_SHA384");
        String encryptedHex = args.getString(ARG_ENCRYPTED_HEX, "");
        long sentBytes = args.getLong(ARG_SENT_BYTES, 0);
        long rcvdBytes = args.getLong(ARG_RCVD_BYTES, 0);
        byte[] rawPayload = args.getByteArray(ARG_RAW_PAYLOAD);

        ImageView btnClose = view.findViewById(R.id.btn_close);
        TextView tvTitle = view.findViewById(R.id.tv_detail_title);
        TextView tvStatusBadge = view.findViewById(R.id.tv_detail_status_badge);
        TextView tvProtoPill = view.findViewById(R.id.tv_detail_proto_pill);
        TextView tvBytesPill = view.findViewById(R.id.tv_detail_bytes_pill);
        TextView tvHostIp = view.findViewById(R.id.tv_detail_host_ip);

        // Security Assessment Views
        TextView tvRiskBadge = view.findViewById(R.id.tv_risk_badge);
        TextView tvRiskScore = view.findViewById(R.id.tv_risk_score);
        TextView tvRiskFlags = view.findViewById(R.id.tv_risk_flags);

        // Decrypted Views
        View layoutDecrypted = view.findViewById(R.id.layout_dialog_decrypted);
        TextView tvFullUrl = view.findViewById(R.id.tv_dialog_full_url);
        TextView tvUrlBreakdown = view.findViewById(R.id.tv_dialog_url_breakdown);
        View layoutQueryParamsSection = view.findViewById(R.id.layout_query_params_section);
        LinearLayout containerQueryParams = view.findViewById(R.id.container_query_params);
        TextView tvPayload = view.findViewById(R.id.tv_dialog_payload);

        // Encrypted Views
        View layoutEncrypted = view.findViewById(R.id.layout_dialog_encrypted);
        TextView tvTlsSpecs = view.findViewById(R.id.tv_dialog_tls_specs);
        TextView tvCiphertext = view.findViewById(R.id.tv_dialog_ciphertext);

        // Buttons
        MaterialButton btnThreatIntel = view.findViewById(R.id.btn_threat_intel);
        MaterialButton btnBlockHost = view.findViewById(R.id.btn_block_host);
        MaterialButton btnCopySecondary = view.findViewById(R.id.btn_copy_secondary);
        MaterialButton btnCopyPrimary = view.findViewById(R.id.btn_copy_primary);

        btnClose.setOnClickListener(v -> dismiss());

        tvTitle.setText(appName + " Traffic");
        tvProtoPill.setText(AdvancedLogParser.resolvePortService(remotePort) + " (:" + remotePort + ")");
        tvBytesPill.setText(Utils.formatBytes(sentBytes + rcvdBytes));
        tvHostIp.setText("Target: " + host + " (" + remoteIp + ":" + remotePort + ")");

        // Advanced URL and Security Risk parsing
        ParsedUrl parsed = AdvancedLogParser.parseUrl(!url.isEmpty() ? url : "https://" + host);

        // Security Assessment rendering
        if (tvRiskBadge != null && parsed.riskAssessment != null) {
            boolean isConfirmedThreat = parsed.riskAssessment.riskLevel == AdvancedLogParser.RiskLevel.SUSPICIOUS
                    || parsed.riskAssessment.riskLevel == AdvancedLogParser.RiskLevel.HIGH_RISK;

            if (isConfirmedThreat) {
                tvRiskBadge.setText(parsed.riskAssessment.riskLevel.label);
                tvRiskBadge.setTextColor(parsed.riskAssessment.riskLevel.color);
                tvRiskScore.setText("Risk Score: " + parsed.riskAssessment.riskScore + "/100 (" + parsed.riskAssessment.riskLevel.label + ")");

                if (!parsed.riskAssessment.riskFlags.isEmpty()) {
                    StringBuilder flagsSb = new StringBuilder();
                    for (String flag : parsed.riskAssessment.riskFlags) {
                        flagsSb.append("• ").append(flag).append("\n");
                    }
                    tvRiskFlags.setText(flagsSb.toString().trim());
                } else {
                    tvRiskFlags.setText("• Confirmed suspicious activity detected.");
                }
            } else {
                tvRiskBadge.setText("CLEAN");
                tvRiskBadge.setTextColor(ContextCompat.getColor(requireContext(), R.color.badgeActiveFg));
                tvRiskScore.setText("Risk Score: 0/100 (CLEAN)");
                tvRiskFlags.setText("• No suspicious or malicious activity detected.\n• Verified benign web connection.");
            }
        }

        if (isDecrypted) {
            tvStatusBadge.setText("DECRYPTED");
            tvStatusBadge.setBackgroundResource(R.drawable.badge_pill_active);
            tvStatusBadge.setTextColor(ContextCompat.getColor(requireContext(), R.color.badgeActiveFg));

            layoutDecrypted.setVisibility(View.VISIBLE);
            layoutEncrypted.setVisibility(View.GONE);

            tvFullUrl.setText(parsed.rawUrl);
            tvUrlBreakdown.setText(String.format("Scheme: %s | Host: %s | Port: %d (%s) | Path: %s",
                    parsed.scheme, parsed.host, parsed.port, parsed.portService, parsed.path));

            // Populate Query Parameters table
            if (parsed.getQueryParamCount() > 0 && containerQueryParams != null && layoutQueryParamsSection != null) {
                layoutQueryParamsSection.setVisibility(View.VISIBLE);
                containerQueryParams.removeAllViews();
                LayoutInflater inflater = LayoutInflater.from(requireContext());

                for (Map.Entry<String, String> qp : parsed.queryParameters.entrySet()) {
                    View paramRow = inflater.inflate(R.layout.item_query_param, containerQueryParams, false);
                    TextView tvKey = paramRow.findViewById(R.id.tv_param_key);
                    TextView tvTag = paramRow.findViewById(R.id.tv_param_tag);
                    TextView tvVal = paramRow.findViewById(R.id.tv_param_value);
                    ImageView btnCopyP = paramRow.findViewById(R.id.btn_copy_param);

                    tvKey.setText(qp.getKey());
                    tvVal.setText(qp.getValue());

                    if (parsed.trackingParameters.containsKey(qp.getKey())) {
                        tvTag.setVisibility(View.VISIBLE);
                        tvTag.setText("TRACKER");
                        tvTag.setTextColor(ContextCompat.getColor(requireContext(), R.color.warning));
                    } else if (parsed.sensitiveParameters.containsKey(qp.getKey())) {
                        tvTag.setVisibility(View.VISIBLE);
                        tvTag.setText("SENSITIVE");
                        tvTag.setTextColor(ContextCompat.getColor(requireContext(), R.color.danger));
                    } else {
                        tvTag.setVisibility(View.GONE);
                    }

                    btnCopyP.setOnClickListener(v -> copyToClipboard(qp.getKey(), qp.getValue()));
                    containerQueryParams.addView(paramRow);
                }
            } else if (layoutQueryParamsSection != null) {
                layoutQueryParamsSection.setVisibility(View.GONE);
            }

            // Payload parsing
            if (rawPayload != null && rawPayload.length > 0) {
                ParsedPayload parsedPayload = AdvancedLogParser.parsePayload(rawPayload);
                if (parsedPayload.isJson && parsedPayload.formattedJson != null) {
                    tvPayload.setText(parsedPayload.formattedJson);
                } else {
                    tvPayload.setText(parsedPayload.textPreview);
                }
            } else {
                tvPayload.setText(payload.isEmpty() ? "<No cleartext body recorded>" : payload);
            }

            btnCopySecondary.setText("Copy Host");
            btnCopySecondary.setOnClickListener(v -> copyToClipboard("Host", host));

            btnCopyPrimary.setText("Copy URL");
            btnCopyPrimary.setOnClickListener(v -> copyToClipboard("URL", url));
        } else {
            tvStatusBadge.setText("ENCRYPTED (TLS)");
            tvStatusBadge.setBackgroundResource(R.drawable.badge_pill_closed);
            tvStatusBadge.setTextColor(ContextCompat.getColor(requireContext(), R.color.badgeClosedFg));

            layoutDecrypted.setVisibility(View.GONE);
            layoutEncrypted.setVisibility(View.VISIBLE);

            String specs = "Protocol: " + tlsVersion + "\n" +
                    "Cipher: " + cipher + "\n" +
                    "SNI Target Domain: " + host + "\n" +
                    "Port: " + remotePort + " (" + AdvancedLogParser.resolvePortService(remotePort) + ")\n" +
                    "Status: Protected by TLS cryptographic layer";
            tvTlsSpecs.setText(specs);

            if (rawPayload != null && rawPayload.length > 0) {
                tvCiphertext.setText(AdvancedLogParser.formatHexAsciiDump(rawPayload, 256));
            } else {
                tvCiphertext.setText(encryptedHex.isEmpty() ? "<No raw ciphertext payload captured>" : encryptedHex);
            }

            btnCopySecondary.setText("Copy Host");
            btnCopySecondary.setOnClickListener(v -> copyToClipboard("Host", host));

            btnCopyPrimary.setText("Copy Hex");
            btnCopyPrimary.setOnClickListener(v -> copyToClipboard("Encrypted Hex", encryptedHex));
        }

        // Action: Threat Intelligence Lookup
        btnThreatIntel.setOnClickListener(v -> {
            String target = (url != null && !url.isEmpty()) ? url : host;
            ThreatIntelManager.openVirusTotalAuto(requireContext(), target, "DOMAIN");
        });

        // Action: Block Host in AdBlock / Firewall
        btnBlockHost.setOnClickListener(v -> {
            AdBlockSubscriptionManager.getInstance(requireContext()).addToBlacklist(host);
            Toast.makeText(requireContext(), "Domain '" + host + "' added to blocklist", Toast.LENGTH_SHORT).show();
            dismiss();
        });
    }

    private void copyToClipboard(String label, String text) {
        if (!isAdded()) return;
        ClipboardManager cm = (ClipboardManager) requireContext().getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm != null) {
            ClipData clip = ClipData.newPlainText(label, text);
            cm.setPrimaryClip(clip);
            Toast.makeText(requireContext(), label + " copied to clipboard", Toast.LENGTH_SHORT).show();
        }
    }
}
