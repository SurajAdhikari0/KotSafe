/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.views;

import android.content.res.ColorStateList;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.ScanReportEntry;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * Bottom Sheet displaying full structured audit reports for background and manual scans.
 */
public class ScanReportDetailsDialog extends BottomSheetDialogFragment {
    public static final String TAG = "ScanReportDetailsDialog";
    private static final String ARG_REPORT = "arg_report";

    private ScanReportEntry mReport;

    public static ScanReportDetailsDialog newInstance(ScanReportEntry report) {
        ScanReportDetailsDialog dialog = new ScanReportDetailsDialog();
        Bundle args = new Bundle();
        args.putSerializable(ARG_REPORT, report);
        dialog.setArguments(args);
        return dialog;
    }

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (getArguments() != null) {
            mReport = (ScanReportEntry) getArguments().getSerializable(ARG_REPORT);
        }
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.dialog_scan_report_details, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        if (mReport == null) {
            dismiss();
            return;
        }

        ImageView iconShield = view.findViewById(R.id.report_icon_shield);
        TextView tvTitle = view.findViewById(R.id.report_title);
        TextView tvTimestamp = view.findViewById(R.id.report_timestamp);
        TextView tvBadgeTrigger = view.findViewById(R.id.report_badge_trigger);

        MaterialCardView cardVerdict = view.findViewById(R.id.report_card_verdict);
        TextView tvScore = view.findViewById(R.id.report_tv_score);
        TextView tvVerdictTitle = view.findViewById(R.id.report_tv_verdict_title);
        TextView tvVerdictDesc = view.findViewById(R.id.report_tv_verdict_desc);

        TextView valApps = view.findViewById(R.id.report_val_apps);
        TextView valSplits = view.findViewById(R.id.report_val_splits);
        TextView valStorage = view.findViewById(R.id.report_val_storage);
        TextView valNetwork = view.findViewById(R.id.report_val_network);
        TextView valDuration = view.findViewById(R.id.report_val_duration);
        TextView tvSummary = view.findViewById(R.id.report_summary_text);
        MaterialButton btnClose = view.findViewById(R.id.report_btn_close);

        // Header
        String tierName = mReport.scanMode != null ? mReport.scanMode : "DEEP";
        tvTitle.setText("🛡️ " + tierName + " Scan Audit Report");

        SimpleDateFormat sdf = new SimpleDateFormat("dd MMM yyyy, hh:mm a", Locale.getDefault());
        String timeStr = sdf.format(new Date(mReport.timestamp));
        String triggerStr = mReport.isBackground ? "⚙️ Automatic Daily Background" : "👤 Manual Interactive";
        tvTimestamp.setText(timeStr + " • " + triggerStr);

        if (mReport.isBackground) {
            tvBadgeTrigger.setText("DAILY AUTO");
            tvBadgeTrigger.setTextColor(0xFF39D3BB);
        } else {
            tvBadgeTrigger.setText("MANUAL");
            tvBadgeTrigger.setTextColor(0xFF58A6FF);
        }

        // Score & Verdict
        tvScore.setText(String.valueOf(mReport.securityScore));
        if (mReport.threatsDetected > 0) {
            cardVerdict.setStrokeColor(0xFFF85149);
            cardVerdict.setCardBackgroundColor(0x1AF85149);
            tvScore.setTextColor(0xFFF85149);
            iconShield.setImageResource(R.drawable.ic_exclamation_triangle_solid);
            iconShield.setImageTintList(ColorStateList.valueOf(0xFFF85149));
            tvVerdictTitle.setText("⚠️ Threats Require Attention");
            tvVerdictDesc.setText(mReport.threatsDetected + " confirmed threat(s) / suspicious artifacts identified.");
        } else if (mReport.suspiciousDetected > 0 || mReport.securityScore < 80) {
            cardVerdict.setStrokeColor(0xFFF0B429);
            cardVerdict.setCardBackgroundColor(0x1AF0B429);
            tvScore.setTextColor(0xFFF0B429);
            iconShield.setImageResource(R.drawable.ic_shield);
            iconShield.setImageTintList(ColorStateList.valueOf(0xFFF0B429));
            tvVerdictTitle.setText("⚡ Suspicious Items Monitored");
            tvVerdictDesc.setText(mReport.suspiciousDetected + " low-risk/suspicious indicators tracked.");
        } else {
            cardVerdict.setStrokeColor(0xFF2EA44F);
            cardVerdict.setCardBackgroundColor(0x1A2EA44F);
            tvScore.setTextColor(0xFF2EA44F);
            iconShield.setImageResource(R.drawable.ic_shield);
            iconShield.setImageTintList(ColorStateList.valueOf(0xFF2EA44F));
            tvVerdictTitle.setText("Clean & Protected");
            tvVerdictDesc.setText("Zero malware, spyware, C2 intrusions, or corrupted split APKs.");
        }

        // Telemetry values
        valApps.setText(mReport.packagesScanned + " packages");
        valSplits.setText(mReport.splitsScanned + " split APKs");
        valStorage.setText(mReport.storageScanned + " files");
        valNetwork.setText((mReport.ipsScanned + mReport.urlsScanned) + " endpoints");

        if (mReport.durationMs > 0) {
            double secs = mReport.durationMs / 1000.0;
            valDuration.setText(String.format(Locale.US, "%.1f seconds", secs));
        } else {
            valDuration.setText("Instant (< 1s)");
        }

        if (mReport.summary != null && !mReport.summary.isEmpty()) {
            tvSummary.setText(mReport.summary);
        }

        // AI Final Layer Threat Verification
        TextView aiVerdictBadge = view.findViewById(R.id.ai_verdict_badge);
        TextView tvAiReportStatus = view.findViewById(R.id.tv_ai_report_status);
        TextView tvAiReportRecommendation = view.findViewById(R.id.tv_ai_report_recommendation);

        com.kotsafe.security.ai.AiConfig aiConfig = new com.kotsafe.security.ai.AiConfig(requireContext());
        if (!aiConfig.isAiEnabled()) {
            if (aiVerdictBadge != null) {
                aiVerdictBadge.setText("DISABLED");
                aiVerdictBadge.setTextColor(0xFF8B949E);
            }
            if (tvAiReportStatus != null) {
                tvAiReportStatus.setText("AI Final Layer Verification is disabled.");
            }
            if (tvAiReportRecommendation != null) {
                tvAiReportRecommendation.setText("Enable in Settings -> AI Protection to verify threats & false positives.");
            }
        } else if (!aiConfig.canAccessAntivirus()) {
            if (aiVerdictBadge != null) {
                aiVerdictBadge.setText("ACCESS OFF");
                aiVerdictBadge.setTextColor(0xFFF0B429);
            }
            if (tvAiReportStatus != null) {
                tvAiReportStatus.setText("Antivirus data access toggle is disabled.");
            }
            if (tvAiReportRecommendation != null) {
                tvAiReportRecommendation.setText("Enable 'Allow Access to Antivirus Reports' in AI Protection Settings.");
            }
        } else {
            if (aiVerdictBadge != null) {
                aiVerdictBadge.setText("ANALYZING");
                aiVerdictBadge.setTextColor(0xFF38BDF8);
            }
            if (tvAiReportStatus != null) {
                tvAiReportStatus.setText("Evaluating heuristic indicators, packages, and false-positive probabilities...");
            }
            com.kotsafe.security.ai.AiClientEngine.getInstance(requireContext())
                    .analyzeAntivirusReport(mReport, new com.kotsafe.security.ai.AiClientEngine.AvTriageCallback() {
                        @Override
                        public void onResult(com.kotsafe.security.ai.AiClientEngine.AvTriageResult result) {
                            if (!isAdded() || getContext() == null) return;
                            if (aiVerdictBadge != null) {
                                aiVerdictBadge.setText("RISK " + result.threatRiskScore + "%");
                                if (result.threatRiskScore >= 70) {
                                    aiVerdictBadge.setTextColor(0xFFF85149);
                                } else if (result.threatRiskScore >= 30) {
                                    aiVerdictBadge.setTextColor(0xFFF0B429);
                                } else {
                                    aiVerdictBadge.setTextColor(0xFF2EA44F);
                                }
                            }
                            if (tvAiReportStatus != null) {
                                tvAiReportStatus.setText(result.aiAssessment + " (False Positive Likelihood: " + result.falsePositiveChance + "%)");
                            }
                            if (tvAiReportRecommendation != null) {
                                tvAiReportRecommendation.setText("Action: " + result.recommendedAction);
                            }
                        }

                        @Override
                        public void onError(String error) {
                            if (!isAdded() || getContext() == null) return;
                            if (aiVerdictBadge != null) {
                                aiVerdictBadge.setText("OFFLINE");
                                aiVerdictBadge.setTextColor(0xFF8B949E);
                            }
                            if (tvAiReportStatus != null) {
                                tvAiReportStatus.setText("AI analysis unavailable: " + error);
                            }
                        }
                    });
        }

        btnClose.setOnClickListener(v -> dismiss());
    }
}
