/*
 * This file is part of KotSafe / KotSafe Cyber Security Project.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.views;

import android.app.Dialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.view.ViewCompat;
import androidx.fragment.app.FragmentManager;

import com.kotsafe.security.R;
import com.kotsafe.security.ai.ThreatInvestigatorEngine;
import com.kotsafe.security.model.AlertRecord;
import com.kotsafe.security.model.SecurityBlocklistManager;
import com.kotsafe.security.model.ThreatIntelManager;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.google.android.material.bottomsheet.BottomSheetDialog;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;
import com.google.android.material.button.MaterialButton;

import java.util.Locale;

/**
 * Interactive Deep Threat Investigation BottomSheet Dialog.
 * Displays correlated findings across AlienVault OTX, ThreatFox, URLhaus,
 * and synthesizes AI indicator motivation, malware attribution, and 1-tap firewall blocking.
 */
public class ThreatInvestigationDialog extends BottomSheetDialogFragment {

    private static final String TAG = "ThreatInvestigateDialog";
    private static final String ARG_IOC_VALUE = "arg_ioc_value";
    private static final String ARG_IOC_TYPE = "arg_ioc_type";
    private static final String ARG_SOURCE_APP = "arg_source_app";
    private static final String ARG_CONTEXT_INFO = "arg_context_info";

    private String mIocValue;
    private String mIocType;
    private String mSourceApp;
    private String mContextInfo;

    // View References
    private TextView mTvIoc;
    private TextView mTvModeBadge;
    private ProgressBar mProgressBar;
    private TextView mTvScore;
    private TextView mTvLevel;
    private TextView mTvVerdict;
    private TextView mTvDecision;
    private TextView mTvConfidence;
    private View mLayoutMalware;
    private TextView mTvMalwareFamily;
    private TextView mBadgeOtx;
    private TextView mBadgeThreatFox;
    private TextView mBadgeUrlhaus;
    private TextView mBadgeVt;
    private TextView mTvIntelDetails;
    private TextView mTvPurpose;
    private TextView mTvReasoning;
    private TextView mTvRemediation;
    private MaterialButton mBtnBlockFirewall;
    private MaterialButton mBtnIsolateApp;
    private MaterialButton mBtnOpenVt;
    private MaterialButton mBtnOpenOtx;
    private MaterialButton mBtnShareDossier;
    private MaterialButton mBtnWhitelist;

    private ThreatInvestigatorEngine.InvestigationResult mLastResult;

    public static ThreatInvestigationDialog newInstance(AlertRecord alert) {
        ThreatInvestigationDialog dialog = new ThreatInvestigationDialog();
        Bundle args = new Bundle();
        if (alert != null) {
            String ioc = alert.sourceApp != null ? alert.sourceApp : "";
            args.putString(ARG_IOC_VALUE, ioc);
            args.putString(ARG_IOC_TYPE, "ALERT");
            args.putString(ARG_SOURCE_APP, alert.sourceApp != null ? alert.sourceApp : "");
            args.putString(ARG_CONTEXT_INFO, alert.title + ": " + alert.message);
        }
        dialog.setArguments(args);
        return dialog;
    }

    public static ThreatInvestigationDialog newInstance(String iocValue, String iocType, String sourceApp, String contextInfo) {
        ThreatInvestigationDialog dialog = new ThreatInvestigationDialog();
        Bundle args = new Bundle();
        args.putString(ARG_IOC_VALUE, iocValue != null ? iocValue : "");
        args.putString(ARG_IOC_TYPE, iocType != null ? iocType : "");
        args.putString(ARG_SOURCE_APP, sourceApp != null ? sourceApp : "");
        args.putString(ARG_CONTEXT_INFO, contextInfo != null ? contextInfo : "");
        dialog.setArguments(args);
        return dialog;
    }

    public static void show(FragmentManager fm, AlertRecord alert) {
        if (fm == null) return;
        ThreatInvestigationDialog dialog = newInstance(alert);
        dialog.show(fm, TAG);
    }

    public static void show(FragmentManager fm, String iocValue, String iocType, String sourceApp, String contextInfo) {
        if (fm == null) return;
        ThreatInvestigationDialog dialog = newInstance(iocValue, iocType, sourceApp, contextInfo);
        dialog.show(fm, TAG);
    }

    public static void show(FragmentManager fm, String iocValue, String contextInfo) {
        if (fm == null) return;
        String type = (iocValue != null && iocValue.matches("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$")) ? "IP" : "DOMAIN";
        show(fm, iocValue, type, "", contextInfo);
    }

    @NonNull
    @Override
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        BottomSheetDialog dialog = (BottomSheetDialog) super.onCreateDialog(savedInstanceState);
        dialog.setOnShowListener(d -> {
            BottomSheetDialog bsd = (BottomSheetDialog) d;
            FrameLayout bottomSheet = bsd.findViewById(com.google.android.material.R.id.design_bottom_sheet);
            if (bottomSheet != null) {
                BottomSheetBehavior<FrameLayout> behavior = BottomSheetBehavior.from(bottomSheet);
                behavior.setState(BottomSheetBehavior.STATE_EXPANDED);
                behavior.setSkipCollapsed(true);
            }
        });
        return dialog;
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.dialog_threat_investigation, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        if (getArguments() != null) {
            mIocValue = getArguments().getString(ARG_IOC_VALUE, "");
            mIocType = getArguments().getString(ARG_IOC_TYPE, "");
            mSourceApp = getArguments().getString(ARG_SOURCE_APP, "");
            mContextInfo = getArguments().getString(ARG_CONTEXT_INFO, "");
        }

        bindViews(view);
        startInvestigation();
    }

    private void bindViews(View v) {
        mTvIoc = v.findViewById(R.id.tv_investigate_ioc);
        mTvModeBadge = v.findViewById(R.id.tv_investigate_mode_badge);
        mProgressBar = v.findViewById(R.id.pb_investigation_loading);
        mTvScore = v.findViewById(R.id.tv_threat_score);
        mTvLevel = v.findViewById(R.id.tv_threat_level);
        mTvVerdict = v.findViewById(R.id.tv_ai_verdict);
        mTvDecision = v.findViewById(R.id.tv_ai_decision);
        mTvConfidence = v.findViewById(R.id.tv_ai_confidence);
        mLayoutMalware = v.findViewById(R.id.layout_malware_family);
        mTvMalwareFamily = v.findViewById(R.id.tv_malware_family);
        mBadgeOtx = v.findViewById(R.id.badge_otx);
        mBadgeThreatFox = v.findViewById(R.id.badge_threatfox);
        mBadgeUrlhaus = v.findViewById(R.id.badge_urlhaus);
        mBadgeVt = v.findViewById(R.id.badge_vt);
        mTvIntelDetails = v.findViewById(R.id.tv_intel_details);
        mTvPurpose = v.findViewById(R.id.tv_indicator_purpose);
        mTvReasoning = v.findViewById(R.id.tv_ai_reasoning);
        mTvRemediation = v.findViewById(R.id.tv_ai_remediation);
        mBtnBlockFirewall = v.findViewById(R.id.btn_block_firewall);
        mBtnIsolateApp = v.findViewById(R.id.btn_isolate_app);
        mBtnOpenVt = v.findViewById(R.id.btn_open_vt);
        mBtnOpenOtx = v.findViewById(R.id.btn_open_otx);
        mBtnShareDossier = v.findViewById(R.id.btn_share_dossier);
        mBtnWhitelist = v.findViewById(R.id.btn_whitelist);

        View btnClose = v.findViewById(R.id.btn_close_dialog);
        if (btnClose != null) {
            btnClose.setOnClickListener(btn -> dismiss());
        }

        View btnCopy = v.findViewById(R.id.btn_copy_ioc);
        if (btnCopy != null) {
            btnCopy.setOnClickListener(btn -> handleCopyIoc());
        }

        if (mBtnShareDossier != null) {
            mBtnShareDossier.setOnClickListener(btn -> handleShareDossier());
        }

        if (!mIocValue.isEmpty()) {
            mTvIoc.setText(mIocValue + (!mIocType.isEmpty() ? " (" + mIocType + ")" : ""));
        } else if (!mContextInfo.isEmpty()) {
            mTvIoc.setText(mContextInfo);
        } else {
            mTvIoc.setText("Extracting IOC from context...");
        }

        mBtnBlockFirewall.setOnClickListener(btn -> handleBlockFirewall());
        mBtnIsolateApp.setOnClickListener(btn -> handleIsolateApp());
        if (mBtnOpenVt != null) {
            mBtnOpenVt.setOnClickListener(btn -> handleOpenVirusTotal());
        }
        if (mBtnOpenOtx != null) {
            mBtnOpenOtx.setOnClickListener(btn -> handleOpenOtx());
        }
        if (mBtnWhitelist != null) {
            mBtnWhitelist.setOnClickListener(btn -> handleWhitelist());
        }

        if (mBadgeVt != null) {
            mBadgeVt.setOnClickListener(b -> handleOpenVirusTotal());
        }
        if (mBadgeOtx != null) {
            mBadgeOtx.setOnClickListener(b -> handleOpenOtx());
        }
    }

    private void startInvestigation() {
        Context ctx = getContext();
        if (ctx == null) return;

        mProgressBar.setVisibility(View.VISIBLE);
        mTvVerdict.setText("CORRELATING THREAT INTEL...");
        mTvDecision.setText("Querying OTX, ThreatFox, URLhaus & AI synthesis");

        ThreatInvestigatorEngine.investigateIoc(ctx, mIocValue, mIocType, mSourceApp, mContextInfo,
                new ThreatInvestigatorEngine.InvestigationCallback() {
                    @Override
                    public void onResult(ThreatInvestigatorEngine.InvestigationResult result) {
                        if (!isAdded() || getContext() == null) return;
                        mLastResult = result;
                        renderResult(result);
                    }

                    @Override
                    public void onError(String error) {
                        if (!isAdded() || getContext() == null) return;
                        mProgressBar.setVisibility(View.GONE);
                        mTvVerdict.setText("INVESTIGATION INCOMPLETE");
                        mTvDecision.setText(error != null ? error : "An error occurred during correlation");
                    }
                });
    }

    private void renderResult(ThreatInvestigatorEngine.InvestigationResult r) {
        mProgressBar.setVisibility(View.GONE);

        // Header
        mTvIoc.setText(r.iocValue + (!r.iocType.isEmpty() ? " (" + r.iocType + ")" : ""));

        // Score and colors
        int prob = r.maliciousProbability;
        mTvScore.setText(prob + "%");
        int scoreColor;
        String levelText;
        int levelBg;
        if (prob >= 70) {
            scoreColor = Color.parseColor("#EF4444"); // Red
            levelText = "CRITICAL RISK";
            levelBg = Color.parseColor("#450A0A");
        } else if (prob >= 35) {
            scoreColor = Color.parseColor("#F59E0B"); // Orange
            levelText = "SUSPICIOUS / ELEVATED";
            levelBg = Color.parseColor("#451A03");
        } else {
            scoreColor = Color.parseColor("#10B981"); // Green
            levelText = "LOW / BENIGN RISK";
            levelBg = Color.parseColor("#064E3B");
        }
        mTvScore.setTextColor(scoreColor);
        mTvLevel.setText(levelText);
        mTvLevel.setTextColor(scoreColor);
        ViewCompat.setBackgroundTintList(mTvLevel, ColorStateList.valueOf(levelBg));

        // Verdict & Decision
        mTvVerdict.setText(r.aiVerdict);
        mTvVerdict.setTextColor(scoreColor);
        mTvDecision.setText("DECISION: " + r.decision);
        mTvConfidence.setText(r.confidence + " CONFIDENCE • " + r.intelProvider);

        // Malware Family
        if (r.malwareFamily != null && !r.malwareFamily.isEmpty()) {
            mLayoutMalware.setVisibility(View.VISIBLE);
            mTvMalwareFamily.setText(r.malwareFamily);
        } else if (r.campaignOrFamily != null && !r.campaignOrFamily.isEmpty() && !r.campaignOrFamily.equalsIgnoreCase("None")) {
            mLayoutMalware.setVisibility(View.VISIBLE);
            mTvMalwareFamily.setText(r.campaignOrFamily);
        } else {
            mLayoutMalware.setVisibility(View.GONE);
        }

        // Multi-Source Badges Highlight
        highlightIntelBadges(r);

        // Details & Dossier
        mTvIntelDetails.setText(r.intelDetails != null && !r.intelDetails.isEmpty() ? r.intelDetails : "No external threat hits found in threat feeds.");
        mTvPurpose.setText(r.purpose != null && !r.purpose.isEmpty() ? r.purpose : "Indicator appears to be standard infrastructure or uncategorized communication.");
        mTvReasoning.setText(r.reasoning != null && !r.reasoning.isEmpty() ? r.reasoning : "Analysis completed based on threat feeds and network heuristics.");
        mTvRemediation.setText(r.remediation != null && !r.remediation.isEmpty() ? r.remediation : "Keep standard protections active.");

        // Configure Action Buttons
        Context ctx = getContext();
        String currentPkg = (ctx != null) ? ctx.getPackageName() : "com.kotsafe.security";
        boolean isKotSafeApp = r.sourceApp != null && (
                r.sourceApp.equalsIgnoreCase(currentPkg)
                || r.sourceApp.equalsIgnoreCase("com.kotsafe.security")
                || r.sourceApp.toLowerCase(Locale.ROOT).contains("kotsafe"));

        if (r.sourceApp != null && !r.sourceApp.isEmpty() && !isKotSafeApp) {
            mBtnIsolateApp.setVisibility(View.VISIBLE);
            mBtnIsolateApp.setEnabled(true);
            mBtnIsolateApp.setText("📱 Isolate Calling App (" + r.sourceApp + ")");
        } else if (isKotSafeApp) {
            mBtnIsolateApp.setVisibility(View.VISIBLE);
            mBtnIsolateApp.setEnabled(false);
            mBtnIsolateApp.setText("🛡️ KotSafe Core (Protected)");
            mBtnIsolateApp.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor("#1E293B")));
            mBtnIsolateApp.setTextColor(Color.parseColor("#94A3B8"));
        } else {
            mBtnIsolateApp.setVisibility(View.GONE);
        }

        boolean isMalicious = (r.maliciousProbability >= 50
                || "CONFIRMED MALICIOUS".equalsIgnoreCase(r.aiVerdict)
                || "MALICIOUS".equalsIgnoreCase(r.intelVerdict)
                || (r.decision != null && r.decision.contains("BLOCK")));

        if (isMalicious) {
            mBtnBlockFirewall.setEnabled(true);
            mBtnBlockFirewall.setVisibility(View.VISIBLE);
            mBtnBlockFirewall.setText("🛡️ Block " + r.iocType + " in Firewall");
            mBtnBlockFirewall.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor("#DC2626")));
            mBtnBlockFirewall.setTextColor(Color.WHITE);
        } else {
            mBtnBlockFirewall.setEnabled(false);
            mBtnBlockFirewall.setVisibility(View.VISIBLE);
            mBtnBlockFirewall.setText("✓ Not Malicious (Protected from Blocking)");
            mBtnBlockFirewall.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor("#1E293B")));
            mBtnBlockFirewall.setTextColor(Color.parseColor("#94A3B8"));
            if (mBtnWhitelist != null) {
                mBtnWhitelist.setTextColor(Color.parseColor("#10B981"));
                mBtnWhitelist.setText("✓ Mark as Safe / Whitelist");
            }
        }
    }

    private void highlightIntelBadges(ThreatInvestigatorEngine.InvestigationResult r) {
        String provider = r.intelProvider != null ? r.intelProvider.toLowerCase(Locale.ROOT) : "";
        if (mBadgeOtx != null) {
            boolean hit = provider.contains("otx");
            ViewCompat.setBackgroundTintList(mBadgeOtx, ColorStateList.valueOf(Color.parseColor(hit ? "#0369A1" : "#1E293B")));
            mBadgeOtx.setTextColor(hit ? Color.WHITE : Color.parseColor("#38BDF8"));
        }
        if (mBadgeThreatFox != null) {
            boolean hit = provider.contains("threatfox");
            ViewCompat.setBackgroundTintList(mBadgeThreatFox, ColorStateList.valueOf(Color.parseColor(hit ? "#6D28D9" : "#1E293B")));
            mBadgeThreatFox.setTextColor(hit ? Color.WHITE : Color.parseColor("#A78BFA"));
        }
        if (mBadgeUrlhaus != null) {
            boolean hit = provider.contains("urlhaus");
            ViewCompat.setBackgroundTintList(mBadgeUrlhaus, ColorStateList.valueOf(Color.parseColor(hit ? "#047857" : "#1E293B")));
            mBadgeUrlhaus.setTextColor(hit ? Color.WHITE : Color.parseColor("#34D399"));
        }
        if (mBadgeVt != null) {
            boolean hit = provider.contains("virustotal") || provider.contains("vt");
            ViewCompat.setBackgroundTintList(mBadgeVt, ColorStateList.valueOf(Color.parseColor(hit ? "#B45309" : "#1E293B")));
            mBadgeVt.setTextColor(hit ? Color.WHITE : Color.parseColor("#FBBF24"));
        }
    }

    private void handleCopyIoc() {
        Context ctx = getContext();
        if (ctx == null) return;
        String val = (mLastResult != null && mLastResult.iocValue != null && !mLastResult.iocValue.isEmpty())
                ? mLastResult.iocValue : mIocValue;
        if (val == null || val.isEmpty()) return;

        ClipboardManager cm = (ClipboardManager) ctx.getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm != null) {
            cm.setPrimaryClip(ClipData.newPlainText("IOC", val));
            Toast.makeText(ctx, "Copied IOC to clipboard", Toast.LENGTH_SHORT).show();
        }
    }

    private void handleShareDossier() {
        Context ctx = getContext();
        if (ctx == null) return;

        String ioc = (mLastResult != null && mLastResult.iocValue != null) ? mLastResult.iocValue : mIocValue;
        String type = (mLastResult != null && mLastResult.iocType != null) ? mLastResult.iocType : mIocType;

        StringBuilder sb = new StringBuilder();
        sb.append("🛡️ KotSafe Threat Intelligence Dossier\n");
        sb.append("• Target IOC: ").append(ioc).append(" (").append(type).append(")\n");
        if (mLastResult != null) {
            sb.append("• Risk Score: ").append(mLastResult.maliciousProbability).append("%\n");
            sb.append("• Verdict: ").append(mLastResult.aiVerdict).append("\n");
            sb.append("• Decision: ").append(mLastResult.decision).append("\n");
            if (mLastResult.malwareFamily != null && !mLastResult.malwareFamily.isEmpty()) {
                sb.append("• Threat Family: ").append(mLastResult.malwareFamily).append("\n");
            }
            if (mLastResult.intelDetails != null && !mLastResult.intelDetails.isEmpty()) {
                sb.append("• Threat Intel: ").append(mLastResult.intelDetails).append("\n");
            }
            if (mLastResult.purpose != null && !mLastResult.purpose.isEmpty()) {
                sb.append("• Motivation: ").append(mLastResult.purpose).append("\n");
            }
            if (mLastResult.remediation != null && !mLastResult.remediation.isEmpty()) {
                sb.append("• Remediation: ").append(mLastResult.remediation).append("\n");
            }
        }

        ClipboardManager cm = (ClipboardManager) ctx.getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm != null) {
            cm.setPrimaryClip(ClipData.newPlainText("Threat Dossier", sb.toString()));
            Toast.makeText(ctx, "Full threat dossier copied to clipboard!", Toast.LENGTH_SHORT).show();
        }
    }

    private void handleBlockFirewall() {
        Context ctx = getContext();
        if (ctx == null) return;

        String target = mLastResult != null && mLastResult.iocValue != null && !mLastResult.iocValue.isEmpty()
                ? mLastResult.iocValue : mIocValue;
        String type = mLastResult != null && mLastResult.iocType != null ? mLastResult.iocType : mIocType;

        boolean isMalicious = mLastResult != null && (
                mLastResult.maliciousProbability >= 50
                || "CONFIRMED MALICIOUS".equalsIgnoreCase(mLastResult.aiVerdict)
                || "MALICIOUS".equalsIgnoreCase(mLastResult.intelVerdict)
                || (mLastResult.decision != null && mLastResult.decision.contains("BLOCK"))
        );

        if (!isMalicious) {
            Toast.makeText(ctx, "Policy Protected: Will not block " + target + " as it is not malicious.", Toast.LENGTH_LONG).show();
            return;
        }

        SecurityBlocklistManager mgr = SecurityBlocklistManager.getInstance(ctx);
        if (SecurityBlocklistManager.isOfficialDomain(target)
                || SecurityBlocklistManager.isTrustedAdOrAnalyticsDomain(target)
                || mgr.isSystemWhitelisted(target)) {
            Toast.makeText(ctx, "Protected: " + target + " is a safe / trusted domain and cannot be blocked.", Toast.LENGTH_LONG).show();
            return;
        }

        String reason = "AI Deep Threat Investigation: " + (mLastResult != null ? mLastResult.aiVerdict : "Malicious IOC");

        if ("IP".equalsIgnoreCase(type)) {
            mgr.blockIp(target, reason, "AI_INVESTIGATOR");
            Toast.makeText(ctx, "Blocked IP " + target + " in Firewall", Toast.LENGTH_SHORT).show();
        } else if ("DOMAIN".equalsIgnoreCase(type)) {
            mgr.blockDomain(target, reason, "AI_INVESTIGATOR");
            Toast.makeText(ctx, "Blocked Domain " + target + " in Firewall", Toast.LENGTH_SHORT).show();
        } else if ("URL".equalsIgnoreCase(type)) {
            mgr.blockUrl(target, reason, "AI_INVESTIGATOR");
            Toast.makeText(ctx, "Blocked URL and Domain in Firewall", Toast.LENGTH_SHORT).show();
        } else if ("HASH".equalsIgnoreCase(type)) {
            mgr.blockHash(target, reason, "AI_INVESTIGATOR");
            Toast.makeText(ctx, "Blocked File Hash in Security Rules", Toast.LENGTH_SHORT).show();
        } else if ("APP".equalsIgnoreCase(type)) {
            if (target.equalsIgnoreCase(ctx.getPackageName()) || target.equalsIgnoreCase("com.kotsafe.security") || target.toLowerCase(Locale.ROOT).contains("kotsafe")) {
                Toast.makeText(ctx, "Protected: KotSafe cannot be blocked in Firewall.", Toast.LENGTH_SHORT).show();
                return;
            }
            mgr.blockApp(target, reason, "AI_INVESTIGATOR");
            Toast.makeText(ctx, "Isolated App " + target + " in Firewall", Toast.LENGTH_SHORT).show();
        } else {
            mgr.blockDomain(target, reason, "AI_INVESTIGATOR");
            Toast.makeText(ctx, "Blocked " + target + " in Firewall", Toast.LENGTH_SHORT).show();
        }

        dismiss();
    }

    private void handleIsolateApp() {
        Context ctx = getContext();
        if (ctx == null) return;

        String app = mLastResult != null && mLastResult.sourceApp != null && !mLastResult.sourceApp.isEmpty()
                ? mLastResult.sourceApp : mSourceApp;

        if (app != null && (app.equalsIgnoreCase(ctx.getPackageName()) || app.equalsIgnoreCase("com.kotsafe.security") || app.toLowerCase(Locale.ROOT).contains("kotsafe"))) {
            Toast.makeText(ctx, "Protected: KotSafe is the core security system and cannot be isolated.", Toast.LENGTH_LONG).show();
            return;
        }

        if (app != null && !app.isEmpty()) {
            SecurityBlocklistManager mgr = SecurityBlocklistManager.getInstance(ctx);
            mgr.blockApp(app, "Isolated via AI Threat Investigation", "AI_INVESTIGATOR");
            Toast.makeText(ctx, "Network access completely isolated for " + app, Toast.LENGTH_SHORT).show();
            dismiss();
        }
    }

    private void handleOpenVirusTotal() {
        Context ctx = getContext();
        if (ctx == null) return;

        String target = mLastResult != null && mLastResult.iocValue != null && !mLastResult.iocValue.isEmpty()
                ? mLastResult.iocValue : mIocValue;
        String type = mLastResult != null && mLastResult.iocType != null ? mLastResult.iocType : mIocType;

        ThreatIntelManager.openVirusTotalAuto(ctx, target, type);
    }

    private void handleOpenOtx() {
        Context ctx = getContext();
        if (ctx == null) return;

        String target = mLastResult != null && mLastResult.iocValue != null && !mLastResult.iocValue.isEmpty()
                ? mLastResult.iocValue : mIocValue;
        String type = mLastResult != null && mLastResult.iocType != null ? mLastResult.iocType : mIocType;

        ThreatIntelManager.openOtxAuto(ctx, target, type);
    }

    private void handleWhitelist() {
        Context ctx = getContext();
        if (ctx == null) return;

        String target = mLastResult != null && mLastResult.iocValue != null && !mLastResult.iocValue.isEmpty()
                ? mLastResult.iocValue : mIocValue;
        String type = mLastResult != null && mLastResult.iocType != null ? mLastResult.iocType : mIocType;

        SecurityBlocklistManager mgr = SecurityBlocklistManager.getInstance(ctx);
        mgr.whitelist(type, target, "GLOBAL", "Marked safe via Deep Threat Investigation");
        Toast.makeText(ctx, "Added " + target + " to Whitelist", Toast.LENGTH_SHORT).show();
        dismiss();
    }
}
