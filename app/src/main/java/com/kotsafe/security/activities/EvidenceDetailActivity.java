/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.activities;

import android.content.Intent;
import android.os.Bundle;
import android.view.MenuItem;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.widget.Toolbar;
import androidx.core.content.ContextCompat;

import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.AntivirusEvidenceItem;
import com.kotsafe.security.model.SecurityBlocklistManager;
import com.kotsafe.security.model.SecurityRulesDb;
import com.kotsafe.security.model.ThreatIntelManager;
import com.google.android.material.button.MaterialButton;

import java.text.DateFormat;
import java.util.Date;

public class EvidenceDetailActivity extends BaseActivity {
    private static final String TAG = "EvidenceDetailActivity";

    public static final String EXTRA_FILE_PATH = "extra_file_path";
    public static final String EXTRA_SHA256 = "extra_sha256";
    public static final String EXTRA_FILE_SIZE = "extra_file_size";
    public static final String EXTRA_MALWARE_FAMILY = "extra_malware_family";
    public static final String EXTRA_TITLE = "extra_title";
    public static final String EXTRA_SUBTITLE = "extra_subtitle";
    public static final String EXTRA_IOC_VALUE = "extra_ioc_value";
    public static final String EXTRA_IOC_TYPE = "extra_ioc_type";
    public static final String EXTRA_SEVERITY = "extra_severity";
    public static final String EXTRA_DETAILS = "extra_details";
    public static final String EXTRA_PACKAGE_NAME = "extra_package_name";
    public static final String EXTRA_RISK_SCORE = "extra_risk_score";
    public static final String EXTRA_TIMESTAMP = "extra_timestamp";
    public static final String EXTRA_IS_SYSTEM_APP = "extra_is_system_app";
    public static final String EXTRA_IS_WHITELISTED = "extra_is_whitelisted";
    public static final String EXTRA_SYSTEM_REASON = "extra_system_reason";
    public static final String EXTRA_AI_EXPLANATION = "extra_ai_explanation";
    public static final String EXTRA_AI_ACTION_PLAN = "extra_ai_action_plan";
    public static final String EXTRA_AI_PROMPT = "extra_ai_prompt";
    public static final String EXTRA_MITRE_TECHNIQUES = "extra_mitre_techniques";

    private String mFilePath;
    private String mSha256;
    private String mFileSize;
    private String mMalwareFamily;
    private String mTitle;
    private String mSubtitle;
    private String mIocValue;
    private String mIocType;
    private String mSeverity;
    private String mDetails;
    private String mPackageName;
    private int mRiskScore;
    private long mTimestamp;
    private boolean mIsSystemApp;
    private boolean mIsWhitelisted;
    private String mSystemReason;
    private String mAiExplanation;
    private String mAiActionPlan;
    private String mAiPrompt;
    private java.util.ArrayList<String> mMitreTechniques;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_evidence_detail);

        Toolbar toolbar = findViewById(R.id.toolbar);
        if (toolbar != null) {
            setSupportActionBar(toolbar);
            if (getSupportActionBar() != null) {
                getSupportActionBar().setDisplayHomeAsUpEnabled(true);
                getSupportActionBar().setTitle(R.string.evidence_detail);
            }
        }

        readIntentData();
        setupViews();
    }

    private void readIntentData() {
        Intent intent = getIntent();
        if (intent != null) {
            mFilePath = intent.getStringExtra(EXTRA_FILE_PATH);
            mSha256 = intent.getStringExtra(EXTRA_SHA256);
            mFileSize = intent.getStringExtra(EXTRA_FILE_SIZE);
            mMalwareFamily = intent.getStringExtra(EXTRA_MALWARE_FAMILY);
            mTitle = intent.getStringExtra(EXTRA_TITLE);
            mSubtitle = intent.getStringExtra(EXTRA_SUBTITLE);
            mIocValue = intent.getStringExtra(EXTRA_IOC_VALUE);
            mIocType = intent.getStringExtra(EXTRA_IOC_TYPE);
            mSeverity = intent.getStringExtra(EXTRA_SEVERITY);
            mDetails = intent.getStringExtra(EXTRA_DETAILS);
            mPackageName = intent.getStringExtra(EXTRA_PACKAGE_NAME);
            mRiskScore = intent.getIntExtra(EXTRA_RISK_SCORE, 0);
            mTimestamp = intent.getLongExtra(EXTRA_TIMESTAMP, System.currentTimeMillis());
            mIsSystemApp = intent.getBooleanExtra(EXTRA_IS_SYSTEM_APP, false);
            mIsWhitelisted = intent.getBooleanExtra(EXTRA_IS_WHITELISTED, false);
            mSystemReason = intent.getStringExtra(EXTRA_SYSTEM_REASON);
            mAiExplanation = intent.getStringExtra(EXTRA_AI_EXPLANATION);
            mAiActionPlan = intent.getStringExtra(EXTRA_AI_ACTION_PLAN);
            mAiPrompt = intent.getStringExtra(EXTRA_AI_PROMPT);
            mMitreTechniques = intent.getStringArrayListExtra(EXTRA_MITRE_TECHNIQUES);
        }

        if (mTitle == null) mTitle = "Evidence Item";
        if (mIocValue == null) mIocValue = "";
        if (mIocType == null) mIocType = "UNKNOWN";
        if (mSeverity == null) mSeverity = AntivirusEvidenceItem.SEVERITY_CLEAN;
        if (mDetails == null) mDetails = "No additional forensic details recorded.";
        if (mFilePath == null || mFilePath.isEmpty()) {
            if (mSubtitle != null && (mSubtitle.startsWith("/") || mSubtitle.contains(java.io.File.separator))) {
                mFilePath = mSubtitle;
            }
        }
        if (mSha256 == null || mSha256.isEmpty()) {
            if (mIocValue != null && mIocValue.length() == 64 && mIocValue.matches("^[a-fA-F0-9]{64}$")) {
                mSha256 = mIocValue;
            }
        }
        if (!mIsSystemApp && mPackageName != null) {
            mIsSystemApp = Utils.isSystemApp(this, mPackageName);
        }
        if (mSystemReason == null || mSystemReason.isEmpty()) {
            mSystemReason = "This app is important to run Android OS services.";
        }

        if ((mAiExplanation == null || mAiExplanation.isEmpty()) && !mIsSystemApp
                && (AntivirusEvidenceItem.SEVERITY_MALICIOUS.equalsIgnoreCase(mSeverity)
                || AntivirusEvidenceItem.SEVERITY_SUSPICIOUS.equalsIgnoreCase(mSeverity))) {
            com.kotsafe.security.ai.ThreatContextBuilder.ThreatExplanationReport fallbackReport =
                    com.kotsafe.security.ai.ThreatContextBuilder.buildReport(mTitle, mPackageName, null, java.util.Collections.singletonList(mDetails));
            mAiExplanation = fallbackReport.plainEnglishRisk;
            mAiActionPlan = fallbackReport.actionPlan;
            mAiPrompt = fallbackReport.conversationalPrompt;
        }
    }

    private void setupViews() {
        TextView tvBadge = findViewById(R.id.tv_evidence_badge);
        TextView tvRiskScore = findViewById(R.id.tv_risk_score);
        TextView tvTitle = findViewById(R.id.tv_evidence_title);
        TextView tvSubtitle = findViewById(R.id.tv_evidence_subtitle);
        TextView tvIocFull = findViewById(R.id.tv_ioc_full);
        TextView tvOriginPackage = findViewById(R.id.tv_origin_package);
        TextView tvDetectionDetails = findViewById(R.id.tv_detection_details);
        TextView tvTimestamp = findViewById(R.id.tv_timestamp);

        View containerFilePath = findViewById(R.id.container_file_path);
        TextView tvFilePath = findViewById(R.id.tv_file_path);
        View btnCopyFilePath = findViewById(R.id.btn_copy_file_path);

        View containerSha256 = findViewById(R.id.container_sha256);
        TextView tvSha256 = findViewById(R.id.tv_sha256);
        View btnCopySha256 = findViewById(R.id.btn_copy_sha256);

        View cardSystemNotice = findViewById(R.id.card_system_app_notice);
        TextView tvSystemNotice = findViewById(R.id.tv_system_app_notice);

        MaterialButton btnBlock = findViewById(R.id.btn_action_block);
        MaterialButton btnWhitelist = findViewById(R.id.btn_action_whitelist);
        MaterialButton btnVt = findViewById(R.id.btn_vt_lookup);
        MaterialButton btnOtx = findViewById(R.id.btn_otx_lookup);
        MaterialButton btnAppDetails = findViewById(R.id.btn_open_app_details);

        tvTitle.setText(mTitle);
        tvSubtitle.setText(mSubtitle != null && !mSubtitle.isEmpty() ? mSubtitle : mIocType);
        tvIocFull.setText(mIocValue + " (" + mIocType + ")");
        tvOriginPackage.setText(mPackageName != null && !mPackageName.isEmpty() ? mPackageName : "Unknown origin");
        tvDetectionDetails.setText(mDetails);

        // Path Display & Copy
        if (mFilePath != null && !mFilePath.isEmpty()) {
            if (containerFilePath != null) containerFilePath.setVisibility(View.VISIBLE);
            if (tvFilePath != null) tvFilePath.setText(mFilePath);
            if (btnCopyFilePath != null) {
                btnCopyFilePath.setOnClickListener(v -> {
                    android.content.ClipboardManager cm = (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
                    if (cm != null) {
                        cm.setPrimaryClip(android.content.ClipData.newPlainText("File Path", mFilePath));
                        Toast.makeText(this, "Copied path to clipboard", Toast.LENGTH_SHORT).show();
                    }
                });
            }
        } else {
            if (containerFilePath != null) containerFilePath.setVisibility(View.GONE);
        }

        // SHA-256 Display & Copy
        if (mSha256 != null && !mSha256.isEmpty()) {
            if (containerSha256 != null) containerSha256.setVisibility(View.VISIBLE);
            if (tvSha256 != null) tvSha256.setText(mSha256);
            if (btnCopySha256 != null) {
                btnCopySha256.setOnClickListener(v -> {
                    android.content.ClipboardManager cm = (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
                    if (cm != null) {
                        cm.setPrimaryClip(android.content.ClipData.newPlainText("SHA-256 Digest", mSha256));
                        Toast.makeText(this, "Copied SHA-256 to clipboard", Toast.LENGTH_SHORT).show();
                    }
                });
            }
        } else {
            if (containerSha256 != null) containerSha256.setVisibility(View.GONE);
        }

        DateFormat df = DateFormat.getDateTimeInstance();
        tvTimestamp.setText(df.format(new Date(mTimestamp)));

        tvRiskScore.setText("Risk Score: " + mRiskScore);

        if (mIsSystemApp) {
            if (cardSystemNotice != null) cardSystemNotice.setVisibility(View.VISIBLE);
            if (tvSystemNotice != null) {
                tvSystemNotice.setText(mSystemReason + "\n\nAll system apps, associated network traffic, and file hashes are whitelisted by default. Threat intelligence detections are downgraded to Low Malicious to protect essential OS operations.");
            }
        } else {
            if (cardSystemNotice != null) cardSystemNotice.setVisibility(View.GONE);
        }

        if (AntivirusEvidenceItem.SEVERITY_MALICIOUS.equalsIgnoreCase(mSeverity)) {
            tvBadge.setText("MALICIOUS");
            tvBadge.setBackgroundResource(R.drawable.bg_badge_threat);
            tvRiskScore.setTextColor(ContextCompat.getColor(this, R.color.danger));
        } else if (AntivirusEvidenceItem.SEVERITY_SUSPICIOUS.equalsIgnoreCase(mSeverity)) {
            tvBadge.setText("SUSPICIOUS");
            tvBadge.setBackgroundResource(R.drawable.bg_badge_threat);
            tvRiskScore.setTextColor(ContextCompat.getColor(this, R.color.warning));
        } else if (AntivirusEvidenceItem.SEVERITY_LOW.equalsIgnoreCase(mSeverity)) {
            tvBadge.setText(mIsSystemApp ? "LOW MALICIOUS (SYSTEM)" : "LOW RISK");
            tvBadge.setBackgroundResource(R.drawable.bg_badge_low_risk);
            tvRiskScore.setTextColor(ContextCompat.getColor(this, R.color.warning));
        } else {
            tvBadge.setText(mIsSystemApp ? "SYSTEM (SAFE)" : "CLEAN");
            tvBadge.setBackgroundResource(R.drawable.bg_badge_service);
            tvRiskScore.setTextColor(ContextCompat.getColor(this, R.color.ok));
        }

        // AI Threat Analysis & Reasoning (Phase 2)
        View cardAi = findViewById(R.id.card_ai_explainer);
        TextView tvAiCatBadge = findViewById(R.id.tv_ai_category_badge);
        TextView tvAiExplanation = findViewById(R.id.tv_ai_explanation_text);
        TextView tvAiActionPlan = findViewById(R.id.tv_ai_action_plan_text);
        MaterialButton btnConsultAi = findViewById(R.id.btn_consult_ai);

        if (mAiExplanation != null && !mAiExplanation.isEmpty() && !mIsSystemApp) {
            if (cardAi != null) cardAi.setVisibility(View.VISIBLE);
            if (tvAiCatBadge != null) {
                String cat = (mMalwareFamily != null && !mMalwareFamily.isEmpty()) ? mMalwareFamily : "SUSPICIOUS";
                tvAiCatBadge.setText(cat);
            }
            if (tvAiExplanation != null) tvAiExplanation.setText(mAiExplanation);
            if (tvAiActionPlan != null) {
                tvAiActionPlan.setText(mAiActionPlan != null && !mAiActionPlan.isEmpty() ? mAiActionPlan : "Recommended: Inspect origin and uninstall if untrusted.");
            }
            if (btnConsultAi != null) {
                btnConsultAi.setOnClickListener(v -> {
                    Intent aiIntent = new Intent(this, AiAssistantActivity.class);
                    String prompt = (mAiPrompt != null && !mAiPrompt.isEmpty())
                            ? mAiPrompt
                            : "Can you explain why " + (mPackageName != null ? mPackageName : "this application") + " was flagged and what action I should take?";
                    aiIntent.putExtra("prompt", prompt);
                    startActivity(aiIntent);
                });
            }
        } else {
            if (cardAi != null) cardAi.setVisibility(View.GONE);
        }

        // MITRE ATT&CK Mobile Matrix Correlation
        View cardMitre = findViewById(R.id.card_mitre_ttp);
        TextView tvMitreBreakdown = findViewById(R.id.tv_mitre_full_breakdown);
        MaterialButton btnOpenMitre = findViewById(R.id.btn_open_mitre_url);

        AntivirusEvidenceItem dummyItem = new AntivirusEvidenceItem(mIocType, mTitle, mSubtitle, mIocValue, mSeverity, mDetails);
        dummyItem.packageName = mPackageName;
        dummyItem.filePath = mFilePath;
        dummyItem.sha256 = mSha256;
        dummyItem.isSystemApp = mIsSystemApp;

        java.util.List<com.kotsafe.security.model.MitreCorrelator.MitreTtp> ttps = com.kotsafe.security.model.MitreCorrelator.correlate(dummyItem);
        if (ttps != null && !ttps.isEmpty()) {
            if (cardMitre != null) cardMitre.setVisibility(View.VISIBLE);
            if (tvMitreBreakdown != null) tvMitreBreakdown.setText(com.kotsafe.security.model.MitreCorrelator.formatTtpBreakdown(ttps));
            if (btnOpenMitre != null) {
                final String targetUrl = ttps.get(0).mitreUrl;
                btnOpenMitre.setOnClickListener(v -> {
                    try {
                        Intent browserIntent = new Intent(Intent.ACTION_VIEW, android.net.Uri.parse(targetUrl != null ? targetUrl : "https://attack.mitre.org/matrices/mobile/"));
                        startActivity(browserIntent);
                    } catch (Exception ignored) {}
                });
            }
        } else {
            if (cardMitre != null) cardMitre.setVisibility(View.GONE);
        }

        // Block Action with System App Protection
        btnBlock.setOnClickListener(v -> {
            if (mIsSystemApp) {
                new androidx.appcompat.app.AlertDialog.Builder(this)
                        .setTitle("System Service Protected")
                        .setMessage("This app is important to run Android OS services.\n\nBlocking this component or its traffic may cause OS services to malfunction or lose connectivity.\n\nAre you sure you want to proceed?")
                        .setPositiveButton("Proceed Anyway", (dialog, which) -> openBlockRuleActivity())
                        .setNegativeButton("Keep Protected", null)
                        .show();
            } else {
                openBlockRuleActivity();
            }
        });

        // Whitelist Action
        btnWhitelist.setOnClickListener(v -> {
            Intent intent = new Intent(this, ManualBlockActivity.class);
            intent.putExtra(ManualBlockActivity.EXTRA_VALUE, mIocValue);
            intent.putExtra(ManualBlockActivity.EXTRA_TYPE, inferRuleType(mIocType));
            intent.putExtra(ManualBlockActivity.EXTRA_ACTION, SecurityRulesDb.ACTION_ALLOW);
            startActivity(intent);
        });

        // VirusTotal lookup
        btnVt.setOnClickListener(v -> {
            if (mIocValue.isEmpty()) return;
            ThreatIntelManager.openVirusTotalAuto(this, mIocValue, mIocType);
        });

        // OTX lookup
        btnOtx.setOnClickListener(v -> {
            if (mIocValue.isEmpty()) return;
            ThreatIntelManager.openOtxAuto(this, mIocValue, mIocType);
        });

        // App Details
        if (mPackageName != null && !mPackageName.isEmpty() && !mPackageName.startsWith("uid:")) {
            btnAppDetails.setVisibility(View.VISIBLE);
            btnAppDetails.setOnClickListener(v -> {
                try {
                    int uid = Utils.getPackageUid(getPackageManager(), mPackageName, 0);
                    Intent intent = new Intent(this, AppDetailsActivity.class);
                    intent.putExtra(AppDetailsActivity.APP_UID_EXTRA, uid);
                    startActivity(intent);
                } catch (Exception e) {
                    Toast.makeText(this, "Could not open app details", Toast.LENGTH_SHORT).show();
                }
            });
        } else {
            btnAppDetails.setVisibility(View.GONE);
        }
    }

    private String inferRuleType(String iocType) {
        if (AntivirusEvidenceItem.TYPE_IP.equals(iocType)) return SecurityRulesDb.TYPE_IP;
        if (AntivirusEvidenceItem.TYPE_URL.equals(iocType)) return SecurityRulesDb.TYPE_DOMAIN;
        if (AntivirusEvidenceItem.TYPE_APP_HASH.equals(iocType)
                || AntivirusEvidenceItem.TYPE_SERVICE_HASH.equals(iocType)
                || "STORAGE_FILE".equals(iocType)) return SecurityRulesDb.TYPE_HASH;
        return SecurityRulesDb.TYPE_DOMAIN;
    }

    private void openBlockRuleActivity() {
        Intent intent = new Intent(this, ManualBlockActivity.class);
        intent.putExtra(ManualBlockActivity.EXTRA_VALUE, mIocValue);
        intent.putExtra(ManualBlockActivity.EXTRA_TYPE, inferRuleType(mIocType));
        intent.putExtra(ManualBlockActivity.EXTRA_ACTION, SecurityRulesDb.ACTION_BLOCK);
        startActivity(intent);
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
}
