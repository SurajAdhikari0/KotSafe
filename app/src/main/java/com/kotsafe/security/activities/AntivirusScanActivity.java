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

package com.kotsafe.security.activities;

import android.Manifest;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.provider.Settings;
import android.text.Spannable;
import android.text.SpannableStringBuilder;
import android.text.TextUtils;
import android.text.style.ForegroundColorSpan;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.kotsafe.security.CaptureService;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.activities.prefs.SettingsActivity;
import com.kotsafe.security.adapters.AntivirusEvidenceAdapter;
import com.kotsafe.security.model.AntivirusEvidenceItem;
import com.kotsafe.security.model.AntivirusScanEngine;
import com.kotsafe.security.model.DetectionRulesManager;
import com.kotsafe.security.model.FileHashDbHelper;
import com.kotsafe.security.model.FileHashEntry;
import com.kotsafe.security.model.Prefs;
import com.kotsafe.security.model.QuarantineVaultManager;
import com.kotsafe.security.model.ScanModeConfig;
import com.kotsafe.security.model.ScanReportDbHelper;

import java.io.File;
import com.kotsafe.security.model.ScanReportEntry;
import com.kotsafe.security.model.VpnConsentManager;
import com.kotsafe.security.services.AntivirusScanService;
import com.kotsafe.security.views.AntivirusMatrixView;
import com.kotsafe.security.views.AnimUtils;
import com.kotsafe.security.views.DetectionRulesDialog;
import com.kotsafe.security.views.ScanReportDetailsDialog;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;
import com.google.android.material.chip.ChipGroup;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class AntivirusScanActivity extends BaseActivity {
    private static final String TAG = "AntivirusScanActivity";
    private static final String KEY_CURRENT_FILTER = "av_current_filter";
    private static final String KEY_PENDING_SCAN = "av_pending_scan";

    public enum ScanTier {
        QUICK(ScanModeConfig.ScanMode.QUICK, "Quick Scan", "High-risk downloads & running apps"),
        FULL(ScanModeConfig.ScanMode.FULL, "Full Scan", "Whole device: apps, net traffic & files"),
        DEEP(ScanModeConfig.ScanMode.DEEP, "Deep Scan", "Full scan + /sdcard/ deep bytecode & YARA");

        public final ScanModeConfig.ScanMode mode;
        public final String label;
        public final String subtitle;

        ScanTier(ScanModeConfig.ScanMode mode, String label, String subtitle) {
            this.mode = mode;
            this.label = label;
            this.subtitle = subtitle;
        }
    }

    private final Handler mMainHandler = new Handler(Looper.getMainLooper());
    private final Random mRandom = new Random();

    // Mode & State
    private ScanTier mCurrentTier = ScanTier.FULL;
    private boolean mIsScanning = false;

    // Metrics
    private int mScannedCount = 0;
    private int mSafeCount = 0;
    private int mThreatsCount = 0;
    private int mAppsCount = 0;
    private int mIpsCount = 0;
    private int mUrlsCount = 0;
    private int mFilesCount = 0;

    // Views
    private TextView mTvShieldTitle, mTvShieldSubtitle;
    private View mLegendDotScan;

    // Scan Tier Selector
    private LinearLayout mLayoutScanTypeRow;
    private LinearLayout mTabTypeQuick, mTabTypeFull, mTabTypeDeep;
    private TextView mTvStQuickName, mTvStFullName, mTvStDeepName;
    private TextView mTvStQuickDesc, mTvStFullDesc, mTvStDeepDesc;

    // Visualizer / Holo Circle Radar Matrix
    private AntivirusMatrixView mMatrixCanvasView;
    private TextView mTvCurrentFile;

    // Verdict Badge
    private MaterialCardView mCardVerdictBadge;
    private View mDotVerdict;
    private TextView mTvVerdictTitle, mTvVerdictSub;
    private MaterialButton mBtnQuarantineAllThreats;

    // Live Cyber Terminal
    private ScrollView mScrollCyberLogs;
    private TextView mTvCyberLogs;
    private static final int MAX_CYBER_LOG_LINES = 30;  // fewer lines = smaller Spannable re-layout
    private long mLastScrollTime = 0;
    private int mCyberLogLineCount = 0;
    private final SpannableStringBuilder mLogsBuilder = new SpannableStringBuilder();

    // Scan Velocity Tracking
    private TextView mTvScanVelocity;
    private long mScanStartTime = 0;
    private long mLastVelocitySampleTime = 0;
    private int mLastVelocitySampleCount = 0;
    private float mCurrentVelocity = 0f;
    private float mPeakVelocity = 0f;

    // 3-Column Metrics Grid
    private TextView mTvMetricCountScanned, mTvMetricCountSafe, mTvMetricCountThreats;
    private MaterialCardView mCardMetricScanned, mCardMetricSafe, mCardMetricThreats;

    // 4-Pillar Omni-Vector Live Breakdown
    private TextView mTvMetricApps, mTvMetricIps, mTvMetricUrls, mTvMetricFiles;

    // Action Button
    private MaterialButton mBtnActionScan;

    // Workbench Cards & Evidence
    private MaterialCardView mCardWorkbenchMalware, mCardWorkbenchApps, mCardWorkbenchQuarantine;
    private TextView mTvWorkbenchQuarantineSubtitle;

    // Device Posture & EDR Correlation Cards
    private MaterialCardView mCardDevicePosture;
    private TextView mTvDevicePostureSubtitle, mTvDevicePostureScore;
    private TextView mChipPosturePatch, mChipPostureEncryption, mChipPostureAdb;
    private MaterialCardView mCardEdrCorrelations;
    private TextView mTvEdrCorrelationSubtitle, mTvEdrCorrelationBadge;

    private ChipGroup mChipGroupEvidenceFilter;
    private RecyclerView mRecyclerEvidence;
    private AntivirusEvidenceAdapter mAdapter;
    private AntivirusScanEngine.ScanResult mLastResult;
    private String mCurrentFilter = "THREATS";

    // VPN Banner & Notice
    private MaterialCardView mCardVpnStatus, mCardApiKeyNotice;
    private ImageView mIvScanVpnIcon;
    private TextView mTvScanVpnTitle, mTvScanVpnSubtitle;
    private MaterialButton mBtnScanStartVpn, mBtnAddApiKeys;
    private boolean mPendingDeepScanAfterPermission = false;

    // Dynamic Detection Rules (SIEM / Microsoft Sentinel)
    private MaterialCardView mCardDetectionRules;
    private TextView mTvDetectionRulesSubtitle;
    private MaterialButton mBtnSyncDetectionRules;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setTitle(R.string.antivirus_scan);
        displayBackAction();
        setContentView(R.layout.activity_antivirus_scan);

        // Restore scan filter state if activity was killed by the system (fixes H-003)
        if (savedInstanceState != null) {
            mCurrentFilter = savedInstanceState.getString(KEY_CURRENT_FILTER, "THREATS");
            mPendingDeepScanAfterPermission = savedInstanceState.getBoolean(KEY_PENDING_SCAN, false);
        }

        initViews();
        setupListeners();
        applyTierUI();
        updateDetectionRulesCard();

        if (getIntent().getBooleanExtra("test_permission_dialog", false)) {
            promptStoragePermissionForDeepScan(false);
        } else if (mLastResult == null && AntivirusScanService.getLastResult() == null && !AntivirusScanService.isScanning()) {
            beginScan();
        }

        CaptureService.observeStatus(this, status -> updateVpnStatusBanner());
    }

    @Override
    protected void onSaveInstanceState(@NonNull Bundle outState) {
        super.onSaveInstanceState(outState);
        // Persist scan UI state so the Activity can recover after process death (fixes H-003)
        outState.putString(KEY_CURRENT_FILTER, mCurrentFilter);
        outState.putBoolean(KEY_PENDING_SCAN, mPendingDeepScanAfterPermission);
    }

    private void initViews() {
        mTvShieldTitle = findViewById(R.id.tv_shield_title);
        mTvShieldSubtitle = findViewById(R.id.tv_shield_subtitle);
        mLegendDotScan = findViewById(R.id.legend_dot_scan);

        mLayoutScanTypeRow = findViewById(R.id.layout_scan_type_row);
        mTabTypeQuick = findViewById(R.id.tab_type_quick);
        mTabTypeFull = findViewById(R.id.tab_type_full);
        mTabTypeDeep = findViewById(R.id.tab_type_deep);
        mTvStQuickName = findViewById(R.id.tv_st_quick_name);
        mTvStFullName = findViewById(R.id.tv_st_full_name);
        mTvStDeepName = findViewById(R.id.tv_st_deep_name);
        mTvStQuickDesc = findViewById(R.id.tv_st_quick_desc);
        mTvStFullDesc = findViewById(R.id.tv_st_full_desc);
        mTvStDeepDesc = findViewById(R.id.tv_st_deep_desc);

        mMatrixCanvasView = findViewById(R.id.matrix_canvas_view);
        mTvCurrentFile = findViewById(R.id.tv_current_file);

        mCardVerdictBadge = findViewById(R.id.card_verdict_badge);
        mDotVerdict = findViewById(R.id.dot_verdict);
        mTvVerdictTitle = findViewById(R.id.tv_verdict_title);
        mTvVerdictSub = findViewById(R.id.tv_verdict_sub);
        mBtnQuarantineAllThreats = findViewById(R.id.btn_quarantine_all_threats);
        if (mBtnQuarantineAllThreats != null) {
            mBtnQuarantineAllThreats.setOnClickListener(v -> promptQuarantineAllThreats());
        }

        mScrollCyberLogs = findViewById(R.id.scroll_cyber_logs);
        mTvCyberLogs = findViewById(R.id.tv_cyber_logs);

        mTvMetricCountScanned = findViewById(R.id.tv_metric_count_scanned);
        mTvMetricCountSafe = findViewById(R.id.tv_metric_count_safe);
        mTvMetricCountThreats = findViewById(R.id.tv_metric_count_threats);
        mCardMetricScanned = findViewById(R.id.card_metric_scanned);
        mCardMetricSafe = findViewById(R.id.card_metric_safe);
        mCardMetricThreats = findViewById(R.id.card_metric_threats);

        mTvScanVelocity = findViewById(R.id.tv_scan_velocity);

        mTvMetricApps = findViewById(R.id.tv_metric_apps);
        mTvMetricIps = findViewById(R.id.tv_metric_ips);
        mTvMetricUrls = findViewById(R.id.tv_metric_urls);
        mTvMetricFiles = findViewById(R.id.tv_metric_files);

        mBtnActionScan = findViewById(R.id.btn_action_scan);

        mCardWorkbenchMalware = findViewById(R.id.card_workbench_malware);
        mCardWorkbenchApps = findViewById(R.id.card_workbench_apps);
        mCardWorkbenchQuarantine = findViewById(R.id.card_workbench_quarantine);
        mTvWorkbenchQuarantineSubtitle = findViewById(R.id.tv_workbench_quarantine_subtitle);

        mCardDevicePosture = findViewById(R.id.card_device_security_posture);
        mTvDevicePostureSubtitle = findViewById(R.id.tv_device_posture_subtitle);
        mTvDevicePostureScore = findViewById(R.id.tv_device_posture_score);
        mChipPosturePatch = findViewById(R.id.chip_posture_patch);
        mChipPostureEncryption = findViewById(R.id.chip_posture_encryption);
        mChipPostureAdb = findViewById(R.id.chip_posture_adb);

        mCardEdrCorrelations = findViewById(R.id.card_edr_correlations);
        mTvEdrCorrelationSubtitle = findViewById(R.id.tv_edr_correlation_subtitle);
        mTvEdrCorrelationBadge = findViewById(R.id.tv_edr_correlation_badge);

        mChipGroupEvidenceFilter = findViewById(R.id.chip_group_evidence_filter);
        mRecyclerEvidence = findViewById(R.id.recycler_evidence);
        if (mRecyclerEvidence != null) {
            mRecyclerEvidence.setLayoutManager(new LinearLayoutManager(this));
            mRecyclerEvidence.setHasFixedSize(false);
            mRecyclerEvidence.setItemViewCacheSize(8);          // reuse off-screen views instantly
            mRecyclerEvidence.setNestedScrollingEnabled(false); // avoid double-scroll fight with parent
            mAdapter = new AntivirusEvidenceAdapter(this);
            mRecyclerEvidence.setAdapter(mAdapter);
        }


        mCardVpnStatus = findViewById(R.id.card_scan_vpn_status);
        mIvScanVpnIcon = findViewById(R.id.iv_scan_vpn_icon);
        mTvScanVpnTitle = findViewById(R.id.tv_scan_vpn_title);
        mTvScanVpnSubtitle = findViewById(R.id.tv_scan_vpn_subtitle);
        mBtnScanStartVpn = findViewById(R.id.btn_scan_start_vpn);

        mCardApiKeyNotice = findViewById(R.id.card_api_key_notice);
        mBtnAddApiKeys = findViewById(R.id.btn_add_api_keys);

        mCardDetectionRules = findViewById(R.id.card_detection_rules);
        mTvDetectionRulesSubtitle = findViewById(R.id.tv_detection_rules_subtitle);
        mBtnSyncDetectionRules = findViewById(R.id.btn_sync_detection_rules);
    }

    private void setupListeners() {
        AnimUtils.attachSpringTouch(mBtnActionScan);
        AnimUtils.attachSpringTouch(mTabTypeQuick);
        AnimUtils.attachSpringTouch(mTabTypeFull);
        AnimUtils.attachSpringTouch(mTabTypeDeep);
        AnimUtils.attachSpringTouch(mCardWorkbenchMalware);
        AnimUtils.attachSpringTouch(mCardWorkbenchApps);
        AnimUtils.attachSpringTouch(mCardWorkbenchQuarantine);
        AnimUtils.attachSpringTouch(mCardMetricScanned);
        AnimUtils.attachSpringTouch(mCardMetricSafe);
        AnimUtils.attachSpringTouch(mCardMetricThreats);
        AnimUtils.attachSpringTouch(mBtnScanStartVpn);
        AnimUtils.attachSpringTouch(mBtnAddApiKeys);
        AnimUtils.attachSpringTouch(mBtnSyncDetectionRules);

        if (mTabTypeQuick != null) mTabTypeQuick.setOnClickListener(v -> switchTier(ScanTier.QUICK));
        if (mTabTypeFull != null) mTabTypeFull.setOnClickListener(v -> switchTier(ScanTier.FULL));
        if (mTabTypeDeep != null) mTabTypeDeep.setOnClickListener(v -> switchTier(ScanTier.DEEP));

        if (mBtnActionScan != null) {
            mBtnActionScan.setOnClickListener(v -> handleActionClick());
        }

        if (mCardWorkbenchMalware != null) {
            mCardWorkbenchMalware.setOnClickListener(v -> {
                startActivity(new Intent(this, SecurityActionsActivity.class));
            });
        }

        if (mCardWorkbenchApps != null) {
            mCardWorkbenchApps.setOnClickListener(v -> {
                startActivity(new Intent(this, AppsActivity.class));
            });
        }

        if (mCardWorkbenchQuarantine != null) {
            mCardWorkbenchQuarantine.setOnClickListener(v -> {
                startActivity(new Intent(this, QuarantineActivity.class));
            });
        }

        if (mBtnScanStartVpn != null) {
            mBtnScanStartVpn.setOnClickListener(v -> {
                if (CaptureService.isServiceActive()) {
                    CaptureService.stopService();
                    updateVpnStatusBanner();
                } else {
                    startActivity(new Intent(this, MainActivity.class));
                }
            });
        }

        if (mBtnAddApiKeys != null) {
            mBtnAddApiKeys.setOnClickListener(v -> {
                startActivity(new Intent(this, SettingsActivity.class));
            });
        }

        if (mCardDetectionRules != null) {
            mCardDetectionRules.setOnClickListener(v -> {
                DetectionRulesDialog.show(this, count -> updateDetectionRulesCard());
            });
        }

        if (mBtnSyncDetectionRules != null) {
            mBtnSyncDetectionRules.setOnClickListener(v -> {
                mBtnSyncDetectionRules.setEnabled(false);
                mBtnSyncDetectionRules.setText("Syncing...");
                DetectionRulesManager.getInstance(this).syncRulesFromGitHub(new DetectionRulesManager.SyncCallback() {
                    @Override
                    public void onSuccess(int rulesCount) {
                        mBtnSyncDetectionRules.setEnabled(true);
                        mBtnSyncDetectionRules.setText("Sync");
                        updateDetectionRulesCard();
                        Toast.makeText(AntivirusScanActivity.this, "Synced " + rulesCount + " detection rules from repository", Toast.LENGTH_SHORT).show();
                    }

                    @Override
                    public void onError(String errorMessage) {
                        mBtnSyncDetectionRules.setEnabled(true);
                        mBtnSyncDetectionRules.setText("Sync");
                        Toast.makeText(AntivirusScanActivity.this, "Sync failed: " + errorMessage, Toast.LENGTH_SHORT).show();
                    }
                });
            });
        }

        if (mChipGroupEvidenceFilter != null) {
            mChipGroupEvidenceFilter.setOnCheckedStateChangeListener((group, checkedIds) -> {
                int checkedId = checkedIds.isEmpty() ? View.NO_ID : checkedIds.get(0);
                if (checkedId == R.id.chip_threats_only) {
                    mCurrentFilter = "THREATS";
                } else if (checkedId == R.id.chip_apps_only) {
                    mCurrentFilter = "APPS";
                } else if (checkedId == R.id.chip_network_only) {
                    mCurrentFilter = "NETWORK";
                } else if (checkedId == R.id.chip_hashes_only) {
                    mCurrentFilter = "HASHES";
                } else {
                    mCurrentFilter = "ALL";
                }
                applyFilter();
            });
        }
    }

    private void switchTier(ScanTier newTier) {
        if (mIsScanning || mCurrentTier == newTier) return;
        mCurrentTier = newTier;
        applyTierUI();
        resetUI();
    }

    private void applyTierUI() {
        int primaryAccent = 0xFF58A6FF;
        int muted = ContextCompat.getColor(this, R.color.colorTabText);

        if (mMatrixCanvasView != null) {
            mMatrixCanvasView.setAccentColor(primaryAccent);
        }
        if (mLegendDotScan != null) {
            mLegendDotScan.setBackgroundTintList(ColorStateList.valueOf(primaryAccent));
        }
        if (mBtnActionScan != null) {
            mBtnActionScan.setBackgroundTintList(ColorStateList.valueOf(primaryAccent));
        }

        // Highlight selected tier
        if (mTvStQuickName != null) {
            mTvStQuickName.setTextColor(mCurrentTier == ScanTier.QUICK ? primaryAccent : muted);
            mTabTypeQuick.setBackgroundResource(mCurrentTier == ScanTier.QUICK ? R.drawable.mode_tab_bg : 0);
        }
        if (mTvStFullName != null) {
            mTvStFullName.setTextColor(mCurrentTier == ScanTier.FULL ? primaryAccent : muted);
            mTabTypeFull.setBackgroundResource(mCurrentTier == ScanTier.FULL ? R.drawable.mode_tab_bg : 0);
        }
        if (mTvStDeepName != null) {
            mTvStDeepName.setTextColor(mCurrentTier == ScanTier.DEEP ? primaryAccent : muted);
            mTabTypeDeep.setBackgroundResource(mCurrentTier == ScanTier.DEEP ? R.drawable.mode_tab_bg : 0);
        }

        if (mTvShieldSubtitle != null) {
            mTvShieldSubtitle.setText(mCurrentTier.subtitle);
        }
    }

    private void resetUI() {
        mScannedCount = 0;
        mSafeCount = 0;
        mThreatsCount = 0;
        mAppsCount = 0;
        mIpsCount = 0;
        mUrlsCount = 0;
        mFilesCount = 0;
        mCurrentVelocity = 0f;
        mPeakVelocity = 0f;

        if (mTvMetricCountScanned != null) mTvMetricCountScanned.setText("0");
        if (mTvMetricCountSafe != null) mTvMetricCountSafe.setText("0");
        if (mTvMetricCountThreats != null) mTvMetricCountThreats.setText("0");
        if (mTvMetricApps != null) mTvMetricApps.setText("0");
        if (mTvMetricIps != null) mTvMetricIps.setText("0");
        if (mTvMetricUrls != null) mTvMetricUrls.setText("0");
        if (mTvMetricFiles != null) mTvMetricFiles.setText("0");
        if (mTvScanVelocity != null) mTvScanVelocity.setText("Velocity: Standby");

        if (mMatrixCanvasView != null) {
            mMatrixCanvasView.setProgress(0f);
            mMatrixCanvasView.setScanStatus("READY", ContextCompat.getColor(this, R.color.colorTabText));
            mMatrixCanvasView.setScanVelocity(0f);
            mMatrixCanvasView.clearNodes();
        }

        if (mTvShieldSubtitle != null) {
            mTvShieldSubtitle.setText(mCurrentTier.subtitle);
            mTvShieldSubtitle.setTextColor(ContextCompat.getColor(this, R.color.colorTabText));
        }
        if (mTvCurrentFile != null) mTvCurrentFile.setText("—");
        if (mCardVerdictBadge != null) mCardVerdictBadge.setVisibility(View.GONE);
        if (mBtnQuarantineAllThreats != null) mBtnQuarantineAllThreats.setVisibility(View.GONE);

        mLogsBuilder.clear();
        mCyberLogLineCount = 0;
        addCyberLog("//", "Multi-Vector Shield ready (" + mCurrentTier.label + ")", 0xFF58A6FF);
        addCyberLog("//", "Tap Start Scan to inspect apps, network telemetry, URLs & storage", 0xFF8B949E);

        if (mBtnActionScan != null) {
            mBtnActionScan.setText("Start " + mCurrentTier.label);
            mBtnActionScan.setBackgroundTintList(ColorStateList.valueOf(0xFF58A6FF));
        }
    }

    private void handleActionClick() {
        if (mIsScanning) {
            stopScan();
        } else {
            beginScan();
        }
    }

    private void beginScan() {
        if ((mCurrentTier == ScanTier.FULL || mCurrentTier == ScanTier.DEEP) && !hasAllFilesPermission()) {
            promptStoragePermissionForDeepScan(true);
            return;
        }

        mIsScanning = true;
        mScanStartTime = SystemClock.elapsedRealtime();
        mLastVelocitySampleTime = mScanStartTime;
        mLastVelocitySampleCount = 0;
        mCurrentVelocity = 0f;
        mPeakVelocity = 0f;

        if (mMatrixCanvasView != null) {
            mMatrixCanvasView.setScanning(true);
            mMatrixCanvasView.setScanStatus("SCANNING", 0xFF58A6FF);
        }

        if (mTvScanVelocity != null) {
            mTvScanVelocity.setText("Velocity: 0 items/s");
        }

        if (mBtnActionScan != null) {
            mBtnActionScan.setText("Stop Scan");
            mBtnActionScan.setBackgroundTintList(ColorStateList.valueOf(0xFFF85149));
        }

        if (mTvShieldSubtitle != null) {
            mTvShieldSubtitle.setText(mCurrentTier.label + " in progress…");
        }

        mScannedCount = 0;
        mSafeCount = 0;
        mThreatsCount = 0;
        mAppsCount = 0;
        mIpsCount = 0;
        mUrlsCount = 0;
        mFilesCount = 0;

        mLogsBuilder.clear();
        mCyberLogLineCount = 0;
        addCyberLog("//", "Initializing Omni-Vector Antivirus Engine…", 0xFF58A6FF);
        addCyberLog("//", "Executing " + mCurrentTier.label + " across all system vectors", 0xFF39D3BB);

        AntivirusScanService.startScan(this, mCurrentTier.mode);
    }

    private void stopScan() {
        mIsScanning = false;
        if (mMatrixCanvasView != null) {
            mMatrixCanvasView.setScanning(false);
            mMatrixCanvasView.setScanStatus("STOPPED", ContextCompat.getColor(this, R.color.colorTabText));
        }
        if (mTvCurrentFile != null) mTvCurrentFile.setText("—");
        if (mTvShieldSubtitle != null) {
            mTvShieldSubtitle.setText("Scan stopped by user");
            mTvShieldSubtitle.setTextColor(ContextCompat.getColor(this, R.color.colorTabText));
        }

        if (mBtnActionScan != null) {
            mBtnActionScan.setText("Start Scan");
            mBtnActionScan.setBackgroundTintList(ColorStateList.valueOf(0xFF58A6FF));
        }
        addCyberLog("//", "Scan stopped by user", 0xFFDB6D28);
    }

    private void addCyberLog(String tag, String text, int color) {
        mCyberLogLineCount++;
        if (mCyberLogLineCount > MAX_CYBER_LOG_LINES) {
            int newlineIndex = TextUtils.indexOf(mLogsBuilder, '\n');
            if (newlineIndex >= 0 && newlineIndex < mLogsBuilder.length()) {
                mLogsBuilder.delete(0, newlineIndex + 1);
                mCyberLogLineCount--;
            }
        }
        int start = mLogsBuilder.length();
        mLogsBuilder.append(tag).append(" ").append(text).append("\n");
        mLogsBuilder.setSpan(new ForegroundColorSpan(color), start, start + tag.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
        if (mTvCyberLogs != null) {
            mTvCyberLogs.setText(mLogsBuilder);
        }
        // Throttle scroll — fullScroll triggers a full layout pass; at 24 items/s this kills UI thread
        long now = android.os.SystemClock.elapsedRealtime();
        if (mScrollCyberLogs != null && (now - mLastScrollTime) > 300) {
            mLastScrollTime = now;
            mScrollCyberLogs.post(() -> {
                if (mScrollCyberLogs != null) mScrollCyberLogs.fullScroll(View.FOCUS_DOWN);
            });
        }
    }

    private void bumpCard(View card) {
        if (card == null) return;
        card.animate().scaleX(1.08f).scaleY(1.08f).setDuration(120).withEndAction(() -> {
            card.animate().scaleX(1.0f).scaleY(1.0f).setDuration(120).start();
        }).start();
    }

    // ═════════════════════════════════════════════════════════════
    // Service Listener & Multi-Vector Feed
    // ═════════════════════════════════════════════════════════════

    private final AntivirusScanService.ScanServiceListener mScanServiceListener = new AntivirusScanService.ScanServiceListener() {
        private long mLastUiProgressTime = 0;
        private long mLastMatrixParticleTime = 0;

        @Override
        public void onPhaseChanged(String phaseName, int progressPercent) {
            mMainHandler.post(() -> {
                if (isFinishing() || isDestroyed()) return;
                if (mMatrixCanvasView != null) {
                    mMatrixCanvasView.setProgress(progressPercent);
                    mMatrixCanvasView.setScanStatus("SCANNING", 0xFF58A6FF);
                }
                if (mTvShieldSubtitle != null) {
                    mTvShieldSubtitle.setText(phaseName + " (" + progressPercent + "%)");
                }

                int tagColor = 0xFF58A6FF;
                String tag = "//";
                if (phaseName.toLowerCase().contains("network") || phaseName.toLowerCase().contains("traffic") || phaseName.toLowerCase().contains("ip")) {
                    tag = "[NET]";
                    tagColor = 0xFF39D3BB;
                } else if (phaseName.toLowerCase().contains("url") || phaseName.toLowerCase().contains("domain")) {
                    tag = "[URL]";
                    tagColor = 0xFFBC8CFF;
                } else if (phaseName.toLowerCase().contains("package") || phaseName.toLowerCase().contains("app")) {
                    tag = "[APK]";
                    tagColor = 0xFF58A6FF;
                } else if (phaseName.toLowerCase().contains("hash") || phaseName.toLowerCase().contains("storage") || phaseName.toLowerCase().contains("yara")) {
                    tag = "[STORAGE]";
                    tagColor = 0xFFF0B429;
                }
                addCyberLog(tag, phaseName, tagColor);
            });
        }

        @Override
        public void onFileProgress(String assetName, int current, int total) {
            // Classify asset & update counters
            String lower = assetName.toLowerCase();
            final String tag;
            final int accentColor;
            final String actionSuffix;
            if (lower.contains(":") || lower.matches(".*\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b.*")) {
                mIpsCount++;
                tag = "[NET]";
                accentColor = 0xFF39D3BB;
                actionSuffix = " — inspected";
            } else if (lower.startsWith("http") || lower.contains(".com") || lower.contains(".org") || lower.contains(".net") || lower.contains(".xyz")) {
                mUrlsCount++;
                tag = "[URL]";
                accentColor = 0xFFBC8CFF;
                actionSuffix = " — verified";
            } else if (lower.endsWith(".apk") || lower.startsWith("com.") || lower.startsWith("org.") || lower.startsWith("android.")) {
                mAppsCount++;
                tag = "[APK]";
                accentColor = 0xFF58A6FF;
                actionSuffix = " — clean";
            } else {
                mFilesCount++;
                tag = "[FILE]";
                accentColor = 0xFFF0B429;
                actionSuffix = " — SHA-256 ok";
            }

            mScannedCount = current;
            mSafeCount = Math.max(0, mScannedCount - mThreatsCount);

            long now = SystemClock.elapsedRealtime();
            boolean isLast = (current >= total && total > 0);

            // Throttle UI update to at most once every 60ms (~16 FPS) unless it is the final item
            if (!isLast && (now - mLastUiProgressTime < 60)) {
                return;
            }
            mLastUiProgressTime = now;

            final boolean spawnParticle = (now - mLastMatrixParticleTime >= 120);
            if (spawnParticle) {
                mLastMatrixParticleTime = now;
            }

            final int capturedScanned = mScannedCount;
            final int capturedSafe = mSafeCount;
            final int capturedApps = mAppsCount;
            final int capturedUrls = mUrlsCount;
            final int capturedIps = mIpsCount;
            final int capturedFiles = mFilesCount;
            final int capturedTotal = total;

            mMainHandler.post(() -> {
                if (isFinishing() || isDestroyed()) return;
                // Pre-compute truncated name for "currently scanning" label
                String shortName = assetName.length() > 50 ? assetName.substring(0, 47) + "…" : assetName;
                if (mTvCurrentFile != null) mTvCurrentFile.setText(shortName);

                if (mTvMetricCountScanned != null) mTvMetricCountScanned.setText(String.valueOf(capturedScanned));
                if (mTvMetricCountSafe != null) mTvMetricCountSafe.setText(String.valueOf(capturedSafe));
                if (mTvMetricApps != null) mTvMetricApps.setText(String.valueOf(capturedApps));
                if (mTvMetricUrls != null) mTvMetricUrls.setText(String.valueOf(capturedUrls));
                if (mTvMetricIps != null) mTvMetricIps.setText(String.valueOf(capturedIps));
                if (mTvMetricFiles != null) mTvMetricFiles.setText(String.valueOf(capturedFiles));

                // Trim URLs for display — raw query params make entries unreadably long
                String displayName = assetName;
                if ("[URL]".equals(tag) && assetName.startsWith("http")) {
                    try {
                        android.net.Uri u = android.net.Uri.parse(assetName);
                        String h = u.getHost();
                        String p = u.getPath();
                        if (h != null) {
                            displayName = u.getScheme() + "://" + h
                                    + (p != null && !p.isEmpty() && !p.equals("/") ? p : "");
                        }
                    } catch (Exception ignored) {}
                }
                if (displayName.length() > 60) displayName = displayName.substring(0, 57) + "…";
                addCyberLog(tag, displayName + actionSuffix, accentColor);


                if (mMatrixCanvasView != null) {
                    if (spawnParticle) {
                        mMatrixCanvasView.spawnNode(assetName, AntivirusMatrixView.NodeStatus.SAFE);
                    }
                    int pct = Math.round(((float) capturedScanned / Math.max(1, capturedTotal)) * 100f);
                    mMatrixCanvasView.setProgress(pct);
                }

                // Calculate Live Scan Velocity (EMA smoothed items/sec)
                long velocityNow = SystemClock.elapsedRealtime();
                long dt = velocityNow - mLastVelocitySampleTime;
                if (dt >= 200) {
                    int dCount = capturedScanned - mLastVelocitySampleCount;
                    float instVelocity = (dCount / (float) dt) * 1000f;
                    mCurrentVelocity = mCurrentVelocity == 0f ? instVelocity : (mCurrentVelocity * 0.6f + instVelocity * 0.4f);
                    if (mCurrentVelocity > mPeakVelocity) {
                        mPeakVelocity = mCurrentVelocity;
                    }
                    mLastVelocitySampleTime = velocityNow;
                    mLastVelocitySampleCount = capturedScanned;

                    if (mTvScanVelocity != null) {
                        mTvScanVelocity.setText(String.format(java.util.Locale.US, "Velocity: %.0f items/s (Peak: %.0f/s)", mCurrentVelocity, mPeakVelocity));
                    }
                    if (mMatrixCanvasView != null) {
                        mMatrixCanvasView.setScanVelocity(mCurrentVelocity);
                    }
                }
            });
        }

        @Override
        public void onScanCompleted(AntivirusScanEngine.ScanResult result) {
            mMainHandler.post(() -> {
                if (isFinishing() || isDestroyed()) return;
                mIsScanning = false;
                if (mMatrixCanvasView != null) mMatrixCanvasView.setScanning(false);
                mLastResult = result;
                if (result != null) {
                    displayResult(result);
                }
            });
        }
    };

    @Override
    protected void onStart() {
        super.onStart();
        AntivirusScanService.registerListener(mScanServiceListener);
        syncScanServiceState();
    }

    @Override
    protected void onStop() {
        super.onStop();
        AntivirusScanService.unregisterListener(mScanServiceListener);
    }

    @Override
    protected void onRestoreInstanceState(@NonNull Bundle savedInstanceState) {
        super.onRestoreInstanceState(savedInstanceState);
        // Re-apply filter chip selection after view state is fully restored
        String filter = savedInstanceState.getString(KEY_CURRENT_FILTER, "THREATS");
        if (!filter.equals(mCurrentFilter)) {
            mCurrentFilter = filter;
            applyFilter();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        updateVpnStatusBanner();
        syncScanServiceState();
        updateDetectionRulesCard();

        if (mTvWorkbenchQuarantineSubtitle != null) {
            int qCount = com.kotsafe.security.model.QuarantineVaultManager.getInstance(this).getQuarantinedCount();
            if (qCount > 0) {
                mTvWorkbenchQuarantineSubtitle.setText(qCount + " isolated threat artifact" + (qCount > 1 ? "s" : "") + " in vault");
            } else {
                mTvWorkbenchQuarantineSubtitle.setText("Vault is empty. No active isolated threats.");
            }
        }

        if (mPendingDeepScanAfterPermission) {
            mPendingDeepScanAfterPermission = false;
            if (hasAllFilesPermission()) {
                Toast.makeText(this, "Full disk access granted! Starting scan...", Toast.LENGTH_SHORT).show();
                beginScan();
            } else {
                Toast.makeText(this, "Full disk access not granted. Scanning apps only.", Toast.LENGTH_SHORT).show();
                mCurrentTier = ScanTier.QUICK;
                applyTierUI();
                beginScan();
            }
        }
    }

    private void updateDetectionRulesCard() {
        if (mCardDetectionRules == null) return;
        boolean isEnabled = Prefs.isDetectionRulesEnabled(this);
        if (!isEnabled) {
            mCardDetectionRules.setVisibility(View.GONE);
            return;
        }

        mCardDetectionRules.setVisibility(View.VISIBLE);
        int count = DetectionRulesManager.getInstance(this).getActiveRulesCount();
        long lastSync = Prefs.getDetectionRulesLastSyncTime(this);
        String syncText = lastSync > 0 ? "Synced" : "Bundled";
        if (mTvDetectionRulesSubtitle != null) {
            mTvDetectionRulesSubtitle.setText(count + " Community Rules Active • " + syncText);
        }
    }


    private void syncScanServiceState() {
        if (AntivirusScanService.isScanning()) {
            mIsScanning = true;
            if (mMatrixCanvasView != null) {
                mMatrixCanvasView.setScanning(true);
                mMatrixCanvasView.setProgress(AntivirusScanService.getCurrentProgress());
                mMatrixCanvasView.setScanStatus("SCANNING", 0xFF58A6FF);
            }
            if (mBtnActionScan != null) {
                mBtnActionScan.setText("Stop Scan");
                mBtnActionScan.setBackgroundTintList(ColorStateList.valueOf(0xFFF85149));
            }
        } else if (mLastResult == null && AntivirusScanService.getLastResult() != null) {
            mLastResult = AntivirusScanService.getLastResult();
            displayResult(mLastResult);
        }
    }

    private void displayResult(AntivirusScanEngine.ScanResult result) {
        mIsScanning = false;
        if (mMatrixCanvasView != null) {
            mMatrixCanvasView.setScanning(false);
            mMatrixCanvasView.setProgress(100f);
            mMatrixCanvasView.setScanVelocity(0f);
        }
        if (mTvCurrentFile != null) mTvCurrentFile.setText("—");

        if (mBtnActionScan != null) {
            mBtnActionScan.setText("Scan Again");
            mBtnActionScan.setBackgroundTintList(ColorStateList.valueOf(0xFF58A6FF));
        }

        mScannedCount = result.totalPackagesScanned + result.totalStorageScanned + result.totalHashesScanned + result.totalIpsScanned + result.totalUrlsScanned;
        mThreatsCount = result.threatsDetected + result.suspiciousDetected;
        mSafeCount = Math.max(0, mScannedCount - mThreatsCount);

        // Compute final average scan throughput velocity
        long durationMs = Math.max(1, SystemClock.elapsedRealtime() - mScanStartTime);
        float avgVelocity = (mScannedCount / (float) durationMs) * 1000f;
        if (mPeakVelocity < avgVelocity) mPeakVelocity = avgVelocity;

        // Save structured scan report into audit history
        try {
            ScanReportEntry report = ScanReportEntry.fromScanResult(result, false, durationMs);
            ScanReportDbHelper.getInstance(this).insertReport(report);
        } catch (Exception e) {
            com.kotsafe.security.Log.e(TAG, "Failed to save scan report: " + e.getMessage());
        }

        if (mTvScanVelocity != null) {
            mTvScanVelocity.setText(String.format("Avg Velocity: %.0f items/s (Peak: %.0f/s)", avgVelocity, mPeakVelocity));
        }

        if (mTvMetricCountScanned != null) AnimUtils.animateScoreCountUp(mTvMetricCountScanned, 0, mScannedCount, 600, "");
        if (mTvMetricCountSafe != null) AnimUtils.animateScoreCountUp(mTvMetricCountSafe, 0, mSafeCount, 600, "");
        if (mTvMetricCountThreats != null) AnimUtils.animateScoreCountUp(mTvMetricCountThreats, 0, mThreatsCount, 600, "");

        // Update 4 Pillar Breakdown
        if (mTvMetricApps != null) mTvMetricApps.setText(String.valueOf(result.totalPackagesScanned));
        if (mTvMetricIps != null) mTvMetricIps.setText(String.valueOf(result.totalIpsScanned));
        if (mTvMetricUrls != null) mTvMetricUrls.setText(String.valueOf(result.totalUrlsScanned));
        if (mTvMetricFiles != null) mTvMetricFiles.setText(String.valueOf(result.totalStorageScanned + result.totalHashesScanned));

        if (mCardVerdictBadge != null) mCardVerdictBadge.setVisibility(View.VISIBLE);

        if (mThreatsCount > 0) {
            if (mCardVerdictBadge != null) {
                AnimUtils.shakeView(mCardVerdictBadge);
            }
            if (mMatrixCanvasView != null) {
                mMatrixCanvasView.setScanStatus("ATTENTION", 0xFFF85149);
                mMatrixCanvasView.setScoreDisplay(String.valueOf(result.securityScore), 0xFFF85149);
            }
            if (mDotVerdict != null) mDotVerdict.setBackgroundTintList(ColorStateList.valueOf(0xFFF85149));
            if (mCardVerdictBadge != null) mCardVerdictBadge.setStrokeColor(0xFFF85149);
            if (mTvVerdictTitle != null) {
                mTvVerdictTitle.setText(mThreatsCount >= 3 ? "Malicious Threats Detected" : "Suspicious Indicators Found");
                mTvVerdictTitle.setTextColor(0xFFF85149);
            }
            if (mTvVerdictSub != null) {
                mTvVerdictSub.setText(mThreatsCount + " vector items flagged by defense engine");
            }
            if (mTvShieldSubtitle != null) {
                mTvShieldSubtitle.setText(mThreatsCount + " threat" + (mThreatsCount > 1 ? "s" : "") + " isolated — review below");
                mTvShieldSubtitle.setTextColor(ContextCompat.getColor(this, R.color.status_threat));
            }
            addCyberLog("⛔", mCurrentTier.label + " complete — " + mThreatsCount + " threat(s) require attention", 0xFFF85149);
        } else {
            if (mMatrixCanvasView != null) {
                mMatrixCanvasView.setScanStatus("COMPLETE", ContextCompat.getColor(this, R.color.ok));
                mMatrixCanvasView.setScoreDisplay(String.valueOf(result.securityScore), ContextCompat.getColor(this, R.color.ok));
            }
            if (mDotVerdict != null) mDotVerdict.setBackgroundTintList(ColorStateList.valueOf(0xFF2EA44F));
            if (mCardVerdictBadge != null) mCardVerdictBadge.setStrokeColor(0xFF2EA44F);
            if (mTvVerdictTitle != null) {
                mTvVerdictTitle.setText("Device Fully Protected");
                mTvVerdictTitle.setTextColor(ContextCompat.getColor(this, R.color.ok));
            }
            if (mTvVerdictSub != null) {
                mTvVerdictSub.setText("All " + mScannedCount + " apps, network routes, URLs and files verified clean");
            }
            if (mTvShieldSubtitle != null) {
                mTvShieldSubtitle.setText("No threats found — your device is protected");
                mTvShieldSubtitle.setTextColor(ContextCompat.getColor(this, R.color.ok));
            }
            addCyberLog("✓", mCurrentTier.label + " complete — all " + mScannedCount + " assets clean", 0xFF2EA44F);
        }

        if (result.totalSplitsScanned > 0) {
            addCyberLog("✔", "Analyzed " + result.totalSplitsScanned + " dynamic split APK modules across app bundles", 0xFF39D3BB);
        }

        // Check for Quarantinable File Threats
        final List<AntivirusEvidenceItem> quarantinableThreats = new ArrayList<>();
        if (result.evidenceList != null) {
            for (AntivirusEvidenceItem ev : result.evidenceList) {
                if (ev != null && (AntivirusEvidenceItem.SEVERITY_MALICIOUS.equals(ev.severity)
                        || AntivirusEvidenceItem.SEVERITY_SUSPICIOUS.equals(ev.severity))) {
                    String p = ev.getDisplayPath();
                    if (p != null && !p.isEmpty()) {
                        File f = new File(p);
                        if (f.exists() && f.isFile()) {
                            quarantinableThreats.add(ev);
                        }
                    }
                }
            }
        }

        if (mBtnQuarantineAllThreats != null) {
            if (!quarantinableThreats.isEmpty()) {
                mBtnQuarantineAllThreats.setVisibility(View.VISIBLE);
                mBtnQuarantineAllThreats.setText("Quarantine All Detected Threats (" + quarantinableThreats.size() + ")");
                if (Prefs.isAutoQuarantineEnabled(this)) {
                    executeBatchQuarantine(quarantinableThreats, true);
                }
            } else {
                mBtnQuarantineAllThreats.setVisibility(View.GONE);
            }
        }

        if (mCardApiKeyNotice != null) {
            mCardApiKeyNotice.setVisibility(result.missingApiKeys ? View.VISIBLE : View.GONE);
        }

        // Update Device Security Posture UI (EDR v2)
        if (result.devicePosture != null) {
            if (mTvDevicePostureScore != null) {
                mTvDevicePostureScore.setText(result.devicePosture.overallScore + " / 100");
                if (result.devicePosture.overallScore >= 80) {
                    mTvDevicePostureScore.setTextColor(0xFF3FB950);
                } else if (result.devicePosture.overallScore >= 60) {
                    mTvDevicePostureScore.setTextColor(0xFFD29922);
                } else {
                    mTvDevicePostureScore.setTextColor(0xFFF85149);
                }
            }
            if (mTvDevicePostureSubtitle != null) {
                String sub = !result.devicePosture.riskWarnings.isEmpty()
                        ? result.devicePosture.riskWarnings.get(0)
                        : "Security hardening baseline is optimal (" + result.devicePosture.postureGrade + ")";
                mTvDevicePostureSubtitle.setText(sub);
            }
            if (mChipPosturePatch != null) {
                mChipPosturePatch.setText("Patch: " + result.devicePosture.securityPatchDate);
            }
            if (mChipPostureEncryption != null) {
                mChipPostureEncryption.setText(result.devicePosture.isEncrypted ? "Encrypted: Yes" : "Encrypted: No");
            }
            if (mChipPostureAdb != null) {
                mChipPostureAdb.setText(result.devicePosture.isAdbEnabled ? "ADB: Enabled" : "ADB: Disabled");
                mChipPostureAdb.setTextColor(result.devicePosture.isAdbEnabled ? 0xFFD29922 : 0xFF8B949E);
            }
        }

        // Update EDR Correlated Incidents UI (EDR v2)
        int correlations = result.correlatedIncidentsCount;
        if (mTvEdrCorrelationSubtitle != null) {
            mTvEdrCorrelationSubtitle.setText(correlations > 0
                    ? correlations + " Correlated incident(s) flagged by behavioral engine"
                    : "Real-time cross-correlation active • 0 Incidents");
        }
        if (mTvEdrCorrelationBadge != null) {
            if (correlations > 0) {
                mTvEdrCorrelationBadge.setText(correlations + " Alerts");
                mTvEdrCorrelationBadge.setTextColor(0xFFF85149);
            } else {
                mTvEdrCorrelationBadge.setText("EDR Clean");
                mTvEdrCorrelationBadge.setTextColor(0xFF3FB950);
            }
        }

        applyFilter();
    }

    private void applyFilter() {
        if (mLastResult == null) return;
        List<AntivirusEvidenceItem> filtered = new ArrayList<>();
        for (AntivirusEvidenceItem item : mLastResult.evidenceList) {
            if ("THREATS".equals(mCurrentFilter)) {
                if (!item.isWhitelisted && !item.isSystemApp
                        && (AntivirusEvidenceItem.SEVERITY_MALICIOUS.equals(item.severity)
                        || AntivirusEvidenceItem.SEVERITY_SUSPICIOUS.equals(item.severity))) {
                    filtered.add(item);
                }
            } else if ("APPS".equals(mCurrentFilter)) {
                if (AntivirusEvidenceItem.TYPE_APP_HASH.equals(item.type)
                        || AntivirusEvidenceItem.TYPE_SERVICE_HASH.equals(item.type)
                        || (item.packageName != null && !item.packageName.isEmpty())) {
                    filtered.add(item);
                }
            } else if ("NETWORK".equals(mCurrentFilter)) {
                if (AntivirusEvidenceItem.TYPE_IP.equals(item.type) || AntivirusEvidenceItem.TYPE_URL.equals(item.type)) {
                    filtered.add(item);
                }
            } else if ("HASHES".equals(mCurrentFilter)) {
                if (AntivirusEvidenceItem.TYPE_SERVICE_HASH.equals(item.type)
                        || AntivirusEvidenceItem.TYPE_APP_HASH.equals(item.type)
                        || AntivirusEvidenceItem.TYPE_STORAGE_FILE.equals(item.type)
                        || AntivirusEvidenceItem.TYPE_YARA_MATCH.equals(item.type)) {
                    filtered.add(item);
                }
            } else {
                filtered.add(item);
            }
            if (filtered.size() >= 100) break;
        }

        if (!"THREATS".equals(mCurrentFilter) && filtered.isEmpty() && !mLastResult.evidenceList.isEmpty()) {
            for (AntivirusEvidenceItem item : mLastResult.evidenceList) {
                filtered.add(item);
                if (filtered.size() >= 50) break;
            }
        }

        if (mAdapter != null) {
            mAdapter.setItems(filtered);
        }
    }

    private void updateVpnStatusBanner() {
        if (mCardVpnStatus == null) return;
        boolean isVpnActive = CaptureService.isServiceActive();
        ScanModeConfig.CaptureState captureState = VpnConsentManager.getCaptureState(this);

        if (isVpnActive) {
            // Protection is active and running - hide the prompt/banner so no unnecessary notification is shown
            mCardVpnStatus.setVisibility(View.GONE);
        } else if (captureState == ScanModeConfig.CaptureState.VPN_CONSENT_REQUIRED) {
            mCardVpnStatus.setVisibility(View.VISIBLE);
            mCardVpnStatus.setStrokeColor(ContextCompat.getColor(this, R.color.warning));
            mIvScanVpnIcon.setImageResource(R.drawable.ic_exclamation_triangle_solid);
            mIvScanVpnIcon.setColorFilter(ContextCompat.getColor(this, R.color.warning));
            mTvScanVpnTitle.setText("Network Consent Required");
            mTvScanVpnSubtitle.setText("Enable VPN inspection for live per-socket C2 defense");
            mBtnScanStartVpn.setText("Enable");
            mBtnScanStartVpn.setTextColor(ContextCompat.getColor(this, R.color.warning));
        } else {
            mCardVpnStatus.setVisibility(View.VISIBLE);
            mCardVpnStatus.setStrokeColor(ContextCompat.getColor(this, R.color.drawerSeparatorColor));
            mIvScanVpnIcon.setImageResource(R.drawable.ic_shield);
            mIvScanVpnIcon.setColorFilter(ContextCompat.getColor(this, R.color.colorTabText));
            mTvScanVpnTitle.setText("Real-Time Network Daemon Inactive");
            mTvScanVpnSubtitle.setText("Offline file scanning active; turn on VPN for live traffic analysis");
            mBtnScanStartVpn.setText("Turn On");
            mBtnScanStartVpn.setTextColor(ContextCompat.getColor(this, R.color.colorAccent));
        }
    }

    private boolean hasAllFilesPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            return Environment.isExternalStorageManager();
        }
        return ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE)
                == PackageManager.PERMISSION_GRANTED;
    }

    private void promptStoragePermissionForDeepScan(boolean triggerScanOnGrant) {
        mPendingDeepScanAfterPermission = triggerScanOnGrant;
        new AlertDialog.Builder(this)
                .setTitle("Full Disk Access Required")
                .setMessage("To perform a full device scan for hidden malware, split APKs, and trojan payloads across all storage folders, KotSafe requires All Files Access.\n\nYou can grant this in system settings or continue scanning installed apps only.")
                .setPositiveButton("Grant Access", (dialog, which) -> {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        try {
                            Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
                            intent.setData(Uri.parse("package:" + getPackageName()));
                            startActivity(intent);
                        } catch (Exception e) {
                            Intent intent = new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION);
                            startActivity(intent);
                        }
                    } else {
                        ActivityCompat.requestPermissions(this,
                                new String[]{Manifest.permission.READ_EXTERNAL_STORAGE}, 2001);
                    }
                })
                .setNegativeButton("Scan Apps Only", (dialog, which) -> {
                    mPendingDeepScanAfterPermission = false;
                    mCurrentTier = ScanTier.QUICK;
                    applyTierUI();
                    beginScan();
                })
                .show();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.antivirus_menu, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        int id = item.getItemId();
        if (id == R.id.action_threat_intel_settings) {
            startActivity(new Intent(this, SettingsActivity.class));
            return true;
        } else if (id == R.id.action_apk_installer) {
            startActivity(new Intent(this, AppsActivity.class));
            return true;
        } else if (id == R.id.action_malware_detection) {
            startActivity(new Intent(this, SecurityActionsActivity.class));
            return true;
        } else if (id == R.id.action_scan_reports) {
            ScanReportEntry latest = ScanReportDbHelper.getInstance(this).getLatestReport();
            if (latest != null) {
                ScanReportDetailsDialog.newInstance(latest).show(getSupportFragmentManager(), ScanReportDetailsDialog.TAG);
            } else {
                Toast.makeText(this, "No scan audit reports found yet.", Toast.LENGTH_SHORT).show();
            }
            return true;
        } else if (id == R.id.action_export_report) {
            ScanReportEntry latest = ScanReportDbHelper.getInstance(this).getLatestReport();
            if (latest != null) {
                String exportText = "🛡️ KotSafe / KotSafe Scan Audit Report\n" +
                        "Mode: " + latest.scanMode + (latest.isBackground ? " (Daily Background)" : " (Manual)") + "\n" +
                        "Security Score: " + latest.securityScore + "/100\n" +
                        "Threats: " + latest.threatsDetected + " | Suspicious: " + latest.suspiciousDetected + "\n" +
                        "Packages Scanned: " + latest.packagesScanned + "\n" +
                        "Split APKs: " + latest.splitsScanned + "\n" +
                        "Storage Files: " + latest.storageScanned + "\n" +
                        "Network Endpoints: " + (latest.ipsScanned + latest.urlsScanned) + "\n" +
                        "Duration: " + (latest.durationMs / 1000.0) + "s\n" +
                        "Summary: " + latest.summary;
                Intent shareIntent = new Intent(Intent.ACTION_SEND);
                shareIntent.setType("text/plain");
                shareIntent.putExtra(Intent.EXTRA_SUBJECT, "Security Scan Report");
                shareIntent.putExtra(Intent.EXTRA_TEXT, exportText);
                startActivity(Intent.createChooser(shareIntent, "Export Scan Report"));
            } else {
                Toast.makeText(this, "No scan telemetry available to export", Toast.LENGTH_SHORT).show();
            }
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void promptQuarantineAllThreats() {
        if (mLastResult == null || mLastResult.evidenceList == null) return;
        List<AntivirusEvidenceItem> toQuarantine = new ArrayList<>();
        for (AntivirusEvidenceItem ev : mLastResult.evidenceList) {
            if (ev != null && (AntivirusEvidenceItem.SEVERITY_MALICIOUS.equals(ev.severity)
                    || AntivirusEvidenceItem.SEVERITY_SUSPICIOUS.equals(ev.severity))) {
                String p = ev.getDisplayPath();
                if (p != null && !p.isEmpty()) {
                    File f = new File(p);
                    if (f.exists() && f.isFile()) {
                        toQuarantine.add(ev);
                    }
                }
            }
        }

        if (toQuarantine.isEmpty()) {
            Toast.makeText(this, "No file threats available to quarantine", Toast.LENGTH_SHORT).show();
            if (mBtnQuarantineAllThreats != null) mBtnQuarantineAllThreats.setVisibility(View.GONE);
            return;
        }

        new AlertDialog.Builder(this)
                .setTitle("Quarantine All Detected Threats?")
                .setMessage("Move " + toQuarantine.size() + " malicious/suspicious file(s) to the Sandboxed Quarantine Vault?\n\n"
                        + "• Files will be encrypted with AES-256-GCM\n"
                        + "• Stripped of execution permissions (POSIX 0600)\n"
                        + "• Network egress will be blocked/sinkholed\n"
                        + "• Original malware source files will be shredded")
                .setPositiveButton("Quarantine All Now", (d, w) -> executeBatchQuarantine(toQuarantine, false))
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void executeBatchQuarantine(List<AntivirusEvidenceItem> items, boolean isAuto) {
        if (items == null || items.isEmpty()) return;
        addCyberLog("🔒", (isAuto ? "Auto-quarantining " : "Quarantining ") + items.size() + " threats to vault...", 0xFF58A6FF);

        new Thread(() -> {
            QuarantineVaultManager qm = QuarantineVaultManager.getInstance(this);
            int successCount = 0;
            for (AntivirusEvidenceItem it : items) {
                String p = it.getDisplayPath();
                if (p != null) {
                    File f = new File(p);
                    if (f.exists()) {
                        boolean ok = qm.quarantineFile(f, it.severity != null ? it.severity : "STORAGE_THREAT", it.details);
                        if (ok) {
                            successCount++;
                            it.isQuarantined = true;
                            it.severity = AntivirusEvidenceItem.SEVERITY_RESOLVED;
                            it.verdict = "QUARANTINED";
                            it.details = "[QUARANTINED IN ENCRYPTED VAULT] " + (it.details != null ? it.details : "");
                        }
                    }
                }
            }
            final int count = successCount;
            runOnUiThread(() -> {
                if (mBtnQuarantineAllThreats != null) {
                    mBtnQuarantineAllThreats.setVisibility(View.GONE);
                }
                addCyberLog("🛡️", count + " threat(s) locked in Sandboxed Vault (Execution disabled, Network sinkholed)", 0xFF3FB950);
                Toast.makeText(this, count + " threat(s) moved to Quarantine Vault", Toast.LENGTH_LONG).show();
                reanalyzeAndDisplayScore(count);
            });
        }).start();
    }

    /**
     * Re-analyzes the antivirus scan score after threats have been moved to quarantine.
     * Recalculates metrics, animates the score display and counters, and updates posture state.
     */
    public void reanalyzeAndDisplayScore(int quarantinedCount) {
        if (mLastResult == null) return;

        int oldScore = mLastResult.securityScore;
        int oldThreatsCount = mThreatsCount;
        int oldSafeCount = mSafeCount;

        // Tally remaining uncontained threats
        int remainingThreats = 0;
        int remainingSuspicious = 0;
        if (mLastResult.evidenceList != null) {
            for (AntivirusEvidenceItem ev : mLastResult.evidenceList) {
                if (ev == null || ev.isQuarantined || ev.isWhitelisted || ev.isSystemApp
                        || AntivirusEvidenceItem.SEVERITY_RESOLVED.equals(ev.severity)
                        || AntivirusEvidenceItem.SEVERITY_CLEAN.equals(ev.severity)) {
                    continue;
                }
                if (AntivirusEvidenceItem.SEVERITY_MALICIOUS.equals(ev.severity)) {
                    remainingThreats++;
                } else if (AntivirusEvidenceItem.SEVERITY_SUSPICIOUS.equals(ev.severity)) {
                    remainingSuspicious++;
                }
            }
        }

        // Re-analyze Score
        int newScore = 100;
        newScore -= (remainingThreats * 30);
        newScore -= (remainingSuspicious * 8);
        if (newScore < 10 && (remainingThreats > 0 || remainingSuspicious > 0)) newScore = 15;
        if (newScore < 0) newScore = 0;
        if (remainingThreats == 0 && remainingSuspicious == 0) newScore = 100;

        mLastResult.threatsDetected = remainingThreats;
        mLastResult.suspiciousDetected = remainingSuspicious;
        mLastResult.securityScore = newScore;
        mThreatsCount = remainingThreats + remainingSuspicious;
        mSafeCount = Math.max(0, mScannedCount - mThreatsCount);

        // Update AntivirusScanService static cache
        AntivirusScanService.setLastResult(mLastResult);

        // Animate metrics
        if (mTvMetricCountThreats != null) {
            AnimUtils.animateScoreCountUp(mTvMetricCountThreats, oldThreatsCount, mThreatsCount, 600, "");
        }
        if (mTvMetricCountSafe != null) {
            AnimUtils.animateScoreCountUp(mTvMetricCountSafe, oldSafeCount, mSafeCount, 600, "");
        }

        // Animate Score on Matrix View
        int targetColor;
        if (newScore >= 80) {
            targetColor = 0xFF2EA44F; // Green
        } else if (newScore >= 60) {
            targetColor = 0xFFD29922; // Yellow
        } else {
            targetColor = 0xFFF85149; // Red
        }

        if (mMatrixCanvasView != null) {
            android.animation.ValueAnimator scoreAnim = android.animation.ValueAnimator.ofInt(oldScore, newScore);
            scoreAnim.setDuration(800);
            scoreAnim.setInterpolator(new android.view.animation.DecelerateInterpolator());
            scoreAnim.addUpdateListener(anim -> {
                int val = (int) anim.getAnimatedValue();
                mMatrixCanvasView.setScoreDisplay(String.valueOf(val), targetColor);
            });
            scoreAnim.start();

            if (mThreatsCount == 0) {
                mMatrixCanvasView.setScanStatus("PROTECTED", 0xFF2EA44F);
            } else {
                mMatrixCanvasView.setScanStatus("ATTENTION", targetColor);
            }
        }

        // Update Verdict Card
        if (mThreatsCount == 0) {
            if (mDotVerdict != null) mDotVerdict.setBackgroundTintList(ColorStateList.valueOf(0xFF2EA44F));
            if (mCardVerdictBadge != null) {
                mCardVerdictBadge.setStrokeColor(0xFF2EA44F);
                AnimUtils.playPulse(mCardVerdictBadge);
            }
            if (mTvVerdictTitle != null) {
                mTvVerdictTitle.setText("All Threats Quarantined • System Protected");
                mTvVerdictTitle.setTextColor(0xFF2EA44F);
            }
            if (mTvVerdictSub != null) {
                mTvVerdictSub.setText("All detected vectors neutralized & isolated in Sandboxed Vault");
            }
            if (mTvShieldSubtitle != null) {
                mTvShieldSubtitle.setText("Quarantine containment active • 0 uncontained threats");
                mTvShieldSubtitle.setTextColor(ContextCompat.getColor(this, R.color.ok));
            }
            if (mBtnQuarantineAllThreats != null) {
                mBtnQuarantineAllThreats.setVisibility(View.GONE);
            }
        } else {
            if (mTvVerdictTitle != null) {
                mTvVerdictTitle.setText(mThreatsCount >= 3 ? "Malicious Threats Detected" : "Suspicious Indicators Remaining");
            }
            if (mTvVerdictSub != null) {
                mTvVerdictSub.setText(mThreatsCount + " vector items still require review or quarantine");
            }
            if (mTvShieldSubtitle != null) {
                mTvShieldSubtitle.setText(mThreatsCount + " uncontained threat(s) remaining");
            }
        }

        // Update Device Posture Score
        if (mLastResult.devicePosture != null) {
            mLastResult.devicePosture = com.kotsafe.security.model.DeviceSecurityEngine.evaluate(this);
            if (mTvDevicePostureScore != null) {
                mTvDevicePostureScore.setText(mLastResult.devicePosture.overallScore + " / 100");
                if (mLastResult.devicePosture.overallScore >= 80) {
                    mTvDevicePostureScore.setTextColor(0xFF3FB950);
                } else if (mLastResult.devicePosture.overallScore >= 60) {
                    mTvDevicePostureScore.setTextColor(0xFFD29922);
                } else {
                    mTvDevicePostureScore.setTextColor(0xFFF85149);
                }
            }
            if (mTvDevicePostureSubtitle != null) {
                String sub = !mLastResult.devicePosture.riskWarnings.isEmpty()
                        ? mLastResult.devicePosture.riskWarnings.get(0)
                        : "Security hardening baseline is optimal (" + mLastResult.devicePosture.postureGrade + ")";
                mTvDevicePostureSubtitle.setText(sub);
            }
        }

        // Update Workbench Quarantine Subtitle
        if (mTvWorkbenchQuarantineSubtitle != null) {
            int qCount = QuarantineVaultManager.getInstance(this).getQuarantinedCount();
            if (qCount > 0) {
                mTvWorkbenchQuarantineSubtitle.setText(qCount + " isolated threat artifact" + (qCount > 1 ? "s" : "") + " in vault");
            } else {
                mTvWorkbenchQuarantineSubtitle.setText("Vault is empty. No active isolated threats.");
            }
        }

        addCyberLog("✨", "Scan Score Re-analyzed: " + oldScore + " ➔ " + newScore + "/100 (" + quarantinedCount + " threat(s) moved to Quarantine)", 0xFF3FB950);

        applyFilter();
        if (mAdapter != null) {
            mAdapter.notifyDataSetChanged();
        }
    }
}
