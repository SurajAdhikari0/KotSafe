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

import android.animation.ObjectAnimator;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageInstaller;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import androidx.core.content.ContextCompat;
import android.view.Gravity;
import android.view.MenuItem;
import android.view.View;
import android.view.animation.AnimationUtils;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.core.content.FileProvider;

import com.kotsafe.security.Log;
import com.kotsafe.security.R;
import com.kotsafe.security.model.AlertRecord;
import com.kotsafe.security.model.AlertStore;
import com.kotsafe.security.model.ApkPreInstallScanner;
import com.kotsafe.security.model.AntivirusEvidenceItem;
import com.kotsafe.security.receivers.ApkInstallReceiver;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Displays the full pre-install scan result and allows the user to install or cancel.
 *
 * Verdict colour logic:
 *   CLEAN      → green  (#4CAF50) — Install button prominent
 *   SUSPICIOUS → amber  (#FF9800) — "Install with Caution" + warning
 *   THREAT     → red    (#F44336) — "Do Not Install" primary, "Install Anyway" danger
 */
public class ApkScanResultActivity extends AppCompatActivity {

    private static final String TAG = "ApkScanResultActivity";
    private static final String FILE_PROVIDER_AUTHORITY = ".fileprovider";

    // UI references
    private MaterialCardView mCardVerdict;
    private ImageView        mImgAppIcon;
    private TextView         mTvAppName;
    private TextView         mTvPackageName;
    private TextView         mTvVersion;
    private TextView         mTvVerdictEmoji;
    private TextView         mTvVerdictLabel;
    private TextView         mTvVerdictSubtitle;
    private TextView         mTvRiskScore;
    private ProgressBar      mProgressRisk;
    private TextView         mTvSha256;
    private TextView         mTvDexResult;
    private TextView         mTvTiResult;
    private TextView         mTvScanDuration;
    private MaterialCardView mCardEvidence;
    private LinearLayout     mContainerEvidence;
    private TextView         mTvThreatWarning;
    private MaterialButton   mBtnInstall;
    private MaterialButton   mBtnCancel;

    // Installing animation UI
    private LinearLayout     mLayoutInstalling;
    private ProgressBar      mProgressInstallingSpinner;
    private TextView         mTvInstallingStatus;
    private TextView         mTvInstallingSubtext;
    private TextView         mTvInstallingPct;
    private ProgressBar      mProgressInstallingBar;

    private ApkPreInstallScanner.PreInstallReport mReport;
    private final ExecutorService mExecutor = Executors.newSingleThreadExecutor();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_apk_scan_result);

        Toolbar toolbar = findViewById(R.id.toolbar);
        if (getSupportActionBar() == null && toolbar != null) {
            setSupportActionBar(toolbar);
        }
        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
            getSupportActionBar().setTitle("Scan Result");
        }

        bindViews();

        mReport = null;
        if (getIntent() != null) {
            mReport = getIntent().getParcelableExtra(ApkInstallerActivity.EXTRA_REPORT);
        }
        if (mReport == null) {
            new AlertDialog.Builder(this)
                    .setTitle("Scan Error")
                    .setMessage("No scan report received. Please select an APK file to scan.")
                    .setPositiveButton("Exit", (d, w) -> finish())
                    .setCancelable(false)
                    .show();
            return;
        }

        populateUi(mReport);
    }

    private void bindViews() {
        mCardVerdict               = findViewById(R.id.card_verdict);
        mImgAppIcon                = findViewById(R.id.img_app_icon);
        mTvAppName                 = findViewById(R.id.tv_app_name);
        mTvPackageName             = findViewById(R.id.tv_package_name);
        mTvVersion                 = findViewById(R.id.tv_version);
        mTvVerdictEmoji            = findViewById(R.id.tv_verdict_emoji);
        mTvVerdictLabel            = findViewById(R.id.tv_verdict_label);
        mTvVerdictSubtitle         = findViewById(R.id.tv_verdict_subtitle);
        mTvRiskScore               = findViewById(R.id.tv_risk_score);
        mProgressRisk              = findViewById(R.id.progress_risk);
        mTvSha256                  = findViewById(R.id.tv_sha256);
        mTvDexResult               = findViewById(R.id.tv_dex_result);
        mTvTiResult                = findViewById(R.id.tv_ti_result);
        mTvScanDuration            = findViewById(R.id.tv_scan_duration);
        mCardEvidence              = findViewById(R.id.card_evidence);
        mContainerEvidence         = findViewById(R.id.container_evidence_items);
        mTvThreatWarning           = findViewById(R.id.tv_threat_warning);
        mBtnInstall                = findViewById(R.id.btn_install);
        mBtnCancel                 = findViewById(R.id.btn_cancel);

        mLayoutInstalling          = findViewById(R.id.layout_installing_progress);
        mProgressInstallingSpinner = findViewById(R.id.progress_installing_spinner);
        mTvInstallingStatus        = findViewById(R.id.tv_installing_status);
        mTvInstallingSubtext       = findViewById(R.id.tv_installing_subtext);
        mTvInstallingPct           = findViewById(R.id.tv_installing_pct);
        mProgressInstallingBar     = findViewById(R.id.progress_installing_bar);
    }

    private void populateUi(ApkPreInstallScanner.PreInstallReport r) {
        // ── App info ──────────────────────────────────────────────────────────
        mTvAppName.setText(r.appName.isEmpty() ? "Unknown App" : r.appName);
        mTvPackageName.setText(r.packageName.isEmpty() ? r.apkPath : r.packageName);

        String sizeStr = formatFileSize(r.apkSizeBytes);
        String ver = r.versionName.isEmpty() ? "Unknown version" : "v" + r.versionName;
        mTvVersion.setText(ver + (sizeStr.isEmpty() ? "" : " · " + sizeStr));

        // Load APK icon asynchronously
        if (!r.apkPath.isEmpty()) {
            mExecutor.execute(() -> {
                Drawable icon = ApkPreInstallScanner.extractApkIcon(this, r.apkPath);
                runOnUiThread(() -> {
                    if (icon != null) mImgAppIcon.setImageDrawable(icon);
                });
            });
        }

        // ── Verdict hero card ──────────────────────────────────────────────────
        int verdictBgColor;
        String emoji, label, subtitle;

        switch (r.verdict) {
            case ApkPreInstallScanner.VERDICT_THREAT:
                verdictBgColor = 0xFFF44336; // Red
                emoji    = "🔴";
                label    = "THREAT DETECTED";
                subtitle = r.tiMalwareFamily.isEmpty()
                        ? "Confirmed malicious — do not install"
                        : "Malware: " + r.tiMalwareFamily;
                break;
            case ApkPreInstallScanner.VERDICT_SUSPICIOUS:
                verdictBgColor = 0xFFFF9800; // Amber
                emoji    = "🟡";
                label    = "SUSPICIOUS";
                subtitle = "Potentially unsafe — install with caution";
                break;
            default: // CLEAN
                verdictBgColor = 0xFF4CAF50; // Green
                emoji    = "🟢";
                label    = "CLEAN";
                subtitle = "No threats detected — safe to install";
                break;
        }

        mCardVerdict.setCardBackgroundColor(verdictBgColor);
        mCardVerdict.startAnimation(AnimationUtils.loadAnimation(this, R.anim.fade_in_up));
        mTvVerdictEmoji.setText(emoji);
        mTvVerdictLabel.setText(label);
        mTvVerdictSubtitle.setText(subtitle);
        mTvRiskScore.setText(r.riskScore + " / 100");
        mProgressRisk.setProgress(0);
        ObjectAnimator.ofInt(mProgressRisk, "progress", 0, r.riskScore)
                .setDuration(750)
                .start();

        // ── Scan detail rows ──────────────────────────────────────────────────
        mTvSha256.setText(r.sha256.isEmpty() ? "N/A" : r.sha256);

        // DEX result
        if (r.dexFeatures.isEmpty()) {
            mTvDexResult.setText("Score: " + r.dexConfidenceScore + "/100 — No suspicious structures");
        } else {
            mTvDexResult.setText("Score: " + r.dexConfidenceScore + "/100 — "
                    + String.join(", ", r.dexFeatures.subList(0, Math.min(2, r.dexFeatures.size()))));
        }

        // TI result
        if (!r.tiQueried) {
            mTvTiResult.setText("Offline — configure API keys in Settings → Threat Intel APIs");
        } else if (r.tiMalicious) {
            mTvTiResult.setText("⛔ MALICIOUS [" + r.tiProvider + "] " + r.tiDetails);
            mTvTiResult.setTextColor(Color.parseColor("#F44336"));
        } else if (r.tiSuspicious) {
            mTvTiResult.setText("⚠ SUSPICIOUS [" + r.tiProvider + "] " + r.tiDetails);
            mTvTiResult.setTextColor(Color.parseColor("#FF9800"));
        } else {
            mTvTiResult.setText("✓ Clean [" + r.tiProvider + "]");
            mTvTiResult.setTextColor(Color.parseColor("#4CAF50"));
        }

        mTvScanDuration.setText(String.format(Locale.US, "%.1f s", r.scanDurationMs / 1000.0));

        // ── Evidence findings ──────────────────────────────────────────────────
        if (!r.evidenceTitles.isEmpty()) {
            mCardEvidence.setVisibility(View.VISIBLE);
            mContainerEvidence.removeAllViews();
            for (int i = 0; i < r.evidenceTitles.size(); i++) {
                addEvidenceRow(r.evidenceTitles.get(i),
                        i < r.evidenceDetails.size()  ? r.evidenceDetails.get(i)  : "",
                        i < r.evidenceSeverity.size() ? r.evidenceSeverity.get(i) : AntivirusEvidenceItem.SEVERITY_LOW);
            }
        }

        // ── Action buttons ─────────────────────────────────────────────────────
        configureActionButtons(r);

        if (r.verdict == ApkPreInstallScanner.VERDICT_THREAT || r.verdict == ApkPreInstallScanner.VERDICT_SUSPICIOUS) {
            try {
                AlertStore.getInstance(this).add(
                        r.verdict == ApkPreInstallScanner.VERDICT_THREAT ? AlertRecord.Severity.HIGH : AlertRecord.Severity.MEDIUM,
                        AlertRecord.AlertType.MALWARE,
                        (r.verdict == ApkPreInstallScanner.VERDICT_THREAT ? "Malicious APK Blocked: " : "Suspicious APK Detected: ") + (r.appName.isEmpty() ? "Unknown App" : r.appName),
                        "Risk score " + r.riskScore + "/100. Package: " + (r.packageName.isEmpty() ? r.apkPath : r.packageName),
                        r.packageName
                );
            } catch (Exception ignored) {}
        }
    }

    private void configureActionButtons(ApkPreInstallScanner.PreInstallReport r) {
        switch (r.verdict) {

            case ApkPreInstallScanner.VERDICT_THREAT:
                mTvThreatWarning.setVisibility(View.VISIBLE);
                mBtnInstall.setText("Install Anyway");
                mBtnInstall.setBackgroundColor(Color.parseColor("#F44336"));
                mBtnCancel.setText("Do Not Install");
                // Swap visual prominence: Cancel is primary for threats
                mBtnCancel.setBackgroundTintList(
                        android.content.res.ColorStateList.valueOf(Color.parseColor("#F44336")));
                mBtnCancel.setTextColor(Color.WHITE);
                mBtnCancel.setStrokeWidth(0);

                mBtnInstall.setOnClickListener(v -> confirmThreatInstall(r));
                mBtnCancel.setOnClickListener(v -> finish());
                break;

            case ApkPreInstallScanner.VERDICT_SUSPICIOUS:
                mBtnInstall.setText("Install with Caution");
                mBtnInstall.setBackgroundTintList(
                        android.content.res.ColorStateList.valueOf(Color.parseColor("#FF9800")));
                mBtnCancel.setText("Cancel");
                mBtnInstall.setOnClickListener(v -> triggerInstall(r));
                mBtnCancel.setOnClickListener(v -> finish());
                break;

            default: // CLEAN
                mBtnInstall.setText("Install");
                mBtnInstall.setBackgroundTintList(
                        android.content.res.ColorStateList.valueOf(Color.parseColor("#4CAF50")));
                mBtnCancel.setText("Cancel");
                mBtnInstall.setOnClickListener(v -> triggerInstall(r));
                mBtnCancel.setOnClickListener(v -> finish());
                break;
        }
    }

    /** Shows a confirmation dialog before installing a THREAT-flagged APK. */
    private void confirmThreatInstall(ApkPreInstallScanner.PreInstallReport r) {
        new AlertDialog.Builder(this)
                .setTitle("⛔ Install Malicious App?")
                .setMessage("This APK has been identified as malicious by threat intelligence.\n\n"
                        + "Installing it may compromise your device and personal data.\n\n"
                        + "Are you absolutely sure you want to proceed?")
                .setPositiveButton("Install Anyway (Risk)", (d, w) -> triggerInstall(r))
                .setNegativeButton("Cancel — Do Not Install", null)
                .setIcon(android.R.drawable.ic_dialog_alert)
                .show();
    }

    private final BroadcastReceiver mInstallStatusReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (intent == null || !ApkInstallReceiver.ACTION_INSTALL_STATUS.equals(intent.getAction())) return;
            int status = intent.getIntExtra(ApkInstallReceiver.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE);
            String msg = intent.getStringExtra(ApkInstallReceiver.EXTRA_MESSAGE);

            if (status == PackageInstaller.STATUS_SUCCESS) {
                Toast.makeText(ApkScanResultActivity.this, "App installed successfully!", Toast.LENGTH_SHORT).show();
                finish();
            } else if (status != PackageInstaller.STATUS_PENDING_USER_ACTION) {
                showInstallingState(false, null, null, 0);
                String reason = getInstallFailureReason(status, msg);
                new AlertDialog.Builder(ApkScanResultActivity.this)
                        .setTitle("Installation Error")
                        .setMessage(reason)
                        .setPositiveButton("Exit", (d, w) -> finish())
                        .setCancelable(false)
                        .show();
            }
        }
    };

    @Override
    protected void onStart() {
        super.onStart();
        IntentFilter filter = new IntentFilter(ApkInstallReceiver.ACTION_INSTALL_STATUS);
        ContextCompat.registerReceiver(this, mInstallStatusReceiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED);
    }

    @Override
    protected void onStop() {
        super.onStop();
        try {
            unregisterReceiver(mInstallStatusReceiver);
        } catch (Exception ignored) {}
    }

    private String getInstallFailureReason(int status, String message) {
        if (message != null && !message.isEmpty()) {
            return message;
        }
        switch (status) {
            case PackageInstaller.STATUS_FAILURE_ABORTED:
                return "Installation was cancelled or aborted by user.";
            case PackageInstaller.STATUS_FAILURE_BLOCKED:
                return "Installation was blocked by device administrator or security policies.";
            case PackageInstaller.STATUS_FAILURE_CONFLICT:
                return "Installation conflict: A different version with conflicting signature is already installed.";
            case PackageInstaller.STATUS_FAILURE_INCOMPATIBLE:
                return "Installation failed: Package is incompatible with this device or Android OS version.";
            case PackageInstaller.STATUS_FAILURE_INVALID:
                return "Installation failed: The APK file is invalid, corrupt, or has parsing errors.";
            case PackageInstaller.STATUS_FAILURE_STORAGE:
                return "Installation failed: Insufficient device storage space.";
            default:
                return "Installation failed with error code: " + status;
        }
    }

    /**
     * Triggers installation of the scanned APK file using Android's PackageInstaller
     * session API, with fallback to Intent.ACTION_VIEW and unknown source permission checks.
     */
    private void triggerInstall(ApkPreInstallScanner.PreInstallReport r) {
        if (r.apkPath == null || r.apkPath.isEmpty()) {
            new AlertDialog.Builder(this)
                    .setTitle("Installation Error")
                    .setMessage("APK file path is not available.")
                    .setPositiveButton("Exit", (d, w) -> finish())
                    .setCancelable(false)
                    .show();
            return;
        }

        File apkFile = new File(r.apkPath);
        if (!apkFile.exists()) {
            new AlertDialog.Builder(this)
                    .setTitle("Installation Error")
                    .setMessage("APK file no longer exists at: " + r.apkPath)
                    .setPositiveButton("Exit", (d, w) -> finish())
                    .setCancelable(false)
                    .show();
            return;
        }

        // Check unknown app sources permission on Android 8.0+ (Oreo)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            if (!getPackageManager().canRequestPackageInstalls()) {
                new AlertDialog.Builder(this)
                        .setTitle("Install Permission Needed")
                        .setMessage("To install applications, KotSafe requires permission to install unknown apps. Please enable 'Allow from this source' in Settings.")
                        .setPositiveButton("Open Settings", (d, w) -> {
                            Intent settingsIntent = new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                                    Uri.parse("package:" + getPackageName()));
                            startActivity(settingsIntent);
                        })
                        .setNegativeButton("Cancel", null)
                        .show();
                return;
            }
        }

        showInstallingState(true, "Starting installation…", "Validating package payload", 5);

        // Primary: Modern PackageInstaller Session API
        mExecutor.execute(() -> {
            try {
                installViaPackageInstallerSession(apkFile);
            } catch (Exception e) {
                Log.w(TAG, "PackageInstaller session failed (" + e.getMessage() + "), falling back to Intent");
                runOnUiThread(() -> {
                    try {
                        installViaIntent(apkFile);
                    } catch (Exception ex) {
                        showInstallingState(false, null, null, 0);
                        new AlertDialog.Builder(this)
                                .setTitle("Installation Error")
                                .setMessage("Could not start package installation:\n\n" + ex.getMessage())
                                .setPositiveButton("Exit", (d, w) -> finish())
                                .setCancelable(false)
                                .show();
                    }
                });
            }
        });
    }

    private void showInstallingState(boolean installing, String status, String subtext, int pct) {
        runOnUiThread(() -> {
            if (installing) {
                if (mLayoutInstalling != null && mLayoutInstalling.getVisibility() != View.VISIBLE) {
                    mLayoutInstalling.setVisibility(View.VISIBLE);
                    mLayoutInstalling.startAnimation(AnimationUtils.loadAnimation(this, R.anim.fade_in_up));
                }
                if (mBtnInstall != null) {
                    mBtnInstall.setEnabled(false);
                    mBtnInstall.setVisibility(View.GONE);
                }
                if (mBtnCancel != null) {
                    mBtnCancel.setText("Dismiss");
                }
            } else {
                if (mLayoutInstalling != null) {
                    mLayoutInstalling.setVisibility(View.GONE);
                }
                if (mBtnInstall != null) {
                    mBtnInstall.setEnabled(true);
                    mBtnInstall.setVisibility(View.VISIBLE);
                }
                if (mBtnCancel != null) {
                    mBtnCancel.setText("Cancel");
                }
            }

            if (mTvInstallingStatus != null && status != null) {
                mTvInstallingStatus.setText(status);
            }
            if (mTvInstallingSubtext != null && subtext != null) {
                mTvInstallingSubtext.setText(subtext);
            }
            if (mTvInstallingPct != null) {
                mTvInstallingPct.setText(pct + "%");
            }
            if (mProgressInstallingBar != null) {
                ObjectAnimator.ofInt(mProgressInstallingBar, "progress", mProgressInstallingBar.getProgress(), pct)
                        .setDuration(250)
                        .start();
            }
        });
    }

    private void installViaPackageInstallerSession(File apkFile) throws Exception {
        showInstallingState(true, "Creating session…", "Opening PackageInstaller session", 15);
        PackageInstaller packageInstaller = getPackageManager().getPackageInstaller();
        PackageInstaller.SessionParams params = new PackageInstaller.SessionParams(
                PackageInstaller.SessionParams.MODE_FULL_INSTALL);
        int sessionId = packageInstaller.createSession(params);
        PackageInstaller.Session session = packageInstaller.openSession(sessionId);

        showInstallingState(true, "Streaming payload…", "Writing APK stream to installer", 25);
        long totalLength = apkFile.length();
        long bytesWritten = 0;

        try (OutputStream out = session.openWrite("package", 0, totalLength);
             InputStream in = new FileInputStream(apkFile)) {
            byte[] buffer = new byte[65536];
            int c;
            int lastReportedPct = 25;
            while ((c = in.read(buffer)) != -1) {
                out.write(buffer, 0, c);
                bytesWritten += c;
                if (totalLength > 0) {
                    int pct = 25 + (int) ((bytesWritten * 65) / totalLength); // 25% to 90%
                    if (pct >= lastReportedPct + 5) {
                        lastReportedPct = pct;
                        String writtenMb = String.format(Locale.US, "%.1f / %.1f MB",
                                bytesWritten / (1024.0 * 1024.0), totalLength / (1024.0 * 1024.0));
                        showInstallingState(true, "Streaming payload…", writtenMb, pct);
                    }
                }
            }
            session.fsync(out);
        }

        showInstallingState(true, "Awaiting confirmation…", "Commiting session to system installer", 95);
        Intent intent = new Intent(this, ApkInstallReceiver.class);
        intent.setPackage(getPackageName());
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            flags |= PendingIntent.FLAG_MUTABLE;
        }
        PendingIntent pendingIntent = PendingIntent.getBroadcast(this, sessionId, intent, flags);
        session.commit(pendingIntent.getIntentSender());

        showInstallingState(true, "Confirmation requested", "Follow the system prompt to complete installation", 100);
    }

    private void installViaIntent(File apkFile) {
        showInstallingState(true, "Launching installer…", "Handing off to system package installer", 100);
        try {
            Intent installIntent = new Intent(Intent.ACTION_VIEW);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                String authority = getPackageName() + FILE_PROVIDER_AUTHORITY;
                Uri apkUri = FileProvider.getUriForFile(this, authority, apkFile);
                installIntent.setDataAndType(apkUri, "application/vnd.android.package-archive");
                installIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            } else {
                installIntent.setDataAndType(Uri.fromFile(apkFile), "application/vnd.android.package-archive");
            }
            installIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

            // Avoid circular intent loop back to KotSafe
            android.content.pm.PackageManager pm = getPackageManager();
            java.util.List<android.content.pm.ResolveInfo> matches = pm.queryIntentActivities(installIntent, 0);
            for (android.content.pm.ResolveInfo info : matches) {
                if (info.activityInfo != null && !getPackageName().equals(info.activityInfo.packageName)) {
                    installIntent.setClassName(info.activityInfo.packageName, info.activityInfo.name);
                    break;
                }
            }

            startActivity(installIntent);
        } catch (Exception e) {
            Log.e(TAG, "Failed to launch installer: " + e.getMessage());
            showInstallingState(false, null, null, 0);
            new AlertDialog.Builder(this)
                    .setTitle("Installation Error")
                    .setMessage("Could not launch package installer:\n\n" + e.getMessage())
                    .setPositiveButton("Exit", (d, w) -> finish())
                    .setCancelable(false)
                    .show();
        }
    }

    /** Inflates a single evidence row into the evidence card container. */
    private void addEvidenceRow(String title, String detail, String severity) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        int padV = dp(10);
        int padH = dp(4);
        row.setPadding(padH, padV, padH, padV);

        // Severity colour dot
        View dot = new View(this);
        LinearLayout.LayoutParams dotLp = new LinearLayout.LayoutParams(dp(10), dp(10));
        dotLp.gravity = Gravity.CENTER_VERTICAL;
        dotLp.setMarginEnd(dp(10));
        dot.setLayoutParams(dotLp);
        int dotColor;
        switch (severity) {
            case AntivirusEvidenceItem.SEVERITY_MALICIOUS:  dotColor = 0xFFF44336; break;
            case AntivirusEvidenceItem.SEVERITY_SUSPICIOUS: dotColor = 0xFFFF9800; break;
            case AntivirusEvidenceItem.SEVERITY_LOW:        dotColor = 0xFF2196F3; break;
            default:                                         dotColor = 0xFF4CAF50; break;
        }
        dot.setBackgroundColor(dotColor);
        // Round the dot
        dot.setBackground(createCircleDrawable(dotColor));
        row.addView(dot);

        // Text column
        LinearLayout textCol = new LinearLayout(this);
        textCol.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams textLp = new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        textCol.setLayoutParams(textLp);

        TextView tvTitle = new TextView(this);
        tvTitle.setText(title);
        tvTitle.setTextSize(13f);
        tvTitle.setTypeface(null, android.graphics.Typeface.BOLD);
        tvTitle.setTextColor(0xFF1A1A2E);
        textCol.addView(tvTitle);

        if (!detail.isEmpty()) {
            TextView tvDetail = new TextView(this);
            tvDetail.setText(detail);
            tvDetail.setTextSize(11f);
            tvDetail.setTextColor(0xFF666666);
            tvDetail.setPadding(0, dp(2), 0, 0);
            textCol.addView(tvDetail);
        }

        row.addView(textCol);

        // Divider between rows
        View divider = new View(this);
        LinearLayout.LayoutParams divLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 1);
        divLp.setMargins(0, 0, 0, 0);
        divider.setLayoutParams(divLp);
        divider.setBackgroundColor(0x1A000000);

        mContainerEvidence.addView(row);
        mContainerEvidence.addView(divider);
    }

    private android.graphics.drawable.ShapeDrawable createCircleDrawable(int color) {
        android.graphics.drawable.ShapeDrawable d =
                new android.graphics.drawable.ShapeDrawable(
                        new android.graphics.drawable.shapes.OvalShape());
        d.getPaint().setColor(color);
        return d;
    }

    private int dp(int val) {
        return (int)(val * getResources().getDisplayMetrics().density);
    }

    private static String formatFileSize(long bytes) {
        if (bytes <= 0) return "";
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format(Locale.US, "%.1f KB", bytes / 1024.0);
        return String.format(Locale.US, "%.1f MB", bytes / (1024.0 * 1024.0));
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        mExecutor.shutdownNow();
    }
}
