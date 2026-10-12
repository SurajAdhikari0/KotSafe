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
import android.content.ContentResolver;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.MenuItem;
import android.view.View;
import android.view.animation.Animation;
import android.view.animation.AnimationUtils;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import com.kotsafe.security.Log;
import com.kotsafe.security.R;
import com.kotsafe.security.model.ApkPreInstallScanner;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Entry activity for the Secure APK Installer.
 *
 * Flow:
 *   1. User taps "Browse Files" or the drop-zone card.
 *   2. System file picker opens, filtered to APK MIME type.
 *   3. Selected URI is copied to a temp cache file (to support content:// URIs).
 *   4. {@link ApkPreInstallScanner#scan} runs on a background executor.
 *   5. Progress is displayed via a ProgressBar + phase label.
 *   6. On completion, {@link ApkScanResultActivity} is started with the report.
 */
public class ApkInstallerActivity extends AppCompatActivity {

    private static final String TAG = "ApkInstallerActivity";
    public static final String EXTRA_REPORT = "apk_pre_install_report";

    private MaterialCardView mCardDropZone;
    private MaterialButton   mBtnBrowse;
    private LinearLayout     mLayoutProgress;
    private ProgressBar      mProgressBar;
    private TextView         mTvProgressPhase;
    private LinearLayout     mContainerRecentScans;
    private TextView         mTvRecentHeader;

    private ImageView        mIvHeroShield;
    private View             mViewLaserScanner;
    private ImageView        mIvPickerIcon;
    private Animation        mPulseAnim;
    private Animation        mLaserAnim;

    private final ExecutorService mExecutor = Executors.newSingleThreadExecutor();

    // File picker launcher — accepts APK MIME type
    private final ActivityResultLauncher<String> mPickApk =
            registerForActivityResult(new ActivityResultContracts.GetContent(), uri -> {
                if (uri != null) {
                    handleApkUri(uri);
                }
            });

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_apk_installer);

        Toolbar toolbar = findViewById(R.id.toolbar);
        if (getSupportActionBar() == null && toolbar != null) {
            setSupportActionBar(toolbar);
        }
        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        }

        mCardDropZone        = findViewById(R.id.card_drop_zone);
        mBtnBrowse           = findViewById(R.id.btn_browse_apk);
        mContainerRecentScans= findViewById(R.id.container_recent_scans);
        mTvRecentHeader      = findViewById(R.id.tv_recent_header);
        mLayoutProgress      = findViewById(R.id.layout_scan_progress);
        mProgressBar         = findViewById(R.id.progress_scan);
        mTvProgressPhase     = findViewById(R.id.tv_progress_phase);
        mIvHeroShield        = findViewById(R.id.iv_hero_shield);
        mViewLaserScanner    = findViewById(R.id.view_laser_scanner);
        mIvPickerIcon        = findViewById(R.id.iv_picker_icon);

        mPulseAnim = AnimationUtils.loadAnimation(this, R.anim.pulse_radar);
        mLaserAnim = AnimationUtils.loadAnimation(this, R.anim.laser_sweep);

        mCardDropZone.setOnClickListener(v -> launchPicker());
        mBtnBrowse.setOnClickListener(v -> launchPicker());

        // Handle incoming APK intent (e.g. opened from a file manager or browser)
        processIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        processIntent(intent);
    }

    private void processIntent(Intent intent) {
        if (intent == null) return;
        Uri apkUri = intent.getData();
        if (apkUri == null && intent.getClipData() != null && intent.getClipData().getItemCount() > 0) {
            apkUri = intent.getClipData().getItemAt(0).getUri();
        }
        if (apkUri != null) {
            handleApkUri(apkUri);
        }
    }

    private void launchPicker() {
        // "application/vnd.android.package-archive" is the MIME type for APK files.
        // Some devices/file managers may also send "*/*" — the user can still select APKs.
        mPickApk.launch("application/vnd.android.package-archive");
    }

    /**
     * Receives the URI from the file picker, copies to a local temp file if needed
     * (content:// URIs can't be passed directly to file APIs), then starts the scan.
     */
    private void handleApkUri(Uri uri) {
        showScanningState(true);

        mExecutor.execute(() -> {
            try {
                // Step 1: Resolve URI to a File
                File apkFile = resolveToFile(uri);
                if (apkFile == null || !apkFile.exists()) {
                    runOnUiThread(() -> {
                        showScanningState(false);
                        new AlertDialog.Builder(this)
                                .setTitle("Error Reading APK")
                                .setMessage("Could not read or parse the selected APK file. The file may be corrupt, inaccessible, or deleted.")
                                .setPositiveButton("Exit", (d, w) -> finish())
                                .setCancelable(false)
                                .show();
                    });
                    return;
                }

                // Step 2: Run the full pre-install scan
                ApkPreInstallScanner.PreInstallReport report = ApkPreInstallScanner.scan(
                        getApplicationContext(),
                        apkFile,
                        (phase, pct) -> runOnUiThread(() -> {
                            if (mTvProgressPhase != null) {
                                mTvProgressPhase.setText(phase);
                            }
                            if (mProgressBar != null) {
                                ObjectAnimator.ofInt(mProgressBar, "progress", mProgressBar.getProgress(), pct)
                                        .setDuration(300)
                                        .start();
                            }
                        })
                );

                // Step 3: Launch result screen
                runOnUiThread(() -> {
                    showScanningState(false);
                    Intent intent = new Intent(this, ApkScanResultActivity.class);
                    intent.putExtra(EXTRA_REPORT, report);
                    startActivity(intent);
                });

            } catch (Exception e) {
                Log.e(TAG, "Scan failed: " + e.getMessage());
                runOnUiThread(() -> {
                    showScanningState(false);
                    new AlertDialog.Builder(this)
                            .setTitle("Scan Error")
                            .setMessage("An error occurred while inspecting the APK:\n\n" + e.getMessage())
                            .setPositiveButton("Exit", (d, w) -> finish())
                            .setCancelable(false)
                            .show();
                });
            }
        });
    }

    /**
     * Converts a content:// or file:// Uri to a concrete java.io.File.
     * For content:// URIs, streams the content to a temp file in the app cache directory.
     */
    private File resolveToFile(Uri uri) throws Exception {
        String scheme = uri.getScheme();
        if (ContentResolver.SCHEME_FILE.equals(scheme)) {
            return new File(uri.getPath());
        }

        // For content:// — copy to cache
        File tempFile = new File(getCacheDir(), "apk_scan_temp.apk");
        try (InputStream in  = getContentResolver().openInputStream(uri);
             FileOutputStream out = new FileOutputStream(tempFile)) {
            if (in == null) return null;
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
        }
        return tempFile;
    }

    private void showScanningState(boolean scanning) {
        mCardDropZone.setAlpha(scanning ? 0.6f : 1.0f);
        mBtnBrowse.setEnabled(!scanning);
        mBtnBrowse.setText(scanning ? "Scanning…" : "Browse Files");
        if (mLayoutProgress != null) {
            if (scanning && mLayoutProgress.getVisibility() != View.VISIBLE) {
                mLayoutProgress.setVisibility(View.VISIBLE);
                Animation fadeIn = AnimationUtils.loadAnimation(this, R.anim.fade_in_up);
                mLayoutProgress.startAnimation(fadeIn);
            } else if (!scanning) {
                mLayoutProgress.setVisibility(View.GONE);
            }
        }
        if (mProgressBar != null && !scanning) {
            mProgressBar.setProgress(0);
        }

        if (scanning) {
            if (mIvHeroShield != null && mPulseAnim != null) {
                mIvHeroShield.startAnimation(mPulseAnim);
            }
            if (mViewLaserScanner != null && mLaserAnim != null) {
                mViewLaserScanner.setVisibility(View.VISIBLE);
                mViewLaserScanner.startAnimation(mLaserAnim);
            }
        } else {
            if (mIvHeroShield != null) {
                mIvHeroShield.clearAnimation();
            }
            if (mViewLaserScanner != null) {
                mViewLaserScanner.clearAnimation();
                mViewLaserScanner.setVisibility(View.GONE);
            }
        }
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
