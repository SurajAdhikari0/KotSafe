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
 * * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.fragments.mitmwizard;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.security.KeyChain;
import android.view.View;
import android.widget.Toast;

import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.content.res.AppCompatResources;

import com.kotsafe.security.Log;
import com.kotsafe.security.MitmAddon;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.interfaces.MitmListener;
import com.kotsafe.security.mitm.MitmAPI;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;

public class InstallCertificate extends StepFragment implements MitmListener {
    private static final String TAG = "InstallCertificate";
    private static final String CA_PEM_KEY = "ca_pem";
    private static final String FALLBACK_EXPORT_KEY = "fallback_export";
    private MitmAddon mAddon;
    private String mCaPem;
    private X509Certificate mCaCert;
    private boolean mFallbackExport;
    private final Handler mMainHandler = new Handler(Looper.getMainLooper());

    private final ActivityResultLauncher<Intent> certExportLauncher =
            registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), this::certExportResult);
    private final ActivityResultLauncher<Intent> certInstallLauncher =
            registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), this::certInstallResult);

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        setStepperStep(3);

        if (savedInstanceState != null) {
            mFallbackExport = savedInstanceState.getBoolean(FALLBACK_EXPORT_KEY);
            mCaPem = savedInstanceState.getString(CA_PEM_KEY);
            if (mCaPem != null)
                mCaCert = Utils.x509FromPem(mCaPem);
        }

        if (mStepTitle != null) {
            mStepTitle.setText("Trust Root CA Certificate");
        }
        if (mStepBadge != null) {
            mStepBadge.setText("STEP 3 OF 4 • SECURITY CREDENTIAL");
            mStepBadge.setTextColor(Color.parseColor("#0EA5E9"));
        }
        if (mStepIcon != null) {
            mStepIcon.setImageResource(R.drawable.ic_shield);
        }

        mStepLabel.setText(R.string.checking_the_certificate);
        mStepButton.setText(canInstallCertViaIntent() ? R.string.install_action : R.string.export_action);
        mStepButton.setEnabled(false);

        showSkipButton(view1 -> new AlertDialog.Builder(view1.getContext())
                .setTitle(R.string.warning)
                .setMessage(R.string.mitm_skip_notice)
                .setNegativeButton(R.string.cancel_action, (dialogInterface, i) -> {})
                .setPositiveButton(R.string.app_intro_skip_button, (d, whichButton) -> {
                    MitmAddon.setCAInstallationSkipped(requireContext(), true);
                    gotoStep(R.id.navto_done);
                })
                .show());

        mAddon = new MitmAddon(requireContext(), this);
    }

    @Override
    public void onSaveInstanceState(@NonNull Bundle outState) {
        super.onSaveInstanceState(outState);
        outState.putString(CA_PEM_KEY, mCaPem);
        outState.putBoolean(FALLBACK_EXPORT_KEY, mFallbackExport);
    }

    @Override
    public void onDestroyView() {
        mAddon.disconnect();
        super.onDestroyView();
    }

    @Override
    public void onResume() {
        super.onResume();

        if (mCaCert != null && Utils.isCAInstalled(mCaCert)) {
            certOk();
            return;
        }

        if (!mAddon.isConnected()) {
            if (!mAddon.connect(0)) {
                new AlertDialog.Builder(requireContext())
                        .setTitle(R.string.error)
                        .setMessage(R.string.mitm_addon_autostart_workaround)
                        .setNegativeButton(R.string.no, (dialogInterface, i) -> {
                            Toast.makeText(requireContext(), "Add-on connection failed", Toast.LENGTH_LONG).show();
                            certFail();
                        })
                        .setPositiveButton(R.string.yes, (d, whichButton) -> {
                            Context ctx = requireContext();
                            Intent launchIntent = ctx.getPackageManager().getLaunchIntentForPackage(MitmAPI.PACKAGE_NAME);
                            if (launchIntent != null)
                                Utils.startActivity(ctx, launchIntent);
                            else {
                                Toast.makeText(requireContext(), "Add-on launch failed", Toast.LENGTH_LONG).show();
                                certFail();
                            }
                        }).show();
            }
        }
    }

    private void certOk() {
        if (!isAdded()) return;

        if (mStepTitle != null) {
            mStepTitle.setText("Root Certificate Verified");
        }
        if (mStepBadge != null) {
            mStepBadge.setText("INSTALLED & TRUSTED (🟢)");
            mStepBadge.setTextColor(Color.parseColor("#10B981"));
        }
        if (mStepLabel != null) {
            mStepLabel.setText(R.string.cert_installed_correctly);
        }
        if (mStepIcon != null) {
            mStepIcon.setImageDrawable(AppCompatResources.getDrawable(requireContext(), R.drawable.ic_check_solid));
            mStepIcon.setColorFilter(mOkColor);
        }

        if (mCardDetails != null) {
            mCardDetails.setVisibility(View.VISIBLE);
            if (mTvDetailsTitle != null) {
                mTvDetailsTitle.setText("Security Trust Status:");
            }
            if (mTvDetailsContent != null) {
                mTvDetailsContent.setText("• Root CA installed in credential storage\n• Android and web browsers trust generated SSL certs\n• Ready for live TLS cleartext decoding");
            }
        }

        if (mBtnRootAction != null) {
            mBtnRootAction.setVisibility(View.GONE);
        }
        if (mSkipButton != null) {
            mSkipButton.setVisibility(View.GONE);
        }

        MitmAddon.setCAInstallationSkipped(requireContext(), false);
        nextStep(R.id.navto_done);
    }

    private void certFail() {
        if (!isAdded()) return;

        if (mStepBadge != null) {
            mStepBadge.setText("CONNECTION ERROR");
            mStepBadge.setTextColor(Color.parseColor("#EF4444"));
        }
        mStepLabel.setText(R.string.ca_cert_export_failed);
        Utils.setTextUrls(mStepLabel, R.string.ca_cert_export_failed, "https://dontkillmyapp.com/xiaomi#app-battery-saver");
        if (mStepIcon != null) {
            mStepIcon.setColorFilter(mDangerColor);
        }
        MitmAddon.setDecryptionSetupDone(requireContext(), false);
    }

    private boolean canInstallCertViaIntent() {
        return (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) && !mFallbackExport;
    }

    private void fallbackToCertExport() {
        mFallbackExport = true;
        onMitmGetCaCertificateResult(mCaPem);
    }

    private void exportCaCertificate() {
        String fname = "KotSafe_CA.crt";
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/x-x509-ca-cert");
        intent.putExtra(Intent.EXTRA_TITLE, fname);

        if (!Utils.launchFileDialog(requireContext(), intent, certExportLauncher))
            certFail();
    }

    private void installCaCertificate() {
        Intent intent = KeyChain.createInstallIntent();
        intent.putExtra(KeyChain.EXTRA_NAME, "KotSafe CA");
        intent.putExtra(KeyChain.EXTRA_CERTIFICATE, mCaPem.getBytes(StandardCharsets.UTF_8));

        try {
            certInstallLauncher.launch(intent);
        } catch (ActivityNotFoundException e) {
            Utils.showToastLong(requireContext(), R.string.no_intent_handler_found);
            fallbackToCertExport();
        }
    }

    private void certExportResult(final ActivityResult result) {
        if ((result.getResultCode() == Activity.RESULT_OK) && (result.getData() != null)) {
            Context ctx = requireContext();
            Uri cert_uri = result.getData().getData();

            if (mCaPem == null) {
                Log.e(TAG, "Certificate not available, cannot export");
                Utils.showToastLong(ctx, R.string.export_failed);
                return;
            }

            boolean written = false;
            try (OutputStream out = ctx.getContentResolver().openOutputStream(cert_uri, "rwt")) {
                if (out != null) {
                    out.write(mCaPem.getBytes(StandardCharsets.UTF_8));
                    written = true;
                }
            } catch (IOException e) {
                e.printStackTrace();
            }

            if (written) {
                Utils.showToastLong(ctx, R.string.cert_exported_now_installed);
                // After export on Android 11+, show Open Settings shortcut
                if (mSkipButton != null) {
                    mSkipButton.setText("Open Android Security Settings");
                    mSkipButton.setVisibility(View.VISIBLE);
                    mSkipButton.setOnClickListener(v -> openSecuritySettings());
                }
            } else {
                Utils.showToastLong(ctx, R.string.export_failed);
            }
        }
    }

    private void openSecuritySettings() {
        try {
            Intent intent = new Intent(Settings.ACTION_SECURITY_SETTINGS);
            startActivity(intent);
        } catch (Exception e) {
            try {
                Intent intent = new Intent(Settings.ACTION_SETTINGS);
                startActivity(intent);
            } catch (Exception ignored) {
                Toast.makeText(requireContext(), "Unable to open Settings app", Toast.LENGTH_SHORT).show();
            }
        }
    }

    private void certInstallResult(final ActivityResult result) {
        if ((result.getResultCode() == Activity.RESULT_OK) && Utils.isCAInstalled(mCaCert))
            certOk();
        else
            fallbackToCertExport();
    }

    @Override
    public void onMitmGetCaCertificateResult(@Nullable String ca_pem) {
        mAddon.disconnect();

        Context context = getContext();
        if (context == null) return;

        mCaPem = ca_pem;
        mStepButton.setText(canInstallCertViaIntent() ? R.string.install_action : R.string.export_action);

        if (mCaPem != null) {
            mCaCert = Utils.x509FromPem(mCaPem);

            if (mCaCert != null) {
                if (Utils.isCAInstalled(mCaCert)) {
                    certOk();
                } else {
                    MitmAddon.setDecryptionSetupDone(context, false);
                    mStepIcon.setColorFilter(mWarnColor);
                    mStepButton.setEnabled(true);

                    if (mCardDetails != null) {
                        mCardDetails.setVisibility(View.VISIBLE);
                        if (mTvDetailsTitle != null) {
                            mTvDetailsTitle.setText("Installation Guide (Android 11–15):");
                        }
                        if (mTvDetailsContent != null) {
                            mTvDetailsContent.setText(
                                    "1. Tap 'Export Certificate' below to save KotSafe_CA.crt\n" +
                                    "2. Open Android Settings ➔ Security ➔ Encryption & Credentials\n" +
                                    "3. Select 'Install a certificate' ➔ 'CA certificate'\n" +
                                    "4. Choose KotSafe_CA.crt and tap 'Install anyway'"
                            );
                        }
                    }

                    // Root option if root access is present
                    if (Utils.isRootAvailable() && mBtnRootAction != null) {
                        mBtnRootAction.setVisibility(View.VISIBLE);
                        mBtnRootAction.setOnClickListener(v -> installCaViaRoot());
                    }

                    if (canInstallCertViaIntent()) {
                        mStepLabel.setText(R.string.install_ca_certificate);
                    } else {
                        mStepLabel.setText(R.string.export_ca_certificate);
                    }

                    mStepButton.setOnClickListener(v -> {
                        if (canInstallCertViaIntent())
                            installCaCertificate();
                        else
                            exportCaCertificate();
                    });

                    // Direct shortcut button to Security settings
                    if (!canInstallCertViaIntent() && mSkipButton != null) {
                        mSkipButton.setText("Open Android Security Settings");
                        mSkipButton.setVisibility(View.VISIBLE);
                        mSkipButton.setOnClickListener(v -> openSecuritySettings());
                    }
                }
            } else {
                Toast.makeText(context, "Add-on did not return certificate", Toast.LENGTH_LONG).show();
                certFail();
            }
        }
    }

    private void installCaViaRoot() {
        Context ctx = getContext();
        if (ctx == null || mCaPem == null) return;

        if (mBtnRootAction != null) {
            mBtnRootAction.setEnabled(false);
            mBtnRootAction.setText("Installing with root permissions...");
        }

        new Thread(() -> {
            boolean success = false;
            try {
                File tempCert = new File(ctx.getCacheDir(), "kotsafe_ca_temp.crt");
                try (FileOutputStream fos = new FileOutputStream(tempCert)) {
                    fos.write(mCaPem.getBytes(StandardCharsets.UTF_8));
                }

                Process p = Runtime.getRuntime().exec("su");
                try (java.io.DataOutputStream os = new java.io.DataOutputStream(p.getOutputStream())) {
                    String tempPath = tempCert.getAbsolutePath();
                    os.writeBytes("HASH=$(toybox openssl x509 -inform PEM -subject_hash_old -in " + tempPath + " -noout 2>/dev/null || openssl x509 -inform PEM -subject_hash_old -in " + tempPath + " -noout 2>/dev/null)\n");
                    os.writeBytes("if [ -z \"$HASH\" ]; then HASH=\"c8750f0d\"; fi\n");

                    // 1. Install user trust store
                    os.writeBytes("mkdir -p /data/misc/user/0/cacerts-added\n");
                    os.writeBytes("cp " + tempPath + " /data/misc/user/0/cacerts-added/$HASH.0\n");
                    os.writeBytes("chmod 644 /data/misc/user/0/cacerts-added/$HASH.0\n");
                    os.writeBytes("chown 1000:1000 /data/misc/user/0/cacerts-added/$HASH.0 2>/dev/null || chown system:system /data/misc/user/0/cacerts-added/$HASH.0 2>/dev/null\n");

                    // 2. Install Magisk module for system-wide trust
                    os.writeBytes("if [ -d \"/data/adb\" ]; then\n");
                    os.writeBytes("  MOD=\"/data/adb/modules/kotsafe_ca\"\n");
                    os.writeBytes("  mkdir -p \"$MOD/system/etc/security/cacerts\"\n");
                    os.writeBytes("  cp " + tempPath + " \"$MOD/system/etc/security/cacerts/$HASH.0\"\n");
                    os.writeBytes("  chmod 644 \"$MOD/system/etc/security/cacerts/$HASH.0\"\n");
                    os.writeBytes("  echo 'id=kotsafe_ca' > \"$MOD/module.prop\"\n");
                    os.writeBytes("  echo 'name=KotSafe MITM CA' >> \"$MOD/module.prop\"\n");
                    os.writeBytes("  echo 'version=1.0' >> \"$MOD/module.prop\"\n");
                    os.writeBytes("  echo 'versionCode=1' >> \"$MOD/module.prop\"\n");
                    os.writeBytes("  echo 'author=KotSafe' >> \"$MOD/module.prop\"\n");
                    os.writeBytes("  echo 'description=Trusts KotSafe MITM Root CA for all apps' >> \"$MOD/module.prop\"\n");
                    os.writeBytes("  touch \"$MOD/auto_mount\"\n");
                    os.writeBytes("fi\n");

                    os.writeBytes("exit\n");
                    os.flush();
                }

                int code = p.waitFor();
                tempCert.delete();
                success = (code == 0);
            } catch (Exception e) {
                Log.w(TAG, "Root install error: " + e.getMessage());
            }

            final boolean finalSuccess = success;
            mMainHandler.post(() -> {
                if (!isAdded()) return;
                if (finalSuccess) {
                    Toast.makeText(ctx, "Installed into System CA Store via root!", Toast.LENGTH_LONG).show();
                    certOk();
                } else {
                    Toast.makeText(ctx, "Root installation failed, please use manual export", Toast.LENGTH_SHORT).show();
                    if (mBtnRootAction != null) {
                        mBtnRootAction.setEnabled(true);
                        mBtnRootAction.setText("⚡ Install into System CA Store (Root)");
                    }
                }
            });
        }, "RootCaInstallThread").start();
    }

    @Override
    public void onMitmServiceConnect() {
        Context ctx = getContext();
        if (ctx == null) return;

        if (!mAddon.requestCaCertificate()) {
            Toast.makeText(ctx, "requestCaCertificate failed", Toast.LENGTH_LONG).show();
            certFail();
        }
    }

    @Override
    public void onMitmServiceDisconnect() {
        Context ctx = getContext();
        if (ctx == null) return;

        if (mCaPem == null) {
            Toast.makeText(ctx, "Add-on disconnected", Toast.LENGTH_LONG).show();
            certFail();
        }
    }
}
