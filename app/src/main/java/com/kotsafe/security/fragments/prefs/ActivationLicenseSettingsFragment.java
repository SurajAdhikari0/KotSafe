/*
 * This file is part of KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.fragments.prefs;

import android.content.Context;
import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.preference.Preference;
import androidx.preference.PreferenceCategory;

import com.kotsafe.security.R;
import com.kotsafe.security.p2p.P2PLicenseManager;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class ActivationLicenseSettingsFragment extends SettingsSubFragment {

    private Preference mBadgePref;
    private Preference mDetailsPref;
    private Preference mMaskedKeyPref;
    private Preference mExpiryPref;

    private PreferenceCategory mStatusCategory;
    private PreferenceCategory mActionsCategory;

    private Preference mActivatePref;
    private Preference mRevalidatePref;
    private Preference mDeactivatePref;

    @Override
    public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
        setPreferencesFromResource(R.xml.pref_activation_license, rootKey);

        mStatusCategory = findPreference("cat_license_status");
        mActionsCategory = findPreference("cat_license_actions");

        mBadgePref = findPreference("pref_license_badge");
        mDetailsPref = findPreference("pref_license_details");
        mMaskedKeyPref = findPreference("pref_license_masked_key");
        mExpiryPref = findPreference("pref_license_expiry");

        mActivatePref = findPreference("pref_license_activate_key");
        mRevalidatePref = findPreference("pref_license_revalidate");
        mDeactivatePref = findPreference("pref_license_deactivate");

        if (mActivatePref != null) {
            mActivatePref.setOnPreferenceClickListener(preference -> {
                showActivationDialog();
                return true;
            });
        }

        if (mRevalidatePref != null) {
            mRevalidatePref.setOnPreferenceClickListener(preference -> {
                revalidateCurrentLicense();
                return true;
            });
        }

        if (mDeactivatePref != null) {
            mDeactivatePref.setOnPreferenceClickListener(preference -> {
                confirmAndDeactivate();
                return true;
            });
        }
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        P2PLicenseManager.getInstance(requireContext()).autoProvisionCommunityLicenseIfNeeded();
        refreshUI();
    }

    @Override
    public void onResume() {
        super.onResume();
        refreshUI();
    }

    private void refreshUI() {
        if (getContext() == null || mActionsCategory == null || mStatusCategory == null) return;

        P2PLicenseManager lm = P2PLicenseManager.getInstance(requireContext());
        boolean isPro = lm.isProActivated();
        String activeKey = lm.getActiveLicenseKey();

        if (isPro) {
            P2PLicenseManager.Tier tier = lm.getLicenseTier();
            int maxDevices = lm.getMaxAllowedExitDevices();

            // 1. Badge
            if (mBadgePref != null) {
                mBadgePref.setTitle("License Status: " + tier.name() + " (Active)");
                mBadgePref.setSummary("Full Security Engines & High-Speed Mesh Enabled");
                mBadgePref.setIcon(R.drawable.ic_shield);
            }

            // 2. Details
            if (mDetailsPref != null) {
                mDetailsPref.setTitle("Entitlement Plan");
                mDetailsPref.setSummary("KotSafe " + tier.name() + " • Up to " + maxDevices + " concurrent devices");
            }

            // 3. Masked Key (Never show full key in UI)
            if (mMaskedKeyPref != null) {
                mMaskedKeyPref.setSummary(maskKey(activeKey));
                if (mStatusCategory.findPreference("pref_license_masked_key") == null) {
                    mStatusCategory.addPreference(mMaskedKeyPref);
                }
            }

            // 4. Expiry
            if (mExpiryPref != null) {
                mExpiryPref.setSummary("1-Year Commercial Entitlement");
                if (mStatusCategory.findPreference("pref_license_expiry") == null) {
                    mStatusCategory.addPreference(mExpiryPref);
                }
            }

            // 5. Action visibility: input field MUST NOT be in the view when active
            if (mActivatePref != null) {
                mActionsCategory.removePreference(mActivatePref);
            }
            if (mRevalidatePref != null && mActionsCategory.findPreference("pref_license_revalidate") == null) {
                mActionsCategory.addPreference(mRevalidatePref);
            }
            if (mDeactivatePref != null && mActionsCategory.findPreference("pref_license_deactivate") == null) {
                mActionsCategory.addPreference(mDeactivatePref);
            }

        } else {
            // Freemium / Unlicensed state
            if (mBadgePref != null) {
                mBadgePref.setTitle("License Status: Freemium");
                mBadgePref.setSummary("Community Free Tier • Limited to 1 exit device");
                mBadgePref.setIcon(R.drawable.ic_lock);
            }

            if (mDetailsPref != null) {
                mDetailsPref.setTitle("Plan & Limits");
                mDetailsPref.setSummary("Free Edition • Single local node mode");
            }

            // Remove masked key and expiry in unlicensed mode
            if (mMaskedKeyPref != null) {
                mStatusCategory.removePreference(mMaskedKeyPref);
            }
            if (mExpiryPref != null) {
                mStatusCategory.removePreference(mExpiryPref);
            }

            // Action visibility: activate field present, revalidate and deactivate removed
            if (mActivatePref != null && mActionsCategory.findPreference("pref_license_activate_key") == null) {
                mActionsCategory.addPreference(mActivatePref);
            }
            if (mRevalidatePref != null) {
                mActionsCategory.removePreference(mRevalidatePref);
            }
            if (mDeactivatePref != null) {
                mActionsCategory.removePreference(mDeactivatePref);
            }
        }
    }

    private void showActivationDialog() {
        if (getContext() == null) return;
        Context ctx = requireContext();

        final EditText input = new EditText(ctx);
        input.setHint("KOT-PRO-XXXXX-XXXXX");
        input.setSingleLine(true);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS);

        int padding = (int) (18 * getResources().getDisplayMetrics().density);
        FrameLayout container = new FrameLayout(ctx);
        container.setPadding(padding, padding / 2, padding, padding / 2);
        container.addView(input);

        new AlertDialog.Builder(ctx)
                .setTitle("Activate KotSafe Pro")
                .setMessage("Enter your 25-character activation key to unlock multi-device exit nodes and high-speed cloud relay.")
                .setView(container)
                .setPositiveButton("Activate", (dialog, which) -> {
                    String rawKey = input.getText().toString().trim();
                    if (rawKey.isEmpty()) {
                        Toast.makeText(ctx, "Please enter an activation key", Toast.LENGTH_SHORT).show();
                        return;
                    }

                    Toast.makeText(ctx, "Verifying activation key...", Toast.LENGTH_SHORT).show();

                    P2PLicenseManager.getInstance(ctx).activateLicense(rawKey, new P2PLicenseManager.LicenseCallback() {
                        @Override
                        public void onSuccess(P2PLicenseManager.Tier tier, int maxDevices, long expiresAt) {
                            if (!isAdded()) return;
                            Toast.makeText(ctx, "✓ KotSafe " + tier + " Activated! Up to " + maxDevices + " devices unlocked.", Toast.LENGTH_LONG).show();
                            refreshUI();
                        }

                        @Override
                        public void onError(String error) {
                            if (!isAdded()) return;
                            new AlertDialog.Builder(ctx)
                                    .setTitle("Activation Failed")
                                    .setMessage(error)
                                    .setPositiveButton("OK", null)
                                    .show();
                            refreshUI();
                        }
                    });
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void revalidateCurrentLicense() {
        if (getContext() == null) return;
        Context ctx = requireContext();
        P2PLicenseManager lm = P2PLicenseManager.getInstance(ctx);
        String activeKey = lm.getActiveLicenseKey();

        if (activeKey.isEmpty()) {
            Toast.makeText(ctx, "No active license to re-validate", Toast.LENGTH_SHORT).show();
            return;
        }

        Toast.makeText(ctx, "Re-validating license with signaling relay...", Toast.LENGTH_SHORT).show();

        lm.activateLicense(activeKey, new P2PLicenseManager.LicenseCallback() {
            @Override
            public void onSuccess(P2PLicenseManager.Tier tier, int maxDevices, long expiresAt) {
                if (!isAdded()) return;
                Toast.makeText(ctx, "✓ License verified. " + tier + " status active (" + maxDevices + " devices).", Toast.LENGTH_SHORT).show();
                refreshUI();
            }

            @Override
            public void onError(String error) {
                if (!isAdded()) return;
                Toast.makeText(ctx, "License verification note: " + error, Toast.LENGTH_LONG).show();
                refreshUI();
            }
        });
    }

    private void confirmAndDeactivate() {
        if (getContext() == null) return;
        Context ctx = requireContext();

        new AlertDialog.Builder(ctx)
                .setTitle("Deactivate License?")
                .setMessage("Are you sure you want to deactivate KotSafe Pro on this device? This will release the seat on the server and return this device to the Freemium tier.")
                .setPositiveButton("Deactivate", (dialog, which) -> {
                    P2PLicenseManager.getInstance(ctx).revokeLicense();
                    Toast.makeText(ctx, "License deactivated. Restored to Freemium tier.", Toast.LENGTH_SHORT).show();
                    refreshUI();
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private String maskKey(String key) {
        if (key == null || key.length() < 4) return "****";
        String suffix = key.substring(key.length() - 4);
        return "****-****-****-" + suffix;
    }
}
