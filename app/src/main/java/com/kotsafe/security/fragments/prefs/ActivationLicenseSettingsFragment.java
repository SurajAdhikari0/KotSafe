/*
 * This file is part of KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.fragments.prefs;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.preference.Preference;
import androidx.preference.PreferenceCategory;

import com.google.android.material.dialog.MaterialAlertDialogBuilder;
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

    private Preference mBuyProPref;
    private Preference mSyncAccountPref;
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

        mBuyProPref = findPreference("pref_license_buy_pro");
        mSyncAccountPref = findPreference("pref_license_sync_account");
        mActivatePref = findPreference("pref_license_activate_key");
        mRevalidatePref = findPreference("pref_license_revalidate");
        mDeactivatePref = findPreference("pref_license_deactivate");

        if (mBuyProPref != null) {
            mBuyProPref.setOnPreferenceClickListener(preference -> {
                try {
                    String deviceId = P2PLicenseManager.getInstance(requireContext()).getOrCreateDeviceId();
                    String deviceName = android.os.Build.MANUFACTURER + " " + android.os.Build.MODEL;
                    String target = "/profile#license?device_id=" + Uri.encode(deviceId) + "&device_name=" + Uri.encode(deviceName);
                    String loginUrl = "https://kotsafe.com/login?redirect=" + Uri.encode(target);
                    startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(loginUrl)));
                } catch (Exception e) {
                    Toast.makeText(getContext(), "Open https://kotsafe.com/login in your browser", Toast.LENGTH_LONG).show();
                }
                return true;
            });
        }

        if (mSyncAccountPref != null) {
            mSyncAccountPref.setOnPreferenceClickListener(preference -> {
                showSyncAccountDialog();
                return true;
            });
        }

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
            int activeDevices = lm.getActiveDevicesCount();
            long expiresAt = lm.getLicenseExpiresAt();

            // 1. Badge
            if (mBadgePref != null) {
                mBadgePref.setTitle("License Status: " + tier.name() + " (Active)");
                mBadgePref.setSummary("Verified by kotsafe.com • High-Speed Mesh & Advanced Engines Enabled");
                mBadgePref.setIcon(R.drawable.ic_shield);
            }

            // 2. Details
            if (mDetailsPref != null) {
                mDetailsPref.setTitle("Entitlement & Seats");
                mDetailsPref.setSummary("KotSafe " + tier.name() + " • " + activeDevices + " of " + maxDevices + " concurrent devices in use");
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
                mExpiryPref.setSummary(formatExpiry(expiresAt));
                if (mStatusCategory.findPreference("pref_license_expiry") == null) {
                    mStatusCategory.addPreference(mExpiryPref);
                }
            }

            // 5. Action visibility
            if (mBuyProPref != null) {
                mActionsCategory.removePreference(mBuyProPref);
            }
            if (mSyncAccountPref != null) {
                mActionsCategory.removePreference(mSyncAccountPref);
            }
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
                mBadgePref.setSummary("Community Free Edition (1 concurrent device limit)");
                mBadgePref.setIcon(R.drawable.ic_lock);
            }

            if (mDetailsPref != null) {
                mDetailsPref.setTitle("Plan & Limits");
                mDetailsPref.setSummary("Free Community Edition • Standard Analytical Engine");
            }

            // Remove masked key and expiry in unlicensed mode
            if (mMaskedKeyPref != null) {
                mStatusCategory.removePreference(mMaskedKeyPref);
            }
            if (mExpiryPref != null) {
                mStatusCategory.removePreference(mExpiryPref);
            }

            // Action visibility
            if (mBuyProPref != null && mActionsCategory.findPreference("pref_license_buy_pro") == null) {
                mActionsCategory.addPreference(mBuyProPref);
            }
            if (mSyncAccountPref != null && mActionsCategory.findPreference("pref_license_sync_account") == null) {
                mActionsCategory.addPreference(mSyncAccountPref);
            }
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

    private void showSyncAccountDialog() {
        if (getContext() == null) return;
        Context ctx = requireContext();

        String knownEmail = com.kotsafe.security.model.KotSafeUserManager.getLoggedInEmail(ctx);

        final EditText input = new EditText(ctx);
        input.setHint("account@example.com");
        input.setSingleLine(true);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS);
        if (knownEmail != null && !knownEmail.isEmpty()) {
            input.setText(knownEmail);
        }

        int padding = (int) (18 * getResources().getDisplayMetrics().density);
        FrameLayout container = new FrameLayout(ctx);
        container.setPadding(padding, padding / 2, padding, padding / 2);
        container.addView(input);

        new MaterialAlertDialogBuilder(ctx)
                .setTitle("Sync License from Account")
                .setMessage("Enter the email address of your kotsafe.com account to auto-activate this device with your subscription.")
                .setView(container)
                .setPositiveButton("Sync & Activate", (dialog, which) -> {
                    String email = input.getText().toString().trim();
                    if (email.isEmpty()) {
                        Toast.makeText(ctx, "Please enter your KotSafe account email", Toast.LENGTH_SHORT).show();
                        return;
                    }
                    performAccountSync(email);
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private void performAccountSync(String email) {
        if (getContext() == null) return;
        Context ctx = requireContext();

        final androidx.appcompat.app.AlertDialog progressDialog = new MaterialAlertDialogBuilder(ctx)
                .setTitle("Syncing License…")
                .setMessage("Connecting to kotsafe.com licensing engine…")
                .setCancelable(false)
                .show();

        P2PLicenseManager.getInstance(ctx).activateFromAccount(email, new P2PLicenseManager.LicenseCallback() {
            @Override
            public void onSuccess(P2PLicenseManager.Tier tier, int maxDevices, long expiresAt) {
                if (getActivity() == null || getActivity().isFinishing()) return;
                progressDialog.dismiss();
                refreshUI();
                new MaterialAlertDialogBuilder(ctx)
                        .setTitle("🎉 KotSafe " + tier.name() + " Activated!")
                        .setMessage("Your mobile phone is now protected with KotSafe " + tier.name() + ".\n\n• Concurrent Devices: " + maxDevices + "\n• High-Speed Mesh Exit Nodes: Enabled\n• MITRE & YARA Defense: Active")
                        .setPositiveButton("Awesome", null)
                        .show();
            }

            @Override
            public void onError(String errorMessage) {
                if (getActivity() == null || getActivity().isFinishing()) return;
                progressDialog.dismiss();
                new MaterialAlertDialogBuilder(ctx)
                        .setTitle("Account Sync Failed")
                        .setMessage(errorMessage)
                        .setPositiveButton("Buy License", (dialog, which) -> {
                            if (mBuyProPref != null) {
                                mBuyProPref.performClick();
                            }
                        })
                        .setNegativeButton("Dismiss", null)
                        .show();
            }
        });
    }

    private void showActivationDialog() {
        if (getContext() == null) return;
        Context ctx = requireContext();

        final EditText input = new EditText(ctx);
        input.setHint("KOT-PRO-XXXXX-XXXXX-XXXXX");
        input.setSingleLine(true);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS);

        int padding = (int) (18 * getResources().getDisplayMetrics().density);
        FrameLayout container = new FrameLayout(ctx);
        container.setPadding(padding, padding / 2, padding, padding / 2);
        container.addView(input);

        new MaterialAlertDialogBuilder(ctx)
                .setTitle("Activate KotSafe Pro")
                .setMessage("Enter your official activation key from kotsafe.com to unlock multi-device exit nodes, deep JA4 forensics, and high-speed cloud relay.")
                .setView(container)
                .setPositiveButton("Activate", (dialog, which) -> {
                    String rawKey = input.getText().toString().trim();
                    if (rawKey.isEmpty()) {
                        Toast.makeText(ctx, "Please enter an activation key", Toast.LENGTH_SHORT).show();
                        return;
                    }

                    Toast.makeText(ctx, "Connecting to kotsafe.com...", Toast.LENGTH_SHORT).show();

                    P2PLicenseManager lm = P2PLicenseManager.getInstance(ctx);
                    lm.activateLicense(rawKey, new P2PLicenseManager.LicenseCallback() {
                        @Override
                        public void onSuccess(P2PLicenseManager.Tier tier, int maxDevices, long expiresAt) {
                            if (!isAdded()) return;
                            new MaterialAlertDialogBuilder(ctx)
                                    .setTitle("KotSafe Pro Activated!")
                                    .setMessage("✓ License verified successfully with kotsafe.com!\n\n" +
                                            "• Plan: " + tier + "\n" +
                                            "• Devices: " + lm.getActiveDevicesCount() + " of " + maxDevices + " in use\n" +
                                            "• Expiry: " + formatExpiry(expiresAt))
                                    .setPositiveButton("Great", null)
                                    .show();
                            refreshUI();
                        }

                        @Override
                        public void onError(String error) {
                            if (!isAdded()) return;
                            new MaterialAlertDialogBuilder(ctx)
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

        Toast.makeText(ctx, "Synchronizing license with kotsafe.com...", Toast.LENGTH_SHORT).show();

        lm.verifyWithServer(new P2PLicenseManager.LicenseCallback() {
            @Override
            public void onSuccess(P2PLicenseManager.Tier tier, int maxDevices, long expiresAt) {
                if (!isAdded()) return;
                Toast.makeText(ctx, "✓ License verified. " + tier + " active (" + lm.getActiveDevicesCount() + "/" + maxDevices + " seats).", Toast.LENGTH_SHORT).show();
                refreshUI();
            }

            @Override
            public void onError(String error) {
                if (!isAdded()) return;
                new MaterialAlertDialogBuilder(ctx)
                        .setTitle("License Notice")
                        .setMessage(error)
                        .setPositiveButton("OK", null)
                        .show();
                refreshUI();
            }
        });
    }

    private void confirmAndDeactivate() {
        if (getContext() == null) return;
        Context ctx = requireContext();

        new MaterialAlertDialogBuilder(ctx)
                .setTitle("Deactivate License?")
                .setMessage("Are you sure you want to deactivate KotSafe on this device?\n\nThis will release your device seat on kotsafe.com so you can activate the license on another device, and return this device to Freemium.")
                .setPositiveButton("Deactivate", (dialog, which) -> {
                    P2PLicenseManager.getInstance(ctx).deactivateLicense(new P2PLicenseManager.DeactivateCallback() {
                        @Override
                        public void onSuccess() {
                            if (!isAdded()) return;
                            Toast.makeText(ctx, "✓ License deactivated. Seat released on kotsafe.com.", Toast.LENGTH_LONG).show();
                            refreshUI();
                        }

                        @Override
                        public void onError(String errorMessage) {
                            if (!isAdded()) return;
                            Toast.makeText(ctx, errorMessage, Toast.LENGTH_LONG).show();
                            refreshUI();
                        }
                    });
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private String maskKey(String key) {
        if (key == null || key.length() < 8) return "****";
        String prefix = key.length() > 8 ? key.substring(0, 8) : "KOT-PRO-";
        String suffix = key.substring(key.length() - 4);
        return prefix + "••••-••••-" + suffix;
    }

    private String formatExpiry(long epochMs) {
        if (epochMs <= 0) {
            return "Lifetime Entitlement (Never Expires)";
        }
        try {
            long remainingDays = (epochMs - System.currentTimeMillis()) / (24 * 60 * 60 * 1000);
            SimpleDateFormat sdf = new SimpleDateFormat("MMM d, yyyy", Locale.US);
            String formattedDate = sdf.format(new Date(epochMs));
            if (remainingDays > 0) {
                return formattedDate + " (" + remainingDays + " days remaining)";
            } else {
                return formattedDate + " (Expired)";
            }
        } catch (Exception e) {
            return "1-Year Commercial Entitlement";
        }
    }
}
