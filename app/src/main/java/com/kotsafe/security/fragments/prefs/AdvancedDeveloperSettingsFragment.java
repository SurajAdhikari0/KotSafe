/*
 * This file is part of KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.fragments.prefs;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.preference.Preference;
import androidx.preference.PreferenceManager;
import androidx.preference.SwitchPreference;

import com.kotsafe.security.R;
import com.kotsafe.security.activities.DocViewerActivity;
import com.kotsafe.security.model.Prefs;

public class AdvancedDeveloperSettingsFragment extends SettingsSubFragment {

    @Override
    public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
        setPreferencesFromResource(R.xml.pref_advanced_developer, rootKey);

        Preference enableAll = findPreference("pref_enable_all_advanced_now");
        if (enableAll != null) {
            enableAll.setOnPreferenceClickListener(pref -> {
                showEnableAllAdvancedDialog();
                return true;
            });
        }

        SwitchPreference localAccessPref = findPreference(com.kotsafe.security.p2p.GatewayPreferenceKeys.LOCAL_SERVICE_ACCESS);
        if (localAccessPref != null) {
            localAccessPref.setOnPreferenceChangeListener((preference, newValue) -> {
                boolean enabling = Boolean.TRUE.equals(newValue);
                if (enabling) {
                    boolean exitActive = PreferenceManager.getDefaultSharedPreferences(requireContext())
                            .getBoolean(com.kotsafe.security.p2p.GatewayPreferenceKeys.EXIT_ENABLED, false);
                    if (!exitActive) {
                        new AlertDialog.Builder(requireContext())
                                .setTitle(R.string.gateway_local_service_requires_exit_title)
                                .setMessage(R.string.gateway_local_service_requires_exit_message)
                                .setIcon(android.R.drawable.ic_dialog_alert)
                                .setPositiveButton(android.R.string.ok, null)
                                .show();
                        return false;
                    }
                    showLocalServiceAccessWarningDialog(localAccessPref);
                    return false;
                } else {
                    return true;
                }
            });
        }
    }

    @Override
    public void onResume() {
        super.onResume();
        SwitchPreference localAccessPref = findPreference(com.kotsafe.security.p2p.GatewayPreferenceKeys.LOCAL_SERVICE_ACCESS);
        if (localAccessPref != null) {
            boolean exitActive = PreferenceManager.getDefaultSharedPreferences(requireContext())
                    .getBoolean(com.kotsafe.security.p2p.GatewayPreferenceKeys.EXIT_ENABLED, false);
            if (!exitActive && localAccessPref.isChecked()) {
                localAccessPref.setChecked(false);
                PreferenceManager.getDefaultSharedPreferences(requireContext())
                        .edit().putBoolean(com.kotsafe.security.p2p.GatewayPreferenceKeys.LOCAL_SERVICE_ACCESS, false).apply();
            }
        }
    }

    private void showLocalServiceAccessWarningDialog(SwitchPreference pref) {
        new AlertDialog.Builder(requireContext())
                .setTitle(R.string.gateway_local_service_warning_title)
                .setMessage(R.string.gateway_local_service_warning_message)
                .setIcon(android.R.drawable.ic_dialog_alert)
                .setPositiveButton(R.string.gateway_local_service_warning_confirm, (dialog, which) -> {
                    SharedPreferences p = PreferenceManager.getDefaultSharedPreferences(requireContext());
                    p.edit().putBoolean(com.kotsafe.security.p2p.GatewayPreferenceKeys.LOCAL_SERVICE_ACCESS, true).apply();
                    if (pref != null) {
                        pref.setChecked(true);
                    }
                    Toast.makeText(requireContext(), R.string.gateway_local_service_enabled_toast, Toast.LENGTH_SHORT).show();
                })
                .setNegativeButton(android.R.string.cancel, (dialog, which) -> {
                    if (pref != null) {
                        pref.setChecked(false);
                    }
                })
                .setOnCancelListener(dialog -> {
                    if (pref != null) {
                        pref.setChecked(false);
                    }
                })
                .show();
    }

    @Override
    public boolean onPreferenceTreeClick(@NonNull Preference preference) {
        String key = preference.getKey();
        if ("dnscrypt_link".equals(key)) {
            DocViewerActivity.start(requireContext(), DocViewerActivity.DOC_DOH_DNSCRYPT);
            return true;
        }
        return super.onPreferenceTreeClick(preference);
    }

    private void showEnableAllAdvancedDialog() {
        new AlertDialog.Builder(requireContext())
                .setTitle(R.string.advanced_mode_dialog_title)
                .setMessage(R.string.advanced_mode_dialog_msg)
                .setPositiveButton(R.string.advanced_mode_enable_all, (dialog, which) -> {
                    SharedPreferences p = PreferenceManager.getDefaultSharedPreferences(requireContext());
                    p.edit()
                            .putBoolean(Prefs.PREF_FULL_PAYLOAD, true)
                            .putBoolean(Prefs.PREF_PCAPNG_ENABLED, true)
                            .putBoolean(Prefs.PREF_DUMP_EXTENSIONS, true)
                            .putBoolean(Prefs.PREF_AUTO_BLOCK_PRIVATE_DNS, true)
                            .putString(Prefs.PREF_BLOCK_QUIC, "always")
                            .putBoolean("pref_auto_daily_deep_scan", true)
                            .putBoolean("pref_detection_rules_enabled", true)
                            .apply();

                    SwitchPreference fullPayload = findPreference("full_payload");
                    if (fullPayload != null) fullPayload.setChecked(true);

                    SwitchPreference autoBlockDns = findPreference("auto_block_private_dns");
                    if (autoBlockDns != null) autoBlockDns.setChecked(true);

                    Toast.makeText(requireContext(), R.string.advanced_mode_all_enabled_toast, Toast.LENGTH_LONG).show();
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }
}
