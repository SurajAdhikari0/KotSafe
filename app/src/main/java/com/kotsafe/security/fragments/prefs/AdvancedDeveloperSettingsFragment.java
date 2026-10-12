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
