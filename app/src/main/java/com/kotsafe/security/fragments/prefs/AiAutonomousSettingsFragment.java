/*
 * This file is part of KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.fragments.prefs;

import android.content.Intent;
import android.os.Bundle;

import androidx.annotation.NonNull;
import androidx.preference.Preference;

import com.kotsafe.security.R;
import com.kotsafe.security.activities.AntivirusScanActivity;

public class AiAutonomousSettingsFragment extends SettingsSubFragment {

    @Override
    public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
        setPreferencesFromResource(R.xml.pref_ai_autonomous, rootKey);

        Preference avScan = findPreference("antivirus_scan_action");
        if (avScan != null) {
            avScan.setOnPreferenceClickListener(pref -> {
                startActivity(new Intent(requireContext(), AntivirusScanActivity.class));
                return true;
            });
        }
    }
}
