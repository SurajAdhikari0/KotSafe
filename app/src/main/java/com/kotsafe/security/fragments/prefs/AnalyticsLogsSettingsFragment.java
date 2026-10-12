/*
 * This file is part of KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.fragments.prefs;

import android.content.Intent;
import android.os.Bundle;

import androidx.preference.Preference;

import com.kotsafe.security.R;
import com.kotsafe.security.activities.LogviewActivity;
import com.kotsafe.security.activities.StatsActivity;
import com.kotsafe.security.activities.StorageManagementActivity;

public class AnalyticsLogsSettingsFragment extends SettingsSubFragment {

    @Override
    public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
        setPreferencesFromResource(R.xml.pref_analytics_logs, rootKey);

        Preference trafficStats = findPreference("pref_traffic_stats");
        if (trafficStats != null) {
            trafficStats.setOnPreferenceClickListener(pref -> {
                startActivity(new Intent(requireContext(), StatsActivity.class));
                return true;
            });
        }

        Preference appLog = findPreference("pref_app_log");
        if (appLog != null) {
            appLog.setOnPreferenceClickListener(pref -> {
                startActivity(new Intent(requireContext(), LogviewActivity.class));
                return true;
            });
        }

        Preference storage = findPreference("storage_management");
        if (storage != null) {
            storage.setOnPreferenceClickListener(pref -> {
                startActivity(new Intent(requireContext(), StorageManagementActivity.class));
                return true;
            });
        }
    }
}
