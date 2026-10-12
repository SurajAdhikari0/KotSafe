/*
 * This file is part of KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.fragments.prefs;

import android.os.Bundle;

import androidx.annotation.NonNull;
import androidx.preference.Preference;

import com.kotsafe.security.R;
import com.kotsafe.security.activities.DocViewerActivity;

public class BackupRestoreSettingsFragment extends SettingsSubFragment {

    @Override
    public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
        setPreferencesFromResource(R.xml.pref_backup_restore, rootKey);
    }

    @Override
    public boolean onPreferenceTreeClick(@NonNull Preference preference) {
        String key = preference.getKey();
        if ("dump_extensions_how_to".equals(key)) {
            DocViewerActivity.start(requireContext(), DocViewerActivity.DOC_WIRESHARK_EXTENSIONS);
            return true;
        }
        return super.onPreferenceTreeClick(preference);
    }
}
