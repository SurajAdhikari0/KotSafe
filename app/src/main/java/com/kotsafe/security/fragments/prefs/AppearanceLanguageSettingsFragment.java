/*
 * This file is part of KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.fragments.prefs;

import android.os.Bundle;

import androidx.preference.Preference;

import com.kotsafe.security.R;
import com.kotsafe.security.activities.prefs.LanguagePickerDialog;

public class AppearanceLanguageSettingsFragment extends SettingsSubFragment {

    @Override
    public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
        setPreferencesFromResource(R.xml.pref_appearance_language, rootKey);

        Preference appLanguage = findPreference("app_language");
        if (appLanguage != null) {
            appLanguage.setOnPreferenceClickListener(pref -> {
                LanguagePickerDialog dialog = new LanguagePickerDialog();
                dialog.show(getChildFragmentManager(), LanguagePickerDialog.TAG);
                return true;
            });
        }
    }
}
