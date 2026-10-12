/*
 * This file is part of KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.fragments.prefs;

import android.os.Bundle;

import com.kotsafe.security.R;

public class KotSafeShieldSettingsFragment extends SettingsSubFragment {
    @Override
    public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
        setPreferencesFromResource(R.xml.pref_kotsafe_shield, rootKey);
    }
}
