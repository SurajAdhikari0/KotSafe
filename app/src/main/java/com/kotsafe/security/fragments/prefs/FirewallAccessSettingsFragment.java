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
import com.kotsafe.security.activities.AppPermissionsActivity;
import com.kotsafe.security.activities.PhysicalSecurityActivity;
import com.kotsafe.security.activities.WifiSecurityActivity;

public class FirewallAccessSettingsFragment extends SettingsSubFragment {

    @Override
    public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
        setPreferencesFromResource(R.xml.pref_firewall_access, rootKey);

        Preference phys = findPreference("physical_security_settings");
        if (phys != null) {
            phys.setOnPreferenceClickListener(pref -> {
                startActivity(new Intent(requireContext(), PhysicalSecurityActivity.class));
                return true;
            });
        }

        Preference perm = findPreference("security_permissions_setup");
        if (perm != null) {
            perm.setOnPreferenceClickListener(pref -> {
                startActivity(new Intent(requireContext(), AppPermissionsActivity.class));
                return true;
            });
        }

        Preference wifi = findPreference("wifi_security_settings");
        if (wifi != null) {
            wifi.setOnPreferenceClickListener(pref -> {
                startActivity(new Intent(requireContext(), WifiSecurityActivity.class));
                return true;
            });
        }
    }
}
