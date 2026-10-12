/*
 * This file is part of KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.fragments.prefs;

import android.content.Intent;
import android.os.Bundle;

import androidx.preference.DropDownPreference;
import androidx.preference.Preference;
import androidx.preference.SwitchPreference;

import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.activities.prefs.VpnExemptionsActivity;
import com.kotsafe.security.model.Prefs;

import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Enumeration;

public class CaptureEngineSettingsFragment extends SettingsSubFragment {

    @Override
    public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
        setPreferencesFromResource(R.xml.pref_capture_engine, rootKey);

        DropDownPreference capInterface = findPreference(Prefs.PREF_CAPTURE_INTERFACE);
        if (capInterface != null) {
            refreshInterfaces(capInterface);
        }

        SwitchPreference rootCapture = findPreference(Prefs.PREF_ROOT_CAPTURE);
        if (rootCapture != null) {
            if (!Utils.isRootAvailable()) {
                rootCapture.setVisible(false);
            }
        }

        Preference vpnExceptions = findPreference(Prefs.PREF_VPN_EXCEPTIONS);
        if (vpnExceptions != null) {
            vpnExceptions.setOnPreferenceClickListener(preference -> {
                startActivity(new Intent(requireContext(), VpnExemptionsActivity.class));
                return true;
            });
        }
    }

    private void refreshInterfaces(DropDownPreference capInterface) {
        ArrayList<String> labels = new ArrayList<>();
        ArrayList<String> values = new ArrayList<>();

        labels.add(getString(R.string.internet));
        values.add("@inet");
        labels.add(getString(R.string.all_interfaces));
        values.add("any");

        try {
            Enumeration<NetworkInterface> ifaces = Utils.getNetworkInterfaces();
            while (ifaces.hasMoreElements()) {
                NetworkInterface iface = ifaces.nextElement();
                if (!iface.isUp()) continue;
                String name = iface.getName();
                labels.add(name);
                values.add(name);
            }
        } catch (SocketException e) {
            e.printStackTrace();
        }

        capInterface.setEntryValues(values.toArray(new String[0]));
        capInterface.setEntries(labels.toArray(new String[0]));
    }
}
