/*
 * This file is part of KotSafe.
 *
 * KotSafe is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * KotSafe is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with KotSafe.  If not, see <http://www.gnu.org/licenses/>.
 * * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.fragments.prefs;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.preference.EditTextPreference;
import androidx.preference.Preference;
import androidx.preference.PreferenceManager;
import androidx.preference.SwitchPreference;

import com.kotsafe.security.CaptureService;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.dialogs.DnsBenchmarkDialog;
import com.kotsafe.security.model.DnsProvider;
import com.kotsafe.security.model.Prefs;

import java.util.Objects;

public class DnsSettings extends SettingsSubFragment {
    private Preference mPrefStatus;
    private SwitchPreference mPrefSystemDns;
    private EditTextPreference mPrefDnsV4;
    private EditTextPreference mPrefDnsV6;
    private SharedPreferences mPrefs;

    @Override
    public void onCreatePreferences(@Nullable Bundle savedInstanceState, @Nullable String rootKey) {
        setPreferencesFromResource(R.xml.dns_preferences, rootKey);

        mPrefs = PreferenceManager.getDefaultSharedPreferences(requireContext());

        mPrefStatus = findPreference("pref_dns_active_status");
        mPrefSystemDns = findPreference(Prefs.PREF_USE_SYSTEM_DNS);
        mPrefDnsV4 = Objects.requireNonNull(findPreference(Prefs.PREF_DNS_SERVER_V4));
        mPrefDnsV6 = Objects.requireNonNull(findPreference(Prefs.PREF_DNS_SERVER_V6));

        mPrefDnsV4.setOnPreferenceChangeListener((preference, newValue) -> {
            boolean valid = Utils.validateIpv4Address(newValue.toString());
            if (valid) {
                mPrefDnsV4.setText(newValue.toString());
                updateActiveStatus();
            }
            return valid;
        });

        mPrefDnsV6.setOnPreferenceChangeListener((preference, newValue) -> {
            String ip = newValue.toString();
            boolean valid = !ip.equals("::") && Utils.validateIpv6Address(ip);
            if (valid) {
                mPrefDnsV6.setText(newValue.toString());
                updateActiveStatus();
            }
            return valid;
        });

        if (mPrefSystemDns != null) {
            mPrefSystemDns.setOnPreferenceChangeListener((preference, newValue) -> {
                boolean systemDns = (Boolean) newValue;
                updateDependencyState(systemDns);
                mPrefs.edit().putBoolean(Prefs.PREF_USE_SYSTEM_DNS, systemDns).apply();
                updateActiveStatus();
                return true;
            });
            updateDependencyState(mPrefSystemDns.isChecked());
        }

        Preference prefPresets = findPreference("pref_dns_presets");
        if (prefPresets != null) {
            prefPresets.setOnPreferenceClickListener(preference -> {
                showPresetPicker();
                return true;
            });
        }

        Preference prefSpeedTest = findPreference("pref_dns_speed_test");
        if (prefSpeedTest != null) {
            prefSpeedTest.setOnPreferenceClickListener(preference -> {
                showPresetPicker();
                return true;
            });
        }

        if (mPrefStatus != null) {
            mPrefStatus.setOnPreferenceClickListener(preference -> {
                showPresetPicker();
                return true;
            });
        }

        Preference prefGuide = findPreference("pref_dnscrypt_guide");
        if (prefGuide != null) {
            prefGuide.setOnPreferenceClickListener(preference -> {
                com.kotsafe.security.activities.DocViewerActivity.start(requireContext(),
                        com.kotsafe.security.activities.DocViewerActivity.DOC_DOH_DNSCRYPT);
                return true;
            });
        }

        updateActiveStatus();
    }

    private void updateDependencyState(boolean useSystemDns) {
        // When system DNS is enabled, custom inputs are informative/disabled
        if (mPrefDnsV4 != null) mPrefDnsV4.setEnabled(!useSystemDns);
        if (mPrefDnsV6 != null) mPrefDnsV6.setEnabled(!useSystemDns);
    }

    private void updateActiveStatus() {
        if (mPrefStatus == null || !isAdded()) return;

        boolean useSystem = Prefs.useSystemDns(mPrefs);
        String dnsV4 = Prefs.getDnsServerV4(mPrefs);
        boolean dohEnabled = mPrefs.getBoolean(Prefs.PREF_ADBLOCK_DOH_ENABLED, false);

        StringBuilder sb = new StringBuilder();
        if (useSystem) {
            sb.append(getString(R.string.dns_mode_system));
            CaptureService service = CaptureService.requireInstance();
            if (service != null) {
                String activeDns = service.getDnsServer();
                if (activeDns != null && !activeDns.isEmpty() && !activeDns.equals("10.215.173.2")) {
                    sb.append(" (").append(activeDns).append(")");
                }
            }
        } else {
            DnsProvider provider = DnsProvider.findByIpv4(dnsV4);
            if (provider != null) {
                sb.append(provider.getName()).append(" (").append(dnsV4).append(")");
            } else {
                sb.append(getString(R.string.dns_mode_custom)).append(": ").append(dnsV4);
            }
        }

        if (dohEnabled) {
            String dohProv = mPrefs.getString(Prefs.PREF_ADBLOCK_DOH_PROVIDER, "cloudflare");
            sb.append(" • DoH (").append(dohProv).append(")");
        }

        mPrefStatus.setSummary(sb.toString());
    }

    private void showPresetPicker() {
        String currentIpv4 = Prefs.getDnsServerV4(mPrefs);
        DnsProvider currentProvider = DnsProvider.findByIpv4(currentIpv4);
        String selectedId = currentProvider != null ? currentProvider.getId() : "cloudflare";

        DnsBenchmarkDialog dialog = DnsBenchmarkDialog.newInstance(selectedId);
        dialog.setOnDnsProviderSelectedListener(this::applyDnsProvider);
        dialog.show(getChildFragmentManager(), DnsBenchmarkDialog.TAG);
    }

    private void applyDnsProvider(@NonNull DnsProvider provider) {
        mPrefs.edit()
                .putBoolean(Prefs.PREF_USE_SYSTEM_DNS, false)
                .putString(Prefs.PREF_DNS_SERVER_V4, provider.getPrimaryIpv4())
                .putString(Prefs.PREF_DNS_SERVER_V6, provider.getPrimaryIpv6() != null ? provider.getPrimaryIpv6() : "2606:4700:4700::1111")
                .putString(Prefs.PREF_ADBLOCK_DOH_PROVIDER, provider.getId())
                .apply();

        if (mPrefSystemDns != null) {
            mPrefSystemDns.setChecked(false);
            updateDependencyState(false);
        }

        if (mPrefDnsV4 != null) {
            mPrefDnsV4.setText(provider.getPrimaryIpv4());
        }

        if (mPrefDnsV6 != null && provider.getPrimaryIpv6() != null) {
            mPrefDnsV6.setText(provider.getPrimaryIpv6());
        }

        updateActiveStatus();

        Toast.makeText(requireContext(),
                getString(R.string.dns_provider_applied, provider.getName()),
                Toast.LENGTH_SHORT).show();
    }

    @Override
    public void onResume() {
        super.onResume();
        updateActiveStatus();
    }
}
