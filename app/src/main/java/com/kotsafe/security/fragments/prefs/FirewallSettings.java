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
 */

package com.kotsafe.security.fragments.prefs;

import android.os.Bundle;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.preference.Preference;
import androidx.preference.SwitchPreference;

import com.kotsafe.security.CaptureService;
import com.kotsafe.security.Log;
import com.kotsafe.security.R;
import com.kotsafe.security.model.Prefs;

public class FirewallSettings extends SettingsSubFragment {
    private static final String TAG = "FirewallSettings";
    private static boolean whitelistWarningAck = false;

    @Override
    public void onCreatePreferences(@Nullable Bundle savedInstanceState, @Nullable String rootKey) {
        setPreferencesFromResource(R.xml.firewall_preferences, rootKey);

        SwitchPreference firewallPref = findPreference(Prefs.PREF_FIREWALL);
        if (firewallPref != null) {
            firewallPref.setOnPreferenceChangeListener((preference, newValue) -> {
                boolean enabled = (Boolean) newValue;
                if (!enabled) {
                    new AlertDialog.Builder(requireContext())
                            .setTitle(R.string.disable_firewall_title)
                            .setIcon(R.drawable.ic_exclamation_triangle_solid)
                            .setMessage(R.string.disable_firewall_warning)
                            .setPositiveButton(R.string.disable_firewall_positive, (dialog, which) -> {
                                Log.d(TAG, "Firewall master toggle confirmed OFF");
                                firewallPref.setChecked(false);
                                getPreferenceManager().getSharedPreferences().edit()
                                        .putBoolean(Prefs.PREF_FIREWALL, false)
                                        .apply();
                                CaptureService.setFirewallEnabled(false);
                            })
                            .setNegativeButton(R.string.keep_firewall_on, (dialog, which) -> {
                                // keep switch checked
                                firewallPref.setChecked(true);
                            })
                            .show();
                    return false;
                } else {
                    Log.d(TAG, "Firewall master toggle: ON");
                    CaptureService.setFirewallEnabled(true);
                    return true;
                }
            });
        }

        SwitchPreference wlPref = findPreference(Prefs.PREF_FIREWALL_WHITELIST_MODE);
        if (wlPref != null) {
            wlPref.setOnPreferenceChangeListener((preference, newValue) -> {
                boolean enabled = (Boolean) newValue;
                if (enabled && !whitelistWarningAck) {
                    new AlertDialog.Builder(requireContext())
                            .setTitle(R.string.whitelist_mode)
                            .setMessage(R.string.firewall_whitelist_notice)
                            .setPositiveButton(R.string.ok, (dialog, which) -> {
                                whitelistWarningAck = true;
                                wlPref.setChecked(true);
                                getPreferenceManager().getSharedPreferences().edit()
                                        .putBoolean(Prefs.PREF_FIREWALL_WHITELIST_MODE, true)
                                        .apply();
                                if (CaptureService.isServiceActive())
                                    CaptureService.requireInstance().reloadFirewallWhitelist();
                            })
                            .setNegativeButton(R.string.cancel_action, (dialog, which) -> {})
                            .show();
                    return false;
                }

                if (CaptureService.isServiceActive()) {
                    // post reload after preference is written
                    new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(() -> {
                        if (CaptureService.isServiceActive())
                            CaptureService.requireInstance().reloadFirewallWhitelist();
                    }, 100);
                }
                return true;
            });
        }

        SwitchPreference screenOffPref = findPreference(Prefs.PREF_FIREWALL_SCREEN_OFF_BLOCK);
        if (screenOffPref != null) {
            screenOffPref.setOnPreferenceChangeListener((preference, newValue) -> {
                boolean enabled = (Boolean) newValue;
                Log.d(TAG, "Screen-off blocking preference changed: " + enabled);
                if (CaptureService.isServiceActive()) {
                    CaptureService.requireInstance().setScreenOffBlockEnabled(enabled);
                }
                return true;
            });
        }
    }
}
