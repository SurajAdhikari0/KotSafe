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
 *
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.fragments.prefs;

import android.content.Context;
import android.content.DialogInterface;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.preference.MultiSelectListPreference;
import androidx.preference.Preference;
import androidx.preference.SwitchPreference;

import com.kotsafe.security.CaptureService;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.AdBlockSubscriptionManager;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

public class AdBlockSettings extends SettingsSubFragment {
    private static final String TAG = "AdBlockSettings";

    @Override
    public void onCreatePreferences(@Nullable Bundle savedInstanceState, @Nullable String rootKey) {
        setPreferencesFromResource(R.xml.ad_block_preferences, rootKey);

        Context context = requireContext();
        AdBlockSubscriptionManager manager = AdBlockSubscriptionManager.getInstance(context);

        SwitchPreference masterSwitch = findPreference("pref_adblock_enabled");
        if (masterSwitch != null) {
            masterSwitch.setOnPreferenceChangeListener((preference, newValue) -> {
                boolean enabled = (Boolean) newValue;
                if (enabled && manager.getTotalRulesCount() == 0) {
                    Toast.makeText(context, R.string.pref_adblock_update_now_summary, Toast.LENGTH_SHORT).show();
                    manager.updateSubscriptions(new AdBlockSubscriptionManager.UpdateCallback() {
                        @Override
                        public void onSuccess(int totalRules, int updatedCount) {
                            if (isAdded()) {
                                Toast.makeText(context, "Loaded " + totalRules + " privacy filter rules", Toast.LENGTH_LONG).show();
                            }
                        }

                        @Override
                        public void onError(String message) {
                            if (isAdded()) {
                                Toast.makeText(context, "Failed to load rules: " + message, Toast.LENGTH_SHORT).show();
                            }
                        }
                    });
                }
                CaptureService service = CaptureService.getInstance();
                if (service != null) {
                    service.reloadBlocklist();
                }
                return true;
            });
        }

        Preference updateNowPref = findPreference("pref_adblock_update_now");
        if (updateNowPref != null) {
            updateNowPref.setOnPreferenceClickListener(preference -> {
                Toast.makeText(context, "Updating subscriptions...", Toast.LENGTH_SHORT).show();
                manager.updateSubscriptions(new AdBlockSubscriptionManager.UpdateCallback() {
                    @Override
                    public void onSuccess(int totalRules, int updatedCount) {
                        if (isAdded()) {
                            Toast.makeText(context, "Updated! Total rules: " + totalRules, Toast.LENGTH_LONG).show();
                        }
                        CaptureService service = CaptureService.getInstance();
                        if (service != null) {
                            service.reloadBlocklist();
                        }
                    }

                    @Override
                    public void onError(String message) {
                        if (isAdded()) {
                            Toast.makeText(context, "Update failed: " + message, Toast.LENGTH_SHORT).show();
                        }
                    }
                });
                return true;
            });
        }

        MultiSelectListPreference feedsPref = findPreference("pref_adblock_active_feeds");
        if (feedsPref != null) {
            feedsPref.setOnPreferenceChangeListener((preference, newValue) -> {
                @SuppressWarnings("unchecked")
                Set<String> selected = (Set<String>) newValue;
                manager.setActiveFeedIds(selected);
                return true;
            });
        }

        Preference whitelistPref = findPreference("pref_adblock_manage_whitelist");
        if (whitelistPref != null) {
            whitelistPref.setOnPreferenceClickListener(preference -> {
                showCustomDomainsDialog(true);
                return true;
            });
        }

        Preference blacklistPref = findPreference("pref_adblock_manage_blacklist");
        if (blacklistPref != null) {
            blacklistPref.setOnPreferenceClickListener(preference -> {
                showCustomDomainsDialog(false);
                return true;
            });
        }
    }

    private void showCustomDomainsDialog(boolean isWhitelist) {
        Context context = getContext();
        if (context == null) return;
        AdBlockSubscriptionManager manager = AdBlockSubscriptionManager.getInstance(context);
        Set<String> domainsSet = isWhitelist ? manager.getCustomWhitelist() : manager.getCustomBlacklist();
        List<String> domainList = new ArrayList<>(domainsSet);
        Collections.sort(domainList);

        String title = isWhitelist ? getString(R.string.pref_adblock_whitelist_title) : getString(R.string.pref_adblock_blacklist_title);

        String[] items = new String[domainList.size() + 1];
        items[0] = "+ Add New Domain";
        for (int i = 0; i < domainList.size(); i++) {
            items[i + 1] = domainList.get(i);
        }

        new AlertDialog.Builder(context)
                .setTitle(title + " (" + domainList.size() + ")")
                .setItems(items, (dialog, which) -> {
                    if (which == 0) {
                        showAddDomainDialog(isWhitelist);
                    } else {
                        String selected = domainList.get(which - 1);
                        showRemoveDomainDialog(isWhitelist, selected);
                    }
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private void showAddDomainDialog(boolean isWhitelist) {
        Context context = getContext();
        if (context == null) return;
        AdBlockSubscriptionManager manager = AdBlockSubscriptionManager.getInstance(context);

        final EditText input = new EditText(context);
        input.setHint("example: telemetry.badapp.com");
        input.setSingleLine(true);

        new AlertDialog.Builder(context)
                .setTitle(isWhitelist ? "Add Whitelist Domain" : "Add Blacklist Domain")
                .setView(input)
                .setPositiveButton("Add", (dialog, which) -> {
                    String domain = input.getText().toString().trim().toLowerCase();
                    if (!domain.isEmpty()) {
                        if (isWhitelist) {
                            manager.addCustomWhitelist(domain);
                        } else {
                            manager.addCustomBlacklist(domain);
                        }
                        Toast.makeText(context, "Added " + domain, Toast.LENGTH_SHORT).show();
                        CaptureService service = CaptureService.getInstance();
                        if (service != null) {
                            service.reloadBlocklist();
                        }
                    }
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private void showRemoveDomainDialog(boolean isWhitelist, String domain) {
        Context context = getContext();
        if (context == null) return;
        AdBlockSubscriptionManager manager = AdBlockSubscriptionManager.getInstance(context);

        new AlertDialog.Builder(context)
                .setTitle("Delete Rule")
                .setMessage("Remove " + domain + " from " + (isWhitelist ? "whitelist" : "blacklist") + "?")
                .setPositiveButton("Remove", (dialog, which) -> {
                    if (isWhitelist) {
                        manager.removeCustomWhitelist(domain);
                    } else {
                        manager.removeCustomBlacklist(domain);
                    }
                    Toast.makeText(context, "Removed " + domain, Toast.LENGTH_SHORT).show();
                    CaptureService service = CaptureService.getInstance();
                    if (service != null) {
                        service.reloadBlocklist();
                    }
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }
}
