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
        androidx.preference.Preference automatic = findPreference("pref_ai_autopilot_resolve");
        automatic.setDependency(com.kotsafe.security.model.DefenderManager.PREF_DEFENDER_AUTO_PILOT);
        androidx.preference.MultiSelectListPreference allowedApps = findPreference(
                com.kotsafe.security.model.Prefs.PREF_SCREEN_OFF_ALLOWED_APPS);
        loadAllowedApps(allowedApps);
        androidx.preference.Preference screenOff = findPreference(
                com.kotsafe.security.model.Prefs.PREF_FIREWALL_SCREEN_OFF_BLOCK);
        screenOff.setOnPreferenceChangeListener((preference, value) -> {
            new android.os.Handler(android.os.Looper.getMainLooper()).post(() -> {
                if (com.kotsafe.security.CaptureService.isServiceActive()) {
                    com.kotsafe.security.CaptureService.requireInstance().setScreenOffBlockEnabled((Boolean) value);
                }
            });
            return true;
        });
        allowedApps.setOnPreferenceChangeListener((preference, value) -> {
            new android.os.Handler(android.os.Looper.getMainLooper()).post(() -> {
                if (com.kotsafe.security.CaptureService.isServiceActive()) {
                    com.kotsafe.security.CaptureService.requireInstance().reloadFirewallWhitelist();
                }
            });
            return true;
        });
    }

    private void loadAllowedApps(androidx.preference.MultiSelectListPreference preference) {
        android.content.Context context = requireContext().getApplicationContext();
        android.content.pm.PackageManager packages = context.getPackageManager();
        java.util.Set<String> selected = new java.util.HashSet<>(preference.getValues());
        int iconSize = Math.round(32 * getResources().getDisplayMetrics().density);
        preference.setEnabled(false);
        preference.setSummary("Loading apps…");
        new Thread(() -> {
            try {
                android.content.Intent launcher = new android.content.Intent(android.content.Intent.ACTION_MAIN)
                        .addCategory(android.content.Intent.CATEGORY_LAUNCHER);
                java.util.Map<String, android.content.pm.ApplicationInfo> indexed = new java.util.HashMap<>();
                for (android.content.pm.ResolveInfo result : packages.queryIntentActivities(launcher, 0)) {
                    android.content.pm.ApplicationInfo app = result.activityInfo.applicationInfo;
                    if (!app.packageName.equals(context.getPackageName())) indexed.put(app.packageName, app);
                }
                for (String packageName : selected) {
                    try {
                        indexed.put(packageName, packages.getApplicationInfo(packageName, 0));
                    } catch (android.content.pm.PackageManager.NameNotFoundException removed) {
                        // Preserve saved selection; a removed app has no selectable row.
                    }
                }
                java.util.Map<String, String> names = new java.util.HashMap<>();
                for (android.content.pm.ApplicationInfo app : indexed.values()) {
                    names.put(app.packageName, packages.getApplicationLabel(app).toString());
                }
                java.util.List<android.content.pm.ApplicationInfo> apps = new java.util.ArrayList<>(indexed.values());
                apps.sort(java.util.Comparator.comparing(app -> names.get(app.packageName), String.CASE_INSENSITIVE_ORDER));
                CharSequence[] labels = new CharSequence[apps.size()];
                CharSequence[] values = new CharSequence[apps.size()];
                for (int i = 0; i < apps.size(); i++) {
                    android.content.pm.ApplicationInfo app = apps.get(i);
                    android.text.SpannableString label = new android.text.SpannableString("  " + names.get(app.packageName));
                    android.graphics.drawable.Drawable icon = packages.getApplicationIcon(app).mutate();
                    icon.setBounds(0, 0, iconSize, iconSize);
                    label.setSpan(new android.text.style.ImageSpan(icon, android.text.style.ImageSpan.ALIGN_BOTTOM),
                            0, 1, android.text.Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                    labels[i] = label;
                    values[i] = app.packageName;
                }
                new android.os.Handler(android.os.Looper.getMainLooper()).post(() -> {
                    if (!isAdded() || findPreference(preference.getKey()) != preference) return;
                    preference.setEntries(labels);
                    preference.setEntryValues(values);
                    preference.setEnabled(true);
                    preference.setSummary("Choose apps for background messages or calls. KotSafe P2P transport is already excluded.");
                });
            } catch (RuntimeException failure) {
                new android.os.Handler(android.os.Looper.getMainLooper()).post(() -> {
                    if (isAdded() && findPreference(preference.getKey()) == preference) {
                        preference.setSummary("Could not load apps. Reopen this page to retry.");
                    }
                });
            }
        }, "ShieldAppPicker").start();
    }

    @Override
    public void onResume() {
        super.onResume();
        androidx.preference.Preference status = findPreference("autopilot_runtime_status");
        if (status != null) status.setSummary(com.kotsafe.security.CaptureService.isFirewallRunning()
                ? "Firewall is running. New block rules must be loaded before they can protect connections."
                : "Firewall is inactive. Saved rules take effect after protection starts.");
    }
}
