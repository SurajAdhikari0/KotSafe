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
 * Copyright 2026 - KotSafe Team
 */

package com.kotsafe.security.activities.prefs;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.MenuItem;
import android.view.View;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.Toolbar;
import androidx.collection.ArraySet;
import androidx.core.content.ContextCompat;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.CaptureService;
import com.kotsafe.security.Log;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.activities.BaseActivity;
import com.kotsafe.security.fragments.AppsToggles;
import com.kotsafe.security.model.AppDescriptor;
import com.kotsafe.security.model.CaptureSettings;
import com.kotsafe.security.model.Prefs;
import com.google.android.material.chip.Chip;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public class VpnExemptionsActivity extends BaseActivity {
    private static final String TAG = "VpnExemptionsActivity";
    private VpnExceptionsFragment mFragment;
    private Chip mChipExemptCount;
    private View mBannerRestartVpn;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_vpn_exemptions);

        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
            getSupportActionBar().setDisplayShowHomeEnabled(true);
            getSupportActionBar().setTitle(R.string.vpn_exemptions);
        }

        mChipExemptCount = findViewById(R.id.chip_exempt_count);
        mBannerRestartVpn = findViewById(R.id.banner_restart_vpn);
        View btnRestartVpn = findViewById(R.id.btn_restart_vpn);

        btnRestartVpn.setOnClickListener(v -> restartVpnService());

        findViewById(R.id.chip_clear_all).setOnClickListener(v -> {
            new MaterialAlertDialogBuilder(this)
                    .setTitle(R.string.warning)
                    .setMessage("Clear all VPN exemptions? All applications will be routed through the KotSafe VPN tunnel.")
                    .setPositiveButton(R.string.delete, (d, w) -> {
                        if (mFragment != null)
                            mFragment.clearAllExemptions();
                    })
                    .setNegativeButton(R.string.cancel_action, (d, w) -> d.dismiss())
                    .show();
        });

        findViewById(R.id.chip_preset_streaming).setOnClickListener(v -> {
            if (mFragment != null)
                mFragment.exemptStreamingApps();
        });

        findViewById(R.id.chip_preset_banking).setOnClickListener(v -> {
            if (mFragment != null)
                mFragment.exemptBankingApps();
        });

        if (savedInstanceState != null)
            mFragment = (VpnExceptionsFragment) getSupportFragmentManager().getFragment(savedInstanceState, "fragment");
        if (mFragment == null)
            mFragment = new VpnExceptionsFragment();

        getSupportFragmentManager().beginTransaction()
                .replace(R.id.fragment, mFragment)
                .commit();

        updateInitialCount();
    }

    private void updateInitialCount() {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        Set<String> saved = prefs.getStringSet(Prefs.PREF_VPN_EXCEPTIONS, null);
        int count = (saved != null) ? saved.size() : 0;
        updateExemptionCount(count);
    }

    public void updateExemptionCount(int count) {
        if (mChipExemptCount != null) {
            mChipExemptCount.setText(count + " Exempted");
        }
    }

    public void notifyServiceRestartNeeded() {
        if (CaptureService.isServiceActive() && mBannerRestartVpn != null) {
            mBannerRestartVpn.setVisibility(View.VISIBLE);
        }
    }

    private void restartVpnService() {
        if (!CaptureService.isServiceActive()) {
            mBannerRestartVpn.setVisibility(View.GONE);
            return;
        }

        CaptureSettings settings = CaptureService.getCaptureSettings();
        CaptureService.stopService();
        Toast.makeText(this, "Stopping VPN tunnel...", Toast.LENGTH_SHORT).show();

        if (settings != null) {
            new Handler(Looper.getMainLooper()).postDelayed(() -> {
                Intent intent = new Intent(this, CaptureService.class);
                intent.putExtra("settings", settings);
                ContextCompat.startForegroundService(this, intent);
                Toast.makeText(this, "VPN Tunnel Restarted with new exemptions", Toast.LENGTH_SHORT).show();
                mBannerRestartVpn.setVisibility(View.GONE);
            }, 750);
        } else {
            mBannerRestartVpn.setVisibility(View.GONE);
        }
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    @Override
    protected void onSaveInstanceState(@NonNull Bundle outState) {
        super.onSaveInstanceState(outState);
        getSupportFragmentManager().putFragment(outState, "fragment", mFragment);
    }

    public static class VpnExceptionsFragment extends AppsToggles {
        private static final String TAG = "VpnExceptions";
        private final Set<String> mExcludedApps = new ArraySet<>();
        private @Nullable SharedPreferences mPrefs;

        @Override
        public void onAttach(@NonNull Context context) {
            super.onAttach(context);
            mPrefs = PreferenceManager.getDefaultSharedPreferences(context);
            assert mPrefs != null;

            mExcludedApps.clear();
            Set<String> saved = mPrefs.getStringSet(Prefs.PREF_VPN_EXCEPTIONS, null);
            if (saved != null) {
                Log.d(TAG, "Loading " + saved.size() + " exceptions");
                mExcludedApps.addAll(saved);
            }
        }

        @Override
        public void onDetach() {
            super.onDetach();
            mPrefs = null;
        }

        @Override
        protected Set<String> getCheckedApps() {
            return mExcludedApps;
        }

        @Override
        public void onAppToggled(AppDescriptor app, boolean checked) {
            String packageName = app.getPackageName();
            if (mExcludedApps.contains(packageName) == checked)
                return;

            if (checked)
                mExcludedApps.add(packageName);
            else
                mExcludedApps.remove(packageName);

            saveExemptions();

            if (getActivity() instanceof VpnExemptionsActivity) {
                VpnExemptionsActivity act = (VpnExemptionsActivity) getActivity();
                act.updateExemptionCount(mExcludedApps.size());
                act.notifyServiceRestartNeeded();
            }
        }

        private void saveExemptions() {
            if (mPrefs == null)
                return;

            mPrefs.edit()
                    .putStringSet(Prefs.PREF_VPN_EXCEPTIONS, mExcludedApps)
                    .apply();
        }

        public void clearAllExemptions() {
            mExcludedApps.clear();
            saveExemptions();
            if (mAdapter != null) {
                mAdapter.setCheckedItems(mExcludedApps);
            }
            if (getActivity() instanceof VpnExemptionsActivity) {
                VpnExemptionsActivity act = (VpnExemptionsActivity) getActivity();
                act.updateExemptionCount(0);
                act.notifyServiceRestartNeeded();
            }
            Toast.makeText(requireContext(), "Cleared all exemptions", Toast.LENGTH_SHORT).show();
        }

        public void exemptStreamingApps() {
            if (mAdapter == null) return;
            List<AppDescriptor> all = mAdapter.getAllApps();
            if (all == null || all.isEmpty()) return;

            Set<String> knownStreamingPackages = new HashSet<>(Arrays.asList(
                    "com.google.android.youtube",
                    "com.netflix.mediaclient",
                    "com.amazon.avod.thirdpartyclient",
                    "com.spotify.music",
                    "com.disney.disneyplus",
                    "tv.twitch.android.app",
                    "in.startv.hotstar",
                    "com.hulu.plus",
                    "com.apple.atve.androidtv.appletv",
                    "com.google.android.apps.youtube.music"
            ));

            String[] streamingKeywords = new String[]{"netflix", "youtube", "spotify", "prime video", "hotstar", "twitch", "disney", "stream"};

            int newlyAdded = 0;
            for (AppDescriptor app : all) {
                String pkg = app.getPackageName().toLowerCase(Locale.getDefault());
                String name = app.getName().toLowerCase(Locale.getDefault());

                boolean match = knownStreamingPackages.contains(app.getPackageName());
                if (!match) {
                    for (String kw : streamingKeywords) {
                        if (pkg.contains(kw) || name.contains(kw)) {
                            match = true;
                            break;
                        }
                    }
                }

                if (match && !mExcludedApps.contains(app.getPackageName())) {
                    mExcludedApps.add(app.getPackageName());
                    newlyAdded++;
                }
            }

            saveExemptions();
            mAdapter.setCheckedItems(mExcludedApps);

            if (getActivity() instanceof VpnExemptionsActivity) {
                VpnExemptionsActivity act = (VpnExemptionsActivity) getActivity();
                act.updateExemptionCount(mExcludedApps.size());
                act.notifyServiceRestartNeeded();
            }

            Toast.makeText(requireContext(), "Exempted " + newlyAdded + " streaming apps", Toast.LENGTH_SHORT).show();
        }

        public void exemptBankingApps() {
            if (mAdapter == null) return;
            List<AppDescriptor> all = mAdapter.getAllApps();
            if (all == null || all.isEmpty()) return;

            String[] bankingKeywords = new String[]{"bank", "pay", "upi", "finance", "wallet", "paypal", "revolut", "chase", "wells", "fidelity", "binance", "crypto", "trading"};

            int newlyAdded = 0;
            for (AppDescriptor app : all) {
                String pkg = app.getPackageName().toLowerCase(Locale.getDefault());
                String name = app.getName().toLowerCase(Locale.getDefault());

                boolean match = false;
                for (String kw : bankingKeywords) {
                    if (pkg.contains(kw) || name.contains(kw)) {
                        match = true;
                        break;
                    }
                }

                if (match && !mExcludedApps.contains(app.getPackageName())) {
                    mExcludedApps.add(app.getPackageName());
                    newlyAdded++;
                }
            }

            saveExemptions();
            mAdapter.setCheckedItems(mExcludedApps);

            if (getActivity() instanceof VpnExemptionsActivity) {
                VpnExemptionsActivity act = (VpnExemptionsActivity) getActivity();
                act.updateExemptionCount(mExcludedApps.size());
                act.notifyServiceRestartNeeded();
            }

            Toast.makeText(requireContext(), "Exempted " + newlyAdded + " banking/finance apps", Toast.LENGTH_SHORT).show();
        }
    }
}
