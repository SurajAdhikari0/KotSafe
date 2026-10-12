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

package com.kotsafe.security.activities;

import android.annotation.SuppressLint;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;

import android.content.res.ColorStateList;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.widget.Toolbar;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentTransaction;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.CaptureService;
import com.kotsafe.security.ConnectionsRegister;
import com.kotsafe.security.Log;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.fragments.EditListFragment;
import com.kotsafe.security.fragments.FirewallLogsFragment;
import com.kotsafe.security.fragments.FirewallStatus;
import com.kotsafe.security.model.FirewallLogDbHelper;
import com.kotsafe.security.model.ListInfo;
import com.kotsafe.security.model.Prefs;
import com.google.android.material.bottomnavigation.BottomNavigationView;

public class FirewallActivity extends BaseActivity {
    private static final String TAG = "Firewall";
    private boolean mHasWhitelist = false;
    private SharedPreferences mPrefs;
    private BottomNavigationView mBottomNav;

    private final Handler mStatsHandler = new Handler(Looper.getMainLooper());
    private final Runnable mStatsRunnable = new Runnable() {
        @Override
        public void run() {
            updateHeaderStats();
            mStatsHandler.postDelayed(this, 1000);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setTitle(R.string.firewall);
        setContentView(R.layout.activity_firewall);

        // New branded header: wire back button manually
        findViewById(R.id.fw_btn_back).setOnClickListener(v -> onBackPressed());

        // Tapping the data flow card opens logs
        View flowBar = findViewById(R.id.firewall_data_flow_bar);
        if (flowBar != null) {
            flowBar.setOnClickListener(v -> showLogs("BLOCKED"));
        }

        // Keep hidden toolbar for AppCompat compat (no title shown)
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        if (getSupportActionBar() != null) getSupportActionBar().setDisplayShowTitleEnabled(false);

        mPrefs = PreferenceManager.getDefaultSharedPreferences(this);
        mBottomNav = findViewById(R.id.firewall_bottom_nav);

        // Show default fragment (Status) on first launch
        if (savedInstanceState == null) {
            showFragment(new FirewallStatus(), false);
        }

        mBottomNav.setOnItemSelectedListener(item -> {
            int id = item.getItemId();
            if (id == R.id.fw_nav_status) {
                showFragment(new FirewallStatus(), false);
                return true;
            } else if (id == R.id.fw_nav_logs) {
                showFragment(new FirewallLogsFragment(), false);
                return true;
            } else if (id == R.id.fw_nav_apps) {
                startActivity(new Intent(FirewallActivity.this, AppsActivity.class));
                return false;   // Don't check this item — we navigated away
            } else if (id == R.id.fw_nav_actions) {
                startActivity(new Intent(FirewallActivity.this, SecurityActionsActivity.class));
                return false;
            } else if (id == R.id.fw_nav_alerts) {
                startActivity(new Intent(FirewallActivity.this, AlertsCenterActivity.class));
                return false;
            } else if (id == R.id.fw_nav_attack) {
                startActivity(new Intent(FirewallActivity.this, MitreAttackActivity.class));
                return false;
            }
            return false;
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        mStatsHandler.post(mStatsRunnable);
        if (mBottomNav != null) {
            Fragment cur = getSupportFragmentManager().findFragmentById(R.id.firewall_fragment_container);
            if (cur instanceof FirewallLogsFragment) {
                mBottomNav.getMenu().findItem(R.id.fw_nav_logs).setChecked(true);
            } else {
                mBottomNav.getMenu().findItem(R.id.fw_nav_status).setChecked(true);
            }
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        mStatsHandler.removeCallbacks(mStatsRunnable);
    }

    private void updateHeaderStats() {
        boolean active = CaptureService.isServiceActive();
        boolean fwEnabled = Prefs.isFirewallEnabled(this, mPrefs);
        boolean isWhitelist = Prefs.isFirewallWhitelistMode(mPrefs);

        // Subtitle
        TextView subtitle = findViewById(R.id.fw_subtitle);
        if (subtitle != null) {
            if (isWhitelist) {
                subtitle.setText("ZERO-TRUST WHITELIST ACTIVE");
            } else {
                subtitle.setText("NETWORK PROTECTION ENGINE");
            }
        }

        // Status badge
        TextView statusText = findViewById(R.id.fw_status_text);
        View statusDot = findViewById(R.id.fw_status_dot);
        if (statusText != null && statusDot != null) {
            if (!active) {
                statusText.setText("OFFLINE");
                statusText.setTextColor(ContextCompat.getColor(this, R.color.ks_grey));
                statusDot.setBackgroundTintList(ColorStateList.valueOf(ContextCompat.getColor(this, R.color.ks_grey)));
            } else if (!fwEnabled) {
                statusText.setText("PAUSED");
                statusText.setTextColor(ContextCompat.getColor(this, R.color.ks_amber));
                statusDot.setBackgroundTintList(ColorStateList.valueOf(ContextCompat.getColor(this, R.color.ks_amber)));
            } else {
                statusText.setText("ACTIVE");
                statusText.setTextColor(ContextCompat.getColor(this, R.color.ks_accent));
                statusDot.setBackgroundTintList(ColorStateList.valueOf(ContextCompat.getColor(this, R.color.ok)));
            }
        }

        // Live flow numbers
        TextView inCount = findViewById(R.id.fw_flow_in_count);
        TextView outCount = findViewById(R.id.fw_flow_out_count);
        if (inCount != null && outCount != null) {
            int checkedConns = CaptureService.getNumCheckedFirewallConnections();
            ConnectionsRegister reg = CaptureService.getConnsRegister();
            int totalConns = (reg != null) ? reg.getConnCount() : 0;
            int incoming = Math.max(checkedConns, totalConns);

            int liveBlocked = (reg != null) ? reg.getNumBlockedConnections() : 0;
            int dbBlocked = 0;
            try {
                dbBlocked = FirewallLogDbHelper.getInstance(this).getBlockedCount();
            } catch (Exception ignored) {}
            int filtered = Math.max(liveBlocked, dbBlocked);

            inCount.setText(Utils.formatIntShort(incoming));
            outCount.setText(Utils.formatIntShort(filtered));
        }
    }

    /** Replace the fragment container with the given fragment. */
    private void showFragment(Fragment fragment, boolean addToBackStack) {
        FragmentTransaction tx = getSupportFragmentManager()
                .beginTransaction()
                .setCustomAnimations(
                        R.anim.slide_in_right, R.anim.slide_out_left,
                        R.anim.slide_in_left,  R.anim.slide_out_right)
                .replace(R.id.firewall_fragment_container, fragment);
        if (addToBackStack) tx.addToBackStack(null);
        tx.commit();
    }

    /** Navigates to the logs tab with a pre-selected filter (e.g. BLOCKED). */
    public void showLogs(String filterChip) {
        if (mBottomNav != null) {
            mBottomNav.setSelectedItemId(R.id.fw_nav_logs);
        }
        showFragment(FirewallLogsFragment.newInstance(filterChip), false);
    }

    /** Called by FirewallStatus to trigger whitelist-tab toggle. */
    @SuppressLint("NotifyDataSetChanged")
    public void recheckTabs() {
        boolean whitelist_mode = Prefs.isFirewallWhitelistMode(mPrefs);
        if (mHasWhitelist == whitelist_mode) return;
        mHasWhitelist = whitelist_mode;
        Log.d(TAG, "Whitelist mode changed → " + whitelist_mode);
    }
}
