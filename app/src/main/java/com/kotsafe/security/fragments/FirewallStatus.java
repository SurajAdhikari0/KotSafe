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

package com.kotsafe.security.fragments;

import android.graphics.Color;
import android.content.res.ColorStateList;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.Animation;
import android.view.animation.AnimationUtils;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.core.content.ContextCompat;
import androidx.core.view.MenuProvider;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.Lifecycle;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.CaptureService;
import com.kotsafe.security.ConnectionsRegister;
import com.kotsafe.security.Log;
import com.kotsafe.security.KotSafe;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.activities.ConnectionsActivity;
import com.kotsafe.security.activities.FirewallActivity;
import com.kotsafe.security.activities.MainActivity;
import com.kotsafe.security.activities.prefs.SettingsActivity;
import com.kotsafe.security.model.Blocklist;
import com.kotsafe.security.model.CaptureStats;
import com.kotsafe.security.model.ConnectionDescriptor;
import com.kotsafe.security.model.FilterDescriptor;
import com.kotsafe.security.model.MatchList;
import com.kotsafe.security.model.Prefs;
import com.kotsafe.security.model.SecurityRulesDb;
import com.kotsafe.security.model.VpnAlertHelper;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.switchmaterial.SwitchMaterial;

public class FirewallStatus extends Fragment implements MenuProvider {
    private static final String TAG = "FirewallStatus";
    private static boolean whitelistWarningAck = false;
    private Handler mHandler;
    private SharedPreferences mPrefs;
    private Menu mMenu;
    private ImageView mStatusIcon;
    private TextView mStatus;
    private TextView mStatusPostureLabel;
    private View mPostureDot;
    private TextView mNumBlocked;
    private TextView mNumChecked;
    private TextView mNumRules;
    private TextView mLastBlock;
    private TextView mModeTitle;
    private TextView mModeDesc;
    private ImageView mModeIcon;
    private SwitchMaterial mSwitchBlockNewApps;
    private Blocklist mBlocklist;
    private MatchList mWhitelist;
    private int mOkColor, mWarnColor, mGrayColor;

    // Shield animation and HUD views
    private View mPulseRing;
    private View mShieldMiddleRing;
    private View mShieldToggleBtn;
    private TextView mHeroThroughputValue;
    private TextView mHeroThroughputLabel;
    private Animation mPulseAnim;
    private long mLastTotalBytes = 0;
    private long mLastTimestampMs = 0;

    @Override
    public View onCreateView(LayoutInflater inflater,
                             ViewGroup container, Bundle savedInstanceState) {
        requireActivity().addMenuProvider(this, getViewLifecycleOwner(), Lifecycle.State.RESUMED);
        return inflater.inflate(R.layout.firewall_status, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        Context ctx = view.getContext();

        mPrefs = PreferenceManager.getDefaultSharedPreferences(ctx);
        mBlocklist = KotSafe.getInstance().getBlocklist();
        mWhitelist = KotSafe.getInstance().getFirewallWhitelist();
        mStatus = view.findViewById(R.id.status);
        mStatusPostureLabel = view.findViewById(R.id.status_posture_label);
        mPostureDot = view.findViewById(R.id.posture_dot);
        mHandler = new Handler(Looper.getMainLooper());
        mStatusIcon = view.findViewById(R.id.status_icon);
        mNumBlocked = view.findViewById(R.id.num_blocked);
        mNumChecked = view.findViewById(R.id.num_checked);
        mNumRules = view.findViewById(R.id.num_rules);
        mLastBlock = view.findViewById(R.id.last_block);
        mPulseRing = view.findViewById(R.id.shield_pulse_ring);
        mShieldMiddleRing = view.findViewById(R.id.shield_middle_ring);
        mShieldToggleBtn = view.findViewById(R.id.shield_toggle_btn);
        mHeroThroughputValue = view.findViewById(R.id.hero_throughput_value);
        mHeroThroughputLabel = view.findViewById(R.id.hero_throughput_label);

        mModeTitle = view.findViewById(R.id.mode_info_title);
        mModeDesc = view.findViewById(R.id.mode_info_desc);
        mModeIcon = view.findViewById(R.id.mode_info_icon);
        mSwitchBlockNewApps = view.findViewById(R.id.switch_block_new_apps);

        mOkColor = ContextCompat.getColor(ctx, R.color.ok);
        mWarnColor = ContextCompat.getColor(ctx, R.color.warning);
        mGrayColor = ContextCompat.getColor(ctx, R.color.lightGray);

        // Load pulse animation
        mPulseAnim = AnimationUtils.loadAnimation(ctx, R.anim.shield_pulse);

        // ── Tap-to-toggle shield circle ──
        View shieldBtn = view.findViewById(R.id.shield_toggle_btn);
        if (shieldBtn != null) {
            shieldBtn.setOnClickListener(v -> toggleFirewall());
        }

        // ── Mode Switch Actions ──
        MaterialButton btnSwitchMode = view.findViewById(R.id.btn_switch_mode);
        if (btnSwitchMode != null) {
            btnSwitchMode.setOnClickListener(v -> showWhitelistModeDialog());
        }
        View cardMode = view.findViewById(R.id.card_mode_info);
        if (cardMode != null) {
            cardMode.setOnClickListener(v -> showWhitelistModeDialog());
        }

        // ── Auto-Block New Apps Switch ──
        if (mSwitchBlockNewApps != null) {
            mSwitchBlockNewApps.setChecked(Prefs.blockNewApps(mPrefs));
            mSwitchBlockNewApps.setOnCheckedChangeListener((btn, isChecked) -> {
                mPrefs.edit().putBoolean(Prefs.PREF_BLOCK_NEW_APPS, isChecked).apply();
            });
        }
        View rowBlockNew = view.findViewById(R.id.row_block_new_apps);
        if (rowBlockNew != null && mSwitchBlockNewApps != null) {
            rowBlockNew.setOnClickListener(v -> mSwitchBlockNewApps.toggle());
        }

        // Show blocked connections on card tap
        View showConns = view.findViewById(R.id.show_connections);
        if (showConns != null) {
            showConns.setOnClickListener(v -> {
                if (getActivity() instanceof FirewallActivity) {
                    ((FirewallActivity) getActivity()).showLogs("BLOCKED");
                } else {
                    FilterDescriptor filter = new FilterDescriptor();
                    filter.filteringStatus = ConnectionDescriptor.FilteringStatus.BLOCKED;
                    filter.appCategory = FilterDescriptor.AppCategory.BLOCKED_ONLY;

                    Intent intent = new Intent(requireContext(), ConnectionsActivity.class)
                            .putExtra(ConnectionsFragment.FILTER_EXTRA, filter);
                    startActivity(intent);
                }
            });
        }
    }

    private void toggleFirewall() {
        if (Prefs.isRootCaptureEnabled(mPrefs)) {
            new AlertDialog.Builder(requireContext())
                    .setTitle("Firewall Unavailable in Root Mode")
                    .setIcon(R.drawable.ic_exclamation_triangle_solid)
                    .setMessage("Firewall packet blocking is strictly supported in VPN Mode.\n\nIn Root Capture Mode, KotSafe operates as a passive packet sniffer and cannot drop or block network traffic. Switch to VPN Mode in Settings to enforce firewall rules.")
                    .setPositiveButton(R.string.ok, (d, which) -> {})
                    .show();
            return;
        }

        boolean isEnabled = Prefs.isFirewallEnabled(requireContext(), mPrefs);
        if (isEnabled) {
            // Confirm with user before disabling protection
            new AlertDialog.Builder(requireContext())
                    .setTitle(R.string.disable_firewall_title)
                    .setIcon(R.drawable.ic_exclamation_triangle_solid)
                    .setMessage(R.string.disable_firewall_warning)
                    .setPositiveButton(R.string.disable_firewall_positive, (d, which) -> {
                        Log.d(TAG, "User confirmed disabling firewall");
                        CaptureService.setFirewallEnabled(false);
                        mPrefs.edit().putBoolean(Prefs.PREF_FIREWALL, false).apply();
                        updateStatus();
                    })
                    .setNegativeButton(R.string.keep_firewall_on, (d, which) -> {
                        Log.d(TAG, "User cancelled disabling firewall");
                    })
                    .show();
        } else {
            // Directly turn ON protection without friction
            Log.d(TAG, "Shield tap → Firewall is now enabled");
            CaptureService.setFirewallEnabled(true);
            mPrefs.edit().putBoolean(Prefs.PREF_FIREWALL, true).apply();
            updateStatus();
        }
    }

    private void showWhitelistModeDialog() {
        boolean currentWhitelist = Prefs.isFirewallWhitelistMode(mPrefs);
        boolean newMode = !currentWhitelist;
        if (newMode && !whitelistWarningAck) {
            AlertDialog dialog = new AlertDialog.Builder(requireContext())
                    .setTitle(R.string.whitelist_mode)
                    .setMessage(R.string.firewall_whitelist_notice)
                    .setPositiveButton(R.string.ok, (d, which) -> {
                        whitelistWarningAck = true;
                        mPrefs.edit().putBoolean(Prefs.PREF_FIREWALL_WHITELIST_MODE, true).apply();
                        reloadMode(true);
                    })
                    .setNegativeButton(R.string.cancel_action, (d, which) -> {})
                    .show();
            dialog.setCanceledOnTouchOutside(false);
        } else {
            mPrefs.edit().putBoolean(Prefs.PREF_FIREWALL_WHITELIST_MODE, newMode).apply();
            reloadMode(true);
        }
    }

    @Override
    public void onResume() {
        super.onResume();
        updateStatus();
    }

    @Override
    public void onPause() {
        super.onPause();
        mHandler.removeCallbacksAndMessages(null);
        if (mPulseRing != null) mPulseRing.clearAnimation();
    }

    @Override
    public void onCreateMenu(@NonNull Menu menu, MenuInflater inflater) {
        inflater.inflate(R.menu.firewall_menu, menu);
        mMenu = menu;

        MenuItem toggleItem = menu.findItem(R.id.toggle_btn);
        if (toggleItem != null) toggleItem.setVisible(false);

        menu.findItem(R.id.whitelist_mode).setChecked(Prefs.isFirewallWhitelistMode(mPrefs));
        menu.findItem(R.id.block_new_apps).setChecked(Prefs.blockNewApps(mPrefs));
        reloadMode(false);
    }

    @Override
    public boolean onMenuItemSelected(@NonNull MenuItem item) {
        int id = item.getItemId();

        if (id == R.id.action_settings) {
            Intent intent = new Intent(requireContext(), SettingsActivity.class);
            startActivity(intent);
            return true;
        } else if (id == R.id.user_guide) {
            Intent browserIntent = new Intent(Intent.ACTION_VIEW, Uri.parse(MainActivity.FIREWALL_DOCS_URL));
            Utils.startActivity(requireContext(), browserIntent);
            return true;
        } else if (id == R.id.block_new_apps) {
            boolean checked = !item.isChecked();
            item.setChecked(checked);
            mPrefs.edit().putBoolean(Prefs.PREF_BLOCK_NEW_APPS, checked).apply();
            if (mSwitchBlockNewApps != null) mSwitchBlockNewApps.setChecked(checked);
            return true;
        } else if (id == R.id.whitelist_mode) {
            showWhitelistModeDialog();
            return true;
        }

        return false;
    }

    private void reloadMode(boolean changed) {
        if (changed && CaptureService.isServiceActive())
            CaptureService.requireInstance().reloadFirewallWhitelist();

        ((FirewallActivity) requireActivity()).recheckTabs();
        updateStatus();
    }

    private void updateStatus() {
        if (!isAdded()) return;
        Context ctx = requireContext();
        ConnectionsRegister reg = CaptureService.getConnsRegister();
        boolean is_running = CaptureService.isServiceActive();
        boolean is_enabled = Prefs.isFirewallEnabled(ctx, mPrefs);
        boolean whitelist_mode = Prefs.isFirewallWhitelistMode(mPrefs);

        // Calculate live network throughput
        CaptureStats stats = CaptureService.getStats();
        long now = System.currentTimeMillis();
        long totalBytes = (stats != null) ? (stats.bytes_sent + stats.bytes_rcvd) : 0;
        long diffBytes = (mLastTotalBytes > 0 && totalBytes >= mLastTotalBytes) ? (totalBytes - mLastTotalBytes) : 0;
        long diffMs = (mLastTimestampMs > 0 && now > mLastTimestampMs) ? (now - mLastTimestampMs) : 1000;
        mLastTotalBytes = totalBytes;
        mLastTimestampMs = now;
        long bytesPerSec = (diffMs > 0) ? (diffBytes * 1000 / diffMs) : 0;

        // Update shield icon + posture label + pulse animation + throughput HUD
        if (Prefs.isRootCaptureEnabled(mPrefs)) {
            mStatusIcon.setImageResource(R.drawable.ic_exclamation_triangle_solid);
            mStatusIcon.setColorFilter(mWarnColor);
            mStatus.setText("Firewall Unavailable in Root Mode");
            if (mStatusPostureLabel != null) {
                mStatusPostureLabel.setText("PASSIVE SNIFFER ONLY (ROOT)");
                mStatusPostureLabel.setTextColor(mWarnColor);
            }
            if (mPostureDot != null) mPostureDot.setBackgroundTintList(ColorStateList.valueOf(mWarnColor));
            if (mShieldToggleBtn != null) mShieldToggleBtn.setBackgroundResource(R.drawable.firewall_shield_warning_bg);
            if (mHeroThroughputValue != null) {
                mHeroThroughputValue.setText("ROOT ONLY");
                mHeroThroughputValue.setTextColor(mWarnColor);
            }
            if (mHeroThroughputLabel != null) mHeroThroughputLabel.setText("FILTERING OFF");
            if (mPulseRing != null) mPulseRing.clearAnimation();
        } else if (CaptureService.isDNSEncrypted() && is_running) {
            mStatusIcon.setImageResource(R.drawable.ic_exclamation_triangle_solid);
            mStatusIcon.setColorFilter(mWarnColor);
            mStatus.setText(R.string.private_dns_hinders_detection);
            if (mStatusPostureLabel != null) {
                mStatusPostureLabel.setText("PRIVATE DNS ACTIVE");
                mStatusPostureLabel.setTextColor(mWarnColor);
            }
            if (mPostureDot != null) mPostureDot.setBackgroundTintList(ColorStateList.valueOf(mWarnColor));
            if (mShieldToggleBtn != null) mShieldToggleBtn.setBackgroundResource(R.drawable.firewall_shield_warning_bg);
            if (mHeroThroughputValue != null) {
                mHeroThroughputValue.setText("DNS RISK");
                mHeroThroughputValue.setTextColor(mWarnColor);
            }
            if (mHeroThroughputLabel != null) mHeroThroughputLabel.setText("BYPASS ACTIVE");
            if (mPulseRing != null) mPulseRing.clearAnimation();
        } else if (is_enabled) {
            mStatusIcon.setImageResource(R.drawable.ic_shield);
            mStatusIcon.setColorFilter(Color.parseColor("#00E5FF"));
            mStatus.setText(R.string.firewall_is_enabled);
            if (mStatusPostureLabel != null) {
                mStatusPostureLabel.setText(is_running ? "ACTIVE ENFORCEMENT" : "ARMED & READY");
                mStatusPostureLabel.setTextColor(mOkColor);
            }
            if (mPostureDot != null) mPostureDot.setBackgroundTintList(ColorStateList.valueOf(mOkColor));
            if (mShieldToggleBtn != null) mShieldToggleBtn.setBackgroundResource(R.drawable.firewall_shield_circle_bg);

            if (mHeroThroughputValue != null) {
                if (is_running && bytesPerSec > 0) {
                    mHeroThroughputValue.setText(Utils.formatBytes(bytesPerSec) + "/s");
                    mHeroThroughputValue.setTextColor(Color.parseColor("#00E5FF"));
                } else if (is_running) {
                    mHeroThroughputValue.setText("PROTECTED");
                    mHeroThroughputValue.setTextColor(Color.parseColor("#10B981"));
                } else {
                    mHeroThroughputValue.setText("ARMED");
                    mHeroThroughputValue.setTextColor(Color.parseColor("#00E5FF"));
                }
            }
            if (mHeroThroughputLabel != null) {
                mHeroThroughputLabel.setText(is_running ? "LIVE THROUGHPUT" : "READY TO ARM");
            }
            // Start pulse animation when enabled
            if (mPulseRing != null && mPulseRing.getAnimation() == null) {
                mPulseRing.startAnimation(mPulseAnim);
            }
        } else {
            mStatusIcon.setImageResource(R.drawable.ic_shield);
            mStatusIcon.setColorFilter(mGrayColor);
            mStatus.setText(R.string.firewall_is_disabled);
            if (mStatusPostureLabel != null) {
                mStatusPostureLabel.setText("FIREWALL DISABLED");
                mStatusPostureLabel.setTextColor(mGrayColor);
            }
            if (mPostureDot != null) mPostureDot.setBackgroundTintList(ColorStateList.valueOf(mGrayColor));
            if (mShieldToggleBtn != null) mShieldToggleBtn.setBackgroundResource(R.drawable.firewall_shield_disabled_bg);
            if (mHeroThroughputValue != null) {
                mHeroThroughputValue.setText("OFFLINE");
                mHeroThroughputValue.setTextColor(mGrayColor);
            }
            if (mHeroThroughputLabel != null) mHeroThroughputLabel.setText("TAP TO ARM");
            if (mPulseRing != null) mPulseRing.clearAnimation();
        }

        // Update mode card
        if (mModeTitle != null && mModeDesc != null) {
            if (whitelist_mode) {
                mModeTitle.setText("Mode: Zero-Trust Whitelist");
                mModeDesc.setText("Blocks all connections except explicitly allowed apps");
                if (mModeIcon != null) mModeIcon.setColorFilter(ContextCompat.getColor(ctx, R.color.colorSecondary));
            } else {
                mModeTitle.setText("Mode: Dynamic Threat Blocklist");
                mModeDesc.setText("Blocks malware IOCs, threat feeds & custom rules");
                if (mModeIcon != null) mModeIcon.setColorFilter(ContextCompat.getColor(ctx, R.color.colorAccent));
            }
        }

        if (mSwitchBlockNewApps != null) {
            mSwitchBlockNewApps.setChecked(Prefs.blockNewApps(mPrefs));
        }

        int liveBlocked = (reg != null) ? reg.getNumBlockedConnections() : 0;
        int dbBlocked = 0;
        try {
            dbBlocked = com.kotsafe.security.model.FirewallLogDbHelper.getInstance(ctx).getBlockedCount();
        } catch (Exception ignored) {}
        mNumBlocked.setText(Utils.formatIntShort(Math.max(liveBlocked, dbBlocked)));
        mNumChecked.setText(Utils.formatIntShort(CaptureService.getNumCheckedFirewallConnections()));

        // LAST EVENT: show "Active" if capture is running and events have happened,
        // otherwise fall back to last block time, then "-" if nothing yet
        boolean capturing = CaptureService.isServiceActive();
        long lastBlock = (reg != null) ? reg.getLastFirewallBlock() : 0;
        long lastEvent = (reg != null) ? reg.getLastFirewallEvent() : 0;
        if (capturing && lastEvent > 0) {
            mLastBlock.setText("Active");
        } else if (lastBlock > 0) {
            mLastBlock.setText(Utils.formatEpochMin(ctx, lastBlock / 1000));
        } else if (capturing) {
            mLastBlock.setText("Active");
        } else {
            mLastBlock.setText("-");
        }

        // RULES: count live rules from SecurityRulesDb (actual firewall DB)
        int dbRules = 0;
        try {
            dbRules = SecurityRulesDb.getInstance(ctx).getRuleCount();
        } catch (Exception ignored) {}
        // Also count legacy blocklist entries as a supplement
        int legacyRules = mBlocklist.getSize() + (whitelist_mode ? mWhitelist.getSize() : 0);
        mNumRules.setText(Utils.formatIntShort(Math.max(dbRules, legacyRules)));

        // Periodic update
        mHandler.postDelayed(this::updateStatus, 1000);
    }
}
