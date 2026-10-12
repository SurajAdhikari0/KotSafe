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

package com.kotsafe.security.fragments;

import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.SwitchCompat;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.AppIconLoader;
import com.kotsafe.security.AppsResolver;
import com.kotsafe.security.CaptureService;
import com.kotsafe.security.ConnectionsRegister;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.AppDescriptor;
import com.kotsafe.security.model.AppNetworkRule;
import com.kotsafe.security.model.AppNetworkRulesManager;
import com.kotsafe.security.model.ConnectionDescriptor;
import com.kotsafe.security.model.Prefs;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;

public class NetworkAccessControlFragment extends Fragment {
    private static final String TAG = "NetworkAccessControl";
    private static final String ARG_UID = "uid";
    private static final String ARG_CONN_ID = "conn_id";

    private int mUid = Utils.UID_UNKNOWN;
    private int mConnId = -1;
    private String mPackageName = "";

    private SharedPreferences mPrefs;
    private AppNetworkRulesManager mRulesManager;
    private AppNetworkRule mRule;

    private ImageView mAppIcon;
    private TextView mAppName;
    private TextView mPackageNameView;

    private MaterialCardView mBannerCard;
    private ImageView mBannerIcon;
    private TextView mBannerTitle;
    private TextView mBannerText;
    private MaterialButton mBtnEnableFirewall;

    private SwitchCompat mSwitchWifi;
    private TextView mStatusWifi;
    private SwitchCompat mSwitchMobile;
    private TextView mStatusMobile;
    private SwitchCompat mSwitchRoaming;
    private TextView mStatusRoaming;
    private SwitchCompat mSwitchBackground;
    private TextView mStatusBackground;
    private SwitchCompat mSwitchLan;
    private TextView mStatusLan;

    private MaterialButton mBtnBlockAll;
    private MaterialButton mBtnAllowAll;
    private MaterialButton mBtnDataSaver;

    public static NetworkAccessControlFragment newInstance(int uid) {
        return newInstance(uid, -1);
    }

    public static NetworkAccessControlFragment newInstance(int uid, int connId) {
        NetworkAccessControlFragment fragment = new NetworkAccessControlFragment();
        Bundle args = new Bundle();
        args.putInt(ARG_UID, uid);
        args.putInt(ARG_CONN_ID, connId);
        fragment.setArguments(args);
        return fragment;
    }

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (getArguments() != null) {
            mUid = getArguments().getInt(ARG_UID, Utils.UID_UNKNOWN);
            mConnId = getArguments().getInt(ARG_CONN_ID, -1);
        }
        Context ctx = requireContext();
        mPrefs = PreferenceManager.getDefaultSharedPreferences(ctx);
        mRulesManager = AppNetworkRulesManager.getInstance(ctx);
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_network_access_control, container, false);

        mAppIcon = view.findViewById(R.id.nac_app_icon);
        mAppName = view.findViewById(R.id.nac_app_name);
        mPackageNameView = view.findViewById(R.id.nac_package_name);

        mBannerCard = view.findViewById(R.id.nac_firewall_banner_card);
        mBannerIcon = view.findViewById(R.id.nac_banner_icon);
        mBannerTitle = view.findViewById(R.id.nac_banner_title);
        mBannerText = view.findViewById(R.id.nac_banner_text);
        mBtnEnableFirewall = view.findViewById(R.id.nac_btn_enable_firewall);

        mSwitchWifi = view.findViewById(R.id.nac_switch_wifi);
        mStatusWifi = view.findViewById(R.id.nac_status_wifi);
        mSwitchMobile = view.findViewById(R.id.nac_switch_mobile);
        mStatusMobile = view.findViewById(R.id.nac_status_mobile);
        mSwitchRoaming = view.findViewById(R.id.nac_switch_roaming);
        mStatusRoaming = view.findViewById(R.id.nac_status_roaming);
        mSwitchBackground = view.findViewById(R.id.nac_switch_background);
        mStatusBackground = view.findViewById(R.id.nac_status_background);
        mSwitchLan = view.findViewById(R.id.nac_switch_lan);
        mStatusLan = view.findViewById(R.id.nac_status_lan);

        mBtnBlockAll = view.findViewById(R.id.nac_btn_block_all);
        mBtnAllowAll = view.findViewById(R.id.nac_btn_allow_all);
        mBtnDataSaver = view.findViewById(R.id.nac_btn_data_saver);

        resolveAppInfo();
        setupListeners(view);

        return view;
    }

    @Override
    public void onResume() {
        super.onResume();
        loadRuleState();
        updateFirewallBanner();
    }

    private void resolveAppInfo() {
        Context ctx = requireContext();
        AppsResolver resolver = new AppsResolver(ctx);
        AppDescriptor app = null;

        if (mUid != Utils.UID_UNKNOWN) {
            app = resolver.getAppByUid(mUid, 0);
        }

        if (app == null && mConnId != -1) {
            ConnectionsRegister reg = CaptureService.getConnsRegister();
            if (reg != null) {
                ConnectionDescriptor conn = reg.getConnById(mConnId);
                if (conn != null) {
                    mUid = conn.uid;
                    app = resolver.getAppByUid(conn.uid, 0);
                }
            }
        }

        Drawable unknown = ContextCompat.getDrawable(ctx, R.drawable.ic_image);
        AppIconLoader.setIcon(mAppIcon, app, unknown);

        if (app != null) {
            mPackageName = app.getPackageName();
            mAppName.setText(app.getName());
            mPackageNameView.setText(String.format("%s (UID: %d)", app.getPackageName(), app.getUid()));
        } else if (mUid != Utils.UID_UNKNOWN) {
            mPackageName = "uid_" + mUid;
            mAppName.setText(getString(R.string.unknown_app));
            mPackageNameView.setText(String.format("UID: %d", mUid));
        } else {
            mPackageName = "unknown";
            mAppName.setText(getString(R.string.unknown_app));
            mPackageNameView.setText("");
        }

        loadRuleState();
    }

    private void loadRuleState() {
        if (mPackageName == null || mPackageName.isEmpty())
            return;

        mRule = mRulesManager.getRule(mPackageName, mUid);
        updateSwitches();
        updateLabels();
    }

    private boolean mIsUpdatingUi = false;

    private boolean isKotSafeApp() {
        if (mPackageName == null) return false;
        String lower = mPackageName.toLowerCase(java.util.Locale.US);
        Context ctx = getContext();
        String myPkg = (ctx != null) ? ctx.getPackageName().toLowerCase(java.util.Locale.US) : "com.kotsafe.security";
        return lower.equals(myPkg) || lower.contains("kotsafe") || mUid == android.os.Process.myUid();
    }

    private void updateSwitches() {
        if (mRule == null) return;
        mIsUpdatingUi = true;
        try {
            if (isKotSafeApp()) {
                mSwitchWifi.setChecked(true);
                mSwitchWifi.setEnabled(false);
                mSwitchMobile.setChecked(true);
                mSwitchMobile.setEnabled(false);
                mSwitchRoaming.setChecked(true);
                mSwitchRoaming.setEnabled(false);
                mSwitchBackground.setChecked(true);
                mSwitchBackground.setEnabled(false);
                mSwitchLan.setChecked(true);
                mSwitchLan.setEnabled(false);
                if (mBtnBlockAll != null) mBtnBlockAll.setEnabled(false);
                if (mBtnDataSaver != null) mBtnDataSaver.setEnabled(false);
                return;
            }
            // Note: checked = Allowed, unchecked = Blocked
            mSwitchWifi.setChecked(!mRule.isWifiBlocked());
            mSwitchMobile.setChecked(!mRule.isMobileBlocked());
            mSwitchRoaming.setChecked(!mRule.isRoamingBlocked());
            mSwitchBackground.setChecked(mRule.isAllowInBackground());
            mSwitchLan.setChecked(!mRule.isLanBlocked());
        } finally {
            mIsUpdatingUi = false;
        }
    }

    private void updateLabels() {
        if (mRule == null || getContext() == null) return;

        Context ctx = requireContext();
        int colorAllowed = ContextCompat.getColor(ctx, R.color.badgeActiveFg);
        int colorBlocked = ContextCompat.getColor(ctx, R.color.badgeBlockedFg);
        int bgAllowed = R.drawable.badge_pill_active;
        int bgBlocked = R.drawable.badge_pill_blocked;

        // Wi-Fi
        if (!mRule.isWifiBlocked()) {
            mStatusWifi.setText(R.string.nac_status_allowed);
            mStatusWifi.setTextColor(colorAllowed);
            mStatusWifi.setBackgroundResource(bgAllowed);
        } else {
            mStatusWifi.setText(R.string.nac_status_blocked);
            mStatusWifi.setTextColor(colorBlocked);
            mStatusWifi.setBackgroundResource(bgBlocked);
        }

        // Mobile Data
        if (!mRule.isMobileBlocked()) {
            mStatusMobile.setText(R.string.nac_status_allowed);
            mStatusMobile.setTextColor(colorAllowed);
            mStatusMobile.setBackgroundResource(bgAllowed);
        } else {
            mStatusMobile.setText(R.string.nac_status_blocked);
            mStatusMobile.setTextColor(colorBlocked);
            mStatusMobile.setBackgroundResource(bgBlocked);
        }

        // Roaming
        if (!mRule.isRoamingBlocked()) {
            mStatusRoaming.setText(R.string.nac_status_allowed);
            mStatusRoaming.setTextColor(colorAllowed);
            mStatusRoaming.setBackgroundResource(bgAllowed);
        } else {
            mStatusRoaming.setText(R.string.nac_status_blocked);
            mStatusRoaming.setTextColor(colorBlocked);
            mStatusRoaming.setBackgroundResource(bgBlocked);
        }

        // Background
        if (mRule.isAllowInBackground()) {
            mStatusBackground.setText(R.string.nac_status_allowed);
            mStatusBackground.setTextColor(colorAllowed);
            mStatusBackground.setBackgroundResource(bgAllowed);
        } else {
            mStatusBackground.setText(R.string.nac_status_blocked);
            mStatusBackground.setTextColor(colorBlocked);
            mStatusBackground.setBackgroundResource(bgBlocked);
        }

        // LAN
        if (!mRule.isLanBlocked()) {
            mStatusLan.setText(R.string.nac_status_allowed);
            mStatusLan.setTextColor(colorAllowed);
            mStatusLan.setBackgroundResource(bgAllowed);
        } else {
            mStatusLan.setText(R.string.nac_status_blocked);
            mStatusLan.setTextColor(colorBlocked);
            mStatusLan.setBackgroundResource(bgBlocked);
        }
    }

    private void updateFirewallBanner() {
        Context ctx = getContext();
        if (ctx == null) return;

        boolean isRunning = CaptureService.isServiceActive();
        boolean isFwOn = Prefs.isFirewallEnabled(ctx, mPrefs);

        if (!isRunning) {
            mBannerTitle.setText("VPN Inactive — Firewall Offline");
            mBannerText.setText("Firewall rules are saved, but network traffic cannot be filtered until VPN Capture is running.");
            mBannerIcon.setImageResource(R.drawable.ic_shield);
            mBannerIcon.setColorFilter(ContextCompat.getColor(ctx, R.color.warning));
            if (mBannerCard != null) {
                mBannerCard.setStrokeColor(ContextCompat.getColor(ctx, R.color.warning));
            }
            mBtnEnableFirewall.setVisibility(View.VISIBLE);
            mBtnEnableFirewall.setText("Turn On VPN");
        } else if (isFwOn) {
            mBannerTitle.setText(R.string.nac_firewall_active);
            mBannerText.setText("Granular network rules are actively enforced by KotSafe.");
            mBannerIcon.setImageResource(R.drawable.ic_shield);
            mBannerIcon.setColorFilter(ContextCompat.getColor(ctx, R.color.ok));
            if (mBannerCard != null) {
                mBannerCard.setStrokeColor(ContextCompat.getColor(ctx, R.color.ok));
            }
            mBtnEnableFirewall.setVisibility(View.GONE);
        } else {
            mBannerTitle.setText("Firewall is Disabled");
            mBannerText.setText(R.string.nac_firewall_off_warning);
            mBannerIcon.setImageResource(R.drawable.ic_shield);
            mBannerIcon.setColorFilter(ContextCompat.getColor(ctx, R.color.warning));
            if (mBannerCard != null) {
                mBannerCard.setStrokeColor(ContextCompat.getColor(ctx, R.color.warning));
            }
            mBtnEnableFirewall.setVisibility(View.VISIBLE);
            mBtnEnableFirewall.setText(R.string.nac_enable_firewall);
        }
    }

    private void setupListeners(View view) {
        mBtnEnableFirewall.setOnClickListener(v -> {
            if (!CaptureService.isServiceActive()) {
                com.kotsafe.security.model.VpnAlertHelper.showVpnRequiredDialog(
                        requireContext(),
                        "Firewall Enforcement",
                        "The firewall requires the VPN Capture service to intercept and block network packets."
                );
            } else {
                mPrefs.edit().putBoolean(Prefs.PREF_FIREWALL, true).apply();
                CaptureService.setFirewallEnabled(true);
                updateFirewallBanner();
                Toast.makeText(requireContext(), "Firewall Enabled", Toast.LENGTH_SHORT).show();
            }
        });

        View rowWifi = view.findViewById(R.id.row_wifi);
        if (rowWifi != null) rowWifi.setOnClickListener(v -> mSwitchWifi.toggle());

        View rowMobile = view.findViewById(R.id.row_mobile);
        if (rowMobile != null) rowMobile.setOnClickListener(v -> mSwitchMobile.toggle());

        View rowRoaming = view.findViewById(R.id.row_roaming);
        if (rowRoaming != null) rowRoaming.setOnClickListener(v -> mSwitchRoaming.toggle());

        View rowBackground = view.findViewById(R.id.row_background);
        if (rowBackground != null) rowBackground.setOnClickListener(v -> mSwitchBackground.toggle());

        View rowLan = view.findViewById(R.id.row_lan);
        if (rowLan != null) rowLan.setOnClickListener(v -> mSwitchLan.toggle());

        mSwitchWifi.setOnCheckedChangeListener((buttonView, isChecked) -> {
            if (mRule != null && !mIsUpdatingUi) {
                mRule.setWifiBlocked(!isChecked);
                saveCurrentRule();
                updateLabels();
            }
        });

        mSwitchMobile.setOnCheckedChangeListener((buttonView, isChecked) -> {
            if (mRule != null && !mIsUpdatingUi) {
                mRule.setMobileBlocked(!isChecked);
                saveCurrentRule();
                updateLabels();
            }
        });

        mSwitchRoaming.setOnCheckedChangeListener((buttonView, isChecked) -> {
            if (mRule != null && !mIsUpdatingUi) {
                mRule.setRoamingBlocked(!isChecked);
                saveCurrentRule();
                updateLabels();
            }
        });

        mSwitchBackground.setOnCheckedChangeListener((buttonView, isChecked) -> {
            if (mRule != null && !mIsUpdatingUi) {
                mRule.setAllowInBackground(isChecked);
                saveCurrentRule();
                updateLabels();
            }
        });

        mSwitchLan.setOnCheckedChangeListener((buttonView, isChecked) -> {
            if (mRule != null && !mIsUpdatingUi) {
                mRule.setLanBlocked(!isChecked);
                saveCurrentRule();
                updateLabels();
            }
        });

        mBtnBlockAll.setOnClickListener(v -> {
            if (mRule != null) {
                mRule.blockAll();
                saveCurrentRule();
                updateSwitches();
                updateLabels();
            }
        });

        mBtnAllowAll.setOnClickListener(v -> {
            if (mRule != null) {
                mRule.allowAll();
                saveCurrentRule();
                updateSwitches();
                updateLabels();
            }
        });

        if (mBtnDataSaver != null) {
            mBtnDataSaver.setOnClickListener(v -> {
                if (mRule != null) {
                    mRule.setWifiBlocked(false);
                    mRule.setMobileBlocked(true);
                    mRule.setRoamingBlocked(true);
                    mRule.setAllowInBackground(true);
                    mRule.setLanBlocked(false);
                    saveCurrentRule();
                    updateSwitches();
                    updateLabels();
                    Toast.makeText(requireContext(), "Data Saver Applied (Cellular & Roaming blocked)", Toast.LENGTH_SHORT).show();
                }
            });
        }
    }

    private void saveCurrentRule() {
        if (isKotSafeApp()) {
            Context ctx = getContext();
            if (ctx != null) {
                Toast.makeText(ctx, "Protected: KotSafe core network access cannot be restricted.", Toast.LENGTH_SHORT).show();
            }
            return;
        }
        if (mRule != null) {
            mRulesManager.setRule(mRule);
            if (!CaptureService.isServiceActive()) {
                Context ctx = getContext();
                if (ctx != null) {
                    Toast.makeText(ctx, "Rule saved. (VPN is off — turn on VPN in Home screen to enforce)", Toast.LENGTH_SHORT).show();
                }
            }
        }
    }
}
