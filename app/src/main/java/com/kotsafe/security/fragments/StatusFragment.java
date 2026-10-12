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

import android.animation.Animator;
import android.animation.Keyframe;
import android.animation.ObjectAnimator;
import android.animation.PropertyValuesHolder;
import android.animation.ValueAnimator;
import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Bundle;
import android.text.method.LinkMovementMethod;
import android.util.Pair;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.ScrollView;
import android.widget.TextView;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.OvershootInterpolator;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.SwitchCompat;
import androidx.core.content.ContextCompat;
import androidx.core.graphics.Insets;
import androidx.core.view.MenuProvider;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.Lifecycle;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.dialogs.DnsBenchmarkDialog;
import com.kotsafe.security.model.DefenderManager;
import com.kotsafe.security.model.DnsProvider;
import com.kotsafe.security.views.AnimUtils;
import android.graphics.Color;
import com.kotsafe.security.p2p.GatewayPreferenceKeys;
import com.kotsafe.security.p2p.GatewayProfile;
import com.kotsafe.security.p2p.GatewayProfileManager;
import com.kotsafe.security.p2p.GatewayTelemetry;
import com.kotsafe.security.model.P2PExitNodeServer;

import com.kotsafe.security.AppsResolver;
import com.kotsafe.security.Log;
import com.kotsafe.security.MitmReceiver;
import com.kotsafe.security.activities.AntivirusScanActivity;
import com.kotsafe.security.activities.AppFilterActivity;
import com.kotsafe.security.activities.AppsActivity;
import com.kotsafe.security.activities.CaptureListActivity;
import com.kotsafe.security.activities.FirewallActivity;
import com.kotsafe.security.activities.HttpRepeaterActivity;
import com.kotsafe.security.activities.PhysicalSecurityActivity;
import com.kotsafe.security.activities.SecurityActionsActivity;
import com.kotsafe.security.activities.StorageManagementActivity;
import com.kotsafe.security.activities.prefs.SettingsActivity;
import com.kotsafe.security.model.AppDescriptor;
import com.kotsafe.security.model.AppState;
import com.kotsafe.security.CaptureService;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.activities.MainActivity;
import com.kotsafe.security.interfaces.AppStateListener;
import com.kotsafe.security.model.CaptureList;
import com.kotsafe.security.model.Prefs;
import com.kotsafe.security.model.CaptureStats;
import com.kotsafe.security.views.PrefSpinner;

import com.kotsafe.security.ui.ShieldHeroView;
import androidx.appcompat.widget.AppCompatSpinner;
import android.widget.Toast;
import com.kotsafe.security.MitmAddon;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public class StatusFragment extends Fragment implements AppStateListener, MenuProvider, SharedPreferences.OnSharedPreferenceChangeListener {
    private static final String TAG = "StatusFragment";
    private Menu mMenu;
    private MenuItem mStartBtn;
    private MenuItem mStopBtn;
    private MenuItem mMenuSettings;
    private TextView mInterfaceInfo;
    private View mCollectorInfoLayout;
    private TextView mCollectorInfoText;
    private ImageView mCollectorInfoIcon;
    private TextView mCaptureStatus;
    private ShieldHeroView mShieldHero;
    private TextView mBtnStartPill;
    private View mQuickSettings;
    private MainActivity mActivity;
    private SharedPreferences mPrefs;
    private Set<String> mAppFilter;
    private boolean mAppFilterEnabled;
    private View mFilterRootDecryptionWarning;
    private View mLastCaptureSection;
    private View mLastCapture;

    // Capture Configuration Controls
    private View mRowTargetApps;
    private ImageView mIvTargetAppsIcon;
    private TextView mTvTargetAppsBadge;
    private TextView mTvTargetAppsDesc;
    private SwitchCompat mAppFilterSwitch;

    private View mRowTrafficDump;
    private AppCompatSpinner mDumpModeSpinner;
    private ImageView mIvDumpModeIcon;
    private TextView mTvDumpModeBadge;
    private TextView mTvDumpModeDesc;

    private View mRowTlsDecryption;
    private ImageView mIvTlsIcon;
    private TextView mTvTlsBadge;
    private TextView mTvTlsDesc;
    private SwitchCompat mTlsDecryptionSwitch;

    private View mRowPayloadMode;
    private ImageView mIvPayloadIcon;
    private TextView mTvPayloadBadge;
    private TextView mTvPayloadDesc;
    private SwitchCompat mPayloadModeSwitch;

    private View mBtnCaptureMoreSettings;

    private View mPulseRing1;
    private View mPulseRing2;
    private final List<Animator> mPulseAnimators = new ArrayList<>();
    private ObjectAnimator mBreathingAnimator;
    private ObjectAnimator mSubtitleGlowAnimator;
    private TextView mStatusSubtitle;
    private View mLiveTelemetrySection;
    private TextView mTelemetryRxBytes;
    private TextView mTelemetryRxPkts;
    private TextView mTelemetryTxBytes;
    private TextView mTelemetryTxPkts;
    private TextView mTelemetryActiveConns;
    private TextView mTelemetryDnsQueries;
    private TextView mTelemetryTotConns;
    private TextView mTelemetryDropped;
    private View mQuickWorkbenchesSection;
    private TextView mPostureFwText;
    private TextView mPostureAvText;
    private TextView mPostureAiText;
    private View mCardBtnOneTapHarden;
    private ImageView mIvHardenShield;
    private TextView mTvHardenStatus;

    // Personal Gateway / P2P Exit Node Card Views
    private View mCardPersonalGateway;
    private TextView mGatewayCardHeader;
    private TextView mGatewayCardNodeName;
    private TextView mGatewayCardBadge;
    private View mGatewayCardIpRow;
    private TextView mGatewayCardIpValue;
    private TextView mGatewayCardTransportLabel;
    private View mGatewayCardTelemetryRow;
    private TextView mGatewayCardPing;
    private TextView mGatewayCardBattery;
    private TextView mGatewayCardNetwork;
    private TextView mGatewayCardStatusMsg;
    private View mGatewayCardAlertBanner;
    private TextView mGatewayBtnWait;
    private TextView mGatewayBtnDisconnect;

    private final GatewayTelemetry.Listener mGatewayTelemetryListener = telemetry -> {
        if (isAdded() && getActivity() != null) {
            requireActivity().runOnUiThread(this::updateGatewayCardUI);
        }
    };

    @Override
    public void onAttach(@NonNull Context context) {
        super.onAttach(context);
        mActivity = (MainActivity) context;
    }

    @Override
    public void onDetach() {
        super.onDetach();
        mActivity.setAppStateListener(null);
        mActivity = null;
    }

    @Override
    public void onResume() {
        super.onResume();

        CaptureService.checkAlwaysOnVpnActivated();
        if (mPrefs != null) {
            mPrefs.registerOnSharedPreferenceChangeListener(this);
            mAppFilter = Prefs.getAppFilterRaw(mPrefs);
            mAppFilterEnabled = Prefs.isAppFilterEnabled(mPrefs);
        }
        refreshCaptureConfiguration();
        refreshStatus();
        updateGatewayCardUI();
        GatewayTelemetry.getInstance().addListener(mGatewayTelemetryListener);
        if(mActivity != null && mActivity.getState() == AppState.ready)
            startReadyAnimation();

        if (mStatusSubtitle != null) {
            if (mSubtitleGlowAnimator != null) mSubtitleGlowAnimator.cancel();
            mSubtitleGlowAnimator = AnimUtils.startBreathingGlow(mStatusSubtitle, 0.72f, 1.0f, 1300);
        }
    }

    @Override
    public void onPause() {
        super.onPause();
        GatewayTelemetry.getInstance().removeListener(mGatewayTelemetryListener);
        if (mPrefs != null) {
            mPrefs.unregisterOnSharedPreferenceChangeListener(this);
        }
        stopReadyAnimation(false);
        if (mSubtitleGlowAnimator != null) {
            mSubtitleGlowAnimator.cancel();
            mSubtitleGlowAnimator = null;
        }
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        stopReadyAnimation(false);
        if (mSubtitleGlowAnimator != null) {
            mSubtitleGlowAnimator.cancel();
            mSubtitleGlowAnimator = null;
        }
        mPulseRing1 = null;
        mPulseRing2 = null;
    }

    @Override
    public View onCreateView(LayoutInflater inflater,
                             ViewGroup container, Bundle savedInstanceState) {
        requireActivity().addMenuProvider(this, getViewLifecycleOwner(), Lifecycle.State.RESUMED);
        return inflater.inflate(R.layout.status, container, false);
    }

    @SuppressLint("ClickableViewAccessibility")
    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        ViewCompat.setOnApplyWindowInsetsListener(view, (v, windowInsets) -> {
            Insets insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars() |
                    WindowInsetsCompat.Type.displayCutout());
            v.setPadding(insets.left, 0, insets.right, insets.bottom);
            return windowInsets;
        });
        ((ScrollView) view).setClipToPadding(false);
        view.post(() -> ((ScrollView) view).scrollTo(0, 0));

        mInterfaceInfo = view.findViewById(R.id.interface_info);
        mCollectorInfoLayout = view.findViewById(R.id.collector_info_layout);
        mCollectorInfoText = mCollectorInfoLayout.findViewById(R.id.collector_info_text);
        mCollectorInfoIcon = mCollectorInfoLayout.findViewById(R.id.collector_info_icon);
        mPulseRing1 = view.findViewById(R.id.pulse_ring_1);
        mPulseRing2 = view.findViewById(R.id.pulse_ring_2);
        mCaptureStatus = view.findViewById(R.id.status_view);
        mShieldHero = view.findViewById(R.id.shield_hero);
        mBtnStartPill = view.findViewById(R.id.btn_start_pill);
        mStatusSubtitle = view.findViewById(R.id.status_subtitle);
        mCardBtnOneTapHarden = view.findViewById(R.id.card_btn_one_tap_harden);
        mIvHardenShield = view.findViewById(R.id.iv_harden_shield);
        mTvHardenStatus = view.findViewById(R.id.tv_harden_status);
        if (mCardBtnOneTapHarden != null) {
            AnimUtils.attachSpringTouch(mCardBtnOneTapHarden);
            View.OnClickListener hardenListener = v -> performOneTapHardening();
            mCardBtnOneTapHarden.setOnClickListener(hardenListener);
            if (mTvHardenStatus != null) mTvHardenStatus.setOnClickListener(hardenListener);
            if (mIvHardenShield != null) mIvHardenShield.setOnClickListener(hardenListener);
        }
        mLiveTelemetrySection = view.findViewById(R.id.live_telemetry_section);
        mTelemetryRxBytes = view.findViewById(R.id.telemetry_rx_bytes);
        mTelemetryRxPkts = view.findViewById(R.id.telemetry_rx_pkts);
        mTelemetryTxBytes = view.findViewById(R.id.telemetry_tx_bytes);
        mTelemetryTxPkts = view.findViewById(R.id.telemetry_tx_pkts);
        mTelemetryActiveConns = view.findViewById(R.id.telemetry_active_conns);
        mTelemetryDnsQueries = view.findViewById(R.id.telemetry_dns_queries);
        mTelemetryTotConns = view.findViewById(R.id.telemetry_tot_conns);
        mTelemetryDropped = view.findViewById(R.id.telemetry_dropped);
        mQuickSettings = view.findViewById(R.id.quick_settings);
        mFilterRootDecryptionWarning = view.findViewById(R.id.app_filter_root_decryption_warning);
        mPrefs = PreferenceManager.getDefaultSharedPreferences(mActivity);
        mAppFilter = Prefs.getAppFilterRaw(mPrefs);
        mAppFilterEnabled = Prefs.isAppFilterEnabled(mPrefs);

        // Bind Capture Configuration Views
        mRowTargetApps = view.findViewById(R.id.row_target_apps);
        mIvTargetAppsIcon = view.findViewById(R.id.iv_target_apps_icon);
        mTvTargetAppsBadge = view.findViewById(R.id.tv_target_apps_badge);
        mTvTargetAppsDesc = view.findViewById(R.id.tv_target_apps_desc);
        mAppFilterSwitch = view.findViewById(R.id.app_filter_switch);

        mRowTrafficDump = view.findViewById(R.id.row_traffic_dump);
        mDumpModeSpinner = view.findViewById(R.id.dump_mode_spinner);
        mIvDumpModeIcon = view.findViewById(R.id.iv_dump_mode_icon);
        mTvDumpModeBadge = view.findViewById(R.id.tv_dump_mode_badge);
        mTvDumpModeDesc = view.findViewById(R.id.tv_dump_mode_desc);

        mRowTlsDecryption = view.findViewById(R.id.row_tls_decryption);
        mIvTlsIcon = view.findViewById(R.id.iv_tls_icon);
        mTvTlsBadge = view.findViewById(R.id.tv_tls_badge);
        mTvTlsDesc = view.findViewById(R.id.tv_tls_desc);
        mTlsDecryptionSwitch = view.findViewById(R.id.tls_decryption_switch);

        mRowPayloadMode = view.findViewById(R.id.row_payload_mode);
        mIvPayloadIcon = view.findViewById(R.id.iv_payload_icon);
        mTvPayloadBadge = view.findViewById(R.id.tv_payload_badge);
        mTvPayloadDesc = view.findViewById(R.id.tv_payload_desc);
        mPayloadModeSwitch = view.findViewById(R.id.payload_mode_switch);

        mBtnCaptureMoreSettings = view.findViewById(R.id.btn_capture_more_settings);

        if (mDumpModeSpinner != null) {
            PrefSpinner.init(mDumpModeSpinner,
                    R.array.pcap_dump_modes, R.array.pcap_dump_modes_labels, R.array.pcap_dump_modes_descriptions,
                    Prefs.PREF_PCAP_DUMP_MODE, Prefs.DEFAULT_DUMP_MODE);
        }

        mLastCaptureSection = view.findViewById(R.id.last_capture_section);
        mLastCapture = view.findViewById(R.id.last_capture);
        if (mLastCapture != null) {
            mLastCapture.setBackgroundResource(R.drawable.rounded_border);
        }

        View viewAllBtn = view.findViewById(R.id.view_all_btn);
        if (viewAllBtn != null) {
            viewAllBtn.setOnClickListener(v ->
                    startActivity(new Intent(requireContext(), CaptureListActivity.class)));
        }

        setupCaptureConfigurationListeners();
        refreshCaptureConfiguration();

        if (mCaptureStatus != null) mCaptureStatus.setOnClickListener(v -> onStatusViewClicked());
        if (mShieldHero != null) mShieldHero.setOnClickListener(v -> onStatusViewClicked());
        if (mBtnStartPill != null) mBtnStartPill.setOnClickListener(v -> onStatusViewClicked());
        View sub = view.findViewById(R.id.status_subtitle);
        if (sub != null) sub.setOnClickListener(v -> onStatusViewClicked());

        View actApps = view.findViewById(R.id.status_action_apps);
        if (actApps != null) actApps.setOnClickListener(v -> startActivity(new Intent(requireContext(), AppsActivity.class)));

        View actHttp = view.findViewById(R.id.status_action_http);
        if (actHttp != null) actHttp.setOnClickListener(v -> {
            View switchBtn = requireActivity().findViewById(R.id.tab_switch_button);
            if (switchBtn != null) switchBtn.performClick();
        });

        View actGate = view.findViewById(R.id.status_action_gate);
        if (actGate != null) actGate.setOnClickListener(v -> startActivity(new Intent(requireContext(), PhysicalSecurityActivity.class)));

        View actDumps = view.findViewById(R.id.status_action_dumps);
        if (actDumps != null) actDumps.setOnClickListener(v -> startActivity(new Intent(requireContext(), CaptureListActivity.class)));

        mQuickWorkbenchesSection = view.findViewById(R.id.quick_workbenches_section);
        mPostureFwText = view.findViewById(R.id.posture_fw_text);
        mPostureAvText = view.findViewById(R.id.posture_av_text);
        mPostureAiText = view.findViewById(R.id.posture_ai_text);

        View postureAi = view.findViewById(R.id.status_posture_ai);
        if (postureAi != null) postureAi.setOnClickListener(v -> startActivity(new Intent(requireContext(), com.kotsafe.security.activities.AiAssistantActivity.class)));

        View postureFw = view.findViewById(R.id.status_posture_firewall);
        if (postureFw != null) postureFw.setOnClickListener(v -> showFirewallToggleDialog());

        View postureAv = view.findViewById(R.id.status_posture_antivirus);
        if (postureAv != null) postureAv.setOnClickListener(v -> showAntivirusToggleDialog());

        View cardFw = view.findViewById(R.id.card_btn_firewall);
        if (cardFw != null) cardFw.setOnClickListener(v -> startActivity(new Intent(requireContext(), FirewallActivity.class)));

        View cardAv = view.findViewById(R.id.card_btn_antivirus);
        if (cardAv != null) cardAv.setOnClickListener(v -> startActivity(new Intent(requireContext(), AntivirusScanActivity.class)));

        View cardApps = view.findViewById(R.id.card_btn_apps);
        if (cardApps != null) cardApps.setOnClickListener(v -> startActivity(new Intent(requireContext(), AppsActivity.class)));

        View cardActions = view.findViewById(R.id.card_btn_actions);
        if (cardActions != null) cardActions.setOnClickListener(v -> startActivity(new Intent(requireContext(), SecurityActionsActivity.class)));

        View cardPhys = view.findViewById(R.id.card_btn_physical_sec);
        if (cardPhys != null) cardPhys.setOnClickListener(v -> startActivity(new Intent(requireContext(), PhysicalSecurityActivity.class)));

        View cardStorage = view.findViewById(R.id.card_btn_storage);
        if (cardStorage != null) cardStorage.setOnClickListener(v -> startActivity(new Intent(requireContext(), StorageManagementActivity.class)));

        View cardAi = view.findViewById(R.id.card_btn_ai_assistant);
        if (cardAi != null) cardAi.setOnClickListener(v -> startActivity(new Intent(requireContext(), com.kotsafe.security.activities.AiAssistantActivity.class)));

        View cardPrivacy = view.findViewById(R.id.card_btn_privacy_scorecard);
        if (cardPrivacy != null) cardPrivacy.setOnClickListener(v -> startActivity(new Intent(requireContext(), com.kotsafe.security.activities.PrivacyScorecardActivity.class)));

        View postureTi = view.findViewById(R.id.status_posture_threats);
        if (postureTi != null) postureTi.setOnClickListener(v -> showSocSentinelDialog());

        // Personal Gateway Card Binding
        mCardPersonalGateway = view.findViewById(R.id.card_personal_gateway);
        mGatewayCardHeader = view.findViewById(R.id.gateway_card_header);
        mGatewayCardNodeName = view.findViewById(R.id.gateway_card_node_name);
        mGatewayCardBadge = view.findViewById(R.id.gateway_card_badge);
        mGatewayCardIpRow = view.findViewById(R.id.gateway_card_ip_row);
        mGatewayCardIpValue = view.findViewById(R.id.gateway_card_ip_value);
        mGatewayCardTransportLabel = view.findViewById(R.id.gateway_card_transport_label);
        mGatewayCardTelemetryRow = view.findViewById(R.id.gateway_card_telemetry_row);
        mGatewayCardPing = view.findViewById(R.id.gateway_card_ping);
        mGatewayCardBattery = view.findViewById(R.id.gateway_card_battery);
        mGatewayCardNetwork = view.findViewById(R.id.gateway_card_network);
        mGatewayCardStatusMsg = view.findViewById(R.id.gateway_card_status_msg);
        mGatewayCardAlertBanner = view.findViewById(R.id.gateway_card_alert_banner);
        mGatewayBtnWait = view.findViewById(R.id.gateway_btn_wait);
        mGatewayBtnDisconnect = view.findViewById(R.id.gateway_btn_disconnect);

        if (mGatewayBtnWait != null) {
            AnimUtils.attachSpringTouch(mGatewayBtnWait);
            mGatewayBtnWait.setOnClickListener(v -> {
                GatewayTelemetry.getInstance().dismissInactiveWarning();
                if (mGatewayCardAlertBanner != null) {
                    mGatewayCardAlertBanner.setVisibility(View.GONE);
                }
                if (getContext() != null) {
                    Toast.makeText(getContext(), "Traffic remains shielded. Waiting for exit node...", Toast.LENGTH_SHORT).show();
                }
            });
        }

        if (mGatewayBtnDisconnect != null) {
            AnimUtils.attachSpringTouch(mGatewayBtnDisconnect);
            mGatewayBtnDisconnect.setOnClickListener(v -> {
                Context ctx = getContext();
                if (ctx != null) {
                    PreferenceManager.getDefaultSharedPreferences(ctx)
                            .edit()
                            .putBoolean(GatewayPreferenceKeys.CLIENT_ENABLED, false)
                            .putBoolean(Prefs.PREF_SOCKS5_ENABLED_KEY, false)
                            .apply();
                    if (CaptureService.isServiceActive()) {
                        CaptureService.updateSocks5Proxy(null, 0);
                    }
                    GatewayTelemetry.getInstance().setHostOnline(false);
                    Toast.makeText(ctx, "P2P Gateway disconnected. Direct internet restored.", Toast.LENGTH_SHORT).show();
                    updateGatewayCardUI();
                }
            });
        }

        if (mCardPersonalGateway != null) {
            AnimUtils.attachSpringTouch(mCardPersonalGateway);
            mCardPersonalGateway.setOnClickListener(v -> {
                Intent intent = new Intent(requireContext(), SettingsActivity.class);
                intent.putExtra(SettingsActivity.TARGET_PREF_EXTRA, "p2p_exit_node_settings");
                startActivity(intent);
            });
        }

        // Register for updates
        MitmReceiver.observeStatus(this, status -> refreshDecryptionStatus());
        CaptureService.observeStats(this, this::onStatsUpdate);

        // Make URLs clickable
        mCollectorInfoText.setMovementMethod(LinkMovementMethod.getInstance());

        // Attach tactile spring touch physics to dial, posture pills, and workbench cards
        if (mCaptureStatus != null) AnimUtils.attachSpringTouch(mCaptureStatus);
        if (mShieldHero != null) AnimUtils.attachSpringTouch(mShieldHero);
        if (mBtnStartPill != null) AnimUtils.attachSpringTouch(mBtnStartPill);
        AnimUtils.attachSpringTouch(sub);
        AnimUtils.attachSpringTouch(actApps);
        AnimUtils.attachSpringTouch(actHttp);
        AnimUtils.attachSpringTouch(actGate);
        AnimUtils.attachSpringTouch(actDumps);
        AnimUtils.attachSpringTouch(postureFw);
        AnimUtils.attachSpringTouch(postureAv);
        AnimUtils.attachSpringTouch(postureTi);
        AnimUtils.attachSpringTouch(postureAi);
        AnimUtils.attachSpringTouch(cardFw);
        AnimUtils.attachSpringTouch(cardAv);
        AnimUtils.attachSpringTouch(cardApps);
        AnimUtils.attachSpringTouch(cardActions);
        AnimUtils.attachSpringTouch(cardPhys);
        AnimUtils.attachSpringTouch(cardStorage);
        AnimUtils.attachSpringTouch(cardAi);

        // Run fluid cascading entrance animation on load
        View[] entranceViews = new View[] {
                postureFw, postureAv, postureTi, postureAi,
                mCardBtnOneTapHarden,
                actApps, actHttp, actGate, actDumps,
                mQuickWorkbenchesSection
        };
        view.post(() -> AnimUtils.playStaggeredEntrance(entranceViews, 60, 40));

        /* Important: call this after all the fields have been initialized */
        mActivity.setAppStateListener(this);
        refreshStatus();
    }

    @Override
    public void onCreateMenu(@NonNull Menu menu, MenuInflater menuInflater) {
        menuInflater.inflate(R.menu.main_menu, menu);

        mMenu = menu;
        mStartBtn = mMenu.findItem(R.id.action_start);
        mStopBtn = mMenu.findItem(R.id.action_stop);
        mMenuSettings = mMenu.findItem(R.id.action_settings);
        refreshStatus();
    }

    @Override
    public boolean onMenuItemSelected(@NonNull MenuItem item) {
        return false;
    }

    private boolean hasEffectiveFilter() {
        return mAppFilterEnabled && (mAppFilter != null) && (!mAppFilter.isEmpty());
    }

    private void recheckFilterWarning() {
        if (mFilterRootDecryptionWarning == null || mPrefs == null) return;
        boolean warn = Prefs.getTlsDecryptionEnabled(mPrefs) &&
                Prefs.isRootCaptureEnabled(mPrefs)
                && !hasEffectiveFilter();
        mFilterRootDecryptionWarning.setVisibility(warn ? View.VISIBLE : View.GONE);
    }

    private void refreshDecryptionStatus() {
        MitmReceiver.Status proxy_status = CaptureService.getMitmProxyStatus();
        Context ctx = getContext();

        if((proxy_status == MitmReceiver.Status.START_ERROR) && (ctx != null))
            Utils.showToastLong(ctx, R.string.mitm_addon_error);

        mInterfaceInfo.setText((proxy_status == MitmReceiver.Status.RUNNING) ? R.string.mitm_addon_running : R.string.mitm_addon_starting);
    }

    private void setupCaptureConfigurationListeners() {
        if (mRowTargetApps != null) {
            mRowTargetApps.setOnClickListener(v -> openAppFilterSelector());
        }
        if (mAppFilterSwitch != null) {
            mAppFilterSwitch.setOnClickListener(v -> onAppFilterSwitchClicked());
        }
        if (mRowTrafficDump != null) {
            mRowTrafficDump.setOnClickListener(v -> {
                if (mDumpModeSpinner != null) mDumpModeSpinner.performClick();
            });
        }
        if (mRowTlsDecryption != null) {
            mRowTlsDecryption.setOnClickListener(v -> {
                if (mTlsDecryptionSwitch != null) {
                    mTlsDecryptionSwitch.setChecked(!mTlsDecryptionSwitch.isChecked());
                    onTlsSwitchClicked();
                }
            });
        }
        if (mTlsDecryptionSwitch != null) {
            mTlsDecryptionSwitch.setOnClickListener(v -> onTlsSwitchClicked());
        }
        if (mRowPayloadMode != null) {
            mRowPayloadMode.setOnClickListener(v -> {
                if (mPayloadModeSwitch != null) {
                    mPayloadModeSwitch.setChecked(!mPayloadModeSwitch.isChecked());
                    onPayloadSwitchClicked();
                }
            });
        }
        if (mPayloadModeSwitch != null) {
            mPayloadModeSwitch.setOnClickListener(v -> onPayloadSwitchClicked());
        }
        if (mBtnCaptureMoreSettings != null) {
            mBtnCaptureMoreSettings.setOnClickListener(v ->
                    startActivity(new Intent(requireContext(), SettingsActivity.class)));
        }
    }

    private void onAppFilterSwitchClicked() {
        boolean hasApps = (mAppFilter != null) && (!mAppFilter.isEmpty());

        if (!hasApps) {
            if (mAppFilterSwitch != null) mAppFilterSwitch.setChecked(false);
            if (getContext() != null) Toast.makeText(requireContext(), "Select target apps to enable filter", Toast.LENGTH_SHORT).show();
            openAppFilterSelector();
            return;
        }

        mAppFilterEnabled = !mAppFilterEnabled;
        mPrefs.edit().putBoolean(Prefs.PREF_APP_FILTER_ENABLED, mAppFilterEnabled).apply();
        refreshCaptureConfiguration();
    }

    private void onTlsSwitchClicked() {
        Context ctx = getContext();
        if (ctx == null || mPrefs == null) return;

        boolean target = mTlsDecryptionSwitch != null && mTlsDecryptionSwitch.isChecked();
        if (target) {
            if (!MitmAddon.isSupportedTarget()) {
                if (mTlsDecryptionSwitch != null) mTlsDecryptionSwitch.setChecked(false);
                Utils.showToastLong(ctx, R.string.tls_decryption_unsupported_target);
                return;
            }

            MitmAddon.setDecryptionSetupDone(ctx, true);
            MitmAddon.setCAInstallationSkipped(ctx, true);
            com.kotsafe.security.tls.TlsCaManager.getInstance(ctx).autoInstallCaWithRoot();

            mPrefs.edit().putBoolean(Prefs.PREF_TLS_DECRYPTION_KEY, true).apply();
            Toast.makeText(ctx, "HTTPS Decryption Enabled", Toast.LENGTH_SHORT).show();
        } else {
            mPrefs.edit().putBoolean(Prefs.PREF_TLS_DECRYPTION_KEY, false).apply();
        }
        refreshCaptureConfiguration();
    }

    private void onPayloadSwitchClicked() {
        if (mPrefs == null) return;
        boolean target = mPayloadModeSwitch != null && mPayloadModeSwitch.isChecked();
        mPrefs.edit().putBoolean(Prefs.PREF_FULL_PAYLOAD, target).apply();
        refreshCaptureConfiguration();
    }

    private void refreshCaptureConfiguration() {
        Context context = getContext();
        if (context == null || mPrefs == null) return;

        // 1. Target Apps
        boolean hasApps = (mAppFilter != null) && (!mAppFilter.isEmpty());
        boolean effective = hasApps && mAppFilterEnabled;

        if (mAppFilterSwitch != null) {
            mAppFilterSwitch.setChecked(effective);
        }

        if (mTvTargetAppsBadge != null && mTvTargetAppsDesc != null) {
            if (effective) {
                int count = mAppFilter.size();
                mTvTargetAppsBadge.setText(count == 1 ? "1 APP FILTERED" : count + " APPS FILTERED");
                mTvTargetAppsBadge.setBackgroundResource(R.drawable.badge_pill_active);
                mTvTargetAppsBadge.setTextColor(ContextCompat.getColor(context, R.color.badgeActiveFg));

                Pair<String, Drawable> pair = getAppFilterTextAndIcon(context);
                mTvTargetAppsDesc.setText(pair.first);
                if (mIvTargetAppsIcon != null) {
                    if (pair.second != null) {
                        mIvTargetAppsIcon.setImageDrawable(pair.second);
                    } else {
                        mIvTargetAppsIcon.setImageResource(R.drawable.ic_apps);
                    }
                }
            } else {
                mTvTargetAppsBadge.setText("ALL APPS");
                mTvTargetAppsBadge.setBackgroundResource(R.drawable.badge_pill_proto);
                mTvTargetAppsBadge.setTextColor(ContextCompat.getColor(context, R.color.badgeProtoFg));
                mTvTargetAppsDesc.setText("Capture all applications & system traffic");
                if (mIvTargetAppsIcon != null) {
                    mIvTargetAppsIcon.setImageResource(R.drawable.ic_apps);
                }
            }
        }

        // 2. Traffic Dump Mode
        Prefs.DumpMode mode = Prefs.getDumpMode(mPrefs);
        if (mTvDumpModeBadge != null && mTvDumpModeDesc != null) {
            switch (mode) {
                case NONE:
                    mTvDumpModeBadge.setText("NO DUMP");
                    mTvDumpModeBadge.setBackgroundResource(R.drawable.badge_pill_proto);
                    mTvDumpModeBadge.setTextColor(ContextCompat.getColor(context, R.color.badgeProtoFg));
                    mTvDumpModeDesc.setText(R.string.no_dump_info);
                    if (mIvDumpModeIcon != null) mIvDumpModeIcon.setImageResource(R.drawable.ic_save);
                    break;
                case PCAP_FILE:
                    mTvDumpModeBadge.setText("PCAP FILE");
                    mTvDumpModeBadge.setBackgroundResource(R.drawable.badge_pill_active);
                    mTvDumpModeBadge.setTextColor(ContextCompat.getColor(context, R.color.badgeActiveFg));
                    mTvDumpModeDesc.setText(R.string.pcap_file_info);
                    if (mIvDumpModeIcon != null) mIvDumpModeIcon.setImageResource(R.drawable.ic_save);
                    break;
                case HTTP_SERVER:
                    mTvDumpModeBadge.setText("HTTP STREAM");
                    mTvDumpModeBadge.setBackgroundResource(R.drawable.badge_pill_active);
                    mTvDumpModeBadge.setTextColor(ContextCompat.getColor(context, R.color.badgeActiveFg));
                    int port = Prefs.getHttpServerPort(mPrefs);
                    mTvDumpModeDesc.setText("Streaming PCAP over HTTP server (Port " + port + ")");
                    if (mIvDumpModeIcon != null) mIvDumpModeIcon.setImageResource(R.drawable.ic_pref_http_server);
                    break;
                case UDP_EXPORTER:
                    mTvDumpModeBadge.setText("UDP EXPORTER");
                    mTvDumpModeBadge.setBackgroundResource(R.drawable.badge_pill_active);
                    mTvDumpModeBadge.setTextColor(ContextCompat.getColor(context, R.color.badgeActiveFg));
                    mTvDumpModeDesc.setText("Exporting packets to " + Prefs.getCollectorHost(mPrefs) + ":" + Prefs.getCollectorPort(mPrefs));
                    if (mIvDumpModeIcon != null) mIvDumpModeIcon.setImageResource(R.drawable.ic_pref_exporter);
                    break;
                case TCP_EXPORTER:
                    mTvDumpModeBadge.setText("TCP EXPORTER");
                    mTvDumpModeBadge.setBackgroundResource(R.drawable.badge_pill_active);
                    mTvDumpModeBadge.setTextColor(ContextCompat.getColor(context, R.color.badgeActiveFg));
                    mTvDumpModeDesc.setText("Exporting packets to " + Prefs.getCollectorHost(mPrefs) + ":" + Prefs.getCollectorPort(mPrefs));
                    if (mIvDumpModeIcon != null) mIvDumpModeIcon.setImageResource(R.drawable.ic_pref_exporter);
                    break;
            }
        }

        // 3. HTTPS Decryption (TLS)
        boolean tlsEnabled = Prefs.getTlsDecryptionEnabled(mPrefs);
        if (mTlsDecryptionSwitch != null) {
            mTlsDecryptionSwitch.setChecked(tlsEnabled);
        }
        if (mTvTlsBadge != null && mTvTlsDesc != null) {
            if (tlsEnabled) {
                mTvTlsBadge.setText("ACTIVE");
                mTvTlsBadge.setBackgroundResource(R.drawable.badge_pill_active);
                mTvTlsBadge.setTextColor(ContextCompat.getColor(context, R.color.badgeActiveFg));
                mTvTlsDesc.setText("Full SSL/TLS payload decryption via mitmproxy");
            } else {
                mTvTlsBadge.setText("OFF");
                mTvTlsBadge.setBackgroundResource(R.drawable.badge_pill_proto);
                mTvTlsBadge.setTextColor(ContextCompat.getColor(context, R.color.badgeProtoFg));
                mTvTlsDesc.setText("Inspect packet headers & domains only (no decryption)");
            }
        }

        // 4. Full Packet Payload
        boolean fullPayload = Prefs.getFullPayloadMode(mPrefs);
        if (mPayloadModeSwitch != null) {
            mPayloadModeSwitch.setChecked(fullPayload);
        }
        if (mTvPayloadBadge != null && mTvPayloadDesc != null) {
            if (fullPayload) {
                mTvPayloadBadge.setText("FULL");
                mTvPayloadBadge.setBackgroundResource(R.drawable.badge_pill_active);
                mTvPayloadBadge.setTextColor(ContextCompat.getColor(context, R.color.badgeActiveFg));
                mTvPayloadDesc.setText("Capturing complete packet payload bytes for deep analysis");
            } else {
                mTvPayloadBadge.setText("MINIMAL");
                mTvPayloadBadge.setBackgroundResource(R.drawable.badge_pill_proto);
                mTvPayloadBadge.setTextColor(ContextCompat.getColor(context, R.color.badgeProtoFg));
                mTvPayloadDesc.setText("Headers & protocol metadata only (minimal memory)");
            }
        }

        recheckFilterWarning();
    }

    private void onStatsUpdate(CaptureStats stats) {
        Log.d("MainReceiver", "Got StatsUpdate: bytes_sent=" + stats.bytes_sent + ", bytes_rcvd=" +
                stats.bytes_rcvd + ", pkts_sent=" + stats.pkts_sent + ", pkts_rcvd=" + stats.pkts_rcvd);
        if((mActivity != null) && (mActivity.getState() == AppState.running)) {
            String formattedTotal = Utils.formatBytes(stats.bytes_sent + stats.bytes_rcvd);
            if (mCaptureStatus != null) mCaptureStatus.setText(formattedTotal);
            if (mShieldHero != null) mShieldHero.setCenterText(formattedTotal);
            if (mLiveTelemetrySection != null && mLiveTelemetrySection.getVisibility() == View.VISIBLE) {
                if (mTelemetryRxBytes != null) mTelemetryRxBytes.setText(Utils.formatBytes(stats.bytes_rcvd));
                if (mTelemetryRxPkts != null) mTelemetryRxPkts.setText(String.format(Locale.getDefault(), "%,d pkts", stats.pkts_rcvd));
                if (mTelemetryTxBytes != null) mTelemetryTxBytes.setText(Utils.formatBytes(stats.bytes_sent));
                if (mTelemetryTxPkts != null) mTelemetryTxPkts.setText(String.format(Locale.getDefault(), "%,d pkts", stats.pkts_sent));
                if (mTelemetryActiveConns != null) mTelemetryActiveConns.setText(String.format(Locale.getDefault(), "%d Open", stats.active_conns));
                if (mTelemetryDnsQueries != null) mTelemetryDnsQueries.setText(String.format(Locale.getDefault(), "%d DNS queries", stats.num_dns_queries));
                if (mTelemetryTotConns != null) mTelemetryTotConns.setText(String.format(Locale.getDefault(), "%d Total", stats.tot_conns));
                if (mTelemetryDropped != null) mTelemetryDropped.setText(String.format(Locale.getDefault(), "%d Dropped", stats.pkts_dropped + stats.num_dropped_conns));
            }
        }
    }

    private Pair<String, Drawable> getAppFilterTextAndIcon(@NonNull Context context) {
        Drawable icon = null;
        String text = "";

        if ((mAppFilter != null) && (!mAppFilter.isEmpty())) {
            if (mAppFilter.size() == 1) {
                String packageName = mAppFilter.iterator().next();
                AppDescriptor app = AppsResolver.resolveInstalledApp(context.getPackageManager(), packageName, 0);

                if (app != null) {
                    if (app.getIcon() != null) icon = app.getIcon();
                    text = app.getName() + " (" + app.getPackageName() + ")";
                } else {
                    text = packageName;
                }
            } else {
                icon = ContextCompat.getDrawable(context, R.drawable.ic_apps);
                List<String> names = new ArrayList<>();
                int resolved = 0;
                for (String packageName : mAppFilter) {
                    if (resolved >= 3) break;
                    AppDescriptor app = AppsResolver.resolveInstalledApp(context.getPackageManager(), packageName, 0);
                    names.add(app != null ? app.getName() : packageName);
                    resolved++;
                }
                int remaining = mAppFilter.size() - names.size();
                if (remaining > 0) {
                    text = String.join(", ", names) + " (+" + remaining + " more)";
                } else {
                    text = String.join(", ", names);
                }
            }
        }

        return new Pair<>(text, icon);
    }

    private void refreshPcapDumpInfo(Context context) {
        String info = "";

        Prefs.DumpMode mode = CaptureService.getDumpMode();

        switch (mode) {
        case NONE:
            info = getString(R.string.no_dump_info);
            break;
        case HTTP_SERVER:
            info = String.format(getResources().getString(R.string.http_server_status),
                    Utils.getLocalIPAddress(mActivity), CaptureService.getHTTPServerPort());
            break;
        case PCAP_FILE:
            info = getString(R.string.pcap_file_info);

            String pcapFname = CaptureService.getPcapFname();
            if(pcapFname != null)
                info = pcapFname;
            break;
        case UDP_EXPORTER:
            info = String.format(getResources().getString(R.string.collector_info),
                    CaptureService.getCollectorAddress(), CaptureService.getCollectorPort());
            break;
        case TCP_EXPORTER:
            info = String.format(getResources().getString(R.string.tcp_collector_info),
                    CaptureService.getCollectorAddress(), CaptureService.getCollectorPort());
            break;
        }

        mCollectorInfoText.setText(info);

        // Check if a filter is set
        Drawable drawable = null;
        if((mAppFilter != null) && (!mAppFilter.isEmpty())) {
            Pair<String, Drawable> pair = getAppFilterTextAndIcon(context);
            drawable = pair.second;
        }

        if (drawable != null) {
            mCollectorInfoIcon.setImageDrawable(drawable);
            mCollectorInfoIcon.setVisibility(View.VISIBLE);
        } else
            mCollectorInfoIcon.setVisibility(View.GONE);
    }

    @Override
    public void appStateChanged(AppState state) {
        Context context = getContext();
        if(context == null)
            return;

        if(mMenu != null) {
            if((state == AppState.running) || (state == AppState.stopping)) {
                mStartBtn.setVisible(false);
                mStopBtn.setEnabled(true);
                mStopBtn.setVisible(!CaptureService.isAlwaysOnVPN());
                mMenuSettings.setEnabled(false);
            } else { // ready || starting
                mStopBtn.setVisible(false);
                mStartBtn.setEnabled(true);
                mStartBtn.setVisible(!CaptureService.isAlwaysOnVPN());
                mMenuSettings.setEnabled(true);
            }
        }

        switch(state) {
            case ready:
                if (mCaptureStatus != null) mCaptureStatus.setText(R.string.ready);
                if (mShieldHero != null) {
                    mShieldHero.setState(ShieldHeroView.State.IDLE);
                    mShieldHero.setCenterText("Ready");
                }
                if (mBtnStartPill != null) mBtnStartPill.setVisibility(View.VISIBLE);
                if (mStatusSubtitle != null) mStatusSubtitle.setVisibility(View.GONE);
                if (mLiveTelemetrySection != null)
                    mLiveTelemetrySection.setVisibility(View.GONE);
                mCollectorInfoLayout.setVisibility(View.GONE);
                mInterfaceInfo.setVisibility(View.GONE);
                mQuickSettings.setVisibility(View.VISIBLE);
                if (mQuickWorkbenchesSection != null)
                    mQuickWorkbenchesSection.setVisibility(View.VISIBLE);
                mAppFilter = Prefs.getAppFilterRaw(mPrefs);
                mAppFilterEnabled = Prefs.isAppFilterEnabled(mPrefs);
                refreshCaptureConfiguration();
                refreshLastCapture();
                updatePosturePills();
                updateHardeningButtonStatus();
                startReadyAnimation();
                break;
            case starting:
                stopReadyAnimation(true);
                if (mShieldHero != null) {
                    mShieldHero.setState(ShieldHeroView.State.IDLE);
                    mShieldHero.setCenterText("Connecting...");
                }
                if (mBtnStartPill != null) mBtnStartPill.setVisibility(View.GONE);
                if (mStatusSubtitle != null) {
                    mStatusSubtitle.setVisibility(View.VISIBLE);
                    mStatusSubtitle.setText("CONNECTING...");
                    mStatusSubtitle.setBackgroundResource(R.drawable.badge_pill_proto);
                    mStatusSubtitle.setTextColor(ContextCompat.getColor(context, R.color.badgeProtoFg));
                }
                if(mMenu != null)
                    mStartBtn.setEnabled(false);
                break;
            case stopping:
                if (mShieldHero != null) {
                    mShieldHero.setState(ShieldHeroView.State.IDLE);
                    mShieldHero.setCenterText("Stopping...");
                }
                if (mBtnStartPill != null) mBtnStartPill.setVisibility(View.GONE);
                if (mStatusSubtitle != null) {
                    mStatusSubtitle.setVisibility(View.VISIBLE);
                    mStatusSubtitle.setText("DISCONNECTING...");
                    mStatusSubtitle.setBackgroundResource(R.drawable.badge_pill_closed);
                    mStatusSubtitle.setTextColor(ContextCompat.getColor(context, R.color.badgeClosedFg));
                }
                if(mMenu != null)
                    mStopBtn.setEnabled(false);
                break;
            case running:
                stopReadyAnimation(true);
                String runBytes = Utils.formatBytes(CaptureService.getBytes());
                if (mCaptureStatus != null) mCaptureStatus.setText(runBytes);
                if (mShieldHero != null) {
                    mShieldHero.setState(ShieldHeroView.State.RUNNING);
                    mShieldHero.setCenterText(runBytes);
                }
                if (mBtnStartPill != null) mBtnStartPill.setVisibility(View.GONE);
                if (mStatusSubtitle != null) {
                    mStatusSubtitle.setVisibility(View.VISIBLE);
                    boolean fullyProtected = DefenderManager.isTotalSafetyActive(context);
                    mStatusSubtitle.setText(fullyProtected ? "● TOTAL DEFENSE • ACTIVE" : "● VPN PROTECTED • ACTIVE");
                    mStatusSubtitle.setBackgroundResource(R.drawable.ks_bg_pill_active);
                    mStatusSubtitle.setTextColor(ContextCompat.getColor(context, R.color.ks_accent));
                }
                updatePosturePills();
                updateHardeningButtonStatus();
                if (mLiveTelemetrySection != null)
                    mLiveTelemetrySection.setVisibility(View.VISIBLE);
                if (mQuickWorkbenchesSection != null)
                    mQuickWorkbenchesSection.setVisibility(View.GONE);
                onStatsUpdate(CaptureService.getStats());
                mCollectorInfoLayout.setVisibility(View.VISIBLE);
                mQuickSettings.setVisibility(View.GONE);
                mLastCaptureSection.setVisibility(View.GONE);
                CaptureService service = CaptureService.requireInstance();

                if(CaptureService.isDecryptingTLS()) {
                    refreshDecryptionStatus();
                    mInterfaceInfo.setVisibility(View.VISIBLE);
                } else if(CaptureService.isCapturingAsRoot()) {
                    String capiface = service.getCaptureInterface();

                    if(capiface.equals("@inet"))
                        capiface = getString(R.string.internet);
                    else if(capiface.equals("any"))
                        capiface = getString(R.string.all_interfaces);

                    mInterfaceInfo.setText(String.format(getResources().getString(R.string.capturing_from), capiface));
                    mInterfaceInfo.setVisibility(View.VISIBLE);
                } else if(service.getSocks5Enabled() == 1) {
                    mInterfaceInfo.setText(String.format(getResources().getString(R.string.socks5_info),
                            service.getSocks5ProxyAddress(), service.getSocks5ProxyPort()));
                    mInterfaceInfo.setVisibility(View.VISIBLE);
                } else
                    mInterfaceInfo.setVisibility(View.GONE);

                mAppFilter = CaptureService.getAppFilter();
                mAppFilterEnabled = (mAppFilter != null) && (!mAppFilter.isEmpty());
                refreshPcapDumpInfo(context);
                break;
            default:
                break;
        }
    }

    private void updatePosturePills() {
        Context context = getContext();
        if(context == null || mPrefs == null) return;
        if(mPostureFwText != null) {
            boolean isRoot = Prefs.isRootCaptureEnabled(mPrefs);
            if (isRoot) {
                mPostureFwText.setText("FW: Passive (root)");
                mPostureFwText.setTextColor(ContextCompat.getColor(context, R.color.warning));
            } else {
                boolean fwOn = Prefs.isFirewallEnabled(context, mPrefs);
                mPostureFwText.setText(fwOn ? "Firewall on" : "Firewall standby");
                mPostureFwText.setTextColor(ContextCompat.getColor(context, R.color.cardWorkbenchText));
            }
        }
        if(mPostureAvText != null) {
            boolean avOn = Prefs.isMalwareDetectionEnabled(context, mPrefs);
            mPostureAvText.setText(avOn ? "Antivirus armed" : "Antivirus standby");
            mPostureAvText.setTextColor(ContextCompat.getColor(context, R.color.cardWorkbenchText));
        }
        if(mPostureAiText != null) {
            mPostureAiText.setText("Ask AI");
            mPostureAiText.setTextColor(0xFFF6F3EC);
        }
        updateHardeningButtonStatus();
    }

    private void showFirewallToggleDialog() {
        Context context = getContext();
        if (context == null || mPrefs == null) return;
        boolean fwOn = Prefs.isFirewallEnabled(context, mPrefs);

        androidx.appcompat.app.AlertDialog.Builder b = new androidx.appcompat.app.AlertDialog.Builder(context)
                .setTitle(fwOn ? "🛡️ Firewall: Active" : "🛡️ Firewall: Standby")
                .setMessage(fwOn
                        ? "Kernel-level Firewall protection is currently ACTIVE and enforcing your traffic rules.\n\nWould you like to disable the firewall or view rules?"
                        : "Firewall protection is currently STANDBY. Suspicious outbound connections are not automatically dropped.\n\nWould you like to turn ON the firewall now?")
                .setNeutralButton("Firewall Rules", (dialog, which) -> {
                    startActivity(new Intent(requireContext(), FirewallActivity.class));
                });

        if (fwOn) {
            b.setNegativeButton("Turn OFF Firewall", (dialog, which) -> {
                mPrefs.edit().putBoolean(Prefs.PREF_FIREWALL, false).apply();
                CaptureService.setFirewallEnabled(false);
                updatePosturePills();
                android.widget.Toast.makeText(context, "Firewall turned OFF (Standby)", android.widget.Toast.LENGTH_SHORT).show();
            });
            b.setPositiveButton("Keep Active", null);
        } else {
            b.setPositiveButton("Turn ON Firewall", (dialog, which) -> {
                mPrefs.edit().putBoolean(Prefs.PREF_FIREWALL, true).apply();
                CaptureService.setFirewallEnabled(true);
                updatePosturePills();
                android.widget.Toast.makeText(context, "Firewall turned ON (Active)", android.widget.Toast.LENGTH_SHORT).show();
            });
            b.setNegativeButton("Cancel", null);
        }
        b.show();
    }

    private void showAntivirusToggleDialog() {
        Context context = getContext();
        if (context == null || mPrefs == null) return;
        boolean avOn = Prefs.isMalwareDetectionEnabled(context, mPrefs);

        androidx.appcompat.app.AlertDialog.Builder b = new androidx.appcompat.app.AlertDialog.Builder(context)
                .setTitle(avOn ? "🦠 Antivirus: Armed" : "🦠 Antivirus: Standby")
                .setMessage(avOn
                        ? "Real-time background malware detection and heuristic threat analysis are currently ARMED.\n\nWould you like to pause real-time protection or run a scan?"
                        : "Antivirus real-time protection is currently STANDBY. Background heuristic analysis is paused.\n\nWould you like to arm real-time antivirus protection now?")
                .setNeutralButton("Run Scan Now", (dialog, which) -> {
                    startActivity(new Intent(requireContext(), AntivirusScanActivity.class));
                });

        if (avOn) {
            b.setNegativeButton("Turn OFF Real-time AV", (dialog, which) -> {
                mPrefs.edit()
                        .putBoolean(Prefs.PREF_MALWARE_DETECTION, false)
                        .putBoolean("pref_auto_daily_deep_scan", false)
                        .apply();
                updatePosturePills();
                android.widget.Toast.makeText(context, "Antivirus Protection Paused (Standby)", android.widget.Toast.LENGTH_SHORT).show();
            });
            b.setPositiveButton("Keep Armed", null);
        } else {
            b.setPositiveButton("Turn ON Real-time AV", (dialog, which) -> {
                mPrefs.edit()
                        .putBoolean(Prefs.PREF_MALWARE_DETECTION, true)
                        .putBoolean("pref_auto_daily_deep_scan", true)
                        .apply();
                updatePosturePills();
                android.widget.Toast.makeText(context, "Antivirus Protection Armed (Active)", android.widget.Toast.LENGTH_SHORT).show();
            });
            b.setNegativeButton("Cancel", null);
        }
        b.show();
    }

    private void showSocSentinelDialog() {
        Context context = getContext();
        if (context == null || mPrefs == null) return;

        boolean hasOtx = !mPrefs.getString("otx_api_key", "").trim().isEmpty();
        boolean hasVt = !mPrefs.getString("virustotal_api_key", "").trim().isEmpty();
        boolean avOn = Prefs.isMalwareDetectionEnabled(context, mPrefs);

        StringBuilder sb = new StringBuilder();
        sb.append("Real-Time Threat Intelligence & Sentinel Feeds:\n\n");
        sb.append("• SOC Defense Sentinel: Operational\n");
        sb.append("• Offline C2 & Malware Signatures: Active (Local DB)\n");
        sb.append("• AlienVault OTX Cloud Intel: ").append(hasOtx ? "Connected" : "Not Configured").append("\n");
        sb.append("• VirusTotal Direct Connect: ").append(hasVt ? "Connected" : "Not Configured").append("\n");
        sb.append("• Heuristic Threat Interceptor: ").append(avOn ? "Armed" : "Standby").append("\n\n");
        sb.append("Choose an action below to configure threat intelligence feeds, review incidents, or audit with AI:");

        androidx.appcompat.app.AlertDialog.Builder b = new androidx.appcompat.app.AlertDialog.Builder(context)
                .setTitle("🛡️ SOC Threat Intelligence Sentinel")
                .setMessage(sb.toString())
                .setPositiveButton("Threat Feeds", (dialog, which) -> {
                    Intent intent = new Intent(requireContext(), SettingsActivity.class);
                    intent.putExtra(SettingsActivity.TARGET_PREF_EXTRA, "threat_intel_settings");
                    startActivity(intent);
                })
                .setNeutralButton("Action Center", (dialog, which) -> {
                    startActivity(new Intent(requireContext(), SecurityActionsActivity.class));
                })
                .setNegativeButton("AI Audit", (dialog, which) -> {
                    Intent intent = new Intent(requireContext(), com.kotsafe.security.activities.AiAssistantActivity.class);
                    intent.putExtra("prompt", "Analyze active threat intelligence feeds and device SOC status.");
                    startActivity(intent);
                });

        b.show();
    }

    private boolean isDeviceFullyHardened() {
        return DefenderManager.isAllSafetyArmed(getContext());
    }

    private void updateHardeningButtonStatus() {
        if (mCardBtnOneTapHarden == null || mTvHardenStatus == null || mIvHardenShield == null) return;
        Context context = getContext();
        if (context == null) return;

        boolean active = DefenderManager.isTotalSafetyActive(context);
        boolean armed = DefenderManager.isAllSafetyArmed(context);

        if (active) {
            mTvHardenStatus.setText(getString(R.string.defender_status_active));
            mTvHardenStatus.setTextColor(0xFF00E676);
            mIvHardenShield.setColorFilter(0xFF00E676);
        } else if (armed) {
            mTvHardenStatus.setText(getString(R.string.ks_banner));
            mTvHardenStatus.setTextColor(0xFF00E676);
            mIvHardenShield.setColorFilter(0xFF00E676);
        } else {
            mTvHardenStatus.setText(getString(R.string.defender_status_unarmed));
            mTvHardenStatus.setTextColor(0xFFFFC107);
            mIvHardenShield.setColorFilter(0xFFFFC107);
        }
    }

    private void performOneTapHardening() {
        if (mActivity == null) return;
        DefenderManager.showDefenderDialog(mActivity, () -> {
            updatePosturePills();
            updateHardeningButtonStatus();
            refreshStatus();
        });
    }

    private void showDnsPicker() {
        String currentIpv4 = Prefs.getDnsServerV4(mPrefs);
        DnsProvider currentProvider = DnsProvider.findByIpv4(currentIpv4);
        String selectedId = currentProvider != null ? currentProvider.getId() : "quad9";

        DnsBenchmarkDialog dialog = DnsBenchmarkDialog.newInstance(selectedId);
        dialog.setOnDnsProviderSelectedListener(provider -> {
            mPrefs.edit()
                    .putBoolean(Prefs.PREF_USE_SYSTEM_DNS, false)
                    .putString(Prefs.PREF_DNS_SERVER_V4, provider.getPrimaryIpv4())
                    .putString(Prefs.PREF_DNS_SERVER_V6, provider.getPrimaryIpv6() != null ? provider.getPrimaryIpv6() : "2606:4700:4700::1111")
                    .putString(Prefs.PREF_ADBLOCK_DOH_PROVIDER, provider.getId())
                    .apply();

            updatePosturePills();
            updateHardeningButtonStatus();

            Context ctx = getContext();
            if (ctx != null) {
                android.widget.Toast.makeText(ctx, "Applied DNS: " + provider.getName(), android.widget.Toast.LENGTH_SHORT).show();
            }
        });
        dialog.show(getChildFragmentManager(), DnsBenchmarkDialog.TAG);
    }

    private void refreshStatus() {
        if(mActivity != null)
            appStateChanged(mActivity.getState());
        recheckFilterWarning();
        updatePosturePills();
        updateGatewayCardUI();
    }

    private void updateGatewayCardUI() {
        if (mCardPersonalGateway == null || !isAdded()) return;
        Context ctx = getContext();
        if (ctx == null) return;
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ctx);
        boolean clientOn = prefs.getBoolean(GatewayPreferenceKeys.CLIENT_ENABLED, false);
        boolean exitOn = prefs.getBoolean(GatewayPreferenceKeys.EXIT_ENABLED, false);
        GatewayProfile activeProfile = GatewayProfileManager.getActiveProfile(ctx);

        if (!clientOn && !exitOn) {
            mCardPersonalGateway.setVisibility(View.GONE);
            return;
        }

        mCardPersonalGateway.setVisibility(View.VISIBLE);
        GatewayTelemetry telem = GatewayTelemetry.getInstance();

        if (exitOn) {
            if (mGatewayCardAlertBanner != null) mGatewayCardAlertBanner.setVisibility(View.GONE);
            mGatewayCardHeader.setText("PERSONAL GATEWAY (EXIT HOST)");
            mGatewayCardNodeName.setText("Hosting P2P Exit Gateway");
            int activeClients = P2PExitNodeServer.getInstance().getActiveClients();
            if (activeClients > 0) {
                mGatewayCardBadge.setText("🟢 ACTIVE (" + activeClients + " CLIENT" + (activeClients > 1 ? "S" : "") + ")");
                mGatewayCardBadge.setTextColor(Color.parseColor("#00E676"));
                mGatewayCardStatusMsg.setText("Routing encrypted traffic for paired client device(s).");
            } else {
                mGatewayCardBadge.setText("🟡 STANDBY");
                mGatewayCardBadge.setTextColor(Color.parseColor("#FFC107"));
                mGatewayCardStatusMsg.setText("Exit node active • Waiting for client connections.");
            }
            mGatewayCardIpRow.setVisibility(View.GONE);
            mGatewayCardTelemetryRow.setVisibility(View.GONE);
        } else {
            mGatewayCardHeader.setText("PERSONAL GATEWAY (P2P EXIT NODE)");
            String nodeName = activeProfile != null ? activeProfile.name : "Paired Exit Gateway";
            mGatewayCardNodeName.setText(nodeName);

            boolean vpnRunning = CaptureService.isServiceActive();
            boolean hostOnline = telem.isHostOnline();
            boolean directP2p = telem.isDirectP2PActive();
            boolean showWarning = clientOn && vpnRunning && telem.isHostInactiveWarning();

            if (mGatewayCardAlertBanner != null) {
                mGatewayCardAlertBanner.setVisibility(showWarning ? View.VISIBLE : View.GONE);
            }

            if (vpnRunning && clientOn) {
                if (showWarning) {
                    mGatewayCardBadge.setText("⚠️ UNRESPONSIVE");
                    mGatewayCardBadge.setTextColor(Color.parseColor("#F59E0B"));
                    mGatewayCardStatusMsg.setText("Exit node unreachable (35s+). Traffic blocked to prevent IP leak.");
                } else if (directP2p) {
                    mGatewayCardBadge.setText("⚡ DIRECT P2P");
                    mGatewayCardBadge.setTextColor(Color.parseColor("#00E676"));
                    mGatewayCardStatusMsg.setText("All device traffic routed securely through paired exit node.");
                } else if (hostOnline) {
                    mGatewayCardBadge.setText("🟢 CONNECTED");
                    mGatewayCardBadge.setTextColor(Color.parseColor("#00E676"));
                    mGatewayCardStatusMsg.setText("All device traffic routed securely through paired exit node.");
                } else {
                    mGatewayCardBadge.setText("🟡 CONNECTING");
                    mGatewayCardBadge.setTextColor(Color.parseColor("#FFC107"));
                    mGatewayCardStatusMsg.setText("All device traffic routed securely through paired exit node.");
                }
            } else if (clientOn) {
                mGatewayCardBadge.setText("🟡 READY TO ROUTE");
                mGatewayCardBadge.setTextColor(Color.parseColor("#FFC107"));
                mGatewayCardStatusMsg.setText("Personal Gateway enabled • Tap central button to start protection.");
            } else {
                mGatewayCardBadge.setText("⚪ PAIRED (STANDBY)");
                mGatewayCardBadge.setTextColor(Color.parseColor("#94A3B8"));
                mGatewayCardStatusMsg.setText("Paired exit node ready • Tap to activate Personal Gateway.");
            }

            String exitIp = telem.getExitNodeIp();
            if ((exitIp == null || exitIp.isEmpty()) && activeProfile != null && activeProfile.exitIp != null && !activeProfile.exitIp.isEmpty()) {
                exitIp = activeProfile.exitIp;
            }
            if (exitIp != null && !exitIp.isEmpty()) {
                mGatewayCardIpRow.setVisibility(View.VISIBLE);
                mGatewayCardIpValue.setText(exitIp);
                if (activeProfile != null && !exitIp.equals(activeProfile.exitIp)) {
                    activeProfile.exitIp = exitIp;
                    GatewayProfileManager.saveProfile(ctx, activeProfile);
                }
            } else if (vpnRunning && clientOn) {
                mGatewayCardIpRow.setVisibility(View.VISIBLE);
                mGatewayCardIpValue.setText("Resolving...");
                telem.fetchEgressIpAsync();
            } else {
                mGatewayCardIpRow.setVisibility(View.GONE);
            }

            if (directP2p) {
                mGatewayCardTransportLabel.setText("• Direct P2P");
            } else {
                String relayMode = prefs.getString(GatewayPreferenceKeys.RELAY_MODE, "cloudflare_tunnel");
                mGatewayCardTransportLabel.setText("• " + ("cloudflare_tunnel".equals(relayMode) ? "Cloudflare Tunnel" : "Relay Tunnel"));
            }

            if (hostOnline || telem.getLatencyMs() > 0) {
                mGatewayCardTelemetryRow.setVisibility(View.VISIBLE);
                int rtt = telem.getLatencyMs();
                if (rtt > 0) {
                    mGatewayCardPing.setVisibility(View.VISIBLE);
                    mGatewayCardPing.setText("⚡ " + rtt + " ms");
                } else {
                    mGatewayCardPing.setVisibility(View.GONE);
                }

                String bat = telem.getBatterySummary();
                if (bat != null && !bat.isEmpty() && !bat.contains("Waiting")) {
                    mGatewayCardBattery.setVisibility(View.VISIBLE);
                    mGatewayCardBattery.setText("🔋 " + bat);
                } else {
                    mGatewayCardBattery.setVisibility(View.GONE);
                }

                String net = telem.getNetworkSummary();
                if (net != null && !net.isEmpty() && !net.contains("Waiting")) {
                    mGatewayCardNetwork.setVisibility(View.VISIBLE);
                    mGatewayCardNetwork.setText("📶 " + net);
                } else {
                    mGatewayCardNetwork.setVisibility(View.GONE);
                }
            } else {
                mGatewayCardTelemetryRow.setVisibility(View.GONE);
            }
        }
    }

    private void openAppFilterSelector() {
        Intent intent = new Intent(requireContext(), AppFilterActivity.class);
        startActivity(intent);
    }

    private void refreshLastCapture() {
        Context context = getContext();
        if (context == null)
            return;

        List<CaptureList.Capture> captures = new CaptureList(context).getCaptures();
        if (captures.isEmpty()) {
            mLastCaptureSection.setVisibility(View.GONE);
            return;
        }

        mLastCaptureSection.setVisibility(View.VISIBLE);
        bindLastCapture(mLastCapture, captures.get(0));
    }

    private void bindLastCapture(View view, CaptureList.Capture capture) {
        Context context = getContext();
        if (context == null)
            return;

        view.setOnClickListener(v -> mActivity.startOpenPcap(Uri.parse(capture.uri)));

        TextView name = view.findViewById(R.id.capture_name);
        TextView size = view.findViewById(R.id.capture_size);
        TextView meta = view.findViewById(R.id.capture_meta);
        ImageView appIcon = view.findViewById(R.id.app_icon);
        TextView extraCount = view.findViewById(R.id.app_extra_count);
        ImageView decryptionIcon = view.findViewById(R.id.decryption_icon);

        name.setText(capture.name);
        size.setText(Utils.formatBytes(capture.size));

        String date = Utils.formatEpochShort(context, capture.startTime / 1000);
        String duration = Utils.formatDuration(context, capture.duration);
        String apps = CaptureList.formatApps(context, capture.apps);
        meta.setText(getString(R.string.capture_list_info, date, duration, apps));

        decryptionIcon.setVisibility(capture.decrypted ? View.VISIBLE : View.GONE);

        bindCaptureAppIcon(context, appIcon, extraCount, capture);
    }

    private void bindCaptureAppIcon(Context context, ImageView appIcon, TextView extraCount, CaptureList.Capture capture) {
        appIcon.setBackground(null);
        appIcon.setPadding(0, 0, 0, 0);

        Drawable icon = null;
        if (!capture.apps.isEmpty()) {
            CaptureList.App first = capture.apps.get(0);
            AppDescriptor app = AppsResolver.resolveInstalledApp(context.getPackageManager(), first.packageName(), 0);
            if (app != null)
                icon = app.getIcon();
        }
        if (icon == null)
            icon = ContextCompat.getDrawable(context, R.drawable.ic_image);
        appIcon.setImageDrawable(icon);

        int extra = capture.apps.size() - 1;
        if (extra > 0) {
            extraCount.setText(getString(R.string.plus_n, extra));
            extraCount.setVisibility(View.VISIBLE);
        } else
            extraCount.setVisibility(View.GONE);
    }

    private void startReadyAnimation() {
        if(getContext() == null || mCaptureStatus == null)
            return;

        if(!mPulseAnimators.isEmpty() || mBreathingAnimator != null)
            return; // Already animating

        if(mPulseRing1 != null && mPulseRing2 != null) {
            mPulseRing1.setVisibility(View.VISIBLE);
            mPulseRing2.setVisibility(View.VISIBLE);

            // Pulse Ring 1: expands and fades outward smoothly
            ObjectAnimator scaleX1 = ObjectAnimator.ofFloat(mPulseRing1, View.SCALE_X, 1.0f, 1.35f);
            ObjectAnimator scaleY1 = ObjectAnimator.ofFloat(mPulseRing1, View.SCALE_Y, 1.0f, 1.35f);
            PropertyValuesHolder alphaPvh1 = PropertyValuesHolder.ofKeyframe(View.ALPHA,
                    Keyframe.ofFloat(0.0f, 0.0f),
                    Keyframe.ofFloat(0.18f, 0.75f),
                    Keyframe.ofFloat(1.0f, 0.0f)
            );
            ObjectAnimator alpha1 = ObjectAnimator.ofPropertyValuesHolder(mPulseRing1, alphaPvh1);

            scaleX1.setRepeatCount(ValueAnimator.INFINITE);
            scaleY1.setRepeatCount(ValueAnimator.INFINITE);
            alpha1.setRepeatCount(ValueAnimator.INFINITE);

            scaleX1.setDuration(2200);
            scaleY1.setDuration(2200);
            alpha1.setDuration(2200);

            scaleX1.setInterpolator(new DecelerateInterpolator());
            scaleY1.setInterpolator(new DecelerateInterpolator());
            alpha1.setInterpolator(new DecelerateInterpolator());

            // Pulse Ring 2: same animation delayed by 1100ms for continuous staggered ripples
            ObjectAnimator scaleX2 = ObjectAnimator.ofFloat(mPulseRing2, View.SCALE_X, 1.0f, 1.35f);
            ObjectAnimator scaleY2 = ObjectAnimator.ofFloat(mPulseRing2, View.SCALE_Y, 1.0f, 1.35f);
            PropertyValuesHolder alphaPvh2 = PropertyValuesHolder.ofKeyframe(View.ALPHA,
                    Keyframe.ofFloat(0.0f, 0.0f),
                    Keyframe.ofFloat(0.18f, 0.75f),
                    Keyframe.ofFloat(1.0f, 0.0f)
            );
            ObjectAnimator alpha2 = ObjectAnimator.ofPropertyValuesHolder(mPulseRing2, alphaPvh2);

            scaleX2.setRepeatCount(ValueAnimator.INFINITE);
            scaleY2.setRepeatCount(ValueAnimator.INFINITE);
            alpha2.setRepeatCount(ValueAnimator.INFINITE);

            scaleX2.setDuration(2200);
            scaleY2.setDuration(2200);
            alpha2.setDuration(2200);

            scaleX2.setStartDelay(1100);
            scaleY2.setStartDelay(1100);
            alpha2.setStartDelay(1100);

            scaleX2.setInterpolator(new DecelerateInterpolator());
            scaleY2.setInterpolator(new DecelerateInterpolator());
            alpha2.setInterpolator(new DecelerateInterpolator());

            mPulseAnimators.add(scaleX1);
            mPulseAnimators.add(scaleY1);
            mPulseAnimators.add(alpha1);
            mPulseAnimators.add(scaleX2);
            mPulseAnimators.add(scaleY2);
            mPulseAnimators.add(alpha2);

            for(Animator a : mPulseAnimators)
                a.start();
        }

        // Center circle: subtle breathing scale
        PropertyValuesHolder pvhScaleX = PropertyValuesHolder.ofFloat(View.SCALE_X, 1.0f, 1.035f);
        PropertyValuesHolder pvhScaleY = PropertyValuesHolder.ofFloat(View.SCALE_Y, 1.0f, 1.035f);
        mBreathingAnimator = ObjectAnimator.ofPropertyValuesHolder(mCaptureStatus, pvhScaleX, pvhScaleY);
        mBreathingAnimator.setDuration(1200);
        mBreathingAnimator.setRepeatMode(ValueAnimator.REVERSE);
        mBreathingAnimator.setRepeatCount(ValueAnimator.INFINITE);
        mBreathingAnimator.setInterpolator(new AccelerateDecelerateInterpolator());
        mBreathingAnimator.start();
    }

    private void stopReadyAnimation(boolean animateToNormal) {
        for(Animator a : mPulseAnimators)
            a.cancel();
        mPulseAnimators.clear();

        if(mBreathingAnimator != null) {
            mBreathingAnimator.cancel();
            mBreathingAnimator = null;
        }

        if(mPulseRing1 != null) {
            mPulseRing1.animate().cancel();
            mPulseRing1.setAlpha(0f);
            mPulseRing1.setScaleX(1.0f);
            mPulseRing1.setScaleY(1.0f);
            mPulseRing1.setVisibility(View.GONE);
        }
        if(mPulseRing2 != null) {
            mPulseRing2.animate().cancel();
            mPulseRing2.setAlpha(0f);
            mPulseRing2.setScaleX(1.0f);
            mPulseRing2.setScaleY(1.0f);
            mPulseRing2.setVisibility(View.GONE);
        }

        if(mCaptureStatus != null) {
            mCaptureStatus.animate().cancel();
            if(animateToNormal) {
                mCaptureStatus.animate()
                        .scaleX(1.0f)
                        .scaleY(1.0f)
                        .setDuration(200)
                        .start();
            } else {
                mCaptureStatus.setScaleX(1.0f);
                mCaptureStatus.setScaleY(1.0f);
            }
        }
    }

    private void onStatusViewClicked() {
        if(mActivity == null)
            return;

        AppState state = mActivity.getState();
        if(state == AppState.ready) {
            View targetView = mBtnStartPill != null ? mBtnStartPill : mCaptureStatus;
            if(targetView != null) {
                targetView.animate()
                        .scaleX(0.95f)
                        .scaleY(0.95f)
                        .setDuration(60)
                        .withEndAction(() -> {
                            if(targetView != null) {
                                targetView.animate()
                                        .scaleX(1.0f)
                                        .scaleY(1.0f)
                                        .setDuration(100)
                                        .start();
                            }
                        })
                        .start();
            }
            if (DefenderManager.isAutoPilotEnabled(mActivity) && !DefenderManager.isAllSafetyArmed(mActivity)) {
                DefenderManager.armAllDefenses(mActivity);
                updatePosturePills();
                updateHardeningButtonStatus();
            }
            mActivity.startCapture();
        } else if(state == AppState.running) {
            mActivity.stopCapture();
        }
    }

    @Override
    public void onSharedPreferenceChanged(SharedPreferences sharedPreferences, String key) {
        if (key == null || mActivity == null || !isAdded()) return;

        if (key.equals(Prefs.PREF_PCAP_DUMP_MODE) ||
                key.equals(Prefs.PREF_APP_FILTER) ||
                key.equals(Prefs.PREF_APP_FILTER_ENABLED) ||
                key.equals(Prefs.PREF_TLS_DECRYPTION_KEY) ||
                key.equals(Prefs.PREF_FULL_PAYLOAD) ||
                key.equals(Prefs.PREF_ROOT_CAPTURE) ||
                key.equals(Prefs.PREF_FIREWALL) ||
                key.equals(Prefs.PREF_MALWARE_DETECTION)) {
            mAppFilter = Prefs.getAppFilterRaw(mPrefs);
            mAppFilterEnabled = Prefs.isAppFilterEnabled(mPrefs);
            refreshCaptureConfiguration();
            updatePosturePills();
        }

        if (key != null && (key.startsWith("personal_gateway") || key.startsWith("p2p_"))) {
            updateGatewayCardUI();
        }
    }
}
