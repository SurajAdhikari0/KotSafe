/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.activities;

import android.content.Intent;
import android.content.res.ColorStateList;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.Log;
import com.kotsafe.security.R;
import com.kotsafe.security.model.Prefs;
import com.github.appintro.AppIntro;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;
import com.google.android.material.switchmaterial.SwitchMaterial;

import org.jetbrains.annotations.Nullable;

public class OnBoardingActivity extends AppIntro {
    private static final String TAG = "OnBoardingActivity";
    public static final String ENABLE_BACK_BUTTON = "back_enabled";

    public static class KotSafeSlideFragment extends Fragment {
        private static final String ARG_SLIDE_INDEX = "slide_index";
        private static final String ARG_IMAGE_RES = "image_res";
        private static final String ARG_IMAGE_TINT = "image_tint";
        private static final String ARG_BADGE_RES = "badge_res";
        private static final String ARG_TITLE_RES = "title_res";
        private static final String ARG_SUBTITLE_RES = "subtitle_res";
        private static final String ARG_F1_TITLE = "f1_title";
        private static final String ARG_F1_DESC = "f1_desc";
        private static final String ARG_F2_TITLE = "f2_title";
        private static final String ARG_F2_DESC = "f2_desc";
        private static final String ARG_F3_TITLE = "f3_title";
        private static final String ARG_F3_DESC = "f3_desc";
        private static final String ARG_F4_TITLE = "f4_title";
        private static final String ARG_F4_DESC = "f4_desc";

        public static KotSafeSlideFragment createInstance(
                int slideIndex,
                int imageRes, int imageTint,
                int badgeRes, int titleRes, int subtitleRes,
                int f1Title, int f1Desc,
                int f2Title, int f2Desc,
                int f3Title, int f3Desc,
                int f4Title, int f4Desc) {
            KotSafeSlideFragment f = new KotSafeSlideFragment();
            Bundle args = new Bundle();
            args.putInt(ARG_SLIDE_INDEX, slideIndex);
            args.putInt(ARG_IMAGE_RES, imageRes);
            args.putInt(ARG_IMAGE_TINT, imageTint);
            args.putInt(ARG_BADGE_RES, badgeRes);
            args.putInt(ARG_TITLE_RES, titleRes);
            args.putInt(ARG_SUBTITLE_RES, subtitleRes);
            args.putInt(ARG_F1_TITLE, f1Title);
            args.putInt(ARG_F1_DESC, f1Desc);
            args.putInt(ARG_F2_TITLE, f2Title);
            args.putInt(ARG_F2_DESC, f2Desc);
            args.putInt(ARG_F3_TITLE, f3Title);
            args.putInt(ARG_F3_DESC, f3Desc);
            args.putInt(ARG_F4_TITLE, f4Title);
            args.putInt(ARG_F4_DESC, f4Desc);
            f.setArguments(args);
            return f;
        }

        @Nullable
        @Override
        public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
            View view = inflater.inflate(R.layout.fragment_kotsafe_intro_slide, container, false);
            Bundle args = getArguments();
            if (args == null) return view;

            int slideIndex = args.getInt(ARG_SLIDE_INDEX, 1);
            int imgRes = args.getInt(ARG_IMAGE_RES);
            int tint = args.getInt(ARG_IMAGE_TINT);

            View iconContainer = view.findViewById(R.id.slide_icon_container);
            ImageView icon = view.findViewById(R.id.slide_icon);
            MaterialCardView heroCard = view.findViewById(R.id.slide_hero_image_card);
            ImageView heroImage = view.findViewById(R.id.slide_hero_image);

            TextView badge = view.findViewById(R.id.slide_badge);
            TextView title = view.findViewById(R.id.slide_title);
            TextView subtitle = view.findViewById(R.id.slide_subtitle);

            TextView f1Title = view.findViewById(R.id.feature_1_title);
            TextView f1Desc = view.findViewById(R.id.feature_1_desc);
            TextView f2Title = view.findViewById(R.id.feature_2_title);
            TextView f2Desc = view.findViewById(R.id.feature_2_desc);
            TextView f3Title = view.findViewById(R.id.feature_3_title);
            TextView f3Desc = view.findViewById(R.id.feature_3_desc);
            TextView f4Title = view.findViewById(R.id.feature_4_title);
            TextView f4Desc = view.findViewById(R.id.feature_4_desc);

            FrameLayout interactiveContainer = view.findViewById(R.id.slide_interactive_container);

            // Configure Top Visual: Emblem for Slide 1, High-Tech Hero Image for Slides 2-6
            if (slideIndex == 1) {
                if (iconContainer != null) iconContainer.setVisibility(View.VISIBLE);
                if (heroCard != null) heroCard.setVisibility(View.GONE);
                if (imgRes != 0 && icon != null) {
                    icon.setImageResource(imgRes);
                    if (tint != 0) {
                        icon.setColorFilter(ContextCompat.getColor(requireContext(), tint));
                    }
                }
            } else {
                if (iconContainer != null) iconContainer.setVisibility(View.GONE);
                if (heroCard != null && heroImage != null) {
                    heroCard.setVisibility(View.VISIBLE);
                    if (imgRes != 0) {
                        heroImage.setImageResource(imgRes);
                    }
                }
            }

            int bRes = args.getInt(ARG_BADGE_RES);
            if (bRes != 0) badge.setText(bRes);

            int tRes = args.getInt(ARG_TITLE_RES);
            if (tRes != 0) title.setText(tRes);

            int sRes = args.getInt(ARG_SUBTITLE_RES);
            if (sRes != 0) subtitle.setText(sRes);

            int f1t = args.getInt(ARG_F1_TITLE);
            if (f1t != 0) f1Title.setText(f1t);
            int f1d = args.getInt(ARG_F1_DESC);
            if (f1d != 0) f1Desc.setText(f1d);

            int f2t = args.getInt(ARG_F2_TITLE);
            if (f2t != 0) f2Title.setText(f2t);
            int f2d = args.getInt(ARG_F2_DESC);
            if (f2d != 0) f2Desc.setText(f2d);

            int f3t = args.getInt(ARG_F3_TITLE);
            if (f3t != 0) f3Title.setText(f3t);
            int f3d = args.getInt(ARG_F3_DESC);
            if (f3d != 0) f3Desc.setText(f3d);

            int f4t = args.getInt(ARG_F4_TITLE);
            if (f4t != 0) f4Title.setText(f4t);
            int f4d = args.getInt(ARG_F4_DESC);
            if (f4d != 0) f4Desc.setText(f4d);

            // Inflate and bind interactive playgrounds
            setupInteractiveWidget(inflater, interactiveContainer, slideIndex);

            return view;
        }

        private void setupInteractiveWidget(LayoutInflater inflater, FrameLayout container, int slideIndex) {
            if (container == null) return;
            container.removeAllViews();

            int colorAccent = ContextCompat.getColor(requireContext(), R.color.colorAccent);
            int colorDrawer = ContextCompat.getColor(requireContext(), R.color.drawerItemColor);

            switch (slideIndex) {
                case 1: {
                    View interView = inflater.inflate(R.layout.intro_interactive_slide_1, container, false);
                    MaterialButton btnStandard = interView.findViewById(R.id.btn_mode_standard);
                    MaterialButton btnFortress = interView.findViewById(R.id.btn_mode_fortress);
                    TextView modeTitle = interView.findViewById(R.id.preview_mode_title);
                    TextView modeDesc = interView.findViewById(R.id.preview_mode_desc);

                    btnStandard.setOnClickListener(v -> {
                        setButtonSelected(btnStandard, true, colorAccent, colorDrawer);
                        setButtonSelected(btnFortress, false, colorAccent, colorDrawer);
                        modeTitle.setText("🛡️ Standard Guard (Balanced)");
                        modeDesc.setText("Zero battery impact • DNS sinkhole filtering • Real-time tracker blocking • Zero root needed");
                    });

                    btnFortress.setOnClickListener(v -> {
                        setButtonSelected(btnFortress, true, colorAccent, colorDrawer);
                        setButtonSelected(btnStandard, false, colorAccent, colorDrawer);
                        modeTitle.setText("⚡ Fortress Mode (Maximum Security)");
                        modeDesc.setText("Full packet inspection • Active YARA heuristic scoring • Immediate malicious IP drops • Encrypted DNS enforcement");
                    });

                    container.addView(interView);
                    break;
                }
                case 2: {
                    View interView = inflater.inflate(R.layout.intro_interactive_slide_2, container, false);
                    MaterialButton btnScan = interView.findViewById(R.id.btn_simulate_scan);
                    ProgressBar progress = interView.findViewById(R.id.progress_scan_demo);
                    ImageView statusIcon = interView.findViewById(R.id.scan_status_icon);
                    TextView statusText = interView.findViewById(R.id.scan_status_text);

                    btnScan.setOnClickListener(v -> {
                        btnScan.setEnabled(false);
                        progress.setVisibility(View.VISIBLE);
                        statusText.setText("Analyzing 1,420 APK signatures and Dalvik bytecodes...");

                        new Handler(Looper.getMainLooper()).postDelayed(() -> {
                            if (!isAdded()) return;
                            progress.setVisibility(View.GONE);
                            btnScan.setEnabled(true);
                            statusIcon.setImageResource(R.drawable.ic_check_solid);
                            statusIcon.setColorFilter(ContextCompat.getColor(requireContext(), R.color.colorAccent));
                            statusText.setText("✅ Test Scan Complete: 0 Threats Found! System 100% Clean & Verified.");
                        }, 850);
                    });

                    container.addView(interView);
                    break;
                }
                case 3: {
                    View interView = inflater.inflate(R.layout.intro_interactive_slide_3, container, false);
                    SwitchMaterial swAds = interView.findViewById(R.id.switch_rule_ads);
                    SwitchMaterial swBg = interView.findViewById(R.id.switch_rule_bg);
                    TextView statsText = interView.findViewById(R.id.firewall_sim_stats);

                    Runnable updateStats = () -> {
                        boolean ads = swAds.isChecked();
                        boolean bg = swBg.isChecked();
                        if (ads && bg) {
                            statsText.setText("🛡️ Filter Active: 2 rules enforced • 0 leaks • 100% On-Device");
                        } else if (ads) {
                            statsText.setText("⚠️ Background leak protection off • Telemetry & tracker filtering active");
                        } else if (bg) {
                            statsText.setText("⚠️ Tracker filter off • Background app data isolation active");
                        } else {
                            statsText.setText("⚠️ All firewall rules disabled: Unfiltered direct traffic");
                        }
                    };

                    swAds.setOnCheckedChangeListener((b, c) -> updateStats.run());
                    swBg.setOnCheckedChangeListener((b, c) -> updateStats.run());

                    container.addView(interView);
                    break;
                }
                case 4: {
                    View interView = inflater.inflate(R.layout.intro_interactive_slide_4, container, false);
                    MaterialButton btnCf = interView.findViewById(R.id.btn_relay_cf);
                    MaterialButton btnVps = interView.findViewById(R.id.btn_relay_vps);
                    MaterialButton btnHome = interView.findViewById(R.id.btn_relay_home);
                    TextView topoTitle = interView.findViewById(R.id.mesh_topology_title);
                    TextView topoDesc = interView.findViewById(R.id.mesh_topology_desc);

                    btnCf.setOnClickListener(v -> {
                        setButtonSelected(btnCf, true, colorAccent, colorDrawer);
                        setButtonSelected(btnVps, false, colorAccent, colorDrawer);
                        setButtonSelected(btnHome, false, colorAccent, colorDrawer);
                        topoTitle.setText("Client ⟷ Cloudflare WSS Edge ⟷ Exit Node");
                        topoDesc.setText("• E2EE AES-256-GCM cipher • Bypasses CGNAT and strict 5G carriers • Zero open ports required");
                    });

                    btnVps.setOnClickListener(v -> {
                        setButtonSelected(btnVps, true, colorAccent, colorDrawer);
                        setButtonSelected(btnCf, false, colorAccent, colorDrawer);
                        setButtonSelected(btnHome, false, colorAccent, colorDrawer);
                        topoTitle.setText("Client ⟷ Dedicated VPS Relay ⟷ Internet");
                        topoDesc.setText("• Full sovereign control • Custom domain & static IP • Direct TCP/WebSocket multiplexing");
                    });

                    btnHome.setOnClickListener(v -> {
                        setButtonSelected(btnHome, true, colorAccent, colorDrawer);
                        setButtonSelected(btnCf, false, colorAccent, colorDrawer);
                        setButtonSelected(btnVps, false, colorAccent, colorDrawer);
                        topoTitle.setText("Client ⟷ Home Gateway (Exit Node) ⟷ Internet");
                        topoDesc.setText("• Free & zero-cost • Browse as if you are on your home Wi-Fi • Full LAN device accessibility");
                    });

                    container.addView(interView);
                    break;
                }
                case 5: {
                    View interView = inflater.inflate(R.layout.intro_interactive_slide_5, container, false);
                    MaterialButton btnTls = interView.findViewById(R.id.btn_proto_tls);
                    MaterialButton btnHttp = interView.findViewById(R.id.btn_proto_http2);
                    MaterialButton btnQuic = interView.findViewById(R.id.btn_proto_quic);
                    MaterialButton btnDns = interView.findViewById(R.id.btn_proto_dns);
                    MaterialButton btnPcap = interView.findViewById(R.id.btn_proto_pcap);

                    TextView termTitle = interView.findViewById(R.id.proto_terminal_title);
                    TextView termContent = interView.findViewById(R.id.proto_terminal_content);

                    MaterialButton[] protoBtns = new MaterialButton[]{btnTls, btnHttp, btnQuic, btnDns, btnPcap};

                    Runnable resetAll = () -> {
                        for (MaterialButton b : protoBtns) {
                            setButtonSelected(b, false, colorAccent, colorDrawer);
                        }
                    };

                    btnTls.setOnClickListener(v -> {
                        resetAll.run();
                        setButtonSelected(btnTls, true, colorAccent, colorDrawer);
                        termTitle.setText("TLS 1.3 Decryption Engine");
                        termContent.setText("SNI: auth.example.com\nCipher: TLS_AES_256_GCM_SHA384\nStatus: Encrypted stream dissected via user CA");
                    });

                    btnHttp.setOnClickListener(v -> {
                        resetAll.run();
                        setButtonSelected(btnHttp, true, colorAccent, colorDrawer);
                        termTitle.setText("HTTP/2 Stream Multiplexer");
                        termContent.setText("HEADERS: :method=POST :path=/api/v2 :scheme=https\nFrame: DATA (1,024 bytes) flags=END_STREAM");
                    });

                    btnQuic.setOnClickListener(v -> {
                        resetAll.run();
                        setButtonSelected(btnQuic, true, colorAccent, colorDrawer);
                        termTitle.setText("QUIC / HTTP/3 UDP Engine");
                        termContent.setText("Initial CID: 0x8f3c1a • Version: 1\nProtocol: UDP 443 detected & deep-inspected");
                    });

                    btnDns.setOnClickListener(v -> {
                        resetAll.run();
                        setButtonSelected(btnDns, true, colorAccent, colorDrawer);
                        termTitle.setText("DNS Sinkhole Responder");
                        termContent.setText("Query: telemetry.tracker.com (A)\nVerdict: Blocked (Sinkholed to 0.0.0.0)");
                    });

                    btnPcap.setOnClickListener(v -> {
                        resetAll.run();
                        setButtonSelected(btnPcap, true, colorAccent, colorDrawer);
                        termTitle.setText("PCAPNG Packet Capture");
                        termContent.setText("Format: PCAP Next Generation\nFeatures: Nanosecond timestamps, drops counter & Wireshark export");
                    });

                    container.addView(interView);
                    break;
                }
                case 6: {
                    View interView = inflater.inflate(R.layout.intro_interactive_slide_6, container, false);
                    CheckBox chk1 = interView.findViewById(R.id.chk_privacy_1);
                    CheckBox chk2 = interView.findViewById(R.id.chk_privacy_2);
                    CheckBox chk3 = interView.findViewById(R.id.chk_privacy_3);
                    TextView verdictText = interView.findViewById(R.id.privacy_verdict_text);

                    Runnable updateVerdict = () -> {
                        if (chk1.isChecked() && chk2.isChecked() && chk3.isChecked()) {
                            verdictText.setText("Trust Verification: 100% Verified Private Enclave 🛡️");
                        } else {
                            verdictText.setText("Trust Settings: Custom privacy policy configuration");
                        }
                    };

                    chk1.setOnCheckedChangeListener((b, c) -> updateVerdict.run());
                    chk2.setOnCheckedChangeListener((b, c) -> updateVerdict.run());
                    chk3.setOnCheckedChangeListener((b, c) -> updateVerdict.run());

                    container.addView(interView);
                    break;
                }
            }
        }

        private void setButtonSelected(MaterialButton btn, boolean selected, int accentColor, int textColor) {
            if (btn == null) return;
            if (selected) {
                btn.setBackgroundTintList(ColorStateList.valueOf(accentColor));
                btn.setTextColor(ContextCompat.getColor(requireContext(), android.R.color.white));
                btn.setStrokeWidth(0);
            } else {
                btn.setBackgroundTintList(ColorStateList.valueOf(0x00000000));
                btn.setTextColor(textColor);
                btn.setStrokeColor(ColorStateList.valueOf(0x406366F1));
                btn.setStrokeWidth((int) (1 * getResources().getDisplayMetrics().density));
            }
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        boolean backEnabled = false;
        setImmersiveMode();

        Intent intent = getIntent();
        if (intent != null)
            backEnabled = intent.getBooleanExtra(ENABLE_BACK_BUTTON, false);

        // Slide 1: KotSafe Cyber Defense Suite
        addSlide(KotSafeSlideFragment.createInstance(
                1,
                R.drawable.ic_logo, 0,
                R.string.kotsafe_intro_badge_1,
                R.string.kotsafe_intro_title_1,
                R.string.kotsafe_intro_subtitle_1,
                R.string.kotsafe_intro_feat_1_1_title, R.string.kotsafe_intro_feat_1_1_desc,
                R.string.kotsafe_intro_feat_1_2_title, R.string.kotsafe_intro_feat_1_2_desc,
                R.string.kotsafe_intro_feat_1_3_title, R.string.kotsafe_intro_feat_1_3_desc,
                R.string.kotsafe_intro_feat_1_4_title, R.string.kotsafe_intro_feat_1_4_desc
        ));

        // Slide 2: Real-Time Antivirus & Malware Defense
        addSlide(KotSafeSlideFragment.createInstance(
                2,
                R.drawable.intro_slide_antivirus, 0,
                R.string.kotsafe_intro_badge_2,
                R.string.kotsafe_intro_title_2,
                R.string.kotsafe_intro_subtitle_2,
                R.string.kotsafe_intro_feat_2_1_title, R.string.kotsafe_intro_feat_2_1_desc,
                R.string.kotsafe_intro_feat_2_2_title, R.string.kotsafe_intro_feat_2_2_desc,
                R.string.kotsafe_intro_feat_2_3_title, R.string.kotsafe_intro_feat_2_3_desc,
                R.string.kotsafe_intro_feat_2_4_title, R.string.kotsafe_intro_feat_2_4_desc
        ));

        // Slide 3: Intelligent App & Domain Firewall
        addSlide(KotSafeSlideFragment.createInstance(
                3,
                R.drawable.intro_slide_firewall, 0,
                R.string.kotsafe_intro_badge_3,
                R.string.kotsafe_intro_title_3,
                R.string.kotsafe_intro_subtitle_3,
                R.string.kotsafe_intro_feat_3_1_title, R.string.kotsafe_intro_feat_3_1_desc,
                R.string.kotsafe_intro_feat_3_2_title, R.string.kotsafe_intro_feat_3_2_desc,
                R.string.kotsafe_intro_feat_3_3_title, R.string.kotsafe_intro_feat_3_3_desc,
                R.string.kotsafe_intro_feat_3_4_title, R.string.kotsafe_intro_feat_3_4_desc
        ));

        // Slide 4: Personal Gateway & P2P Encrypted Mesh
        addSlide(KotSafeSlideFragment.createInstance(
                4,
                R.drawable.intro_slide_mesh, 0,
                R.string.kotsafe_intro_badge_4,
                R.string.kotsafe_intro_title_4,
                R.string.kotsafe_intro_subtitle_4,
                R.string.kotsafe_intro_feat_4_1_title, R.string.kotsafe_intro_feat_4_1_desc,
                R.string.kotsafe_intro_feat_4_2_title, R.string.kotsafe_intro_feat_4_2_desc,
                R.string.kotsafe_intro_feat_4_3_title, R.string.kotsafe_intro_feat_4_3_desc,
                R.string.kotsafe_intro_feat_4_4_title, R.string.kotsafe_intro_feat_4_4_desc
        ));

        // Slide 5: Deep Packet Inspection & Decryption
        addSlide(KotSafeSlideFragment.createInstance(
                5,
                R.drawable.intro_slide_inspection, 0,
                R.string.kotsafe_intro_badge_5,
                R.string.kotsafe_intro_title_5,
                R.string.kotsafe_intro_subtitle_5,
                R.string.kotsafe_intro_feat_5_1_title, R.string.kotsafe_intro_feat_5_1_desc,
                R.string.kotsafe_intro_feat_5_2_title, R.string.kotsafe_intro_feat_5_2_desc,
                R.string.kotsafe_intro_feat_5_3_title, R.string.kotsafe_intro_feat_5_3_desc,
                R.string.kotsafe_intro_feat_5_4_title, R.string.kotsafe_intro_feat_5_4_desc
        ));

        // Slide 6: Zero-Log Privacy & Transparency
        addSlide(KotSafeSlideFragment.createInstance(
                6,
                R.drawable.intro_slide_privacy, 0,
                R.string.kotsafe_intro_badge_6,
                R.string.kotsafe_intro_title_6,
                R.string.kotsafe_intro_subtitle_6,
                R.string.kotsafe_intro_feat_6_1_title, R.string.kotsafe_intro_feat_6_1_desc,
                R.string.kotsafe_intro_feat_6_2_title, R.string.kotsafe_intro_feat_6_2_desc,
                R.string.kotsafe_intro_feat_6_3_title, R.string.kotsafe_intro_feat_6_3_desc,
                R.string.kotsafe_intro_feat_6_4_title, R.string.kotsafe_intro_feat_6_4_desc
        ));

        showStatusBar(true);
        setSkipButtonEnabled(true);
        setIndicatorEnabled(true);
        setSystemBackButtonLocked(!backEnabled);

        // Theme colors for navigation controls
        int colorAccent = ContextCompat.getColor(this, R.color.colorAccent);
        int colorAccentLight = ContextCompat.getColor(this, R.color.colorAccentLight);
        setIndicatorColor(colorAccent, colorAccentLight);
        setBackArrowColor(colorAccent);
        setColorSkipButton(colorAccent);
        setNextArrowColor(colorAccent);
        setColorDoneText(colorAccent);
    }

    @Override
    protected void onSkipPressed(@Nullable Fragment currentFragment) {
        Log.d(TAG, "onSkipPressed");
        super.onSkipPressed(currentFragment);
        runMainActivity();
    }

    @Override
    protected void onDonePressed(@Nullable Fragment currentFragment) {
        Log.d(TAG, "onDonePressed");
        super.onDonePressed(currentFragment);
        runMainActivity();
    }

    private void runMainActivity() {
        Prefs.refreshAppVersion(PreferenceManager.getDefaultSharedPreferences(this));

        // Mandatory Authentication: New users must authenticate before accessing security services
        Intent loginIntent = new Intent(this, LoginActivity.class);
        loginIntent.putExtra(LoginActivity.EXTRA_FROM_ONBOARDING, true);
        loginIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        startActivity(loginIntent);
        finish();
    }
}
