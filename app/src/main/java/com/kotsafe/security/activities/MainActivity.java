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

import android.Manifest;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;

import androidx.activity.OnBackPressedCallback;
import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts.RequestPermission;
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult;
import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.appcompat.app.ActionBarDrawerToggle;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatDelegate;
import androidx.appcompat.widget.Toolbar;
import androidx.appcompat.widget.PopupMenu;
import androidx.core.content.ContextCompat;
import com.kotsafe.security.views.AnimUtils;
import androidx.core.content.pm.PackageInfoCompat;
import androidx.core.graphics.Insets;
import androidx.core.view.GravityCompat;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.drawerlayout.widget.DrawerLayout;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.preference.PreferenceManager;
import androidx.core.widget.ImageViewCompat;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewpager2.adapter.FragmentStateAdapter;
import androidx.viewpager2.widget.ViewPager2;

import android.content.res.ColorStateList;
import android.os.Build;
import android.animation.ObjectAnimator;
import android.graphics.Color;
import android.os.Bundle;
import android.os.SystemClock;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AlphaAnimation;
import android.view.animation.Animation;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import com.kotsafe.security.AppsResolver;
import com.kotsafe.security.Billing;
import com.kotsafe.security.BuildConfig;
import com.kotsafe.security.CaptureHelper;
import com.kotsafe.security.ConnectionsRegister;
import com.kotsafe.security.Log;
import com.kotsafe.security.MitmReceiver;
import com.kotsafe.security.KotSafe;
import com.kotsafe.security.VpnReconnectService;
import com.kotsafe.security.activities.prefs.SettingsActivity;
import com.kotsafe.security.activities.AlertsCenterActivity;
import com.kotsafe.security.activities.MitreAttackActivity;
import com.kotsafe.security.fragments.DataViewContainerFragment;
import com.kotsafe.security.fragments.StatusFragment;
import com.kotsafe.security.interfaces.AppStateListener;
import com.kotsafe.security.model.AppDescriptor;
import com.kotsafe.security.model.AppStats;
import com.kotsafe.security.model.AppState;
import com.kotsafe.security.CaptureService;
import com.kotsafe.security.model.Blocklist;
import com.kotsafe.security.model.CaptureSettings;
import com.kotsafe.security.MitmAddon;
import com.kotsafe.security.model.CaptureStats;
import com.kotsafe.security.model.ConnectionDescriptor;
import com.kotsafe.security.model.ListInfo;
import com.kotsafe.security.model.CaptureList;
import com.kotsafe.security.model.Prefs;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import android.content.res.Configuration;
import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.google.android.material.navigation.NavigationView;
import com.google.android.material.tabs.TabLayout;
import com.google.android.material.tabs.TabLayoutMediator;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends BaseActivity {
    private Billing mIab;
    private ViewPager2 mPager;
    private BottomNavigationView mBottomNav;
    private AppState mState;
    private AppStateListener mListener;
    private File mKeylogFile;
    private SharedPreferences mPrefs;
    private CaptureHelper mCapHelper;
    private AlertDialog mPcapLoadDialog;
    private ExecutorService mPcapExecutor;
    private MenuItem mMenuItemOpenPcap;

    // Navbar live-status
    private TextView mToolbarStatusLabel;
    private ImageView mToolbarLogo;
    private Animation mLogoPulse;

    // Swap-button color cycle: 0=green, 1=blue, 2=yellow
    private int mSwapColorIndex = 0;
    private static final int[] SWAP_COLORS = {
        0xFF22C55E,  // green
        0xFF3B82F6,  // blue
        0xFFEAB308   // yellow
    };

    // helps detecting duplicate state reporting of STOPPED in MutableLiveData
    private boolean mWasStarted = false;
    private boolean mStartPressed = false;
    private boolean mDecEmptyRulesNoticeShown = false;
    private boolean mExtensionsNoticeShown = false;
    private boolean mDecryptPcap = false;

    private static final String TAG = "Main";

    private static final int POS_STATUS = 0;
    private static final int POS_CONNECTIONS = 1;
    private static final int TOTAL_COUNT = 2;

    public static final String TELEGRAM_GROUP_NAME = "KotSafe";
    public static final String GITHUB_PROJECT_URL = "https://github.com/CyberResercher/Kotsafe";
    public static final String DOCS_URL = "https://github.com/CyberResercher/Kotsafe#readme";
    public static final String PRIVACY_POLICY_URL = GITHUB_PROJECT_URL + "/blob/main/KotSafe_User_Guide/README.md";
    public static final String TLS_DECRYPTION_DOCS_URL = GITHUB_PROJECT_URL + "/blob/main/KotSafe_User_Guide/05_TLS_DECRYPTION_AND_INSPECTION.md";
    public static final String PAID_FEATURES_URL = GITHUB_PROJECT_URL + "/blob/main/KotSafe_User_Guide/README.md";
    public static final String FIREWALL_DOCS_URL = GITHUB_PROJECT_URL + "/blob/main/KotSafe_User_Guide/02_FIREWALL_AND_NETWORK_ACCESS_CONTROL.md";
    public static final String MALWARE_DETECTION_DOCS_URL = GITHUB_PROJECT_URL + "/blob/main/KotSafe_User_Guide/03_ANTIVIRUS_AND_MALWARE_DEFENSE.md";
    public static final String API_DOCS_URL = GITHUB_PROJECT_URL + "/blob/main/KotSafe_User_Guide/README.md";
    public static final String PCAPNG_DOCS_URL = GITHUB_PROJECT_URL + "/blob/main/KotSafe_User_Guide/README.md";

    private final ActivityResultLauncher<Intent> sslkeyfileExportLauncher =
            registerForActivityResult(new StartActivityForResult(), this::sslkeyfileExportResult);
    private final ActivityResultLauncher<String> requestPermissionLauncher =
            registerForActivityResult(new RequestPermission(), isGranted ->
                Log.d(TAG, "Write permission " + (isGranted ? "granted" : "denied"))
            );
    private final ActivityResultLauncher<Intent> peerInfoLauncher =
            registerForActivityResult(new StartActivityForResult(), this::peerInfoResult);
    private final ActivityResultLauncher<Intent> pcapFileOpenLauncher =
            registerForActivityResult(new StartActivityForResult(), this::pcapFileOpenResult);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        setTheme(R.style.AppTheme_NoActionBar);
        super.onCreate(savedInstanceState);

        setContentView(R.layout.main_activity);
        setTitle("KotSafe");
        mPrefs = PreferenceManager.getDefaultSharedPreferences(this);

        int appver = Prefs.getAppVersion(mPrefs);
        if(appver <= 0) {
            // First run, start on-boarding
            // only refresh app version on on-boarding done
            Intent intent = new Intent(MainActivity.this, OnBoardingActivity.class);
            startActivity(intent);
            finish();
            return;
        } else {
            if (appver < 92)
                showWhatsNew();

            Prefs.refreshAppVersion(mPrefs);
        }

        mIab = Billing.newInstance(this);

        initPeerAppInfo();
        initAppState();

        mCapHelper = new CaptureHelper(this);
        mCapHelper.setListener(success -> {
            if(!success) {
                Log.w(TAG, "Capture start failed");
                appStateReady();
            }
        });

        mPager = findViewById(R.id.pager);
        Utils.fixViewPager2Insets(mPager);
        setupTabs();

        mBottomNav = findViewById(R.id.bottom_navigation);
        if (mBottomNav != null) {
            mBottomNav.setOnItemSelectedListener(item -> {
                int itemId = item.getItemId();
                if (itemId == R.id.nav_bottom_home) {
                    mPager.setCurrentItem(POS_STATUS);
                    resetDataView();
                    return true;
                } else if (itemId == R.id.nav_bottom_firewall) {
                    startActivity(new Intent(MainActivity.this, FirewallActivity.class));
                    return false;
                } else if (itemId == R.id.nav_bottom_scan) {
                    startActivity(new Intent(MainActivity.this, AntivirusScanActivity.class));
                    return false;
                } else if (itemId == R.id.nav_bottom_settings) {
                    startActivity(new Intent(MainActivity.this, SettingsActivity.class));
                    return false;
                }
                return false;
            });
        }

        /* Register for service status */
        CaptureService.observeStatus(this, serviceStatus -> {
            Log.d(TAG, "Service status: " + serviceStatus.name());

            if (serviceStatus == CaptureService.ServiceStatus.STARTED) {
                appStateRunning();
                mWasStarted = true;
            } else if(mWasStarted) { /* STARTED -> STOPPED */
                // The service may still be active (on premature native termination)
                if (CaptureService.isServiceActive())
                    CaptureService.stopService();

                mKeylogFile = MitmReceiver.getKeylogFilePath(MainActivity.this);
                if(!mKeylogFile.exists() || !CaptureService.isDecryptingTLS())
                    mKeylogFile = null;

                Log.d(TAG, "sslkeylog? " + (mKeylogFile != null));

                CaptureSettings settings = CaptureService.getCaptureSettings();

                // do not show "PCAP saved" dialog and keylog export if capture was started through API
                if((settings != null) && settings.api_capture) {
                    if(mKeylogFile != null) {
                        // optionally save SSLKEYLOGFILE to the Downloads directory under the
                        // user-provided name, then drop the cached keylog
                        if (!settings.sslkeylog_name.isBlank()
                                && writeKeylogToDownloads(settings.sslkeylog_name))
                            Utils.showToast(this, R.string.save_ok);

                        discardKeylogFile();
                    }

                    // reset the decryption list after API capture in case it was set
                    if(!settings.decryption_rules_json.isBlank())
                        KotSafe.getInstance().getDecryptionList().reload();
                } else {
                    if ((settings != null) && (settings.dump_mode == Prefs.DumpMode.PCAP_FILE)) {
                        showPcapActionDialog();

                        // will export the keylogfile after saving/sharing pcap
                    } else if (mKeylogFile != null)
                        startExportSslkeylogfile();
                }

                appStateReady();
                mWasStarted = false;
                mStartPressed = false;
            } else /* STOPPED -> STOPPED */
                appStateReady();
        });
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();

        if(!CaptureService.isServiceActive()) {
            boolean ignored = getTmpPcapPath().delete();
        }

        mCapHelper = null;
    }

    @Override
    protected void onPostCreate(Bundle savedInstanceState) {
        super.onPostCreate(savedInstanceState);
        setupToolbar();
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        if (intent != null) {
            String pcapUri = intent.getStringExtra(CaptureListActivity.OPEN_PCAP_EXTRA);
            if (pcapUri != null)
                startOpenPcap(Uri.parse(pcapUri));

            if (intent.getBooleanExtra(com.kotsafe.security.model.VpnAlertHelper.EXTRA_REQUEST_START_VPN, false)) {
                intent.removeExtra(com.kotsafe.security.model.VpnAlertHelper.EXTRA_REQUEST_START_VPN);
                if (!CaptureService.isServiceActive()) {
                    startCapture();
                } else {
                    CaptureService.stopService();
                    if (mPager != null) {
                        mPager.postDelayed(this::startCapture, 1200);
                    }
                }
            }
            if ("connections".equals(intent.getStringExtra("open_tab"))) {
                intent.removeExtra("open_tab");
                mPager.setCurrentItem(POS_CONNECTIONS);
            }
            handleGatewayIntent(intent);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (getIntent() != null && "connections".equals(getIntent().getStringExtra("open_tab"))) {
            getIntent().removeExtra("open_tab");
            mPager.setCurrentItem(POS_CONNECTIONS);
        }

        Intent intent = getIntent();
        if (intent != null) {
            if (intent.getBooleanExtra(com.kotsafe.security.model.VpnAlertHelper.EXTRA_REQUEST_START_VPN, false)) {
                intent.removeExtra(com.kotsafe.security.model.VpnAlertHelper.EXTRA_REQUEST_START_VPN);
                if (!CaptureService.isServiceActive()) {
                    startCapture();
                } else {
                    CaptureService.stopService();
                    if (mPager != null) {
                        mPager.postDelayed(this::startCapture, 1200);
                    }
                }
            }
            handleGatewayIntent(intent);
        }
    }

    private void handleGatewayIntent(Intent intent) {
        if (intent == null || intent.getData() == null) return;
        Uri uri = intent.getData();
        if ("kotsafe-gateway".equals(uri.getScheme())) {
            intent.setData(null);
            String raw = uri.toString();
            try {
                com.kotsafe.security.p2p.SecurePairingBundle bundle =
                        com.kotsafe.security.p2p.SecurePairingBundle.parse(raw);
                new AlertDialog.Builder(this)
                        .setTitle("Personal Gateway Pairing")
                        .setMessage("Connect to Exit Node Room:\n" + bundle.room + "\n\nRelay: " + bundle.controlUrl + "\n\nDo you want to pair and route traffic through this exit node?")
                        .setPositiveButton("Connect & Route", (dialog, which) -> {
                            SharedPreferences p = PreferenceManager.getDefaultSharedPreferences(MainActivity.this);
                            if (bundle.controlUrl != null && !bundle.controlUrl.isEmpty()) {
                                if (bundle.controlUrl.contains("130.210.16.110")) {
                                    p.edit().putString("personal_gateway_relay_mode", "direct_vps").apply();
                                } else if (bundle.controlUrl.contains("trycloudflare.com")) {
                                    p.edit().putString("personal_gateway_relay_mode", "cloudflare_tunnel").apply();
                                } else {
                                    p.edit().putString("personal_gateway_relay_mode", "custom")
                                            .putString("personal_gateway_custom_relay_url", bundle.controlUrl)
                                            .apply();
                                }
                                com.kotsafe.security.model.backend.BackendProviderFactory.invalidateCache();
                            }
                            com.kotsafe.security.model.backend.CustomHttpProvider.configureCipher(bundle.room, bundle.pairingSecret);

                            String deviceId = p.getString(com.kotsafe.security.p2p.GatewayPreferenceKeys.DEVICE_ID, "");
                            if (deviceId.isEmpty()) {
                                deviceId = "dev_" + Utils.genRandomString(12);
                                p.edit().putString(com.kotsafe.security.p2p.GatewayPreferenceKeys.DEVICE_ID, deviceId).apply();
                            }
                            final String fDeviceId = deviceId;
                            com.kotsafe.security.model.BackendProvider bp =
                                    com.kotsafe.security.model.backend.BackendProviderFactory.getConfigured(MainActivity.this);
                            if (bp != null) {
                                bp.claimPairing(bundle, fDeviceId, new com.kotsafe.security.model.BackendProvider.ClaimCallback() {
                                    @Override
                                    public void onSuccess(String clientToken, long expiresInSeconds) {
                                        runOnUiThread(() -> {
                                            p.edit()
                                                    .putString(com.kotsafe.security.p2p.GatewayPreferenceKeys.PAIRING_BUNDLE, raw)
                                                    .putString(Prefs.PREF_P2P_BACKEND_PAIRING, clientToken)
                                                    .putBoolean(com.kotsafe.security.p2p.GatewayPreferenceKeys.CLIENT_ENABLED, true)
                                                    .putBoolean(Prefs.PREF_SOCKS5_ENABLED_KEY, true)
                                                    .putString(Prefs.PREF_SOCKS5_PROXY_IP_KEY, "127.0.0.1")
                                                    .putString(Prefs.PREF_SOCKS5_PROXY_HOST_KEY, "127.0.0.1")
                                                    .putString(Prefs.PREF_SOCKS5_PROXY_PORT_KEY, "8095")
                                                    .putBoolean(Prefs.PREF_SOCKS5_AUTH_ENABLED_KEY, false)
                                                    .putString(Prefs.PREF_BLOCK_QUIC, Prefs.BLOCK_QUIC_MODE_ALWAYS)
                                                    .putString(Prefs.PREF_IP_MODE, Prefs.IP_MODE_BOTH)
                                                    .apply();

                                            String profName = "Exit Node (" + (bundle.room.length() > 8 ? bundle.room.substring(0, 8) : bundle.room) + ")";
                                            com.kotsafe.security.p2p.GatewayProfile prof = new com.kotsafe.security.p2p.GatewayProfile(
                                                    "prof_" + System.currentTimeMillis(), profName, raw, clientToken, System.currentTimeMillis());
                                            com.kotsafe.security.p2p.GatewayProfileManager.saveProfile(MainActivity.this, prof);
                                            com.kotsafe.security.p2p.GatewayProfileManager.setActiveProfile(MainActivity.this, prof);

                                            try {
                                                com.kotsafe.security.model.backend.CustomHttpProvider.ensureCipherConfigured(MainActivity.this);
                                                bp.startRelayLoopback(clientToken, 8095);
                                                CaptureService.updateSocks5Proxy("127.0.0.1", 8095);
                                            } catch (Exception ignored) {}

                                            Toast.makeText(MainActivity.this, "Paired successfully with Exit Node!", Toast.LENGTH_SHORT).show();
                                            if (!CaptureService.isServiceActive()) {
                                                startCapture();
                                            } else {
                                                CaptureService.stopService();
                                                Toast.makeText(MainActivity.this, "Restarting VPN Capture to route traffic...", Toast.LENGTH_SHORT).show();
                                                if (mPager != null) {
                                                    mPager.postDelayed(() -> startCapture(), 1000);
                                                }
                                            }
                                        });
                                    }

                                    @Override
                                    public void onError(String message) {
                                        runOnUiThread(() -> {
                                            Toast.makeText(MainActivity.this, "Failed to pair: " + message, Toast.LENGTH_LONG).show();
                                        });
                                    }
                                });
                            }
                        })
                        .setNegativeButton(android.R.string.cancel, null)
                        .show();
            } catch (Exception e) {
                Log.w(TAG, "Failed to parse gateway URI: " + e.getMessage());
            }
        }
    }

    private void setupToolbar() {
        Toolbar toolbar = findViewById(R.id.toolbar);
        if (toolbar != null) {
            setSupportActionBar(toolbar);
            if (getSupportActionBar() != null) {
                getSupportActionBar().setDisplayShowTitleEnabled(false);
            }
        }

        // Wire redesign top action buttons
        View btnAccount = findViewById(R.id.btn_account);
        if (btnAccount != null) {
            AnimUtils.attachSpringTouch(btnAccount);
            btnAccount.setOnClickListener(v -> showSecurityProfileDialog());
        }

        View btnStop = findViewById(R.id.btn_stop);
        if (btnStop != null) {
            AnimUtils.attachSpringTouch(btnStop);
            btnStop.setOnClickListener(v -> stopCapture());
        }

        View btnMore = findViewById(R.id.btn_more);
        if (btnMore != null) {
            AnimUtils.attachSpringTouch(btnMore);
            btnMore.setOnClickListener(this::showMorePopupMenu);
        }

        // Wire live-status views
        mToolbarStatusLabel = findViewById(R.id.toolbar_status_label);
        mToolbarLogo = findViewById(R.id.toolbar_logo);

        // Build a subtle pulse animation for the logo when capture is running
        mLogoPulse = new AlphaAnimation(1f, 0.55f);
        mLogoPulse.setDuration(900);
        mLogoPulse.setRepeatCount(Animation.INFINITE);
        mLogoPulse.setRepeatMode(Animation.REVERSE);

        updateToolbarStatus();
    }

    private void showMorePopupMenu(View anchor) {
        PopupMenu popup = new PopupMenu(this, anchor);
        popup.getMenuInflater().inflate(R.menu.main_activity_menu, popup.getMenu());
        MenuItem pcapItem = popup.getMenu().findItem(R.id.open_pcap);
        if (pcapItem != null) {
            pcapItem.setEnabled((mState == AppState.ready) || (mState == AppState.starting));
        }
        MenuItem themeToggle = popup.getMenu().findItem(R.id.action_theme_toggle);
        if (themeToggle != null) {
            boolean isNight = (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES;
            themeToggle.setIcon(isNight ? R.drawable.ic_theme_sun : R.drawable.ic_theme_moon);
            themeToggle.setTitle(isNight ? R.string.theme_light : R.string.theme_dark);
        }
        popup.setOnMenuItemClickListener(this::onOptionsItemSelected);
        popup.show();
    }

    /**
     * Updates the live status dot + label in the toolbar branding area to reflect
     * the current AppState.  Called from every appState*() transition method.
     */
    private void updateToolbarStatus() {
        View btnStop = findViewById(R.id.btn_stop);
        if (btnStop != null) {
            btnStop.setVisibility((mState == AppState.running) ? View.VISIBLE : View.GONE);
        }

        if (mToolbarStatusLabel == null) return;

        final String text;
        final int color;
        final boolean pulse;

        if (mState == null || mState == AppState.ready) {
            text  = "● IDLE";
            color = ContextCompat.getColor(this, R.color.ks_accent);
            pulse = false;
        } else if (mState == AppState.starting) {
            text  = "⊙ STARTING";
            color = Color.parseColor("#F59E0B"); // amber
            pulse = true;
        } else if (mState == AppState.running) {
            text  = "● PROTECTED";
            color = ContextCompat.getColor(this, R.color.ks_accent);
            pulse = true;
        } else { // stopping
            text  = "◌ STOPPING";
            color = Color.parseColor("#FF9800"); // orange
            pulse = false;
        }

        mToolbarStatusLabel.setText(text);
        mToolbarStatusLabel.setTextColor(color);

        // Pulse the shield logo while the VPN is active
        if (mToolbarLogo != null) {
            if (pulse) {
                if (mToolbarLogo.getAnimation() == null) {
                    mToolbarLogo.startAnimation(mLogoPulse);
                }
            } else {
                mToolbarLogo.clearAnimation();
                mToolbarLogo.setAlpha(1f);
            }
        }
    }

    private void showWhatsNew() {
        new AlertDialog.Builder(this)
                .setTitle(R.string.whats_new)
                .setMessage(
                        "- New Capture List view\n" +
                        "- Implement app isolation (Firewall)\n" +
                        "- Add ability to import/export settings\n" +
                        "- Android 17 support\n" +
                        "- Mitm addon v2.3 (mitmproxy 12.2.3)\n" +
                        "- Translations: BN, FR, HI, JA, KO, MS, UR, VI\n" +
                        "- Bug fixes and dependency updates\n"
                )
                .setNeutralButton(R.string.ok, (dialogInterface, i) -> {})
                .show();
    }

    private void checkPaidDrawerEntries() {
        // Firewall & Malware toggles moved to their respective primary bottom tabs
    }


    @RequiresApi(api = Build.VERSION_CODES.TIRAMISU)
    private void requestNotificationPermission() {
        try {
            requestPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS);
        } catch (ActivityNotFoundException e) {
            Utils.showToastLong(this, R.string.no_intent_handler_found);
        }
    }

    // On debug builds, if the user also has the non-debug app installed (peer app), unlock the
    // already-purchased features also on this beta app
    private void initPeerAppInfo() {
        if(!BuildConfig.APPLICATION_ID.equals("com.kotsafe.security.debug"))
            return;

        final String peerAppPackage = "com.kotsafe.security";

        AppDescriptor peer = AppsResolver.resolveInstalledApp(getPackageManager(), peerAppPackage, 0);
        if(peer == null) {
            Log.d(TAG, "Peer app not found");
            mIab.clearPeerSkus();
            return;
        }

        PackageInfo pInfo = peer.getPackageInfo();
        if((pInfo == null) || (PackageInfoCompat.getLongVersionCode(pInfo) < 56)) {
            Log.d(TAG, "Unsupported peer app version found");
            mIab.clearPeerSkus();
            return;
        }

        // Verify that the peer signature
        Utils.BuildType buildType = Utils.getVerifiedBuild(this, peerAppPackage);
        if((buildType != Utils.BuildType.FDROID) && (buildType != Utils.BuildType.PLAYSTORE) && (buildType != Utils.BuildType.GITHUB)) {
            Log.d(TAG, "Unsupported peer app build: " + buildType.name());
            mIab.clearPeerSkus();
            return;
        }

        Log.d(TAG, "Valid peer app found (" + pInfo.versionName + " - " + PackageInfoCompat.getLongVersionCode(pInfo) + ")");
        Intent intent = new Intent(Intent.ACTION_VIEW);
        intent.setClassName(peerAppPackage, "com.kotsafe.security.activities.CaptureCtrl");
        intent.putExtra("action", "get_peer_info");

        try {
            peerInfoLauncher.launch(intent);
        } catch (ActivityNotFoundException e) {
            Log.d(TAG, "Peer app launch failed");
            mIab.clearPeerSkus();
        }
    }

    private void peerInfoResult(final ActivityResult result) {
        if((result.getResultCode() == RESULT_OK) && (result.getData() != null)) {
            Intent data = result.getData();

            try {
                @SuppressWarnings("unchecked")
                HashSet<String> skus = Utils.getSerializableExtra(data, "skus", HashSet.class);

                if(skus != null) {
                    Log.d(TAG, "Found peer app info");

                    mIab.handlePeerSkus(skus);

                    // success
                    return;
                }
            } catch (ClassCastException ignored) {}
        }

        // fail
        Log.d(TAG, "Invalid peer app result");
        mIab.clearPeerSkus();
    }

    private static class MainStateAdapter extends FragmentStateAdapter {
        MainStateAdapter(final FragmentActivity fa) { super(fa); }

        @NonNull
        @Override
        public Fragment createFragment(int position) {
            Log.d(TAG, "createFragment");

            switch (position) {
                default: // Deliberate fall-through to status tab
                case POS_STATUS:
                    return new StatusFragment();
                case POS_CONNECTIONS:
                    return new DataViewContainerFragment();
            }
        }

        @Override
        public int getItemCount() {  return TOTAL_COUNT;  }

        public int getPageTitle(final int position) {
            switch (position) {
                default: // Deliberate fall-through to status tab
                case POS_STATUS:
                    return R.string.status;
                case POS_CONNECTIONS:
                    return R.string.connections_view;
            }
        }
    }

    private void setupTabs() {
        final MainStateAdapter stateAdapter = new MainStateAdapter(this);
        mPager.setAdapter(stateAdapter);

        final TextView tabStatus = findViewById(R.id.tab_status);
        final TextView tabTraffic = findViewById(R.id.tab_traffic);
        if (tabStatus != null && tabTraffic != null) {
            AnimUtils.attachSpringTouch(tabStatus);
            AnimUtils.attachSpringTouch(tabTraffic);
            tabStatus.setSelected(true);
            tabTraffic.setSelected(false);
            tabStatus.setOnClickListener(v -> mPager.setCurrentItem(POS_STATUS));
            tabTraffic.setOnClickListener(v -> {
                if (mPager.getCurrentItem() != POS_CONNECTIONS) {
                    mPager.setCurrentItem(POS_CONNECTIONS);
                } else {
                    cycleDataView();
                }
            });
        }

        View switchButton = findViewById(R.id.tab_switch_button);
        if (switchButton != null) {
            AnimUtils.attachSpringTouch(switchButton);
            switchButton.setOnClickListener(v -> cycleDataView());
            switchButton.setOnLongClickListener(v -> {
                if (mPager != null && mPager.getCurrentItem() != POS_CONNECTIONS) {
                    mPager.setCurrentItem(POS_CONNECTIONS);
                }
                Fragment container = getFragmentAtPos(POS_CONNECTIONS);
                if (container instanceof DataViewContainerFragment) {
                    ((DataViewContainerFragment) container).resetToConnectionsView();
                    updateDataViewMode(DataViewContainerFragment.VIEW_CONNECTIONS);
                    Toast.makeText(MainActivity.this, R.string.connections_view, Toast.LENGTH_SHORT).show();
                }
                return true;
            });
            updateTabSwitchButton();
        }

        updateDataViewMode(DataViewContainerFragment.VIEW_CONNECTIONS);

        mPager.registerOnPageChangeCallback(new ViewPager2.OnPageChangeCallback() {
            @Override
            public void onPageSelected(int position) {
                super.onPageSelected(position);
                if (tabStatus != null && tabTraffic != null) {
                    tabStatus.setSelected(position == POS_STATUS);
                    tabTraffic.setSelected(position != POS_STATUS);
                }
                if (mBottomNav != null) {
                    if (position == POS_STATUS) {
                        mBottomNav.getMenu().findItem(R.id.nav_bottom_home).setChecked(true);
                    }
                }
            }
        });
    }

    public void cycleDataView() {
        if (mPager == null) return;
        int currentTab = mPager.getCurrentItem();

        if (currentTab != POS_CONNECTIONS) {
            mPager.setCurrentItem(POS_CONNECTIONS);
        }

        Fragment container = getFragmentAtPos(POS_CONNECTIONS);
        if (container instanceof DataViewContainerFragment) {
            DataViewContainerFragment dv = (DataViewContainerFragment) container;
            dv.toggleView();
            updateDataViewMode(dv.getCurrentView());
        }
    }

    public void updateDataViewMode(int currentView) {
        TextView tabTraffic = findViewById(R.id.tab_traffic);
        android.widget.ImageButton switchButton = findViewById(R.id.tab_switch_button);
        if (tabTraffic == null || switchButton == null) return;

        // Sequence: Traffic (Green) -> HTTP Request (Red) -> HTTP Repeated (Yellow) -> Traffic (Green)
        if (currentView == DataViewContainerFragment.VIEW_CONNECTIONS) {
            tabTraffic.setText(R.string.ks_tab_traffic);
            switchButton.setImageTintList(ColorStateList.valueOf(Color.parseColor("#0E9F83"))); // Green
            switchButton.setContentDescription("Switch to HTTP Request");
        } else if (currentView == DataViewContainerFragment.VIEW_HTTP_LOG) {
            tabTraffic.setText("HTTP Request");
            switchButton.setImageTintList(ColorStateList.valueOf(Color.parseColor("#E63946"))); // Red
            switchButton.setContentDescription("Switch to HTTP Repeated");
        } else { // VIEW_HTTP_REPEATER
            tabTraffic.setText("HTTP Repeated");
            switchButton.setImageTintList(ColorStateList.valueOf(Color.parseColor("#F59E0B"))); // Yellow
            switchButton.setContentDescription("Switch to Traffic");
        }
    }

    private void toggleDataView() {
        Fragment container = getFragmentAtPos(POS_CONNECTIONS);
        if (container instanceof DataViewContainerFragment) {
            ((DataViewContainerFragment) container).toggleView();
        }
    }

    private void resetDataView() {
        Fragment container = getFragmentAtPos(POS_CONNECTIONS);
        if (container instanceof DataViewContainerFragment) {
            ((DataViewContainerFragment) container).resetToConnectionsView();
        }
    }

    private void switchToHttpDataView() {
        Fragment container = getFragmentAtPos(POS_CONNECTIONS);
        if (container instanceof DataViewContainerFragment) {
            ((DataViewContainerFragment) container).switchToHttpView();
        }
    }

    @Override
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        // This is required to properly handle the DPAD down press on Android TV, to properly
        // focus the tab content
        if(keyCode == KeyEvent.KEYCODE_DPAD_DOWN) {
            View view = getCurrentFocus();

            Log.d(TAG, "onKeyDown focus " + view.getClass().getName());

            if(view instanceof TabLayout.TabView) {
                int pos = mPager.getCurrentItem();
                View focusOverride = null;

                Log.d(TAG, "TabLayout.TabView focus pos " + pos);

                if(pos == POS_STATUS)
                    focusOverride = findViewById(R.id.main_screen);
                else if(pos == POS_CONNECTIONS)
                    focusOverride = findViewById(R.id.connections_view);

                if(focusOverride != null) {
                    focusOverride.requestFocus();
                    return true;
                }
            }
        } else if(keyCode == KeyEvent.KEYCODE_DPAD_RIGHT) {
            // Clicking "right" from the connections view goes to the fab down item
            if(mPager.getCurrentItem() == POS_CONNECTIONS) {
                RecyclerView rview = findViewById(R.id.connections_view);

                if(rview.getFocusedChild() != null) {
                    Log.d(TAG, "onKeyDown (right) focus " + rview.getFocusedChild());

                    View fab = findViewById(R.id.fabDown);

                    if(fab != null) {
                        fab.requestFocus();
                        return true;
                    }
                }
            }
        }

        return super.onKeyDown(keyCode, event);
    }

    public void setAppStateListener(AppStateListener listener) {
        mListener = listener;
    }

    private void notifyAppState() {
        if(mListener != null)
            mListener.appStateChanged(mState);

        refreshOpenPcapItem();
    }

    public void appStateReady() {
        mState = AppState.ready;
        notifyAppState();
        updateTabSwitchButton();
        updateToolbarStatus();

        if(mPcapLoadDialog != null)
            checkLoadedPcap();
    }

    public void appStateStarting() {
        mState = AppState.starting;
        notifyAppState();
        updateToolbarStatus();
    }

    public void appStateRunning() {
        mState = AppState.running;
        notifyAppState();
        updateTabSwitchButton();
        updateToolbarStatus();
        resetDataView();

        if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
            checkVpnLockdownNotice();
        else if(mStartPressed) { // STOPPED -> STARTED
            if(CaptureService.isDecryptingTLS() && !CaptureService.isCapturingAsRoot())
                checkDecryptionRulesNotice();
        }

        if (mIab.isFirewallVisible()) {
            Blocklist blocklist = KotSafe.getInstance().getBlocklist();
            if (blocklist.hasCountryRules())
                blocklist.showNoticeIfGeoMissing(this);
        }
    }

    public void appStateStopping() {
        mState = AppState.stopping;
        notifyAppState();
        updateToolbarStatus();
    }

    private void updateTabSwitchButton() {
        View switchButton = findViewById(R.id.tab_switch_button);
        if (switchButton != null) {
            switchButton.setVisibility(android.view.View.VISIBLE);
        }
    }

    private void checkDecryptionRulesNotice() {
        if(!mDecEmptyRulesNoticeShown && KotSafe.getInstance().getDecryptionList().isEmpty()) {
            new AlertDialog.Builder(this)
                    .setMessage(R.string.tls_decryption_no_rules_notice)
                    .setPositiveButton(R.string.yes, (d, whichButton) -> {
                        Intent intent = new Intent(MainActivity.this, EditListActivity.class);
                        intent.putExtra(EditListActivity.LIST_TYPE_EXTRA, ListInfo.Type.DECRYPTION_LIST);
                        startActivity(intent);
                    })
                    .setNegativeButton(R.string.no, (d, whichButton) -> {
                    })
                    .show();
            mDecEmptyRulesNoticeShown = true;
        }
    }

    private void dismissPcapLoadDialog() {
        if(mPcapLoadDialog != null) {
            mPcapLoadDialog.dismiss();
            mPcapLoadDialog = null;
        }

        mPcapExecutor = null;
    }

    private void checkLoadedPcap() {
        dismissPcapLoadDialog();

        if(!CaptureService.hasError()) {
            // pcap file loaded successfully
            ConnectionsRegister reg = CaptureService.getConnsRegister();

            if((reg != null) && (reg.getConnCount() > 0)
                    && !CaptureService.hasSeenDumpExtensions()
                    && !mExtensionsNoticeShown
            ) {
                new AlertDialog.Builder(this)
                        .setMessage(getString(R.string.kotsafe_trailer_notice,
                                getString(R.string.unknown_app), getString(R.string.dump_extensions)))
                        .setPositiveButton(R.string.ok, (d, whichButton) -> mExtensionsNoticeShown = true)
                        .show();
            } else
                Utils.showToastLong(this, R.string.pcap_load_success);

            mPager.setCurrentItem(POS_CONNECTIONS);
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.Q)
    private void checkVpnLockdownNotice() {
        if(!Prefs.lockdownVpnNoticeShown(mPrefs) && Prefs.isFirewallEnabled(this, mPrefs) && !CaptureService.isLockdownVPN()) {
            AlertDialog dialog = new AlertDialog.Builder(this)
                    .setMessage(R.string.vpn_lockdown_notice)
                    .setPositiveButton(R.string.yes, (d, whichButton) -> Utils.startActivity(this, new Intent("android.net.vpn.SETTINGS")))
                    .setNegativeButton(R.string.no, (d, whichButton) -> {})
                    .show();
            dialog.setCanceledOnTouchOutside(false);

            Prefs.setLockdownVpnNoticeShown(mPrefs);
        }
    }

    private void openTelegram() {
        Intent intent;

        try {
            Utils.getPackageInfo(getPackageManager(), "org.telegram.messenger", 0);

            // Open directly into the telegram app
            intent = new Intent(Intent.ACTION_VIEW, Uri.parse("tg://resolve?domain=" + TELEGRAM_GROUP_NAME));
        } catch (Exception e) {
            // Telegram not found, open in the browser
            intent = new Intent(Intent.ACTION_VIEW, Uri.parse("http://t.me/" + TELEGRAM_GROUP_NAME));
        }

        Utils.startActivity(this, intent);
    }

    /*private void rateApp() {
        try {
            // If playstore is installed
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse("market://details?id=" + this.getPackageName())));
        } catch (android.content.ActivityNotFoundException e) {
            // If playstore is not available
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse("http://play.google.com/store/apps/details?id=" + this.getPackageName())));
        }
    }*/

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.main_activity_menu, menu);

        mMenuItemOpenPcap = menu.findItem(R.id.open_pcap);
        refreshOpenPcapItem();

        MenuItem themeToggle = menu.findItem(R.id.action_theme_toggle);
        if (themeToggle != null) {
            boolean isNight = (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES;
            themeToggle.setIcon(isNight ? R.drawable.ic_theme_sun : R.drawable.ic_theme_moon);
            themeToggle.setTitle(isNight ? R.string.theme_light : R.string.theme_dark);
        }

        return true;
    }

    // opening a PCAP is only allowed while no capture is running
    private void refreshOpenPcapItem() {
        if(mMenuItemOpenPcap != null)
            mMenuItemOpenPcap.setEnabled((mState == AppState.ready) || (mState == AppState.starting));
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        int id = item.getItemId();

        if(id == R.id.action_start) {
            mStartPressed = true;
            startCapture();
            return true;
        } else if(id == R.id.action_stop) {
            stopCapture();
            return true;
        } else if(id == R.id.open_pcap) {
            selectOpenPcapFile();
            return true;
        } else if (id == R.id.action_alerts_center) {
            Intent intent = new Intent(MainActivity.this, AlertsCenterActivity.class);
            startActivity(intent);
            return true;
        } else if (id == R.id.action_shield_center) {
            Intent intent = new Intent(MainActivity.this, AppPermissionsActivity.class);
            startActivity(intent);
            return true;
        } else if (id == R.id.action_mitre_navigator) {
            Intent intent = new Intent(MainActivity.this, MitreAttackActivity.class);
            startActivity(intent);
            return true;
        } else if (id == R.id.action_settings) {
            Intent intent = new Intent(MainActivity.this, SettingsActivity.class);
            startActivity(intent);
            return true;
        } else if (id == R.id.action_theme_toggle) {
            toggleThemeMode();
            return true;
        } else if (id == R.id.action_profile) {
            showSecurityProfileDialog();
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    private void toggleThemeMode() {
        boolean isNight = (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES;
        String newMode = isNight ? Prefs.THEME_MODE_LIGHT : Prefs.THEME_MODE_DARK;
        Prefs.setThemeMode(this, newMode);
        int nightMode = isNight ? AppCompatDelegate.MODE_NIGHT_NO : AppCompatDelegate.MODE_NIGHT_YES;
        AppCompatDelegate.setDefaultNightMode(nightMode);
        getDelegate().setLocalNightMode(nightMode);
    }

    private void showSecurityProfileDialog() {
        View dialogView = getLayoutInflater().inflate(R.layout.dialog_security_profile, null);
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setView(dialogView)
                .create();

        if (dialog.getWindow() != null) {
            dialog.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
        }

        TextView aboutVersion = dialogView.findViewById(R.id.profile_about_version);
        if (aboutVersion != null) {
            String rawVer = Utils.getAppVersion(this);
            aboutVersion.setText(rawVer.startsWith("v") ? rawVer : ("v" + rawVer));
        }

        View.OnClickListener openAboutAction = v -> {
            dialog.dismiss();
            Intent intent = new Intent(MainActivity.this, AboutActivity.class);
            startActivity(intent);
        };

        View btnProfileAbout = dialogView.findViewById(R.id.btn_profile_about);
        if (btnProfileAbout != null) {
            btnProfileAbout.setOnClickListener(openAboutAction);
        }

        View cardProfileAbout = dialogView.findViewById(R.id.card_profile_about);
        if (cardProfileAbout != null) {
            cardProfileAbout.setOnClickListener(openAboutAction);
        }

        View cardPhysicalSec = dialogView.findViewById(R.id.card_profile_physical_security);
        if (cardPhysicalSec != null) {
            cardPhysicalSec.setOnClickListener(v -> {
                dialog.dismiss();
                startActivity(new Intent(MainActivity.this, com.kotsafe.security.activities.PhysicalSecurityActivity.class));
            });
        }

        View closeBtn = dialogView.findViewById(R.id.btn_profile_close);
        if (closeBtn != null) {
            closeBtn.setOnClickListener(v -> dialog.dismiss());
        }

        dialog.show();
    }

    private void initAppState() {
        boolean is_active = CaptureService.isServiceActive();

        if (!is_active) {
            appStateReady();

            // KotSafe could have been closed unexpectedly (e.g. due to low memory), try to export
            // the keylog file if exists
            mKeylogFile = MitmReceiver.getKeylogFilePath(MainActivity.this);
            if(mKeylogFile.exists())
                startExportSslkeylogfile();
        } else
            appStateRunning();
    }

    private void doStartCaptureService(String input_pcap_path) {
        if (mCapHelper == null) {
            Log.e(TAG, "Activity destroyed, capture cannot start");
            return;
        }

        appStateStarting();

        // Clear loaded basename if this is a new capture (not from loaded file)
        if (input_pcap_path == null)
            KotSafe.getInstance().setLoadedPcapBasename(null);

        KotSafe.getInstance().setIsDecryptingPcap(mDecryptPcap);
        mDecryptPcap = false;

        CaptureSettings settings = new CaptureSettings(this, mPrefs);
        settings.input_pcap_path = input_pcap_path;

        // to properly show decrypted PCAP files, full payload must be enabled
        if (KotSafe.getInstance().isDecryptingPcap())
            settings.full_payload = true;

        mCapHelper.startCapture(settings);
    }

    public void startCapture() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                requestNotificationPermission();
            }
        }

        if (VpnReconnectService.isAvailable())
            VpnReconnectService.stopService();

        if(showRemoteServerAlert())
            return;

        if(Prefs.getTlsDecryptionEnabled(mPrefs) && MitmAddon.isSupportedTarget()) {
            if (MitmAddon.needsSetup(this)) {
                Intent intent = new Intent(this, MitmSetupWizard.class);
                startActivity(intent);
                return;
            }

            if (!MitmAddon.getNewVersionAvailable(this).isEmpty()) {
                new AlertDialog.Builder(this)
                        .setTitle(R.string.update_available)
                        .setMessage(R.string.mitm_addon_update_available)
                        .setCancelable(false)
                        .setPositiveButton(R.string.update_action, (dialog, whichButton) -> {
                            Intent intent = new Intent(this, MitmSetupWizard.class);
                            startActivity(intent);
                        })
                        .setNegativeButton(R.string.cancel_action, (dialog, whichButton) -> {
                            MitmAddon.ignoreNewVersion(this);
                            startCapture();
                        })
                        .show();

                return;
            }
        }

        if(!Prefs.isRootCaptureEnabled(mPrefs) && (Utils.getRunningVpn(this) != null)) {
            new AlertDialog.Builder(this)
                    .setTitle(R.string.active_vpn_detected)
                    .setMessage(R.string.disconnect_vpn_confirm)
                    .setPositiveButton(R.string.ok, (dialog, whichButton) -> doStartCaptureService(null))
                    .setNegativeButton(R.string.cancel_action, (dialog, whichButton) -> {})
                    .show();
        } else
            doStartCaptureService(null);
    }

    public void stopCapture() {
        appStateStopping();
        CaptureService.stopService();
    }

    // see also CaptureCtrl.checkRemoteServerNotAllowed
    private boolean showRemoteServerAlert() {
        if(mPrefs.getBoolean(Prefs.PREF_REMOTE_COLLECTOR_ACK, false))
            return false; // already acknowledged

        boolean exporterEnabled = (Prefs.getDumpMode(mPrefs) == Prefs.DumpMode.UDP_EXPORTER) ||
                (Prefs.getDumpMode(mPrefs) == Prefs.DumpMode.TCP_EXPORTER);

        if((exporterEnabled && !Utils.isLocalNetworkAddress(Prefs.getCollectorHost(mPrefs))) ||
                (Prefs.getSocks5Enabled(mPrefs) && !Utils.isLocalNetworkAddress(Prefs.getSocks5ProxyHost(mPrefs)))) {
            Log.i(TAG, "Showing possible scan notice");

            AlertDialog dialog = new AlertDialog.Builder(this)
                    .setTitle(R.string.warning)
                    .setMessage(R.string.remote_collector_notice)
                    .setPositiveButton(R.string.ok, (d, whichButton) -> mPrefs.edit().putBoolean(Prefs.PREF_REMOTE_COLLECTOR_ACK, true).apply())
                    .show();
            dialog.setCanceledOnTouchOutside(false);
            return true;
        }

        return false;
    }

    public void showPcapActionDialog() {
        Log.d(TAG, "showPcapActionDialog called");

        if(CaptureService.isUserDefinedPcapUri())
            return;

        Uri pcapUri = CaptureService.getPcapUri();
        if(pcapUri == null)
            return;

        CaptureStats stats = CaptureService.getStats();
        Log.d(TAG, "Pcap dump size is " + stats.pcap_dump_size);

        if(stats.pcap_dump_size <= 0) {
            deletePcapFile(pcapUri); // empty file, delete
            discardKeylogFile();
            return;
        }

        String pcapName = CaptureService.getPcapFname();
        if(pcapName == null)
            pcapName = "unknown";

        final String finalPcapName = pcapName;
        String message = String.format(getResources().getString(R.string.pcap_file_action), pcapName, Utils.formatBytes(stats.pcap_dump_size));

        final boolean[] pcapDeleted = {false};

        AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
        builder.setMessage(message);

        builder.setPositiveButton(R.string.share, (dialog, which) -> Utils.shareCapture(this, pcapUri));
        builder.setNegativeButton(R.string.delete, (dialog, which) -> {
            deletePcapFile(pcapUri);
            pcapDeleted[0] = true;
        });
        builder.setNeutralButton(R.string.ok, (dialog, which) -> {});
        builder.setOnDismissListener(dialogInterface -> {
            if(!pcapDeleted[0]) {
                exportSiblingKeylogFile(finalPcapName);
                savePacketCapture();
                notifyAppState();
            } else
                discardKeylogFile();
        });

        AlertDialog dialog = builder.create();
        dialog.setCanceledOnTouchOutside(false);
        dialog.show();
    }

    // Auto-exports the in-cache SSL keylog as a sibling .keylog file in Downloads/KotSafe/,
    // matching the basename of the just-saved pcap. The cached keylog is then removed.
    private void exportSiblingKeylogFile(String pcapName) {
        int dotIndex = pcapName.lastIndexOf('.');
        String baseName = (dotIndex > 0) ? pcapName.substring(0, dotIndex) : pcapName;
        writeKeylogToDownloads(baseName + ".keylog");
        discardKeylogFile();
    }

    // Copy the cached SSL keylog into Downloads/KotSafe/<name>. Shows export_failed on
    // I/O error
    private boolean writeKeylogToDownloads(String name) {
        if (mKeylogFile == null)
            return false;

        Uri uri = Utils.getDownloadsUri(this, name);
        if (uri == null) {
            Log.e(TAG, "Cannot create keylog file " + name);
            return false;
        }

        try (OutputStream out = getContentResolver().openOutputStream(uri, "rwt")) {
            Utils.copy(mKeylogFile, out);
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            Utils.showToastLong(this, R.string.export_failed);
            return false;
        }
    }

    private void discardKeylogFile() {
        if (mKeylogFile == null)
            return;

        //noinspection ResultOfMethodCallIgnored
        mKeylogFile.delete();
        mKeylogFile = null;
    }

    private void deletePcapFile(Uri pcapUri) {
        boolean deleted = false;

        // The getContentResolver().delete in some Android versions does not work, try to delete
        // using file path first
        String fpath = Utils.uriToFilePath(this, pcapUri);
        if(fpath != null) {
            Log.d(TAG, "deletePcapFile: path=" + fpath);

            try {
                deleted = new File(fpath).delete();
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            Log.d(TAG, "deletePcapFile: uri=" + pcapUri);

            try {
                deleted = (getContentResolver().delete(pcapUri, null, null) == 1);
            } catch (UnsupportedOperationException | SecurityException e) {
                e.printStackTrace();
            }
        }

        if(!deleted)
            Utils.showToast(MainActivity.this, R.string.delete_error);
    }

    public AppState getState() {
        return(mState);
    }

    private void startExportSslkeylogfile() {
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        intent.putExtra(Intent.EXTRA_TITLE, "sslkeylogfile.txt");

        Log.d(TAG, "startExportSslkeylogfile: launching dialog");
        Utils.launchFileDialog(this, intent, sslkeyfileExportLauncher);
    }

    private void sslkeyfileExportResult(final ActivityResult result) {
        if((result.getResultCode() == RESULT_OK) && (result.getData() != null) && (mKeylogFile != null)) {
            try(OutputStream out = getContentResolver().openOutputStream(result.getData().getData(), "rwt")) {
                Utils.copy(mKeylogFile, out);
                Utils.showToast(this, R.string.save_ok);
            } catch (IOException e) {
                e.printStackTrace();
                Utils.showToastLong(this, R.string.export_failed);
            }
        }

        if(mKeylogFile != null) {
            // upon closing the dialog, delete the keylog
            discardKeylogFile();
        }
    }

    private void selectOpenPcapFile() {
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");

        Log.d(TAG, "selectOpenPcapFile: launching dialog");
        Utils.launchFileDialog(this, intent, pcapFileOpenLauncher);
    }

    private void pcapFileOpenResult(final ActivityResult result) {
        if ((result.getResultCode() == RESULT_OK) && (result.getData() != null)) {
            Uri uri = result.getData().getData();
            if (uri == null)
                return;

            Log.d(TAG, "pcapFileOpenResult: " + uri);
            startOpenPcap(uri);
        }
    }

    public void startOpenPcap(Uri pcap_uri) {
        if (pcap_uri == null) {
            Log.w(TAG, "startOpenPcap: null URI provided");
            return;
        }

        boolean isPcapng = Utils.isPcapng(this, pcap_uri);

        // Extract and store the base filename (without extension)
        Utils.UriStat stat = Utils.getUriStat(this, pcap_uri);
        if (stat != null && stat.name != null) {
            String name = stat.name;
            int dotIndex = name.lastIndexOf('.');
            String basename = (dotIndex > 0) ? name.substring(0, dotIndex) : name;
            KotSafe.getInstance().setLoadedPcapBasename(basename);
        } else {
            KotSafe.getInstance().setLoadedPcapBasename(null);
        }

        mPcapExecutor = Executors.newSingleThreadExecutor();

        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(R.string.loading);
        builder.setMessage(R.string.pcap_load_in_progress);

        mPcapLoadDialog = builder.create();
        mPcapLoadDialog.setCanceledOnTouchOutside(false);
        mPcapLoadDialog.setOnCancelListener(dialogInterface -> {
            Log.i(TAG, "Abort PCAP loading");

            if (mPcapExecutor != null) {
                mPcapExecutor.shutdownNow();
                mPcapExecutor = null;
            }

            if (CaptureService.isServiceActive())
                CaptureService.stopService();

            Utils.showToastLong(this, R.string.pcap_file_load_aborted);
        });
        mPcapLoadDialog.setOnDismissListener(dialog -> mPcapLoadDialog = null);
        mPcapLoadDialog.show();

        // get an actual file path which can be read from the native side
        String path = Utils.uriToFilePath(this, pcap_uri);
        if((path == null) || !Utils.isReadable(path)) {
            // Unable to get a direct file path (e.g. for files in Downloads). Copy file to the
            // cache directory
            File out = getTmpPcapPath();
            out.deleteOnExit();
            String abs_path = out.getAbsolutePath();

            // PCAP file can be big, copy in a different thread
            mPcapExecutor.execute(() -> {
                try (InputStream in_stream = getContentResolver().openInputStream(pcap_uri)) {
                    Utils.copy(in_stream, out);
                } catch (IOException | RuntimeException e) {
                    e.printStackTrace();

                    runOnUiThread(() -> {
                        Utils.showToastLong(this, R.string.copy_error);
                        dismissPcapLoadDialog();
                    });
                    return;
                }

                // No direct path means no sibling .keylog can be located for plain pcap
                runOnUiThread(() -> prepareKeylogAndStart(abs_path, isPcapng, null));
            });
        } else {
            Log.d(TAG, "pcapFileOpenResult: path: " + path);

            // For plain pcap with a real file path, check for a sibling .keylog file
            File siblingKeylog = null;
            if (!isPcapng)
                siblingKeylog = Utils.findSiblingKeylog(path);

            prepareKeylogAndStart(path, isPcapng, siblingKeylog);
        }
    }

    private void prepareKeylogAndStart(String pcap_path, boolean isPcapng, File sibling_keylog) {
        // dialog gets nullified when the user cancels the load
        if (mPcapLoadDialog == null)
            return;

        //noinspection ResultOfMethodCallIgnored
        getKeylogPath().delete();

        boolean canDecrypt = KotSafe.getInstance().isUsharkAvailable();

        if (isPcapng && canDecrypt) {
            mPcapExecutor.execute(() -> {
                File out = getKeylogPath();
                out.deleteOnExit();
                CaptureService.extractKeylogFromPcapng(pcap_path, out.getAbsolutePath());
                boolean hasKeylog = out.exists() && (out.length() > 0);

                runOnUiThread(() -> {
                    if (mPcapLoadDialog == null)
                        return;
                    mDecryptPcap = hasKeylog;
                    doStartCaptureService(pcap_path);
                });
            });
        } else if ((sibling_keylog != null) && canDecrypt) {
            mPcapExecutor.execute(() -> {
                File out = getKeylogPath();
                out.deleteOnExit();
                try (InputStream in_stream = new FileInputStream(sibling_keylog)) {
                    Utils.copy(in_stream, out);
                } catch (IOException | RuntimeException e) {
                    e.printStackTrace();
                }

                runOnUiThread(() -> {
                    if (mPcapLoadDialog == null)
                        return;
                    mDecryptPcap = out.exists() && (out.length() > 0);
                    doStartCaptureService(pcap_path);
                });
            });
        } else {
            mDecryptPcap = false;
            doStartCaptureService(pcap_path);
        }
    }

    private File getTmpPcapPath() {
        return new File(getCacheDir() + "/tmp.pcap");
    }

    private File getKeylogPath() {
        // NOTE: keep in sync with run_libpcap
        return new File(getCacheDir() + "/sslkeylog.txt");
    }

    private void savePacketCapture() {
        CaptureSettings settings = CaptureService.getCaptureSettings();
        Uri pcap_uri = CaptureService.getPcapUri();
        String pcap_fname = CaptureService.getPcapFname();

        if ((settings == null) ||
                (settings.dump_mode != Prefs.DumpMode.PCAP_FILE) ||
                (pcap_uri == null) ||
                (pcap_fname == null))
            return;

        CaptureStats stats = CaptureService.getStats();
        if (stats.pcap_dump_size <= 0)
            // ignore empty captures
            return;

        long start_time = CaptureService.getCaptureStartTime();
        long duration = (SystemClock.elapsedRealtime() - CaptureService.getCaptureStartTimeMonotonic()) / 1000;
        ConnectionsRegister reg = CaptureService.getConnsRegister();
        ArrayList<CaptureList.App> captured_apps = new ArrayList<>();

        if (reg != null) {
            List<AppStats> apps_stats = reg.getAppsStats();
            apps_stats.sort((a, b) -> Long.compare(b.sentBytes + b.rcvdBytes, a.sentBytes + a.rcvdBytes));
            AppsResolver resolver = new AppsResolver(this);

            // When an app filter is set, skip virtual apps like netd, Unknown, etc. to
            // make the ui more consistent to the filter. Add them only if no non-virtual app is captured
            boolean skip_virtual = settings.app_filter.isEmpty();
            ArrayList<CaptureList.App> virtual_apps = new ArrayList<>();

            for (AppStats s : apps_stats) {
                AppDescriptor app = resolver.getAppByUid(s.getUid(), 0);
                if ((app == null) || (app.getPackageName() == null))
                    continue;

                CaptureList.App target = new CaptureList.App(app.getUid(), app.getPackageName(), app.getName());
                if (skip_virtual && app.isVirtual())
                    virtual_apps.add(target);
                else
                    captured_apps.add(target);
            }

            if (captured_apps.isEmpty())
                captured_apps.addAll(virtual_apps);
        }

        boolean decrypted = false;
        if (CaptureService.isDecryptingTLS() && (reg != null)) {
            // check if any connection was actually decrypted
            int cnt = reg.getConnCount();
            for (int i = 0; i < cnt; i++) {
                ConnectionDescriptor cd = reg.getConn(i);
                if ((cd != null) && cd.isDecrypted()) {
                    decrypted = true;
                    break;
                }
            }
        }

        CaptureList.Capture capture = new CaptureList.Capture(pcap_uri.toString(), pcap_fname, start_time, duration,
                stats.pcap_dump_size, stats.bytes_sent + stats.bytes_rcvd, decrypted,
                captured_apps);

        Log.d(TAG, "Save capture in list: " + capture.name + " - " + capture.size + " B");
        CaptureList capture_list = new CaptureList(this);
        capture_list.add(capture);
    }
}
