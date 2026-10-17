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
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
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
import android.view.animation.LinearInterpolator;
import android.view.animation.RotateAnimation;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.content.ClipboardManager;
import android.content.ClipData;
import android.widget.TextView;
import android.widget.Toast;
import android.widget.EditText;
import com.kotsafe.security.model.CloudSyncManager;
import com.kotsafe.security.model.TotpHelper;

import com.kotsafe.security.p2p.GatewayPreferenceKeys;
import com.kotsafe.security.p2p.GatewayProfile;
import com.kotsafe.security.p2p.GatewayProfileManager;
import com.kotsafe.security.p2p.GatewayTelemetry;
import com.kotsafe.security.model.P2PExitNodeServer;

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
import com.google.android.gms.auth.api.signin.GoogleSignIn;
import com.google.android.gms.auth.api.signin.GoogleSignInOptions;
import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.google.android.material.navigation.NavigationView;
import com.google.android.material.tabs.TabLayout;
import com.google.android.material.tabs.TabLayoutMediator;
import com.google.firebase.FirebaseApp;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseUser;
import com.kotsafe.security.model.BiometricLockManager;
import com.kotsafe.security.model.KotSafeUserManager;
import com.google.android.material.textfield.TextInputLayout;
import com.google.android.material.textfield.TextInputEditText;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends BaseActivity {
    private static boolean sBiometricUnlockedThisSession = false;
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

    // Exit node active connection banner
    private View mBannerExitNodeConnected;
    private TextView mTvBannerExitName;
    private TextView mTvBannerExitBadge;
    private TextView mTvBannerExitIp;
    private TextView mTvBannerDeviceIp;
    private TextView mTvBannerPing;
    private ImageButton mBtnRefreshExitNodeBanner;
    private final GatewayTelemetry.Listener mExitNodeTelemetryListener =
            telemetry -> runOnUiThread(this::updateExitNodeBannerUI);

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
    private static boolean sReopenProfileOnRecreate = false;

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
        // Ensure status bar icons are black in light mode because Home top bar is light/white
        boolean isNight = (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES;
        androidx.core.view.WindowInsetsControllerCompat insetsController =
                androidx.core.view.WindowCompat.getInsetsController(getWindow(), getWindow().getDecorView());
        if (insetsController != null) {
            insetsController.setAppearanceLightStatusBars(!isNight);
        }
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

        // Mandatory Authentication: Zero-Trust requires active cloud identity or explicit Guest Mode
        boolean isAuthenticated = KotSafeUserManager.isUserAuthenticated(this);
        boolean isGuest = KotSafeUserManager.isGuestMode(this);
        if (!isAuthenticated && !isGuest) {
            Intent loginIntent = new Intent(this, LoginActivity.class);
            loginIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            startActivity(loginIntent);
            finish();
            return;
        }

        if (isAuthenticated) {
            try {
                FirebaseUser curUser = FirebaseAuth.getInstance().getCurrentUser();
                if (curUser != null) {
                    CloudSyncManager.getInstance(this).syncUserOnAuth(curUser);
                }
                KotSafeUserManager.autoEncryptPlaintextSecretIfPresent(this);
            } catch (Exception ignored) {}
        }

        if (savedInstanceState == null) {
            mIab = Billing.newInstance(this);
            initPeerAppInfo();
        } else {
            if (mIab == null) mIab = Billing.newInstance(this);
        }

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

        if (sReopenProfileOnRecreate) {
            sReopenProfileOnRecreate = false;
            Log.d("KotSafeTheme", "Reopening profile dialog on theme recreate");
            if (mPager != null) {
                mPager.post(this::showSecurityProfileDialog);
            }
        }

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

        GatewayTelemetry.getInstance().removeListener(mExitNodeTelemetryListener);

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
            if (intent.getBooleanExtra("open_connected_devices", false)) {
                intent.removeExtra("open_connected_devices");
                if (mPager != null) {
                    mPager.postDelayed(() -> showSecurityProfileDialog(true), 300);
                }
            }
            handleGatewayIntent(intent);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        // In Home / MainActivity, the top bar is top_brand_bar (light/white in day mode),
        // so status bar icons MUST be black (!isNight) so they are clearly visible!
        boolean isNight = (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES;
        androidx.core.view.WindowInsetsControllerCompat insetsController =
                androidx.core.view.WindowCompat.getInsetsController(getWindow(), getWindow().getDecorView());
        if (insetsController != null) {
            insetsController.setAppearanceLightStatusBars(!isNight);
        }

        GatewayTelemetry.getInstance().addListener(mExitNodeTelemetryListener);
        updateExitNodeBannerUI();

        // Mandatory Authentication: Ensure active session or guest mode is present
        boolean isAuthenticated = KotSafeUserManager.isUserAuthenticated(this);
        boolean isGuest = KotSafeUserManager.isGuestMode(this);
        if (!isAuthenticated && !isGuest) {
            Intent loginIntent = new Intent(this, LoginActivity.class);
            loginIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            startActivity(loginIntent);
            finish();
            return;
        }

        if (isAuthenticated && BiometricLockManager.isBiometricEnabled(this) && !sBiometricUnlockedThisSession) {
            BiometricLockManager.authenticate(this, "KotSafe Locked", "Scan fingerprint or face to unlock", new BiometricLockManager.AuthCallback() {
                @Override
                public void onSuccess() {
                    sBiometricUnlockedThisSession = true;
                }
                @Override
                public void onError(String message) {
                    Toast.makeText(MainActivity.this, "Authentication failed: " + message, Toast.LENGTH_SHORT).show();
                    finish();
                }
                @Override
                public void onCancelled() {
                    finish();
                }
            });
        }

        if (isAuthenticated) {
            // Cloud database telemetry heartbeat & real-time listeners
            com.kotsafe.security.model.CloudSyncManager.getInstance(this).sendHeartbeat();
            com.kotsafe.security.model.CloudSyncManager.getInstance(this).startCommandListener();
            com.kotsafe.security.model.CloudSyncManager.getInstance(this).startNewDeviceLoginListener();
            com.kotsafe.security.model.CloudSyncManager.getInstance(this).startCrossDeviceRuleSyncListener();
        }

        if (getIntent() != null && "connections".equals(getIntent().getStringExtra("open_tab"))) {
            getIntent().removeExtra("open_tab");
            mPager.setCurrentItem(POS_CONNECTIONS);
        }

        if (getIntent() != null && getIntent().getBooleanExtra("open_connected_devices", false)) {
            getIntent().removeExtra("open_connected_devices");
            if (mPager != null) {
                mPager.postDelayed(() -> showSecurityProfileDialog(true), 600);
            }
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
                                if (com.kotsafe.security.model.backend.BackendProviderFactory.isRelayEndpoint(bundle.controlUrl)) {
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

        // Wire exit node active banner
        mBannerExitNodeConnected = findViewById(R.id.banner_exit_node_connected);
        mTvBannerExitName = findViewById(R.id.tv_banner_exit_name);
        mTvBannerExitBadge = findViewById(R.id.tv_banner_exit_badge);
        mTvBannerExitIp = findViewById(R.id.tv_banner_exit_ip);
        mTvBannerDeviceIp = findViewById(R.id.tv_banner_device_ip);
        mTvBannerPing = findViewById(R.id.tv_banner_ping);
        mBtnRefreshExitNodeBanner = findViewById(R.id.btn_refresh_exit_node_banner);

        if (mBannerExitNodeConnected != null) {
            AnimUtils.attachSpringTouch(mBannerExitNodeConnected);
            mBannerExitNodeConnected.setOnClickListener(v -> {
                if (!KotSafeUserManager.isUserAuthenticated(this)) {
                    KotSafeUserManager.redirectToLoginWithNotice(this, "P2P Exit Gateway");
                    return;
                }
                Intent intent = new Intent(this, SettingsActivity.class);
                intent.putExtra(SettingsActivity.TARGET_PREF_EXTRA, "p2p_exit_node_settings");
                startActivity(intent);
            });
        }

        if (mBtnRefreshExitNodeBanner != null) {
            AnimUtils.attachSpringTouch(mBtnRefreshExitNodeBanner);
            mBtnRefreshExitNodeBanner.setOnClickListener(v -> refreshExitNodeIpAndTelemetry(mBtnRefreshExitNodeBanner));
        }

        updateToolbarStatus();
        updateExitNodeBannerUI();
    }

    private void refreshExitNodeIpAndTelemetry(View refreshIcon) {
        if (refreshIcon != null) {
            RotateAnimation rotate = new RotateAnimation(0f, 360f,
                    Animation.RELATIVE_TO_SELF, 0.5f, Animation.RELATIVE_TO_SELF, 0.5f);
            rotate.setDuration(700);
            rotate.setInterpolator(new LinearInterpolator());
            refreshIcon.startAnimation(rotate);
        }
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        boolean exitOn = prefs.getBoolean(GatewayPreferenceKeys.EXIT_ENABLED, false);
        if (exitOn) {
            Toast.makeText(this, "🔄 Refreshing Host Public IP...", Toast.LENGTH_SHORT).show();
            GatewayTelemetry.getInstance().setDeviceIp(null);
            GatewayTelemetry.getInstance().fetchDeviceIpAsync(true);
            updateExitNodeBannerUI();
            return;
        }

        Toast.makeText(this, "🔄 Refreshing IP addresses & exit node telemetry...", Toast.LENGTH_SHORT).show();
        GatewayTelemetry.getInstance().forceRefreshAllIpsAsync(8095, () -> runOnUiThread(() -> {
            updateExitNodeBannerUI();
            String exitIp = GatewayTelemetry.getInstance().getExitNodeIp();
            if (exitIp != null && !exitIp.isEmpty()) {
                Toast.makeText(this, "✅ Refreshed Exit IP: " + exitIp, Toast.LENGTH_SHORT).show();
            } else {
                Toast.makeText(this, "✅ Telemetry & Device IP refreshed.", Toast.LENGTH_SHORT).show();
            }
        }));
    }

    private void updateExitNodeBannerUI() {
        if (mBannerExitNodeConnected == null) return;
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        boolean clientOn = prefs.getBoolean(GatewayPreferenceKeys.CLIENT_ENABLED, false);
        boolean exitOn = prefs.getBoolean(GatewayPreferenceKeys.EXIT_ENABLED, false);
        boolean vpnActive = CaptureService.isServiceActive();

        if ((!clientOn && !exitOn) || !vpnActive) {
            mBannerExitNodeConnected.setVisibility(View.GONE);
            return;
        }

        GatewayTelemetry telem = GatewayTelemetry.getInstance();
        GatewayProfile activeProfile = GatewayProfileManager.getActiveProfile(this);

        if (exitOn) {
            mBannerExitNodeConnected.setVisibility(View.VISIBLE);
            if (mTvBannerExitName != null) mTvBannerExitName.setText("Hosting Exit Gateway");
            int clients = P2PExitNodeServer.getInstance().getActiveClients();
            if (mTvBannerExitBadge != null) {
                mTvBannerExitBadge.setText(clients > 0 ? "🟢 ACTIVE (" + clients + ")" : "🟡 STANDBY");
                mTvBannerExitBadge.setTextColor(Color.parseColor(clients > 0 ? "#00E676" : "#FFC107"));
            }
            String devIp = telem.getDeviceIp();
            if (mTvBannerExitIp != null) {
                mTvBannerExitIp.setText("Host IP: " + (devIp != null && !devIp.isEmpty() ? devIp : "Detecting..."));
            }
            if (devIp == null || devIp.isEmpty()) {
                telem.fetchDeviceIpAsync(false);
            }
            if (mTvBannerDeviceIp != null) mTvBannerDeviceIp.setVisibility(View.GONE);
            if (mTvBannerPing != null) mTvBannerPing.setVisibility(View.GONE);
            return;
        }

        mBannerExitNodeConnected.setVisibility(View.VISIBLE);
        String nodeName = (activeProfile != null && activeProfile.name != null && !activeProfile.name.isEmpty())
                ? activeProfile.name : "Paired Exit Node";
        if (mTvBannerExitName != null) mTvBannerExitName.setText(nodeName);

        boolean hostOnline = telem.isHostOnline();
        boolean directP2p = telem.isDirectP2PActive();
        boolean showWarning = telem.isHostInactiveWarning();

        if (mTvBannerExitBadge != null) {
            if (showWarning) {
                mTvBannerExitBadge.setText("⚠️ UNRESPONSIVE");
                mTvBannerExitBadge.setTextColor(Color.parseColor("#F59E0B"));
            } else if (directP2p) {
                mTvBannerExitBadge.setText("⚡ DIRECT P2P");
                mTvBannerExitBadge.setTextColor(Color.parseColor("#00E676"));
            } else if (hostOnline) {
                mTvBannerExitBadge.setText("🟢 CONNECTED");
                mTvBannerExitBadge.setTextColor(Color.parseColor("#00E676"));
            } else {
                mTvBannerExitBadge.setText("🟡 CONNECTING");
                mTvBannerExitBadge.setTextColor(Color.parseColor("#FFC107"));
            }
        }

        String exitIp = telem.getExitNodeIp();
        String devIp = telem.getDeviceIp();

        if ((exitIp == null || exitIp.isEmpty()) && activeProfile != null && activeProfile.exitIp != null && !activeProfile.exitIp.isEmpty()) {
            exitIp = activeProfile.exitIp;
        }
        if (exitIp != null && !exitIp.isEmpty() && activeProfile != null && !exitIp.equals(activeProfile.exitIp)) {
            activeProfile.exitIp = exitIp;
            GatewayProfileManager.saveProfile(this, activeProfile);
        }

        if (mTvBannerExitIp != null) {
            if (exitIp != null && !exitIp.isEmpty()) {
                mTvBannerExitIp.setText("🛡️ Exit IP: " + exitIp);
            } else {
                mTvBannerExitIp.setText("🛡️ Exit IP: Detecting...");
            }
        }

        if (mTvBannerDeviceIp != null) {
            if (devIp != null && !devIp.isEmpty()) {
                mTvBannerDeviceIp.setVisibility(View.VISIBLE);
                mTvBannerDeviceIp.setText("• Real: " + devIp);
            } else {
                mTvBannerDeviceIp.setVisibility(View.VISIBLE);
                mTvBannerDeviceIp.setText("• Real: Detecting...");
                telem.fetchDeviceIpAsync();
            }
        }

        if (mTvBannerPing != null) {
            int rtt = telem.getLatencyMs();
            if (rtt > 0) {
                mTvBannerPing.setVisibility(View.VISIBLE);
                mTvBannerPing.setText("• ⚡ " + rtt + "ms");
            } else {
                mTvBannerPing.setVisibility(View.GONE);
            }
        }
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

        updateExitNodeBannerUI();
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
        Prefs.applyThemeMode(newMode);
        overridePendingTransition(android.R.anim.fade_in, android.R.anim.fade_out);
    }

    private void showSecurityProfileDialog() {
        showSecurityProfileDialog(false);
    }

    private void showSecurityProfileDialog(boolean openDevicesSubpage) {
        View dialogView = getLayoutInflater().inflate(R.layout.dialog_security_profile, null);
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setView(dialogView)
                .create();

        if (dialog.getWindow() != null) {
            dialog.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
        }

        android.widget.ViewFlipper viewFlipper = dialogView.findViewById(R.id.viewflipper_profile);

        TextView aboutVersion = dialogView.findViewById(R.id.profile_about_version);
        if (aboutVersion != null) {
            String rawVer = Utils.getAppVersion(this);
            aboutVersion.setText(rawVer.startsWith("v") ? rawVer : ("v" + rawVer));
        }

        // Close X button
        View btnCloseX = dialogView.findViewById(R.id.btn_profile_close_x);
        if (btnCloseX != null) {
            btnCloseX.setOnClickListener(v -> dialog.dismiss());
        }

        // Done button
        View btnDone = dialogView.findViewById(R.id.btn_profile_done);
        if (btnDone != null) {
            btnDone.setOnClickListener(v -> dialog.dismiss());
        }


        // Sign-in and recovery navigation
        androidx.core.widget.NestedScrollView profileScrollView = (androidx.core.widget.NestedScrollView) dialogView.findViewById(R.id.viewflipper_profile).getParent();
        View rowSigninRecovery = dialogView.findViewById(R.id.row_profile_signin_recovery);
        if (rowSigninRecovery != null && viewFlipper != null) {
            rowSigninRecovery.setOnClickListener(v -> {
                viewFlipper.setDisplayedChild(1);
                if (profileScrollView != null) profileScrollView.post(() -> profileScrollView.scrollTo(0, 0));
            });
        }

        View btnSetup2faHero = dialogView.findViewById(R.id.btn_profile_setup_2fa_hero);
        if (btnSetup2faHero != null && viewFlipper != null) {
            btnSetup2faHero.setOnClickListener(v -> {
                viewFlipper.setDisplayedChild(1);
                if (profileScrollView != null) profileScrollView.post(() -> profileScrollView.scrollTo(0, 0));
            });
        }

        View btnBack = dialogView.findViewById(R.id.btn_profile_back);
        if (btnBack != null && viewFlipper != null) {
            btnBack.setOnClickListener(v -> {
                viewFlipper.setDisplayedChild(0);
                if (profileScrollView != null) profileScrollView.post(() -> profileScrollView.scrollTo(0, 0));
            });
        }

        // Connected devices subpage navigation
        View rowConnectedDevices = dialogView.findViewById(R.id.row_profile_connected_devices);
        if (rowConnectedDevices != null && viewFlipper != null) {
            rowConnectedDevices.setOnClickListener(v -> {
                viewFlipper.setDisplayedChild(2);
                if (profileScrollView != null) profileScrollView.post(() -> profileScrollView.scrollTo(0, 0));
            });
        }

        View btnDevicesBack = dialogView.findViewById(R.id.btn_profile_devices_back);
        if (btnDevicesBack != null && viewFlipper != null) {
            btnDevicesBack.setOnClickListener(v -> {
                viewFlipper.setDisplayedChild(0);
                if (profileScrollView != null) profileScrollView.post(() -> profileScrollView.scrollTo(0, 0));
            });
        }

        // ── Account identity and security area ───────────────────────────────
        TextView tvAvatarInitial = dialogView.findViewById(R.id.tv_profile_avatar_initial);
        TextView tvUserName = dialogView.findViewById(R.id.tv_profile_user_name);
        TextView tvUserEmail = dialogView.findViewById(R.id.tv_profile_account_email);
        TextView tvStatusChip = dialogView.findViewById(R.id.tv_profile_status_chip);
        View dotStatus = dialogView.findViewById(R.id.dot_profile_status);
        View badgeVerified = dialogView.findViewById(R.id.badge_profile_verified);
        View layoutGuestBanner = dialogView.findViewById(R.id.layout_guest_banner);
        View btnChangePwd = dialogView.findViewById(R.id.btn_profile_change_pwd);
        View btnResetPwd = dialogView.findViewById(R.id.btn_profile_reset_pwd);
        View btnSetup2fa = dialogView.findViewById(R.id.btn_profile_setup_2fa);
        View btnSignOut = dialogView.findViewById(R.id.btn_profile_sign_out);
        View btnSignIn = dialogView.findViewById(R.id.btn_profile_sign_in);

        boolean isAuthenticated = KotSafeUserManager.isUserAuthenticated(this);
        String email = KotSafeUserManager.getLoggedInEmail(this);
        String name = KotSafeUserManager.getDisplayName(this);

        if (isAuthenticated) {
            if (layoutGuestBanner != null) layoutGuestBanner.setVisibility(View.GONE);
            if (badgeVerified != null) badgeVerified.setVisibility(View.VISIBLE);
            if (btnSignOut != null) btnSignOut.setVisibility(View.VISIBLE);

            if (tvUserName != null) tvUserName.setText(name);
            if (tvUserEmail != null) tvUserEmail.setText(email != null ? email : "KotSafe Cloud Member");
            if (tvAvatarInitial != null) {
                String initial = (name != null && !name.isEmpty()) ? String.valueOf(name.charAt(0)).toUpperCase() : "K";
                tvAvatarInitial.setText(initial);
            }
            if (tvStatusChip != null) {
                tvStatusChip.setText("Cloud Active Sentinel");
                tvStatusChip.setTextColor(ContextCompat.getColor(this, R.color.profileSuccessText));
            }
            if (dotStatus != null) {
                dotStatus.setBackgroundTintList(ColorStateList.valueOf(
                        ContextCompat.getColor(this, R.color.profileSuccess)));
            }

            if (btnChangePwd != null) {
                btnChangePwd.setOnClickListener(v -> showChangePasswordDialog());
            }

            if (btnResetPwd != null) {
                btnResetPwd.setOnClickListener(v -> showPasswordResetDialog(email));
            }

            TextView tv2faStatus = dialogView.findViewById(R.id.tv_profile_2fa_status);
            View card2faHero = dialogView.findViewById(R.id.card_profile_2fa_hero);
            TextView tvBtnSetup2fa = (TextView) btnSetup2fa;

            Runnable[] refreshHolder = new Runnable[1];
            refreshHolder[0] = () -> {
                KotSafeUserManager.isTwoFactorEnabled(MainActivity.this, new KotSafeUserManager.Callback<Boolean>() {
                    @Override
                    public void onSuccess(Boolean enabled) {
                        if (isFinishing() || isDestroyed()) return;
                        boolean is2faOn = enabled != null && enabled;
                        if (tv2faStatus != null) {
                            tv2faStatus.setText(is2faOn ? "On · Authenticator App" : "Off · Recommended");
                            tv2faStatus.setTextColor(ContextCompat.getColor(MainActivity.this,
                                    is2faOn ? R.color.profileSuccess : R.color.profileWarning));
                        }
                        if (card2faHero != null) {
                            card2faHero.setVisibility(is2faOn ? View.GONE : View.VISIBLE);
                        }
                        if (tvBtnSetup2fa != null) {
                            if (is2faOn) {
                                tvBtnSetup2fa.setText("Disable two-factor");
                                tvBtnSetup2fa.setOnClickListener(v -> showDisable2FaConfirmDialog(refreshHolder[0]));
                            } else {
                                tvBtnSetup2fa.setText("Set up two-factor");
                                tvBtnSetup2fa.setOnClickListener(v -> showSetup2FaDialog(refreshHolder[0]));
                            }
                        }

                        TextView btnViewBackupCodes = dialogView.findViewById(R.id.btn_profile_view_backup_codes);
                        if (btnViewBackupCodes != null) {
                            if (is2faOn) {
                                btnViewBackupCodes.setVisibility(View.VISIBLE);
                                KotSafeUserManager.getBackupCodesRemainingCount(MainActivity.this, new KotSafeUserManager.Callback<Integer>() {
                                    @Override
                                    public void onSuccess(Integer count) {
                                        if (isFinishing() || isDestroyed()) return;
                                        int remaining = count != null ? count : 0;
                                        btnViewBackupCodes.setText(remaining > 0 ? ("Backup recovery codes (" + remaining + " left)") : "Generate new backup codes");
                                        btnViewBackupCodes.setOnClickListener(v -> showBackupCodesDialog(remaining == 0, refreshHolder[0]));
                                    }
                                    @Override
                                    public void onError(String message) {
                                        btnViewBackupCodes.setText("View backup recovery codes");
                                        btnViewBackupCodes.setOnClickListener(v -> showBackupCodesDialog(false, refreshHolder[0]));
                                    }
                                });
                            } else {
                                btnViewBackupCodes.setVisibility(View.GONE);
                            }
                        }
                    }

                    @Override
                    public void onError(String message) {}
                });
            };
            refreshHolder[0].run();

            // Biometric App Lock Toggle
            com.google.android.material.switchmaterial.SwitchMaterial switchBiometrics = dialogView.findViewById(R.id.switch_profile_biometrics);
            TextView tvBiometricDesc = dialogView.findViewById(R.id.tv_profile_biometric_desc);
            if (switchBiometrics != null) {
                boolean supported = BiometricLockManager.isBiometricSupported(this);
                if (!supported) {
                    if (tvBiometricDesc != null) tvBiometricDesc.setText("Not enrolled or not supported on this device");
                    switchBiometrics.setEnabled(false);
                    switchBiometrics.setChecked(false);
                } else {
                    boolean enabled = BiometricLockManager.isBiometricEnabled(this);
                    switchBiometrics.setChecked(enabled);
                    if (tvBiometricDesc != null) {
                        tvBiometricDesc.setText(enabled ? "Fingerprint/Face lock is active" : "Fingerprint or face unlock");
                    }
                    switchBiometrics.setOnCheckedChangeListener((btn, isChecked) -> {
                        if (isChecked == BiometricLockManager.isBiometricEnabled(this)) return;
                        if (isChecked) {
                            BiometricLockManager.authenticate(this, "Enable Biometric Security", "Scan fingerprint or face to lock KotSafe", new BiometricLockManager.AuthCallback() {
                                @Override
                                public void onSuccess() {
                                    BiometricLockManager.setBiometricEnabled(MainActivity.this, true);
                                    if (tvBiometricDesc != null) tvBiometricDesc.setText("Fingerprint/Face lock is active");
                                    KotSafeUserManager.logSecurityEvent(MainActivity.this, "BIOMETRIC_ARMED", "Biometric App Lock Armed", "Fingerprint / Face authentication enabled");
                                    Toast.makeText(MainActivity.this, "Biometric app lock armed!", Toast.LENGTH_SHORT).show();
                                }
                                @Override
                                public void onError(String message) {
                                    switchBiometrics.setChecked(false);
                                    Toast.makeText(MainActivity.this, "Biometric authentication failed: " + message, Toast.LENGTH_SHORT).show();
                                }
                                @Override
                                public void onCancelled() {
                                    switchBiometrics.setChecked(false);
                                }
                            });
                        } else {
                            BiometricLockManager.authenticate(this, "Disable Biometric Security", "Verify identity to disarm app lock", new BiometricLockManager.AuthCallback() {
                                @Override
                                public void onSuccess() {
                                    BiometricLockManager.setBiometricEnabled(MainActivity.this, false);
                                    if (tvBiometricDesc != null) tvBiometricDesc.setText("Fingerprint or face unlock");
                                    KotSafeUserManager.logSecurityEvent(MainActivity.this, "BIOMETRIC_DISARMED", "Biometric App Lock Disarmed", "Fingerprint / Face authentication removed");
                                    Toast.makeText(MainActivity.this, "Biometric app lock disarmed", Toast.LENGTH_SHORT).show();
                                }
                                @Override
                                public void onError(String message) {
                                    switchBiometrics.setChecked(true);
                                    Toast.makeText(MainActivity.this, "Failed to verify identity: " + message, Toast.LENGTH_SHORT).show();
                                }
                                @Override
                                public void onCancelled() {
                                    switchBiometrics.setChecked(true);
                                }
                            });
                        }
                    });
                }
            }

            // Recent Security Activity Audit Log
            View rowSecurityActivity = dialogView.findViewById(R.id.row_profile_security_activity);
            if (rowSecurityActivity != null) {
                rowSecurityActivity.setOnClickListener(v -> showSecurityActivityDialog());
            }

            if (btnSetup2faHero != null) {
                btnSetup2faHero.setOnClickListener(v -> showSetup2FaDialog(refreshHolder[0]));
            }

            if (btnSignOut != null) {
                btnSignOut.setOnClickListener(v -> {
                    new AlertDialog.Builder(this)
                            .setTitle("Sign Out of KotSafe")
                            .setMessage("Are you sure you want to sign out? P2P mesh and cloud protection will require sign-in to reactivate.")
                            .setPositiveButton("Sign Out", (d, w) -> {
                                dialog.dismiss();
                                sBiometricUnlockedThisSession = false;
                                KotSafeUserManager.signOut(this, () -> {
                                    Intent intent = new Intent(this, LoginActivity.class);
                                    intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
                                    startActivity(intent);
                                    finish();
                                });
                            })
                            .setNegativeButton("Cancel", null)
                            .show();
                });
            }
        } else {
            if (layoutGuestBanner != null) layoutGuestBanner.setVisibility(View.VISIBLE);
            if (badgeVerified != null) badgeVerified.setVisibility(View.GONE);
            if (btnSignOut != null) btnSignOut.setVisibility(View.GONE);

            if (btnSignIn != null) {
                btnSignIn.setOnClickListener(v -> {
                    dialog.dismiss();
                    startActivity(new Intent(this, LoginActivity.class));
                });
            }
            if (tvUserName != null) tvUserName.setText("Guest Sentinel");
            if (tvUserEmail != null) tvUserEmail.setText("Local Shield Active (P2P Locked)");
            if (tvAvatarInitial != null) tvAvatarInitial.setText("G");
            if (tvStatusChip != null) {
                tvStatusChip.setText("Guest Mode • Local Only");
                tvStatusChip.setTextColor(ContextCompat.getColor(this, R.color.profileWarning));
            }
            if (dotStatus != null) {
                dotStatus.setBackgroundTintList(ColorStateList.valueOf(
                        ContextCompat.getColor(this, R.color.profileWarning)));
            }
        }
        // ── Connected Devices & Active Sessions ──────────────────────────────
        LinearLayout layoutDevicesSubpageList = dialogView.findViewById(R.id.layout_profile_devices_subpage_list);
        TextView tvDevicesCountBadge = dialogView.findViewById(R.id.tv_profile_connected_devices_badge);
        TextView tvSubpageDevicesCount = dialogView.findViewById(R.id.tv_profile_subpage_devices_count);

        if (isAuthenticated) {
            String uid = com.google.firebase.auth.FirebaseAuth.getInstance().getCurrentUser() != null
                    ? com.google.firebase.auth.FirebaseAuth.getInstance().getCurrentUser().getUid()
                    : null;
            loadAndBindConnectedDevices(dialog, layoutDevicesSubpageList, tvDevicesCountBadge, tvSubpageDevicesCount, uid);
        } else {
            if (layoutDevicesSubpageList != null) {
                layoutDevicesSubpageList.removeAllViews();
                CloudSyncManager.DeviceInfo localDev = CloudSyncManager.getInstance(this).createCurrentDeviceInfo(null);
                View devView = createDeviceItemView(dialog, localDev, null, layoutDevicesSubpageList, tvDevicesCountBadge, tvSubpageDevicesCount);
                layoutDevicesSubpageList.addView(devView);
            }
            if (tvDevicesCountBadge != null) {
                tvDevicesCountBadge.setText("1 LOCAL");
            }
            if (tvSubpageDevicesCount != null) {
                tvSubpageDevicesCount.setText("1 LOCAL");
            }
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

        if (openDevicesSubpage && viewFlipper != null) {
            viewFlipper.setDisplayedChild(2);
            if (profileScrollView != null) {
                profileScrollView.post(() -> profileScrollView.scrollTo(0, 0));
            }
        }

        dialog.show();
        android.view.Window profileWindow = dialog.getWindow();
        if (profileWindow != null) {
            profileWindow.setBackgroundDrawableResource(android.R.color.transparent);
            profileWindow.setGravity(android.view.Gravity.BOTTOM);
            int densityAdjustedMargin = Math.round(16 * getResources().getDisplayMetrics().density);
            int width = getResources().getDisplayMetrics().widthPixels - (densityAdjustedMargin * 2);
            int height = Math.round(getResources().getDisplayMetrics().heightPixels * 0.90f);
            profileWindow.setLayout(width, height);
        }
    }

    private void loadAndBindConnectedDevices(AlertDialog profileDialog, LinearLayout container, TextView countView, TextView subpageCountView, String uid) {
        if (container == null) return;
        CloudSyncManager.getInstance(this).loadUserDevices(uid, new CloudSyncManager.DeviceListCallback() {
            @Override
            public void onDevicesLoaded(List<CloudSyncManager.DeviceInfo> devices) {
                if (isFinishing() || isDestroyed()) return;
                container.removeAllViews();

                for (CloudSyncManager.DeviceInfo dev : devices) {
                    View devView = createDeviceItemView(profileDialog, dev, uid, container, countView, subpageCountView);
                    container.addView(devView);
                }

                int total = devices.size();
                String countText = total + " ACTIVE";
                if (countView != null) {
                    countView.setText(countText);
                }
                if (subpageCountView != null) {
                    subpageCountView.setText(countText);
                }
            }

            @Override
            public void onError(String error) {
                Log.w(TAG, "Failed loading connected devices: " + error);
            }
        });
    }

    private View createDeviceItemView(AlertDialog profileDialog, CloudSyncManager.DeviceInfo dev, String uid, LinearLayout container, TextView countView, TextView subpageCountView) {
        View itemView = getLayoutInflater().inflate(R.layout.item_profile_device, container, false);
        TextView tvModel = itemView.findViewById(R.id.tv_device_model);
        TextView tvOsVersion = itemView.findViewById(R.id.tv_device_os_version);
        TextView tvAppBuild = itemView.findViewById(R.id.tv_device_app_build);
        TextView tvHardwareId = itemView.findViewById(R.id.tv_device_hardware_id);
        TextView tvThreatPosture = itemView.findViewById(R.id.tv_device_threat_posture);
        TextView tvMeshTunnel = itemView.findViewById(R.id.tv_device_mesh_tunnel);
        TextView tvLastHeartbeat = itemView.findViewById(R.id.tv_device_last_heartbeat);

        TextView tvSessionStatus = itemView.findViewById(R.id.tv_device_session_status);
        View dotStatus = itemView.findViewById(R.id.dot_device_status);
        View btnSignOut = itemView.findViewById(R.id.btn_device_sign_out);

        // Protected Mode Banner Elements
        View layoutProtectionBanner = itemView.findViewById(R.id.layout_device_protection_banner);
        ImageView ivProtectionShield = itemView.findViewById(R.id.iv_device_protection_shield);
        TextView tvProtectionTitle = itemView.findViewById(R.id.tv_device_protection_title);
        TextView chipProtectionState = itemView.findViewById(R.id.chip_device_protection_state);
        TextView tvProtectionDesc = itemView.findViewById(R.id.tv_device_protection_desc);

        if (tvModel != null) {
            tvModel.setText(dev.model != null && !dev.model.isEmpty() ? dev.model : "KotSafe Sentinel Device");
        }

        // 1. Status Dot: Green (Online), Blue (Relay/Mesh), Red (Offline)
        if (dotStatus != null && tvSessionStatus != null) {
            dotStatus.setBackgroundTintList(null); // Clear any existing tint filter
            if ("RELAY".equalsIgnoreCase(dev.statusType) || "MESH".equalsIgnoreCase(dev.statusType)) {
                // Blue Dot: Relay / Mesh Node
                dotStatus.setBackgroundResource(R.drawable.bg_profile_status_dot_blue);
                tvSessionStatus.setText("Mesh Relay Active • P2P Sync");
                tvSessionStatus.setTextColor(ContextCompat.getColor(this, R.color.profileAccentStrong));
            } else if (!dev.isOnline || "OFFLINE".equalsIgnoreCase(dev.statusType)) {
                // Red Dot: Offline Session
                dotStatus.setBackgroundResource(R.drawable.bg_profile_status_dot_red);
                tvSessionStatus.setText("Offline • Inactive Session");
                tvSessionStatus.setTextColor(ContextCompat.getColor(this, R.color.profileDanger));
            } else {
                // Green Dot: Online Active Session
                dotStatus.setBackgroundResource(R.drawable.bg_profile_status_dot);
                if (dev.isCurrentDevice) {
                    tvSessionStatus.setText("Active Session • This Device");
                } else {
                    tvSessionStatus.setText("Active Session • Online");
                }
                tvSessionStatus.setTextColor(ContextCompat.getColor(this, R.color.profileSuccessText));
            }
        }

        // 2. Device Protected Mode Status
        boolean isDeviceProtected = dev.isCurrentDevice ? (mState == AppState.running) : dev.isProtected;
        if (layoutProtectionBanner != null && tvProtectionTitle != null && chipProtectionState != null && tvProtectionDesc != null) {
            if (isDeviceProtected) {
                layoutProtectionBanner.setBackgroundResource(R.drawable.bg_profile_green_card);
                if (ivProtectionShield != null) {
                    ivProtectionShield.setColorFilter(ContextCompat.getColor(this, R.color.profileSuccess));
                }
                tvProtectionTitle.setText("Protected Mode: ACTIVE");
                tvProtectionTitle.setTextColor(ContextCompat.getColor(this, R.color.profileSuccessText));
                chipProtectionState.setText("ARMED");
                chipProtectionState.setBackgroundResource(R.drawable.bg_profile_pill_green);
                chipProtectionState.setTextColor(ContextCompat.getColor(this, R.color.profileSuccessText));
                tvProtectionDesc.setText("Zero-Trust Shield Armed • Antivirus Active • VPN ON");
                tvProtectionDesc.setTextColor(ContextCompat.getColor(this, R.color.profileSuccessMuted));
            } else {
                layoutProtectionBanner.setBackgroundResource(R.drawable.bg_profile_card);
                if (ivProtectionShield != null) {
                    ivProtectionShield.setColorFilter(ContextCompat.getColor(this, R.color.profileWarning));
                }
                tvProtectionTitle.setText("Protected Mode: UNPROTECTED");
                tvProtectionTitle.setTextColor(ContextCompat.getColor(this, R.color.profileWarning));
                chipProtectionState.setText("PAUSED");
                chipProtectionState.setBackgroundResource(R.drawable.bg_profile_pill_yellow);
                chipProtectionState.setTextColor(ContextCompat.getColor(this, R.color.profileWarning));
                tvProtectionDesc.setText("Protection Paused • Traffic Unfiltered • Caution");
                tvProtectionDesc.setTextColor(ContextCompat.getColor(this, R.color.profileTextSecondary));
            }
        }

        // 3. Detailed Specifications
        if (tvOsVersion != null) {
            tvOsVersion.setText(dev.osVersion != null && !dev.osVersion.isEmpty() ? dev.osVersion : "Android");
        }

        if (tvAppBuild != null) {
            String ver = dev.appVersion != null && !dev.appVersion.isEmpty()
                    ? dev.appVersion
                    : BuildConfig.VERSION_NAME;
            if (!ver.startsWith("v")) ver = "v" + ver;
            tvAppBuild.setText(ver);
        }

        if (tvHardwareId != null) {
            String hwId = dev.deviceId != null ? dev.deviceId : "unknown";
            if (hwId.length() > 14) {
                hwId = hwId.substring(0, 8) + "..." + hwId.substring(hwId.length() - 4);
            }
            tvHardwareId.setText("HW: " + hwId);
        }

        if (tvThreatPosture != null) {
            tvThreatPosture.setText(dev.threatScore + " / 100 Secure");
            tvThreatPosture.setTextColor(ContextCompat.getColor(this,
                    dev.threatScore >= 80 ? R.color.profileSuccessText : R.color.profileWarning));
        }

        if (tvMeshTunnel != null) {
            tvMeshTunnel.setText(dev.meshStatus != null && !dev.meshStatus.isEmpty()
                    ? dev.meshStatus
                    : "Zero-Trust Direct");
        }

        if (tvLastHeartbeat != null) {
            long diffMs = System.currentTimeMillis() - dev.lastHeartbeat;
            if (diffMs < 60_000) {
                tvLastHeartbeat.setText("Just now");
            } else if (diffMs < 3600_000) {
                tvLastHeartbeat.setText((diffMs / 60_000) + "m ago");
            } else if (diffMs < 86_400_000L * 2) {
                tvLastHeartbeat.setText((diffMs / 3600_000) + "h ago");
            } else {
                java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat("MMM dd, HH:mm", java.util.Locale.getDefault());
                tvLastHeartbeat.setText(sdf.format(new java.util.Date(dev.lastHeartbeat)));
            }
        }

        // 4. Sign Out Action
        if (btnSignOut != null) {
            AnimUtils.attachSpringTouch(btnSignOut);
            btnSignOut.setOnClickListener(v -> {
                showDeviceSignoutConfirmDialog(profileDialog, dev, uid, container, countView, subpageCountView);
            });
        }

        // 5. Remote Defense Actions (For other connected devices in account mesh)
        View layoutRemoteActions = itemView.findViewById(R.id.layout_device_remote_actions);
        View btnRemoteArm = itemView.findViewById(R.id.btn_remote_arm);
        View btnRemoteScan = itemView.findViewById(R.id.btn_remote_scan);
        View btnRemoteKillSwitch = itemView.findViewById(R.id.btn_remote_kill_switch);
        TextView tvRemoteArmText = itemView.findViewById(R.id.tv_remote_arm_text);

        if (!dev.isCurrentDevice) {
            if (layoutRemoteActions != null) {
                layoutRemoteActions.setVisibility(View.VISIBLE);
            }
            if (btnRemoteArm != null) {
                AnimUtils.attachSpringTouch(btnRemoteArm);
                if (tvRemoteArmText != null) {
                    tvRemoteArmText.setText(dev.isProtected ? "Disarm" : "Arm");
                }
                btnRemoteArm.setOnClickListener(v -> {
                    String cmd = dev.isProtected ? "REMOTE_DISARM" : "REMOTE_ARM";
                    Toast.makeText(this, "Sending " + (dev.isProtected ? "Disarm" : "Arm") + " to " + dev.model + "...", Toast.LENGTH_SHORT).show();
                    CloudSyncManager.getInstance(this).sendRemoteDefenseCommand(uid, dev.deviceId, cmd, () -> {
                        Toast.makeText(this, "Defense command delivered to " + dev.model, Toast.LENGTH_SHORT).show();
                        loadAndBindConnectedDevices(profileDialog, container, countView, subpageCountView, uid);
                    }, error -> {
                        Toast.makeText(this, "Failed delivering command: " + error, Toast.LENGTH_SHORT).show();
                    });
                });
            }
            if (btnRemoteScan != null) {
                AnimUtils.attachSpringTouch(btnRemoteScan);
                btnRemoteScan.setOnClickListener(v -> {
                    Toast.makeText(this, "Dispatching Antivirus Scan to " + dev.model + "...", Toast.LENGTH_SHORT).show();
                    CloudSyncManager.getInstance(this).sendRemoteDefenseCommand(uid, dev.deviceId, "REMOTE_SCAN", () -> {
                        Toast.makeText(this, "Security scan initiated on " + dev.model, Toast.LENGTH_SHORT).show();
                    }, error -> {
                        Toast.makeText(this, "Failed dispatching scan: " + error, Toast.LENGTH_SHORT).show();
                    });
                });
            }
            if (btnRemoteKillSwitch != null) {
                AnimUtils.attachSpringTouch(btnRemoteKillSwitch);
                btnRemoteKillSwitch.setOnClickListener(v -> {
                    showRemoteKillSwitchConfirmDialog(profileDialog, dev, uid, container, countView, subpageCountView);
                });
            }
        } else {
            if (layoutRemoteActions != null) {
                layoutRemoteActions.setVisibility(View.GONE);
            }
        }

        return itemView;
    }

    private void showRemoteKillSwitchConfirmDialog(AlertDialog profileDialog, CloudSyncManager.DeviceInfo dev, String uid, LinearLayout container, TextView countView, TextView subpageCountView) {
        View modalView = getLayoutInflater().inflate(R.layout.dialog_device_signout_confirm, null);
        AlertDialog confirmDialog = new AlertDialog.Builder(this)
                .setView(modalView)
                .create();

        if (confirmDialog.getWindow() != null) {
            confirmDialog.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
        }

        TextView tvDevName = modalView.findViewById(R.id.tv_modal_device_name);
        TextView tvDevSub = modalView.findViewById(R.id.tv_modal_device_sub);
        TextView tvTitle = modalView.findViewById(R.id.tv_modal_title);
        TextView tvDesc = modalView.findViewById(R.id.tv_modal_desc);
        View btnCancel = modalView.findViewById(R.id.btn_modal_cancel);
        TextView btnConfirmText = modalView.findViewById(R.id.tv_modal_confirm_text);
        View btnConfirm = modalView.findViewById(R.id.btn_modal_confirm_signout);

        if (tvTitle != null) tvTitle.setText("Zero-Trust Kill Switch");
        if (tvDevName != null) tvDevName.setText(dev.model != null ? dev.model : "Remote Device");
        if (tvDevSub != null) tvDevSub.setText("Target Device • Immediate Remote Lockdown");
        if (tvDesc != null) {
            tvDesc.setText("Engaging the Kill Switch will immediately sever all active VPN tunnels, scrub cached security logs, and lock KotSafe with mandatory Biometric/PIN re-authentication on " + dev.model + ".");
        }
        if (btnConfirmText != null) btnConfirmText.setText("Engage Kill Switch");

        if (btnCancel != null) {
            AnimUtils.attachSpringTouch(btnCancel);
            btnCancel.setOnClickListener(v -> confirmDialog.dismiss());
        }

        if (btnConfirm != null) {
            AnimUtils.attachSpringTouch(btnConfirm);
            btnConfirm.setOnClickListener(v -> {
                btnConfirm.setEnabled(false);
                confirmDialog.dismiss();
                Toast.makeText(this, "Engaging Kill Switch on " + dev.model + "...", Toast.LENGTH_SHORT).show();
                CloudSyncManager.getInstance(this).sendRemoteDefenseCommand(uid, dev.deviceId, "REMOTE_KILL_SWITCH", () -> {
                    Toast.makeText(this, "Kill Switch successfully engaged on " + dev.model, Toast.LENGTH_SHORT).show();
                    loadAndBindConnectedDevices(profileDialog, container, countView, subpageCountView, uid);
                }, error -> {
                    Toast.makeText(this, "Kill switch failed: " + error, Toast.LENGTH_SHORT).show();
                });
            });
        }

        confirmDialog.show();
        if (confirmDialog.getWindow() != null) {
            confirmDialog.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
            int margin = Math.round(24 * getResources().getDisplayMetrics().density);
            int width = getResources().getDisplayMetrics().widthPixels - (margin * 2);
            confirmDialog.getWindow().setLayout(width, android.view.ViewGroup.LayoutParams.WRAP_CONTENT);
        }
    }

    private void showDeviceSignoutConfirmDialog(AlertDialog profileDialog, CloudSyncManager.DeviceInfo dev, String uid, LinearLayout container, TextView countView, TextView subpageCountView) {
        View modalView = getLayoutInflater().inflate(R.layout.dialog_device_signout_confirm, null);
        AlertDialog confirmDialog = new AlertDialog.Builder(this)
                .setView(modalView)
                .create();

        if (confirmDialog.getWindow() != null) {
            confirmDialog.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
        }

        TextView tvDevName = modalView.findViewById(R.id.tv_modal_device_name);
        TextView tvDevSub = modalView.findViewById(R.id.tv_modal_device_sub);
        View btnCancel = modalView.findViewById(R.id.btn_modal_cancel);
        View btnConfirm = modalView.findViewById(R.id.btn_modal_confirm_signout);

        if (tvDevName != null) {
            String name = dev.model != null ? dev.model : "Device";
            if (dev.isCurrentDevice) name += " (This Device)";
            tvDevName.setText(name);
        }

        if (tvDevSub != null) {
            String devSub = (dev.osVersion != null ? dev.osVersion : "Android")
                    + (dev.isCurrentDevice ? " • Current Active Session" : " • Remote Session");
            tvDevSub.setText(devSub);
        }

        if (btnCancel != null) {
            AnimUtils.attachSpringTouch(btnCancel);
            btnCancel.setOnClickListener(v -> confirmDialog.dismiss());
        }

        if (btnConfirm != null) {
            AnimUtils.attachSpringTouch(btnConfirm);
            btnConfirm.setOnClickListener(v -> {
                btnConfirm.setEnabled(false);
                confirmDialog.dismiss();

                if (dev.isCurrentDevice) {
                    if (profileDialog != null) profileDialog.dismiss();
                    Toast.makeText(this, "Signing out current device...", Toast.LENGTH_SHORT).show();
                    CloudSyncManager.getInstance(this).revokeDeviceSession(uid, dev.deviceId, () -> {
                        KotSafeUserManager.signOut(this, () -> {
                            Intent intent = new Intent(this, LoginActivity.class);
                            intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
                            startActivity(intent);
                            finish();
                        });
                    }, error -> {
                        KotSafeUserManager.signOut(this, () -> {
                            Intent intent = new Intent(this, LoginActivity.class);
                            intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
                            startActivity(intent);
                            finish();
                        });
                    });
                } else {
                    Toast.makeText(this, "Revoking session for " + dev.model + "...", Toast.LENGTH_SHORT).show();
                    CloudSyncManager.getInstance(this).revokeDeviceSession(uid, dev.deviceId, () -> {
                        Toast.makeText(this, "Device session revoked successfully", Toast.LENGTH_SHORT).show();
                        loadAndBindConnectedDevices(profileDialog, container, countView, subpageCountView, uid);
                    }, error -> {
                        Toast.makeText(this, "Failed to revoke session: " + error, Toast.LENGTH_SHORT).show();
                    });
                }
            });
        }

        confirmDialog.show();
        if (confirmDialog.getWindow() != null) {
            confirmDialog.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
            int margin = Math.round(24 * getResources().getDisplayMetrics().density);
            int width = getResources().getDisplayMetrics().widthPixels - (margin * 2);
            confirmDialog.getWindow().setLayout(width, android.view.ViewGroup.LayoutParams.WRAP_CONTENT);
        }
    }


    private void showChangePasswordDialog() {
        View view = getLayoutInflater().inflate(R.layout.dialog_change_password, null);
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setView(view)
                .create();

        if (dialog.getWindow() != null) {
            dialog.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
        }

        TextInputLayout tilCurrent = view.findViewById(R.id.til_current_password);
        TextInputLayout tilNew = view.findViewById(R.id.til_new_password);
        TextInputLayout tilConfirm = view.findViewById(R.id.til_confirm_password);
        TextInputEditText etCurrent = view.findViewById(R.id.et_current_password);
        TextInputEditText etNew = view.findViewById(R.id.et_new_password);
        TextInputEditText etConfirm = view.findViewById(R.id.et_confirm_password);
        View btnCancel = view.findViewById(R.id.btn_cancel_change_pwd);
        View btnSubmit = view.findViewById(R.id.btn_submit_change_pwd);

        if (btnCancel != null) {
            btnCancel.setOnClickListener(v -> dialog.dismiss());
        }

        if (btnSubmit != null) {
            btnSubmit.setOnClickListener(v -> {
                String currPass = etCurrent != null && etCurrent.getText() != null ? etCurrent.getText().toString().trim() : "";
                String newPass = etNew != null && etNew.getText() != null ? etNew.getText().toString().trim() : "";
                String confirmPass = etConfirm != null && etConfirm.getText() != null ? etConfirm.getText().toString().trim() : "";

                if (tilCurrent != null) tilCurrent.setError(null);
                if (tilNew != null) tilNew.setError(null);
                if (tilConfirm != null) tilConfirm.setError(null);

                if (currPass.isEmpty()) {
                    if (tilCurrent != null) tilCurrent.setError("Current password is required");
                    return;
                }
                if (newPass.length() < 8) {
                    if (tilNew != null) tilNew.setError("New password must be at least 8 characters");
                    return;
                }
                if (!newPass.equals(confirmPass)) {
                    if (tilConfirm != null) tilConfirm.setError("Passwords do not match");
                    return;
                }

                btnSubmit.setEnabled(false);
                KotSafeUserManager.changePassword(currPass, newPass, new KotSafeUserManager.Callback<Void>() {
                    @Override
                    public void onSuccess(Void result) {
                        runOnUiThread(() -> {
                            Toast.makeText(MainActivity.this, "Password updated successfully!", Toast.LENGTH_LONG).show();
                            dialog.dismiss();
                        });
                    }

                    @Override
                    public void onError(String message) {
                        runOnUiThread(() -> {
                            btnSubmit.setEnabled(true);
                            if (tilCurrent != null) tilCurrent.setError(message);
                            Toast.makeText(MainActivity.this, message, Toast.LENGTH_LONG).show();
                        });
                    }
                });
            });
        }

        dialog.show();
    }

    private void showPasswordResetDialog(String userEmail) {
        if (userEmail == null || userEmail.trim().isEmpty()) {
            Toast.makeText(this, "No registered email found to send reset link.", Toast.LENGTH_SHORT).show();
            return;
        }

        new AlertDialog.Builder(this)
                .setTitle("Reset Password Link")
                .setMessage("A secure password recovery email will be dispatched to:\n\n" + userEmail + "\n\nFollow the link in the email to set a new password.")
                .setIcon(R.drawable.ic_lock)
                .setPositiveButton("Send Reset Link", (dialog, which) -> {
                    KotSafeUserManager.sendPasswordResetEmail(this, userEmail, new KotSafeUserManager.Callback<Void>() {
                        @Override
                        public void onSuccess(Void result) {
                            runOnUiThread(() -> {
                                Toast.makeText(MainActivity.this, "Password reset email sent to " + userEmail, Toast.LENGTH_LONG).show();
                            });
                        }

                        @Override
                        public void onError(String message) {
                            runOnUiThread(() -> {
                                Toast.makeText(MainActivity.this, "Failed to send reset email: " + message, Toast.LENGTH_LONG).show();
                            });
                        }
                    });
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void showSetup2FaDialog(Runnable onEnabledSuccess) {
        View view = getLayoutInflater().inflate(R.layout.dialog_setup_2fa, null);
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setView(view)
                .create();

        if (dialog.getWindow() != null) {
            dialog.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
        }

        String secret = TotpHelper.generateSecret();
        String formattedSecret = TotpHelper.formatSecret(secret);
        String userEmail = KotSafeUserManager.getLoggedInEmail(this);
        String otpUri = TotpHelper.generateOtpAuthUri("KotSafe", userEmail, secret);

        View layoutStep1 = view.findViewById(R.id.layout_step1_scan);
        View layoutStep2 = view.findViewById(R.id.layout_step2_verify);
        ImageView ivQrCode = view.findViewById(R.id.iv_2fa_qr_code);
        TextView tvSecret = view.findViewById(R.id.tv_2fa_secret_key);
        View btnCopy = view.findViewById(R.id.btn_copy_2fa_secret);
        TextView badgeBackupRequired = view.findViewById(R.id.badge_backup_required);
        TextView tvBackupStatus = view.findViewById(R.id.tv_backup_status_hint);
        View btnOpenAuth = view.findViewById(R.id.btn_open_authenticator);
        View btnCancel = view.findViewById(R.id.btn_cancel_setup_2fa);
        View btnStep1Next = view.findViewById(R.id.btn_step1_next);
        View btnStep2Back = view.findViewById(R.id.btn_step2_back);
        EditText etCode = view.findViewById(R.id.et_2fa_verify_code);
        TextView tvError = view.findViewById(R.id.tv_2fa_setup_error);
        View btnSubmit = view.findViewById(R.id.btn_submit_setup_2fa);

        if (ivQrCode != null) {
            Bitmap qrBitmap = TotpHelper.generateQrCode(otpUri, 480, 480);
            if (qrBitmap != null) {
                ivQrCode.setImageBitmap(qrBitmap);
            }
        }

        if (tvSecret != null) tvSecret.setText(formattedSecret);

        final boolean[] hasCopiedKey = {false};

        Runnable doCopyAction = () -> {
            android.content.ClipboardManager clipboard = (android.content.ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            android.content.ClipData clip = android.content.ClipData.newPlainText("KotSafe 2FA Backup Key", secret);
            if (clipboard != null) clipboard.setPrimaryClip(clip);

            hasCopiedKey[0] = true;

            if (btnCopy instanceof TextView) {
                ((TextView) btnCopy).setText("✓ Copied");
            }
            if (badgeBackupRequired != null) {
                badgeBackupRequired.setText("✓ Saved");
                badgeBackupRequired.setTextColor(ContextCompat.getColor(this, R.color.profileSuccess));
                badgeBackupRequired.setBackgroundResource(R.drawable.bg_profile_pill_green);
            }
            if (tvBackupStatus != null) {
                tvBackupStatus.setText("✓ Backup key copied! Store it safely for future recovery.");
                tvBackupStatus.setTextColor(ContextCompat.getColor(this, R.color.profileSuccess));
            }
            if (tvError != null) tvError.setVisibility(View.GONE);

            // Inform the user immediately about storing this key for unexpected app loss / reset
            new AlertDialog.Builder(this)
                    .setTitle("🔑 Save Your Backup Key")
                    .setMessage("Your backup secret key has been copied:\n\n" + formattedSecret + "\n\n" +
                            "⚠️ CRITICAL INSTRUCTION:\n" +
                            "Please save this key in a secure place (password manager, offline note, or safe storage).\n\n" +
                            "If your phone is lost, damaged, or your authenticator app is reset unexpectedly or uninstalled, this key is the ONLY way to regain access to your KotSafe account.")
                    .setIcon(R.drawable.ic_profile_key)
                    .setPositiveButton("I Understand, Saved It", null)
                    .show();
        };

        if (btnCopy != null) {
            btnCopy.setOnClickListener(v -> doCopyAction.run());
        }

        if (btnOpenAuth != null) {
            btnOpenAuth.setOnClickListener(v -> {
                try {
                    Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(otpUri));
                    startActivity(intent);
                } catch (Exception e) {
                    Toast.makeText(this, "No Authenticator app found. Please copy the key manually into Google Authenticator or Authy.", Toast.LENGTH_LONG).show();
                }
            });
        }

        if (btnCancel != null) btnCancel.setOnClickListener(v -> dialog.dismiss());

        // Step 1 -> Step 2 transition: ONLY when key is backed up
        if (btnStep1Next != null) {
            btnStep1Next.setOnClickListener(v -> {
                if (!hasCopiedKey[0]) {
                    new AlertDialog.Builder(this)
                            .setTitle("Backup Key Required")
                            .setMessage("You cannot proceed until you backup your secret key.\n\n" +
                                    "If your phone is lost, or your authenticator app is reset unexpectedly or uninstalled, this key is the ONLY way to recover your KotSafe account.")
                            .setIcon(R.drawable.ic_profile_key)
                            .setPositiveButton("Copy Key Now", (d, w) -> doCopyAction.run())
                            .setNegativeButton("Cancel", null)
                            .show();
                    return;
                }

                if (layoutStep1 != null && layoutStep2 != null) {
                    layoutStep1.setVisibility(View.GONE);
                    layoutStep2.setVisibility(View.VISIBLE);
                    if (etCode != null) {
                        etCode.requestFocus();
                    }
                }
            });
        }

        // Step 2 -> Step 1 back navigation
        if (btnStep2Back != null) {
            btnStep2Back.setOnClickListener(v -> {
                if (layoutStep1 != null && layoutStep2 != null) {
                    layoutStep2.setVisibility(View.GONE);
                    layoutStep1.setVisibility(View.VISIBLE);
                }
            });
        }

        final int[] failedEnrollmentAttempts = {0};

        if (btnSubmit != null) {
            btnSubmit.setOnClickListener(v -> {
                String raw = etCode != null && etCode.getText() != null ? etCode.getText().toString().trim() : "";
                String code = raw.replaceAll("\\s+", "");
                if (code.length() != 6 || !code.matches("\\d{6}")) {
                    if (tvError != null) {
                        tvError.setText("Please enter a valid 6-digit number (e.g. 123456).");
                        tvError.setVisibility(View.VISIBLE);
                    }
                    return;
                }

                btnSubmit.setEnabled(false);
                KotSafeUserManager.enableTwoFactor(this, secret, code, new KotSafeUserManager.Callback<Void>() {
                    @Override
                    public void onSuccess(Void result) {
                        runOnUiThread(() -> {
                            dialog.dismiss();
                            show2FaSuccessDialog();
                            if (onEnabledSuccess != null) onEnabledSuccess.run();
                        });
                    }

                    @Override
                    public void onError(String message) {
                        runOnUiThread(() -> {
                            failedEnrollmentAttempts[0]++;
                            btnSubmit.setEnabled(true);
                            if (tvError != null) {
                                if (failedEnrollmentAttempts[0] >= 5) {
                                    tvError.setText("Too many invalid attempts. For your security, this key was invalidated. Please restart setup.");
                                    btnSubmit.setEnabled(false);
                                } else {
                                    tvError.setText(message + " (" + (5 - failedEnrollmentAttempts[0]) + " attempts left)");
                                }
                                tvError.setVisibility(View.VISIBLE);
                            }
                        });
                    }
                });
            });
        }

        dialog.show();
    }

    private void show2FaSuccessDialog() {
        View successView = getLayoutInflater().inflate(R.layout.dialog_2fa_success, null);
        AlertDialog successDialog = new AlertDialog.Builder(this)
                .setView(successView)
                .create();

        if (successDialog.getWindow() != null) {
            successDialog.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
        }

        View btnDone = successView.findViewById(R.id.btn_2fa_success_done);
        if (btnDone != null) {
            btnDone.setOnClickListener(v -> {
                successDialog.dismiss();
                showBackupCodesDialog(true, null);
            });
        }

        successDialog.show();
    }

    private void showDisable2FaConfirmDialog(Runnable onDisabledSuccess) {
        View view = getLayoutInflater().inflate(R.layout.dialog_disable_2fa, null);
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setView(view)
                .create();

        if (dialog.getWindow() != null) {
            dialog.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
        }

        View tilCode = view.findViewById(R.id.til_disable_2fa_code);
        EditText etCode = view.findViewById(R.id.et_disable_2fa_code);
        TextView tvSwitch = view.findViewById(R.id.tv_switch_to_password_verify);
        View layoutPassword = view.findViewById(R.id.layout_password_verify_container);
        EditText etPassword = view.findViewById(R.id.et_disable_2fa_password);
        TextView tvError = view.findViewById(R.id.tv_disable_2fa_error);
        View btnCancel = view.findViewById(R.id.btn_cancel_disable_2fa);
        View btnConfirm = view.findViewById(R.id.btn_confirm_turn_off_2fa);

        final boolean[] usePassword = {false};

        if (tvSwitch != null) {
            tvSwitch.setOnClickListener(v -> {
                usePassword[0] = !usePassword[0];
                if (tvError != null) tvError.setVisibility(View.GONE);
                if (usePassword[0]) {
                    if (tilCode != null) tilCode.setVisibility(View.GONE);
                    if (layoutPassword != null) layoutPassword.setVisibility(View.VISIBLE);
                    tvSwitch.setText("Have your authenticator? Verify with 6-digit code instead");
                    if (etPassword != null) etPassword.requestFocus();
                } else {
                    if (tilCode != null) tilCode.setVisibility(View.VISIBLE);
                    if (layoutPassword != null) layoutPassword.setVisibility(View.GONE);
                    tvSwitch.setText("Lost authenticator? Verify with account password instead");
                    if (etCode != null) etCode.requestFocus();
                }
            });
        }

        if (btnCancel != null) btnCancel.setOnClickListener(v -> dialog.dismiss());

        if (btnConfirm != null) {
            btnConfirm.setOnClickListener(v -> {
                if (tvError != null) tvError.setVisibility(View.GONE);

                if (usePassword[0]) {
                    String password = etPassword != null && etPassword.getText() != null ? etPassword.getText().toString().trim() : "";
                    if (password.isEmpty()) {
                        if (tvError != null) {
                            tvError.setText("Please enter your account password.");
                            tvError.setVisibility(View.VISIBLE);
                        }
                        return;
                    }

                    btnConfirm.setEnabled(false);
                    KotSafeUserManager.disableTwoFactorWithPassword(this, password, new KotSafeUserManager.Callback<Void>() {
                        @Override
                        public void onSuccess(Void result) {
                            runOnUiThread(() -> {
                                dialog.dismiss();
                                Toast.makeText(MainActivity.this, "Two-factor authentication has been turned off.", Toast.LENGTH_SHORT).show();
                                if (onDisabledSuccess != null) onDisabledSuccess.run();
                            });
                        }

                        @Override
                        public void onError(String message) {
                            runOnUiThread(() -> {
                                btnConfirm.setEnabled(true);
                                if (tvError != null) {
                                    tvError.setText(message != null ? message : "Verification failed.");
                                    tvError.setVisibility(View.VISIBLE);
                                }
                            });
                        }
                    });
                } else {
                    String raw = etCode != null && etCode.getText() != null ? etCode.getText().toString().trim() : "";
                    String code = raw.replaceAll("\\s+", "");
                    boolean is6Digit = code.length() == 6 && code.matches("\\d{6}");
                    boolean isBackupCode = code.replace("-", "").length() == 8;

                    if (!is6Digit && !isBackupCode) {
                        if (tvError != null) {
                            tvError.setText("Please enter your 6-digit Authenticator code or an 8-digit Backup code.");
                            tvError.setVisibility(View.VISIBLE);
                        }
                        return;
                    }

                    btnConfirm.setEnabled(false);
                    if (isBackupCode) {
                        KotSafeUserManager.verifyAndConsumeBackupCode(this, code, new KotSafeUserManager.Callback<Boolean>() {
                            @Override
                            public void onSuccess(Boolean valid) {
                                runOnUiThread(() -> {
                                    if (Boolean.TRUE.equals(valid)) {
                                        KotSafeUserManager.disableTwoFactor(MainActivity.this, new KotSafeUserManager.Callback<Void>() {
                                            @Override
                                            public void onSuccess(Void result) {
                                                runOnUiThread(() -> {
                                                    dialog.dismiss();
                                                    Toast.makeText(MainActivity.this, "Two-factor authentication turned off using backup recovery code.", Toast.LENGTH_SHORT).show();
                                                    if (onDisabledSuccess != null) onDisabledSuccess.run();
                                                });
                                            }

                                            @Override
                                            public void onError(String message) {
                                                runOnUiThread(() -> {
                                                    btnConfirm.setEnabled(true);
                                                    if (tvError != null) {
                                                        tvError.setText("Failed to disable 2FA: " + message);
                                                        tvError.setVisibility(View.VISIBLE);
                                                    }
                                                });
                                            }
                                        });
                                    } else {
                                        btnConfirm.setEnabled(true);
                                        if (tvError != null) {
                                            tvError.setText("Invalid or already used backup code.");
                                            tvError.setVisibility(View.VISIBLE);
                                        }
                                    }
                                });
                            }

                            @Override
                            public void onError(String message) {
                                runOnUiThread(() -> {
                                    btnConfirm.setEnabled(true);
                                    if (tvError != null) {
                                        tvError.setText("Error verifying backup code: " + message);
                                        tvError.setVisibility(View.VISIBLE);
                                    }
                                });
                            }
                        });
                        return;
                    }

                    KotSafeUserManager.disableTwoFactorWithTotp(this, code, new KotSafeUserManager.Callback<Void>() {
                        @Override
                        public void onSuccess(Void result) {
                            runOnUiThread(() -> {
                                dialog.dismiss();
                                Toast.makeText(MainActivity.this, "Two-factor authentication has been turned off.", Toast.LENGTH_SHORT).show();
                                if (onDisabledSuccess != null) onDisabledSuccess.run();
                            });
                        }

                        @Override
                        public void onError(String message) {
                            runOnUiThread(() -> {
                                btnConfirm.setEnabled(true);
                                if (tvError != null) {
                                    tvError.setText(message != null ? message : "Invalid 6-digit code.");
                                    tvError.setVisibility(View.VISIBLE);
                                }
                            });
                        }
                    });
                }
            });
        }

        dialog.show();
    }

    private void showBackupCodesDialog(boolean generateNew, Runnable onRefresh) {
        View view = getLayoutInflater().inflate(R.layout.dialog_backup_codes, null);
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setView(view)
                .create();

        if (dialog.getWindow() != null) {
            dialog.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
        }

        TextView[] codeViews = new TextView[]{
                view.findViewById(R.id.tv_backup_code_1),
                view.findViewById(R.id.tv_backup_code_2),
                view.findViewById(R.id.tv_backup_code_3),
                view.findViewById(R.id.tv_backup_code_4),
                view.findViewById(R.id.tv_backup_code_5),
                view.findViewById(R.id.tv_backup_code_6),
                view.findViewById(R.id.tv_backup_code_7),
                view.findViewById(R.id.tv_backup_code_8),
                view.findViewById(R.id.tv_backup_code_9),
                view.findViewById(R.id.tv_backup_code_10)
        };

        final List<String> currentCodes = new ArrayList<>();

        View btnClose = view.findViewById(R.id.btn_close_backup_codes);
        if (btnClose != null) btnClose.setOnClickListener(v -> dialog.dismiss());

        View btnDone = view.findViewById(R.id.btn_done_backup_codes);
        if (btnDone != null) btnDone.setOnClickListener(v -> {
            dialog.dismiss();
            if (onRefresh != null) onRefresh.run();
        });

        View btnCopy = view.findViewById(R.id.btn_copy_all_backup_codes);

        KotSafeUserManager.generateAndSaveBackupCodes(this, new KotSafeUserManager.Callback<List<String>>() {
            @Override
            public void onSuccess(List<String> codes) {
                if (isFinishing() || isDestroyed()) return;
                currentCodes.clear();
                if (codes != null) currentCodes.addAll(codes);
                for (int i = 0; i < codeViews.length; i++) {
                    if (codeViews[i] != null && i < currentCodes.size()) {
                        codeViews[i].setText(String.format(java.util.Locale.US, "%02d. %s", i + 1, currentCodes.get(i)));
                    }
                }
            }

            @Override
            public void onError(String message) {
                Toast.makeText(MainActivity.this, "Failed to generate backup codes: " + message, Toast.LENGTH_SHORT).show();
            }
        });

        if (btnCopy != null) {
            btnCopy.setOnClickListener(v -> {
                if (currentCodes.isEmpty()) return;
                StringBuilder sb = new StringBuilder();
                sb.append("KotSafe 2-Step Verification Backup Codes\n");
                sb.append("Each code can be used once to regain access to your account.\n\n");
                for (int i = 0; i < currentCodes.size(); i++) {
                    sb.append(String.format(java.util.Locale.US, "%02d. %s\n", i + 1, currentCodes.get(i)));
                }
                sb.append("\nSaved on: ").append(new java.util.Date().toString()).append("\n");

                ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                if (clipboard != null) {
                    clipboard.setPrimaryClip(ClipData.newPlainText("KotSafe Backup Codes", sb.toString()));
                    Toast.makeText(MainActivity.this, "All 10 backup codes copied to clipboard!", Toast.LENGTH_LONG).show();
                }
            });
        }

        dialog.show();
    }

    private void showSecurityActivityDialog() {
        View view = getLayoutInflater().inflate(R.layout.dialog_security_activity, null);
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setView(view)
                .create();

        if (dialog.getWindow() != null) {
            dialog.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
        }

        LinearLayout container = view.findViewById(R.id.container_security_activity_items);
        ProgressBar progress = view.findViewById(R.id.progress_security_activity);
        TextView tvEmpty = view.findViewById(R.id.tv_empty_security_activity);
        View btnClose = view.findViewById(R.id.btn_close_security_activity);
        View btnBack = view.findViewById(R.id.btn_back_security_activity);
        View btnRefresh = view.findViewById(R.id.btn_refresh_security_activity);

        if (btnClose != null) btnClose.setOnClickListener(v -> dialog.dismiss());
        if (btnBack != null) btnBack.setOnClickListener(v -> dialog.dismiss());

        Runnable loadLogs = () -> {
            if (progress != null) progress.setVisibility(View.VISIBLE);
            if (tvEmpty != null) tvEmpty.setVisibility(View.GONE);
            if (container != null) container.removeAllViews();

            KotSafeUserManager.getRecentSecurityLogs(this, 25, new KotSafeUserManager.Callback<List<Map<String, Object>>>() {
                @Override
                public void onSuccess(List<Map<String, Object>> logs) {
                    if (isFinishing() || isDestroyed()) return;
                    if (progress != null) progress.setVisibility(View.GONE);
                    if (logs == null || logs.isEmpty()) {
                        if (tvEmpty != null) tvEmpty.setVisibility(View.VISIBLE);
                        return;
                    }

                    if (container != null) {
                        for (Map<String, Object> log : logs) {
                            View itemView = getLayoutInflater().inflate(R.layout.item_security_log, container, false);
                            TextView tvTitle = itemView.findViewById(R.id.tv_log_title);
                            TextView tvSubtitle = itemView.findViewById(R.id.tv_log_subtitle);
                            ImageView imgIcon = itemView.findViewById(R.id.img_log_icon);

                            String title = (String) log.get("title");
                            String desc = (String) log.get("description");
                            String model = (String) log.get("deviceModel");
                            Object timeObj = log.get("timestamp");

                            String timeStr = "Recent";
                            if (timeObj instanceof com.google.firebase.Timestamp) {
                                java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat("MMM dd, yyyy · HH:mm", java.util.Locale.getDefault());
                                timeStr = sdf.format(((com.google.firebase.Timestamp) timeObj).toDate());
                            }

                            if (tvTitle != null) tvTitle.setText(title != null ? title : "Security Activity");
                            if (tvSubtitle != null) {
                                String sub = (model != null ? model : "Device") + " • " + timeStr;
                                if (desc != null && !desc.isEmpty()) {
                                    sub += "\n" + desc;
                                }
                                tvSubtitle.setText(sub);
                            }

                            String eventType = (String) log.get("eventType");
                            if (imgIcon != null && eventType != null) {
                                if (eventType.contains("2FA")) {
                                    imgIcon.setImageResource(R.drawable.ic_profile_2fa_phone);
                                } else if (eventType.contains("BACKUP")) {
                                    imgIcon.setImageResource(R.drawable.ic_profile_key);
                                } else if (eventType.contains("BIOMETRIC")) {
                                    imgIcon.setImageResource(R.drawable.ic_profile_key);
                                } else if (eventType.contains("LOGIN")) {
                                    imgIcon.setImageResource(R.drawable.ic_device_phone);
                                } else {
                                    imgIcon.setImageResource(R.drawable.ic_shield);
                                }
                            }

                            container.addView(itemView);
                        }
                    }
                }

                @Override
                public void onError(String message) {
                    if (isFinishing() || isDestroyed()) return;
                    if (progress != null) progress.setVisibility(View.GONE);
                    if (tvEmpty != null) {
                        tvEmpty.setText("Failed to load activity logs: " + message);
                        tvEmpty.setVisibility(View.VISIBLE);
                    }
                }
            });
        };

        if (btnRefresh != null) btnRefresh.setOnClickListener(v -> loadLogs.run());
        loadLogs.run();

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
