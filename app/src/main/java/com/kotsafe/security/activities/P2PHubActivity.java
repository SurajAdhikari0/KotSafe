package com.kotsafe.security.activities;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.PowerManager;
import android.provider.Settings;
import android.util.Log;
import android.view.MenuItem;
import android.view.View;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.widget.SwitchCompat;
import androidx.appcompat.widget.Toolbar;
import androidx.preference.PreferenceManager;

import com.google.mlkit.vision.barcode.common.Barcode;
import com.google.mlkit.vision.codescanner.GmsBarcodeScanner;
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions;
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning;
import com.kotsafe.security.CaptureService;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.activities.prefs.P2PAppRoutingActivity;
import com.kotsafe.security.activities.prefs.SettingsActivity;
import com.kotsafe.security.fragments.prefs.P2PExitNodeSettings;
import com.kotsafe.security.model.KotSafeUserManager;
import com.kotsafe.security.model.Prefs;
import com.kotsafe.security.model.BackendProvider;
import com.kotsafe.security.model.P2PExitNodeServer;
import com.kotsafe.security.model.P2PExitNodeService;
import com.kotsafe.security.model.backend.BackendProviderFactory;
import com.kotsafe.security.model.backend.CustomHttpProvider;
import com.kotsafe.security.p2p.EgressLeakDialog;
import com.kotsafe.security.p2p.GatewayPreferenceKeys;
import com.kotsafe.security.p2p.GatewayProfile;
import com.kotsafe.security.p2p.GatewayProfileManager;
import com.kotsafe.security.p2p.GatewayTelemetry;
import com.kotsafe.security.p2p.SecurePairingBundle;

public class P2PHubActivity extends BaseActivity implements GatewayTelemetry.Listener {
    private static final String TAG = "P2PHubActivity";

    // Mode Switcher
    private View mTabHost;
    private View mTabClient;
    private TextView mTvTabHostTitle;
    private TextView mTvTabClientTitle;
    private View mContainerHost;
    private View mContainerClient;
    private boolean mIsHostTab = true;

    // Host Views
    private SwitchCompat mSwitchHost;
    private TextView mTvHostStatusBadge;
    private ImageView mIvHostQr;
    private TextView mTvHostRoomId;
    private TextView mTvActiveClientsCount;
    private View mBtnCopyQrLink;
    private View mBtnRegenerateQr;
    private SwitchCompat mSwitchHostLowBattery;
    private SwitchCompat mSwitchHostWifiOnly;

    // Client Views
    private SwitchCompat mSwitchClient;
    private TextView mTvClientStatusBadge;
    private TextView mTvClientNodeName;
    private TextView mTvClientNodeTelemetry;
    private View mBtnClientScanQr;
    private View mBtnClientPasteCode;

    // Client Telemetry HUD
    private View mLayoutClientTelemetryHud;
    private TextView mTvClientPingJitter;
    private TextView mTvClientSpeed;
    private TextView mTvClientTransport;
    private TextView mTvClientHostHealth;

    // Client 1-Tap Egress IP Leak Checker & Guards
    private View mBtnClientCheckLeak;
    private SwitchCompat mSwitchClientKillSwitch;
    private SwitchCompat mSwitchClientLocalLan;

    // Timezone Sentinel
    private View mCardTimezoneAdvisory;
    private TextView mTvTimezoneAdvisoryText;
    private View mBtnFixTimezone;

    // Utilities & Info
    private View mBtnHubAppRouting;
    private View mBtnHubAdvancedSettings;
    private View mBtnActionP2pInfo;

    private SharedPreferences mPrefs;
    private SecurePairingBundle mHostBundle;
    private BackendProvider mActiveBackendProvider;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_p2p_hub);

        mPrefs = PreferenceManager.getDefaultSharedPreferences(this);
        mActiveBackendProvider = BackendProviderFactory.getConfigured(this);

        Toolbar toolbar = findViewById(R.id.toolbar);
        if (toolbar != null) {
            setSupportActionBar(toolbar);
            if (getSupportActionBar() != null) {
                getSupportActionBar().setDisplayHomeAsUpEnabled(true);
                getSupportActionBar().setDisplayShowHomeEnabled(true);
            }
        }

        View scrollView = findViewById(R.id.p2p_hub_scroll);
        if (scrollView != null) {
            final int basePadBottom = (int) (32 * getResources().getDisplayMetrics().density);
            androidx.core.view.ViewCompat.setOnApplyWindowInsetsListener(scrollView, (v, insets) -> {
                int bottomInset = insets.getInsets(androidx.core.view.WindowInsetsCompat.Type.navigationBars() |
                        androidx.core.view.WindowInsetsCompat.Type.systemBars()).bottom;
                v.setPadding(v.getPaddingLeft(), v.getPaddingTop(), v.getPaddingRight(), basePadBottom + bottomInset);
                return insets;
            });
        }

        initViews();
        setupModeSwitcher();
        setupHostMode();
        setupClientMode();
        setupUtilities();
    }

    @Override
    protected void onResume() {
        super.onResume();
        GatewayTelemetry.getInstance().addListener(this);
        if (mPrefs.getBoolean(GatewayPreferenceKeys.CLIENT_ENABLED, false)) {
            ensureClientRelayLoopbackRunning();
        }
        updateHostUI();
        updateClientUI();
        updateTelemetryUI();
    }

    @Override
    protected void onPause() {
        super.onPause();
        GatewayTelemetry.getInstance().removeListener(this);
    }

    @Override
    public void onTelemetryChanged(GatewayTelemetry telemetry) {
        runOnUiThread(this::updateTelemetryUI);
    }

    private void initViews() {
        mTabHost = findViewById(R.id.tab_host_mode);
        mTabClient = findViewById(R.id.tab_client_mode);
        mTvTabHostTitle = findViewById(R.id.tv_tab_host_title);
        mTvTabClientTitle = findViewById(R.id.tv_tab_client_title);
        mContainerHost = findViewById(R.id.container_host_mode);
        mContainerClient = findViewById(R.id.container_client_mode);

        mSwitchHost = findViewById(R.id.switch_host_enable);
        mTvHostStatusBadge = findViewById(R.id.tv_host_status_badge);
        mIvHostQr = findViewById(R.id.iv_host_qr);
        mTvHostRoomId = findViewById(R.id.tv_host_room_id);
        mTvActiveClientsCount = findViewById(R.id.tv_active_clients_count);
        mBtnCopyQrLink = findViewById(R.id.btn_copy_qr_link);
        mBtnRegenerateQr = findViewById(R.id.btn_regenerate_qr);
        mSwitchHostLowBattery = findViewById(R.id.switch_host_low_battery);
        mSwitchHostWifiOnly = findViewById(R.id.switch_host_wifi_only);

        mSwitchClient = findViewById(R.id.switch_client_enable);
        mTvClientStatusBadge = findViewById(R.id.tv_client_status_badge);
        mTvClientNodeName = findViewById(R.id.tv_client_node_name);
        mTvClientNodeTelemetry = findViewById(R.id.tv_client_node_telemetry);
        mBtnClientScanQr = findViewById(R.id.btn_client_scan_qr);
        mBtnClientPasteCode = findViewById(R.id.btn_client_paste_code);

        mLayoutClientTelemetryHud = findViewById(R.id.layout_client_telemetry_hud);
        mTvClientPingJitter = findViewById(R.id.tv_client_ping_jitter);
        mTvClientSpeed = findViewById(R.id.tv_client_speed);
        mTvClientTransport = findViewById(R.id.tv_client_transport);
        mTvClientHostHealth = findViewById(R.id.tv_client_host_health);

        mBtnClientCheckLeak = findViewById(R.id.btn_client_check_leak);
        mSwitchClientKillSwitch = findViewById(R.id.switch_client_kill_switch);
        mSwitchClientLocalLan = findViewById(R.id.switch_client_local_lan);

        mCardTimezoneAdvisory = findViewById(R.id.card_timezone_advisory);
        mTvTimezoneAdvisoryText = findViewById(R.id.tv_timezone_advisory_text);
        mBtnFixTimezone = findViewById(R.id.btn_fix_timezone);

        mBtnHubAppRouting = findViewById(R.id.btn_hub_app_routing);
        mBtnHubAdvancedSettings = findViewById(R.id.btn_hub_advanced_settings);
        mBtnActionP2pInfo = findViewById(R.id.btn_action_p2p_info);
    }

    private void setupModeSwitcher() {
        boolean clientOn = mPrefs.getBoolean(GatewayPreferenceKeys.CLIENT_ENABLED, false);
        boolean exitOn = mPrefs.getBoolean(GatewayPreferenceKeys.EXIT_ENABLED, false);

        if (clientOn && !exitOn) {
            selectClientTab();
        } else {
            selectHostTab();
        }

        mTabHost.setOnClickListener(v -> selectHostTab());
        mTabClient.setOnClickListener(v -> selectClientTab());
    }

    private void selectHostTab() {
        mIsHostTab = true;
        mTabHost.setBackgroundResource(R.drawable.bg_tab_p2p_active);
        mTabClient.setBackgroundResource(R.drawable.bg_tab_p2p_inactive);
        mTvTabHostTitle.setTextColor(getResources().getColor(R.color.p2pAccent));
        mTvTabClientTitle.setTextColor(getResources().getColor(R.color.cardWorkbenchSubtext));
        mContainerHost.setVisibility(View.VISIBLE);
        mContainerClient.setVisibility(View.GONE);
    }

    private void selectClientTab() {
        mIsHostTab = false;
        mTabClient.setBackgroundResource(R.drawable.bg_tab_p2p_active);
        mTabHost.setBackgroundResource(R.drawable.bg_tab_p2p_inactive);
        mTvTabClientTitle.setTextColor(getResources().getColor(R.color.p2pAccent));
        mTvTabHostTitle.setTextColor(getResources().getColor(R.color.cardWorkbenchSubtext));
        mContainerClient.setVisibility(View.VISIBLE);
        mContainerHost.setVisibility(View.GONE);
    }

    // ==================== HOST MODE ====================
    private void setupHostMode() {
        loadOrGenerateHostBundle(false);

        mSwitchHost.setOnCheckedChangeListener((buttonView, isChecked) -> {
            if (!buttonView.isPressed()) return;

            if (isChecked) {
                if (!KotSafeUserManager.isUserAuthenticated(this)) {
                    buttonView.setChecked(false);
                    KotSafeUserManager.redirectToLoginWithNotice(this, "Exit Node Hosting");
                    return;
                }
                boolean consentAgreed = mPrefs.getBoolean(GatewayPreferenceKeys.HOST_CONSENT_AGREED, false);
                if (!consentAgreed) {
                    showHostLegalWarningDialog();
                    return;
                }
                enableHostMode();
            } else {
                disableHostMode();
            }
            updateHostUI();
        });

        mBtnCopyQrLink.setOnClickListener(v -> {
            if (mHostBundle != null) {
                ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                if (clipboard != null) {
                    ClipData clip = ClipData.newPlainText("KotSafe P2P Pairing Link", mHostBundle.toQrUri());
                    clipboard.setPrimaryClip(clip);
                    Toast.makeText(this, "📋 Pairing link copied to clipboard!", Toast.LENGTH_SHORT).show();
                }
            }
        });

        mBtnRegenerateQr.setOnClickListener(v -> {
            new AlertDialog.Builder(this)
                    .setTitle("Regenerate Pairing Key")
                    .setMessage("Generating a new pairing key will disconnect all currently paired devices until they scan the new QR code. Proceed?")
                    .setPositiveButton("Regenerate", (dialog, which) -> {
                        loadOrGenerateHostBundle(true);
                        Toast.makeText(this, "✨ Fresh pairing key & QR generated!", Toast.LENGTH_SHORT).show();
                    })
                    .setNegativeButton("Cancel", null)
                    .show();
        });

        if (mSwitchHostLowBattery != null) {
            mSwitchHostLowBattery.setChecked(mPrefs.getBoolean(GatewayPreferenceKeys.HOST_PAUSE_ON_LOW_BATTERY, false));
            mSwitchHostLowBattery.setOnCheckedChangeListener((buttonView, isChecked) -> {
                if (!buttonView.isPressed()) return;
                mPrefs.edit().putBoolean(GatewayPreferenceKeys.HOST_PAUSE_ON_LOW_BATTERY, isChecked).apply();
                Toast.makeText(this, isChecked ? "🔋 Low battery safeguard enabled (<20%)" : "Low battery safeguard disabled", Toast.LENGTH_SHORT).show();
            });
        }

        if (mSwitchHostWifiOnly != null) {
            mSwitchHostWifiOnly.setChecked(mPrefs.getBoolean(GatewayPreferenceKeys.HOST_WIFI_ONLY, false));
            mSwitchHostWifiOnly.setOnCheckedChangeListener((buttonView, isChecked) -> {
                if (!buttonView.isPressed()) return;
                mPrefs.edit().putBoolean(GatewayPreferenceKeys.HOST_WIFI_ONLY, isChecked).apply();
                Toast.makeText(this, isChecked ? "📶 Wi-Fi only hosting enabled" : "Wi-Fi only hosting disabled", Toast.LENGTH_SHORT).show();
            });
        }
    }

    private void loadOrGenerateHostBundle(boolean forceNew) {
        String effectiveControl = BackendProviderFactory.getEffectiveControlUrl(this);
        String cachedUri = mPrefs.getString(GatewayPreferenceKeys.PAIRING_BUNDLE, "");
        String existingToken = mPrefs.getString(Prefs.PREF_P2P_BACKEND_PAIRING, "");

        if (!forceNew && !cachedUri.isEmpty() && !existingToken.isEmpty()) {
            try {
                SecurePairingBundle parsed = SecurePairingBundle.parse(cachedUri);
                if (effectiveControl.equals(parsed.controlUrl)) {
                    mHostBundle = parsed;
                }
            } catch (Exception ignored) {}
        }

        if (mHostBundle == null || forceNew) {
            String initialRoom = "room_" + Utils.genRandomString(20);
            String initialSecret = Utils.genRandomString(48);
            mHostBundle = new SecurePairingBundle(initialRoom, initialSecret, effectiveControl);
            mPrefs.edit()
                    .putString(GatewayPreferenceKeys.PAIRING_BUNDLE, mHostBundle.toQrUri())
                    .putString(Prefs.PREF_P2P_BACKEND_PAIRING, "host_" + mHostBundle.room)
                    .apply();
        }

        if (mTvHostRoomId != null) {
            mTvHostRoomId.setText("Room: " + mHostBundle.room);
        }

        Bitmap qrBmp = P2PExitNodeSettings.generateQrBitmap(mHostBundle.toQrUri(), 400);
        if (qrBmp != null && mIvHostQr != null) {
            mIvHostQr.setImageBitmap(qrBmp);
        }
    }

    private void enableHostMode() {
        mPrefs.edit().putBoolean(GatewayPreferenceKeys.EXIT_ENABLED, true).apply();
        if (mPrefs.getBoolean(GatewayPreferenceKeys.CLIENT_ENABLED, false)) {
            mPrefs.edit().putBoolean(GatewayPreferenceKeys.CLIENT_ENABLED, false).apply();
            disableSocks5Redirection();
        }
        checkBatteryOptimizationsForExitNode();
        P2PExitNodeService.start(this);
        Toast.makeText(this, "🚀 Exit Node hosting activated!", Toast.LENGTH_SHORT).show();
    }

    private void checkBatteryOptimizationsForExitNode() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
            if (pm != null && !pm.isIgnoringBatteryOptimizations(getPackageName())) {
                try {
                    Intent intent = new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
                    intent.setData(Uri.parse("package:" + getPackageName()));
                    startActivity(intent);
                } catch (Exception e) {
                    try {
                        Intent intent = new Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS);
                        startActivity(intent);
                    } catch (Exception ignored) {}
                }
            }
        }
    }

    private void disableHostMode() {
        mPrefs.edit().putBoolean(GatewayPreferenceKeys.EXIT_ENABLED, false).apply();
        P2PExitNodeService.stop(this);
        Toast.makeText(this, "Exit Node stopped.", Toast.LENGTH_SHORT).show();
    }

    private void showHostLegalWarningDialog() {
        new AlertDialog.Builder(this)
                .setTitle(R.string.p2p_host_legal_warning_title)
                .setMessage(R.string.p2p_host_legal_warning_body)
                .setPositiveButton(R.string.p2p_host_legal_agree_btn, (dialog, which) -> {
                    mPrefs.edit().putBoolean(GatewayPreferenceKeys.HOST_CONSENT_AGREED, true).apply();
                    mSwitchHost.setChecked(true);
                    enableHostMode();
                    updateHostUI();
                })
                .setNegativeButton(R.string.p2p_host_legal_decline_btn, (dialog, which) -> {
                    mSwitchHost.setChecked(false);
                    updateHostUI();
                })
                .show();
    }

    private void updateHostUI() {
        boolean exitOn = mPrefs.getBoolean(GatewayPreferenceKeys.EXIT_ENABLED, false);
        mSwitchHost.setChecked(exitOn);

        int activeClients = P2PExitNodeServer.getInstance().getActiveClients();
        if (exitOn) {
            if (activeClients > 0) {
                mTvHostStatusBadge.setText("🟢 ACTIVE (" + activeClients + " CLIENTS)");
                mTvHostStatusBadge.setTextColor(Color.parseColor("#00E676"));
            } else {
                mTvHostStatusBadge.setText("🟡 STANDBY (WAITING)");
                mTvHostStatusBadge.setTextColor(Color.parseColor("#F59E0B"));
            }
        } else {
            mTvHostStatusBadge.setText("⚪ READY TO PAIR");
            mTvHostStatusBadge.setTextColor(Color.parseColor("#38BDF8"));
        }

        mTvActiveClientsCount.setText("Active Connected Devices: " + activeClients);
    }

    // ==================== CLIENT MODE ====================
    private void setupClientMode() {
        mSwitchClient.setOnCheckedChangeListener((buttonView, isChecked) -> {
            if (!buttonView.isPressed()) return;

            if (isChecked) {
                if (!KotSafeUserManager.isUserAuthenticated(this)) {
                    buttonView.setChecked(false);
                    KotSafeUserManager.redirectToLoginWithNotice(this, "P2P Peer Gateway");
                    return;
                }
                boolean consentAgreed = mPrefs.getBoolean(GatewayPreferenceKeys.CLIENT_CONSENT_AGREED, false);
                if (!consentAgreed) {
                    showClientLegalWarningDialog();
                    return;
                }
                enableClientMode();
            } else {
                disableClientMode();
            }
            updateClientUI();
        });

        mBtnClientScanQr.setOnClickListener(v -> startQrScanFlow());
        mBtnClientPasteCode.setOnClickListener(v -> showPastePairingDialog());

        if (mBtnClientCheckLeak != null) {
            mBtnClientCheckLeak.setOnClickListener(v -> {
                ensureClientRelayLoopbackRunning();
                EgressLeakDialog.show(this, 8095, () -> {
                    mPrefs.edit().putBoolean(GatewayPreferenceKeys.KILL_SWITCH, true).apply();
                    if (mSwitchClientKillSwitch != null) mSwitchClientKillSwitch.setChecked(true);
                    Toast.makeText(this, "🛡️ Strict P2P Kill-Switch Activated!", Toast.LENGTH_SHORT).show();
                });
            });
        }

        if (mSwitchClientKillSwitch != null) {
            mSwitchClientKillSwitch.setChecked(mPrefs.getBoolean(GatewayPreferenceKeys.KILL_SWITCH, false));
            mSwitchClientKillSwitch.setOnCheckedChangeListener((buttonView, isChecked) -> {
                if (!buttonView.isPressed()) return;
                mPrefs.edit().putBoolean(GatewayPreferenceKeys.KILL_SWITCH, isChecked).apply();
                Toast.makeText(this, isChecked ? "🛡️ Kill-Switch Enabled: Internet blocked if peer drops" : "Kill-Switch Disabled", Toast.LENGTH_SHORT).show();
            });
        }

        if (mSwitchClientLocalLan != null) {
            mSwitchClientLocalLan.setChecked(mPrefs.getBoolean(GatewayPreferenceKeys.LOCAL_SERVICE_ACCESS, false));
            mSwitchClientLocalLan.setOnCheckedChangeListener((buttonView, isChecked) -> {
                if (!buttonView.isPressed()) return;
                if (isChecked) {
                    new AlertDialog.Builder(this)
                            .setTitle(R.string.gateway_local_service_warning_title)
                            .setMessage(R.string.gateway_local_service_warning_message)
                            .setIcon(android.R.drawable.ic_dialog_alert)
                            .setPositiveButton(R.string.gateway_local_service_warning_confirm, (dialog, which) -> {
                                mPrefs.edit().putBoolean(GatewayPreferenceKeys.LOCAL_SERVICE_ACCESS, true).apply();
                                mSwitchClientLocalLan.setChecked(true);
                                Toast.makeText(this, R.string.gateway_local_service_enabled_toast, Toast.LENGTH_SHORT).show();
                            })
                            .setNegativeButton(android.R.string.cancel, (dialog, which) -> {
                                mSwitchClientLocalLan.setChecked(false);
                            })
                            .setOnCancelListener(dialog -> {
                                mSwitchClientLocalLan.setChecked(false);
                            })
                            .show();
                } else {
                    mPrefs.edit().putBoolean(GatewayPreferenceKeys.LOCAL_SERVICE_ACCESS, false).apply();
                    Toast.makeText(this, "Local LAN Access Disabled", Toast.LENGTH_SHORT).show();
                }
            });
        }
    }

    private void startQrScanFlow() {
        try {
            GmsBarcodeScannerOptions options = new GmsBarcodeScannerOptions.Builder()
                    .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
                    .enableAutoZoom()
                    .build();

            GmsBarcodeScanner scanner = GmsBarcodeScanning.getClient(this, options);
            scanner.startScan()
                    .addOnSuccessListener(barcode -> {
                        String raw = barcode.getRawValue();
                        if (raw != null && !raw.trim().isEmpty()) {
                            handleScannedPairingQr(raw.trim());
                        }
                    })
                    .addOnFailureListener(e -> {
                        Log.w(TAG, "Code Scanner unavailable: " + e.getMessage());
                        showPastePairingDialog();
                    });
        } catch (Throwable t) {
            Log.e(TAG, "Barcode Scanner error: " + t.getMessage());
            showPastePairingDialog();
        }
    }

    private void showPastePairingDialog() {
        final EditText input = new EditText(this);
        input.setHint("kotsafe-gateway://... or pairing URI");
        input.setSingleLine(false);
        input.setMaxLines(3);

        int padding = (int) (18 * getResources().getDisplayMetrics().density);
        FrameLayout container = new FrameLayout(this);
        container.setPadding(padding, padding / 2, padding, padding / 2);
        container.addView(input);

        new AlertDialog.Builder(this)
                .setTitle("Paste Connection Code")
                .setMessage("Paste the kotsafe-gateway:// pairing link copied from the Host device:")
                .setView(container)
                .setPositiveButton("Connect", (dialog, which) -> {
                    String raw = input.getText().toString().trim();
                    if (!raw.isEmpty()) {
                        handleScannedPairingQr(raw);
                    } else {
                        Toast.makeText(this, "Please enter a valid pairing link", Toast.LENGTH_SHORT).show();
                    }
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void handleScannedPairingQr(String raw) {
        try {
            SecurePairingBundle bundle = SecurePairingBundle.parse(raw);
            Toast.makeText(this, "Pairing with " + bundle.room + "...", Toast.LENGTH_SHORT).show();

            String profName = "Exit Node (" + (bundle.room.length() > 8 ? bundle.room.substring(0, 8) : bundle.room) + ")";
            String effectiveClientToken = "client_" + bundle.room;
            GatewayProfile prof = new GatewayProfile("prof_" + System.currentTimeMillis(), profName, bundle.toQrUri(), effectiveClientToken, System.currentTimeMillis());

            if (bundle.exitIp != null && !bundle.exitIp.isEmpty()) {
                prof.exitIp = bundle.exitIp;
                GatewayTelemetry.getInstance().setExitNodeIp(bundle.exitIp);
            }

            GatewayProfileManager.saveProfile(this, prof);
            GatewayProfileManager.setActiveProfile(this, prof);

            mPrefs.edit()
                    .putString(GatewayPreferenceKeys.PAIRING_BUNDLE, bundle.toQrUri())
                    .putString(Prefs.PREF_P2P_BACKEND_PAIRING, effectiveClientToken)
                    .apply();

            CustomHttpProvider.configureCipher(bundle.room, bundle.pairingSecret);

            boolean consentAgreed = mPrefs.getBoolean(GatewayPreferenceKeys.CLIENT_CONSENT_AGREED, false);
            if (!consentAgreed) {
                showClientLegalWarningDialog();
            } else {
                enableClientMode();
                updateClientUI();
            }
        } catch (Exception e) {
            Log.e(TAG, "Pairing error: " + e.getMessage());
            Toast.makeText(this, "Invalid pairing code: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private void enableClientMode() {
        if (mPrefs.getBoolean(GatewayPreferenceKeys.EXIT_ENABLED, false)) {
            mPrefs.edit().putBoolean(GatewayPreferenceKeys.EXIT_ENABLED, false).apply();
            P2PExitNodeService.stop(this);
        }
        mPrefs.edit().putBoolean(GatewayPreferenceKeys.CLIENT_ENABLED, true).apply();
        ensureClientRelayLoopbackRunning();
        applySocks5Redirection();
        Toast.makeText(this, "🛡️ Connected to P2P Exit Gateway!", Toast.LENGTH_SHORT).show();
    }

    private void disableClientMode() {
        mPrefs.edit().putBoolean(GatewayPreferenceKeys.CLIENT_ENABLED, false).apply();
        stopClientRelayLoopback();
        disableSocks5Redirection();
        Toast.makeText(this, "P2P Gateway disconnected.", Toast.LENGTH_SHORT).show();
    }

    private void applySocks5Redirection() {
        mPrefs.edit().putBoolean(Prefs.PREF_SOCKS5_ENABLED_KEY, true).apply();
        ensureClientRelayLoopbackRunning();
        if (CaptureService.isServiceActive()) {
            CaptureService.updateSocks5Proxy("127.0.0.1", 8095);
        }
    }

    private void disableSocks5Redirection() {
        mPrefs.edit().putBoolean(Prefs.PREF_SOCKS5_ENABLED_KEY, false).apply();
        stopClientRelayLoopback();
        if (CaptureService.isServiceActive()) {
            CaptureService.updateSocks5Proxy(null, 0);
        }
    }

    private void ensureClientRelayLoopbackRunning() {
        new Thread(() -> {
            try {
                GatewayProfile activeProf = GatewayProfileManager.getActiveProfile(this);
                String bundleUri = mPrefs.getString(GatewayPreferenceKeys.PAIRING_BUNDLE, "");
                if (activeProf != null && activeProf.pairingBundle != null && !activeProf.pairingBundle.isEmpty()) {
                    bundleUri = activeProf.pairingBundle;
                }
                String backendToken = "";
                if (bundleUri != null && !bundleUri.isEmpty()) {
                    try {
                        SecurePairingBundle parsed = SecurePairingBundle.parse(bundleUri);
                        if (parsed != null && parsed.room != null && !parsed.room.isEmpty()) {
                            backendToken = "client_" + parsed.room;
                            mPrefs.edit()
                                    .putString(GatewayPreferenceKeys.PAIRING_BUNDLE, bundleUri)
                                    .putString(Prefs.PREF_P2P_BACKEND_PAIRING, backendToken)
                                    .apply();
                            CustomHttpProvider.configureCipher(parsed.room, parsed.pairingSecret);
                        }
                    } catch (Exception ignored) {}
                }
                if (backendToken.isEmpty()) {
                    backendToken = mPrefs.getString(Prefs.PREF_P2P_BACKEND_PAIRING, "");
                }
                if (mActiveBackendProvider == null) {
                    mActiveBackendProvider = BackendProviderFactory.getConfigured(this);
                }
                if (mActiveBackendProvider != null && !backendToken.isEmpty()) {
                    CustomHttpProvider.ensureCipherConfigured(this);
                    mActiveBackendProvider.startRelayLoopback(backendToken, 8095);
                    Log.i(TAG, "Personal Gateway client loopback actively running on 8095 for " + backendToken);
                }
            } catch (Throwable t) {
                Log.w(TAG, "ensureClientRelayLoopbackRunning error: " + t.getMessage());
            }
        }, "KotSafe-ClientRelayLoopback").start();
    }

    private void stopClientRelayLoopback() {
        new Thread(() -> {
            try {
                if (mActiveBackendProvider != null) {
                    mActiveBackendProvider.stopRelayLoopback();
                } else {
                    BackendProvider bp = BackendProviderFactory.getConfigured(this);
                    if (bp != null) bp.stopRelayLoopback();
                }
            } catch (Throwable ignored) {}
        }, "KotSafe-StopClientLoopback").start();
    }

    private void showClientLegalWarningDialog() {
        new AlertDialog.Builder(this)
                .setTitle(R.string.p2p_client_legal_warning_title)
                .setMessage(R.string.p2p_client_legal_warning_body)
                .setPositiveButton(R.string.p2p_client_legal_agree_btn, (dialog, which) -> {
                    mPrefs.edit().putBoolean(GatewayPreferenceKeys.CLIENT_CONSENT_AGREED, true).apply();
                    mSwitchClient.setChecked(true);
                    enableClientMode();
                    updateClientUI();
                })
                .setNegativeButton(R.string.p2p_client_legal_decline_btn, (dialog, which) -> {
                    mSwitchClient.setChecked(false);
                    updateClientUI();
                })
                .show();
    }

    private void updateClientUI() {
        boolean clientOn = mPrefs.getBoolean(GatewayPreferenceKeys.CLIENT_ENABLED, false);
        mSwitchClient.setChecked(clientOn);

        GatewayProfile activeProfile = GatewayProfileManager.getActiveProfile(this);
        if (activeProfile != null && activeProfile.name != null && !activeProfile.name.isEmpty()) {
            mTvClientNodeName.setText(activeProfile.name);
            if (clientOn) {
                mTvClientStatusBadge.setText("🟢 ACTIVE ROUTE");
                mTvClientStatusBadge.setTextColor(Color.parseColor("#00E676"));
                String exitIp = GatewayTelemetry.getInstance().getExitNodeIp();
                if (exitIp != null && !exitIp.isEmpty()) {
                    mTvClientNodeTelemetry.setText("Egress IP: " + exitIp + " • Zero-Trust Tunnel Active");
                } else {
                    mTvClientNodeTelemetry.setText("All traffic routed through exit gateway");
                }
            } else {
                mTvClientStatusBadge.setText("⚪ PAIRED (STANDBY)");
                mTvClientStatusBadge.setTextColor(Color.parseColor("#94A3B8"));
                mTvClientNodeTelemetry.setText("Paired exit gateway ready • Switch on to route traffic");
            }
        } else {
            mTvClientNodeName.setText("No paired exit node");
            mTvClientStatusBadge.setText("⚪ STANDBY");
            mTvClientStatusBadge.setTextColor(Color.parseColor("#38BDF8"));
            mTvClientNodeTelemetry.setText("Scan a pairing QR code or paste link to configure gateway");
        }

        if (mSwitchClientKillSwitch != null) {
            mSwitchClientKillSwitch.setChecked(mPrefs.getBoolean(GatewayPreferenceKeys.KILL_SWITCH, false));
        }
        if (mSwitchClientLocalLan != null) {
            mSwitchClientLocalLan.setChecked(mPrefs.getBoolean(GatewayPreferenceKeys.LOCAL_SERVICE_ACCESS, false));
        }

        if (mCardTimezoneAdvisory != null) {
            if (clientOn) {
                String exitCountry = mPrefs.getString("p2p_last_egress_country", "IN");
                com.kotsafe.security.p2p.TimezoneSentinel.TimezoneAudit tzAudit =
                        com.kotsafe.security.p2p.TimezoneSentinel.auditTimezone(exitCountry);
                if (tzAudit.isMismatch) {
                    mCardTimezoneAdvisory.setVisibility(View.VISIBLE);
                    if (mTvTimezoneAdvisoryText != null) {
                        mTvTimezoneAdvisoryText.setText(tzAudit.advisoryText);
                    }
                    if (mBtnFixTimezone != null) {
                        mBtnFixTimezone.setOnClickListener(v -> com.kotsafe.security.p2p.TimezoneSentinel.openDateSettings(this));
                    }
                } else {
                    mCardTimezoneAdvisory.setVisibility(View.GONE);
                }
            } else {
                mCardTimezoneAdvisory.setVisibility(View.GONE);
            }
        }

        updateTelemetryUI();
    }

    private void updateTelemetryUI() {
        boolean clientOn = mPrefs.getBoolean(GatewayPreferenceKeys.CLIENT_ENABLED, false);
        if (mLayoutClientTelemetryHud == null) return;

        if (clientOn) {
            mLayoutClientTelemetryHud.setVisibility(View.VISIBLE);
            GatewayTelemetry telemetry = GatewayTelemetry.getInstance();

            // RTT Ping & Jitter
            int latency = telemetry.getLatencyMs();
            int jitter = telemetry.getJitterMs();
            if (mTvClientPingJitter != null) {
                if (latency >= 0) {
                    mTvClientPingJitter.setText(latency + " ms" + (jitter >= 0 ? " (± " + jitter + "ms)" : ""));
                    if (latency < 80) {
                        mTvClientPingJitter.setTextColor(Color.parseColor("#00E676"));
                    } else if (latency < 180) {
                        mTvClientPingJitter.setTextColor(Color.parseColor("#38BDF8"));
                    } else {
                        mTvClientPingJitter.setTextColor(Color.parseColor("#F59E0B"));
                    }
                } else {
                    mTvClientPingJitter.setText("-- ms (Waiting)");
                    mTvClientPingJitter.setTextColor(Color.parseColor("#94A3B8"));
                }
            }

            // Speeds
            if (mTvClientSpeed != null) {
                mTvClientSpeed.setText(telemetry.getSpeedSummary());
            }

            // Transport Mode
            if (mTvClientTransport != null) {
                if (telemetry.isDirectP2PActive()) {
                    mTvClientTransport.setText("⚡ Direct P2P UDP");
                    mTvClientTransport.setTextColor(Color.parseColor("#00E676"));
                } else {
                    mTvClientTransport.setText("🔒 Encrypted Relay");
                    mTvClientTransport.setTextColor(Color.parseColor("#38BDF8"));
                }
            }

            // Remote Host Health
            if (mTvClientHostHealth != null) {
                if (telemetry.isHostOnline()) {
                    int bat = telemetry.getBatteryPercent();
                    String batStr = (bat >= 0) ? "🔋 " + bat + "%" + (telemetry.isCharging() ? "⚡" : "") : "🔋 Online";
                    String netStr = !telemetry.getWifiSsid().isEmpty() ? "Wi-Fi" : (!telemetry.getCarrierName().isEmpty() ? telemetry.getCarrierName() : "Uplink OK");
                    mTvClientHostHealth.setText(batStr + " • " + netStr);
                    mTvClientHostHealth.setTextColor(Color.parseColor("#00E676"));
                } else {
                    mTvClientHostHealth.setText("⚪ Peer Standby");
                    mTvClientHostHealth.setTextColor(Color.parseColor("#94A3B8"));
                }
            }
        } else {
            mLayoutClientTelemetryHud.setVisibility(View.GONE);
        }
    }

    // ==================== UTILITIES ====================
    private void setupUtilities() {
        mBtnHubAppRouting.setOnClickListener(v -> {
            startActivity(new Intent(this, P2PAppRoutingActivity.class));
        });

        mBtnHubAdvancedSettings.setOnClickListener(v -> {
            Intent intent = new Intent(this, SettingsActivity.class);
            intent.putExtra(SettingsActivity.TARGET_PREF_EXTRA, "p2p_exit_node_settings");
            startActivity(intent);
        });

        if (mBtnActionP2pInfo != null) {
            mBtnActionP2pInfo.setOnClickListener(v -> {
                com.kotsafe.security.p2p.P2PInfoDialog.show(this);
            });
        }
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
}
