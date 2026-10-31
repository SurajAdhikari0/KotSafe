package com.kotsafe.security.activities;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.os.Bundle;
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
import com.kotsafe.security.p2p.GatewayPreferenceKeys;
import com.kotsafe.security.p2p.GatewayProfile;
import com.kotsafe.security.p2p.GatewayProfileManager;
import com.kotsafe.security.p2p.GatewayTelemetry;
import com.kotsafe.security.p2p.SecurePairingBundle;

public class P2PHubActivity extends BaseActivity {
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

    // Client Views
    private SwitchCompat mSwitchClient;
    private TextView mTvClientStatusBadge;
    private TextView mTvClientNodeName;
    private TextView mTvClientNodeTelemetry;
    private View mBtnClientScanQr;
    private View mBtnClientPasteCode;

    // Utilities
    private View mBtnHubAppRouting;
    private View mBtnHubAdvancedSettings;
    private View mBtnActionFullSettings;

    private SharedPreferences mPrefs;
    private SecurePairingBundle mHostBundle;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_p2p_hub);

        mPrefs = PreferenceManager.getDefaultSharedPreferences(this);

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
        updateHostUI();
        updateClientUI();
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

        mSwitchClient = findViewById(R.id.switch_client_enable);
        mTvClientStatusBadge = findViewById(R.id.tv_client_status_badge);
        mTvClientNodeName = findViewById(R.id.tv_client_node_name);
        mTvClientNodeTelemetry = findViewById(R.id.tv_client_node_telemetry);
        mBtnClientScanQr = findViewById(R.id.btn_client_scan_qr);
        mBtnClientPasteCode = findViewById(R.id.btn_client_paste_code);

        mBtnHubAppRouting = findViewById(R.id.btn_hub_app_routing);
        mBtnHubAdvancedSettings = findViewById(R.id.btn_hub_advanced_settings);
        mBtnActionFullSettings = findViewById(R.id.btn_action_full_settings);
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
        P2PExitNodeService.start(this);
        Toast.makeText(this, "🚀 Exit Node hosting activated!", Toast.LENGTH_SHORT).show();
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
        applySocks5Redirection();
        Toast.makeText(this, "🛡️ Connected to P2P Exit Gateway!", Toast.LENGTH_SHORT).show();
    }

    private void disableClientMode() {
        mPrefs.edit().putBoolean(GatewayPreferenceKeys.CLIENT_ENABLED, false).apply();
        disableSocks5Redirection();
        Toast.makeText(this, "P2P Gateway disconnected.", Toast.LENGTH_SHORT).show();
    }

    private void applySocks5Redirection() {
        mPrefs.edit().putBoolean(Prefs.PREF_SOCKS5_ENABLED_KEY, true).apply();
        if (CaptureService.isServiceActive()) {
            CaptureService.updateSocks5Proxy("127.0.0.1", 8095);
        }
    }

    private void disableSocks5Redirection() {
        mPrefs.edit().putBoolean(Prefs.PREF_SOCKS5_ENABLED_KEY, false).apply();
        if (CaptureService.isServiceActive()) {
            CaptureService.updateSocks5Proxy(null, 0);
        }
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
    }

    // ==================== UTILITIES ====================
    private void setupUtilities() {
        mBtnHubAppRouting.setOnClickListener(v -> {
            startActivity(new Intent(this, P2PAppRoutingActivity.class));
        });

        View.OnClickListener openFullSettings = v -> {
            Intent intent = new Intent(this, SettingsActivity.class);
            intent.putExtra(SettingsActivity.TARGET_PREF_EXTRA, "p2p_exit_node_settings");
            startActivity(intent);
        };

        mBtnHubAdvancedSettings.setOnClickListener(openFullSettings);
        if (mBtnActionFullSettings != null) {
            mBtnActionFullSettings.setOnClickListener(openFullSettings);
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
