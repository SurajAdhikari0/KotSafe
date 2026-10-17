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

package com.kotsafe.security.activities.prefs;

import android.app.LocaleManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.LocaleList;
import android.provider.Settings;
import android.text.InputType;
import android.util.AttributeSet;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Toast;

import androidx.activity.OnBackPressedCallback;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.fragment.app.FragmentTransaction;
import androidx.preference.DropDownPreference;
import androidx.preference.EditTextPreference;
import androidx.preference.Preference;
import androidx.preference.PreferenceFragmentCompat;
import androidx.preference.PreferenceManager;
import androidx.preference.SwitchPreference;

import com.kotsafe.security.Billing;
import com.kotsafe.security.Log;
import com.kotsafe.security.KotSafe;
import com.kotsafe.security.Utils;
import com.kotsafe.security.MitmAddon;
import com.kotsafe.security.VpnReconnectService;
import com.kotsafe.security.activities.BaseActivity;
import com.kotsafe.security.dialogs.ConnectionsLogSizeDialog;
import java.text.NumberFormat;
import com.kotsafe.security.activities.MainActivity;
import com.kotsafe.security.activities.LogviewActivity;
import com.kotsafe.security.activities.MitmSetupWizard;
import com.kotsafe.security.activities.StatsActivity;
import com.kotsafe.security.fragments.prefs.DnsSettings;
import com.kotsafe.security.fragments.prefs.FirewallSettings;
import com.kotsafe.security.fragments.prefs.GeoipSettings;
import com.kotsafe.security.fragments.prefs.Socks5Settings;
import com.kotsafe.security.fragments.prefs.KotSafeShieldSettingsFragment;
import com.kotsafe.security.fragments.prefs.AdvancedDeveloperSettingsFragment;
import com.kotsafe.security.fragments.prefs.AiAutonomousSettingsFragment;
import com.kotsafe.security.fragments.prefs.FirewallAccessSettingsFragment;
import com.kotsafe.security.fragments.prefs.CaptureEngineSettingsFragment;
import com.kotsafe.security.fragments.prefs.StreamingProxySettingsFragment;
import com.kotsafe.security.fragments.prefs.BackupRestoreSettingsFragment;
import com.kotsafe.security.fragments.prefs.AnalyticsLogsSettingsFragment;
import com.kotsafe.security.fragments.prefs.AppearanceLanguageSettingsFragment;
import com.kotsafe.security.fragments.prefs.ActivationLicenseSettingsFragment;
import com.kotsafe.security.interfaces.FragmentViewCreatedListener;
import com.kotsafe.security.model.Prefs;
import com.kotsafe.security.R;

import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Locale;

public class SettingsActivity extends BaseActivity implements PreferenceFragmentCompat.OnPreferenceStartFragmentCallback,
        FragmentManager.OnBackStackChangedListener,
        FragmentViewCreatedListener {
    private static final String TAG = "SettingsActivity";
    private static final String ACTION_LANG_RESTART = "lang_restart";
    public static final String TARGET_PREF_EXTRA = "target_pref";
    private WindowInsetsCompat mInsets = null;
    private OnBackPressedCallback mLangRestartCallback;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setTitle(R.string.title_activity_settings); // note: setting via manifest does not honor custom locale
        displayBackAction();
        setContentView(R.layout.fragment_activity);

        // Settings top bar has dark navy #0B1D38 background: status bar icons must be crisp white
        androidx.core.view.WindowInsetsControllerCompat insetsController =
                androidx.core.view.WindowCompat.getInsetsController(getWindow(), getWindow().getDecorView());
        if (insetsController != null) {
            insetsController.setAppearanceLightStatusBars(false);
        }

        if (savedInstanceState == null) {
            Intent intent = getIntent();
            String targetPref = intent != null ? intent.getStringExtra(TARGET_PREF_EXTRA) : null;
            if ("p2p_exit_node_settings".equals(targetPref)) {
                getSupportFragmentManager()
                        .beginTransaction()
                        .replace(R.id.fragment, new com.kotsafe.security.fragments.prefs.P2PExitNodeSettings(), "p2p_exit_node_settings")
                        .commit();
                setTitle(R.string.p2p_exit_node_title);
            } else if ("advanced_developer_settings".equals(targetPref)) {
                if (!com.kotsafe.security.model.KotSafeUserManager.isUserAuthenticated(this)) {
                    com.kotsafe.security.model.KotSafeUserManager.redirectToLoginWithNotice(this, "Advanced & Developer Mode");
                    finish();
                } else {
                    getSupportFragmentManager()
                            .beginTransaction()
                            .replace(R.id.fragment, new AdvancedDeveloperSettingsFragment(), "advanced_developer_settings")
                            .commit();
                    setTitle("Advanced & Developer Mode");
                }
            } else {
                getSupportFragmentManager()
                        .beginTransaction()
                        .replace(R.id.fragment, new SettingsFragment(), "root")
                        .commit();
            }
        }

        getSupportFragmentManager().addOnBackStackChangedListener(this);

        // After a locale change the parent activity stack is stale, so back must re-launch MainActivity.
        // Only relevant while the root SettingsFragment is showing — nested settings fragments pop normally.
        Intent intent = getIntent();
        if ((intent != null) && ACTION_LANG_RESTART.equals(intent.getAction())) {
            mLangRestartCallback = new OnBackPressedCallback(true) {
                @Override
                public void handleOnBackPressed() {
                    Intent restart = new Intent(SettingsActivity.this, MainActivity.class);
                    restart.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    startActivity(restart);
                    finish();
                }
            };
            getOnBackPressedDispatcher().addCallback(this, mLangRestartCallback);
        }
    }

    @Nullable
    @Override
    public View onCreateView(@Nullable View parent, @NonNull String name, @NonNull Context context, @NonNull AttributeSet attrs) {
        View view = super.onCreateView(parent, name, context, attrs);
        if (view != null)
            ViewCompat.setOnApplyWindowInsetsListener(view, (v, windowInsets) -> {
                mInsets = windowInsets;
                return windowInsets;
            });

        return view;
    }

    @Override
    public void onFragmentViewCreated(@NonNull View view) {
        // necessary, otherwise insets are not dispatched after fragment replace
        if (mInsets != null)
            ViewCompat.dispatchApplyWindowInsets(view, mInsets);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.settings_menu, menu);
        return super.onCreateOptionsMenu(menu);
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        if (item.getItemId() == R.id.action_search_settings) {
            openSearchDialog();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    public void openSearchDialog() {
        SettingsSearchDialog dialog = SettingsSearchDialog.newInstance();
        dialog.setOnSearchItemSelectedListener(this::handleSearchNavigation);
        dialog.show(getSupportFragmentManager(), SettingsSearchDialog.TAG);
    }

    public void openLanguagePickerDialog() {
        LanguagePickerDialog dialog = LanguagePickerDialog.newInstance();
        dialog.show(getSupportFragmentManager(), LanguagePickerDialog.TAG);
    }

    public void handleSearchNavigation(SettingsSearchDialog.SearchItem item) {
        if (item.actionType == SettingsSearchDialog.ActionType.ACTIVITY) {
            if (item.targetClass != null) {
                Intent intent = new Intent(this, item.targetClass);
                startActivity(intent);
            }
        } else if (item.actionType == SettingsSearchDialog.ActionType.FRAGMENT) {
            if (getSupportFragmentManager().getBackStackEntryCount() > 0) {
                getSupportFragmentManager().popBackStackImmediate(null, FragmentManager.POP_BACK_STACK_INCLUSIVE);
            }
            Preference dummyPref = new Preference(this);
            dummyPref.setKey(item.key);
            Fragment f = getSupportFragmentManager().findFragmentById(R.id.fragment);
            if (f instanceof PreferenceFragmentCompat) {
                onPreferenceStartFragment((PreferenceFragmentCompat) f, dummyPref);
            }
        } else if (item.actionType == SettingsSearchDialog.ActionType.LANGUAGE) {
            openLanguagePickerDialog();
        } else if (item.actionType == SettingsSearchDialog.ActionType.SCROLL) {
            if (getSupportFragmentManager().getBackStackEntryCount() > 0) {
                getSupportFragmentManager().popBackStackImmediate(null, FragmentManager.POP_BACK_STACK_INCLUSIVE);
            }
            Fragment f = getSupportFragmentManager().findFragmentById(R.id.fragment);
            if (f instanceof SettingsFragment) {
                ((SettingsFragment) f).scrollToPreference(item.key);
            }
            if (Prefs.PREF_CONNECTIONS_LOG_SIZE.equals(item.key)) {
                ConnectionsLogSizeDialog dialog = ConnectionsLogSizeDialog.newInstance();
                if (f instanceof SettingsFragment) {
                    dialog.setListener(newSize -> ((SettingsFragment) f).updateConnectionsLogSizeSummary());
                }
                dialog.show(getSupportFragmentManager(), ConnectionsLogSizeDialog.TAG);
            }
        }
    }

    @Override
    public boolean onPreferenceStartFragment(@NonNull PreferenceFragmentCompat caller, @NonNull Preference pref) {
        PreferenceFragmentCompat targetFragment = null;
        String prefKey = pref.getKey();

        Log.d(TAG, "startFragment: " + prefKey);

        if(prefKey.equals("kotsafe_shield_settings")) {
            targetFragment = new KotSafeShieldSettingsFragment();
            setTitle("KotSafe Shield");
        } else if(prefKey.equals("advanced_developer_settings")) {
            if (!com.kotsafe.security.model.KotSafeUserManager.isUserAuthenticated(this)) {
                com.kotsafe.security.model.KotSafeUserManager.redirectToLoginWithNotice(this, "Advanced & Developer Mode");
                return true;
            }
            targetFragment = new AdvancedDeveloperSettingsFragment();
            setTitle("Advanced & Developer Mode");
        } else if(prefKey.equals("ai_autonomous_settings")) {
            targetFragment = new AiAutonomousSettingsFragment();
            setTitle("AI & Autonomous");
        } else if(prefKey.equals("firewall_access_settings")) {
            targetFragment = new FirewallAccessSettingsFragment();
            setTitle("Firewall & Access Control");
        } else if(prefKey.equals("capture_engine_settings")) {
            targetFragment = new CaptureEngineSettingsFragment();
            setTitle("Capture Engine and Interface");
        } else if(prefKey.equals("streaming_proxy_settings")) {
            targetFragment = new StreamingProxySettingsFragment();
            setTitle("Streaming Proxy");
        } else if(prefKey.equals("backup_restore_settings")) {
            targetFragment = new BackupRestoreSettingsFragment();
            setTitle("Backup & Restore");
        } else if(prefKey.equals("analytics_logs_settings")) {
            targetFragment = new AnalyticsLogsSettingsFragment();
            setTitle("Analytics");
        } else if(prefKey.equals("appearance_language_settings")) {
            targetFragment = new AppearanceLanguageSettingsFragment();
            setTitle("Appearance and Language");
        } else if(prefKey.equals("activation_license_settings")) {
            targetFragment = new ActivationLicenseSettingsFragment();
            setTitle("License Activation");
        } else if(prefKey.equals("geolocation")) {
            targetFragment = new GeoipSettings();
            setTitle(R.string.geolocation);
        } else if(prefKey.equals("dns_settings")) {
            targetFragment = new DnsSettings();
            setTitle(R.string.dns_servers);
        } else if(prefKey.equals("adblock_settings") || prefKey.equals("adguard_dns_settings")) {
            targetFragment = new com.kotsafe.security.fragments.prefs.AdBlockSettings();
            setTitle(R.string.ad_block_shield);
        } else if(prefKey.equals("socks5_settings")) {
            targetFragment = new Socks5Settings();
            setTitle(R.string.socks5_proxy);
        } else if(prefKey.equals("firewall_settings")) {
            targetFragment = new FirewallSettings();
            setTitle(R.string.firewall);
        } else if(prefKey.equals("threat_intel_settings")) {
            targetFragment = new com.kotsafe.security.fragments.prefs.ThreatIntelApiSettings();
            setTitle(R.string.threat_intel_apis);
        } else if(prefKey.equals("ai_protection_settings")) {
            targetFragment = new com.kotsafe.security.fragments.prefs.AiProtectionSettings();
            setTitle(R.string.ai_protection_title);
        } else if(prefKey.equals("p2p_exit_node_settings")) {
            targetFragment = new com.kotsafe.security.fragments.prefs.P2PExitNodeSettings();
            setTitle(R.string.p2p_exit_node_title);
        } else if(prefKey.equals("port_mapping")) {
            startActivity(new Intent(this, com.kotsafe.security.activities.prefs.PortMapActivity.class));
            return true;
        } else if(prefKey.equals("netguard_firewall_settings")) {
            startActivity(new Intent(this, com.kotsafe.security.activities.FirewallActivity.class));
            return true;
        }

        if(targetFragment != null) {
            getSupportFragmentManager()
                    .beginTransaction()
                    .replace(R.id.fragment, targetFragment, pref.getKey())
                    .setTransition(FragmentTransaction.TRANSIT_FRAGMENT_OPEN)
                    .addToBackStack(pref.getKey())
                    .commit();
            return true;
        }

        return false;
    }

    @Override
    public void onBackStackChanged() {
        Fragment f = getSupportFragmentManager().findFragmentById(R.id.fragment);
        boolean atRoot = f instanceof SettingsFragment;

        if(atRoot) {
            setTitle(R.string.title_activity_settings);

            var view = f.getView();
            if ((mInsets != null) && (view != null))
                ViewCompat.dispatchApplyWindowInsets(view, mInsets);
        }

        if (mLangRestartCallback != null)
            mLangRestartCallback.setEnabled(atRoot);
    }

    public static class SettingsFragment extends PreferenceFragmentCompat {
        private SwitchPreference mTlsDecryption;
        private SwitchPreference mFullPayloadEnabled;
        private SwitchPreference mRootCaptureEnabled;
        private SwitchPreference mAutoBlockPrivateDNS;
        private EditTextPreference mMitmproxyOpts;
        private DropDownPreference mIpMode;
        private DropDownPreference mCapInterface;
        private DropDownPreference mBlockQuic;
        private Preference mConnectionsLogSize;
        private Preference mVpnExceptions;
        private Preference mSocks5Settings;
        private Preference mDnsSettings;
        private Preference mPortMapping;
        private Preference mMitmWizard;
        private SwitchPreference mMalwareDetectionEnabled;
        private SwitchPreference mPcapngEnabled;
        private SwitchPreference mDumpExtensions;
        private SwitchPreference mRestartOnDisconnect;
        private SwitchPreference mAdvancedFeaturesSwitch;
        private Preference mEnableAllAdvancedPref;
        private Billing mIab;
        private SettingsBackupHandler mBackupHandler;
        private boolean mHasStartedMitmWizard;
        private boolean mRootDecryptionNoticeShown = false;

        @Override
        public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
            setPreferencesFromResource(R.xml.root_preferences, rootKey);
            mIab = Billing.newInstance(requireContext());
            mBackupHandler = new SettingsBackupHandler(this);

            setupSearchPref();

            Intent intent = requireActivity().getIntent();
            if(intent != null) {
                String target_pref = intent.getStringExtra(TARGET_PREF_EXTRA);
                if(target_pref != null) {
                    scrollToPreference(target_pref);
                }
            }
        }

        @Override
        public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
            super.onViewCreated(view, savedInstanceState);

            ViewCompat.setOnApplyWindowInsetsListener(view, (v, windowInsets) -> {
                Insets insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars() |
                        WindowInsetsCompat.Type.displayCutout());
                v.setPadding(insets.left, 0, insets.right, insets.bottom);

                return WindowInsetsCompat.CONSUMED;
            });
        }

        @Override
        public boolean onPreferenceTreeClick(@NonNull Preference preference) {
            String key = preference.getKey();
            if (key != null && (key.endsWith("_settings") || key.equals("geolocation") || key.equals("dns_settings"))) {
                if (getActivity() instanceof PreferenceFragmentCompat.OnPreferenceStartFragmentCallback) {
                    return ((PreferenceFragmentCompat.OnPreferenceStartFragmentCallback) getActivity())
                            .onPreferenceStartFragment(this, preference);
                }
            }
            Intent intent = preference.getIntent();
            if(intent != null) {
                Utils.startActivity(requireContext(), intent);
                return true;
            }

            return super.onPreferenceTreeClick(preference);
        }

        @Override
        public void onResume() {
            super.onResume();

            Preference devPref = findPreference("advanced_developer_settings");
            if (devPref != null) {
                if (!com.kotsafe.security.model.KotSafeUserManager.isUserAuthenticated(requireContext())) {
                    devPref.setSummary("🔒 Sign-in required • Deep packet capture, TLS decryption & Wireshark tools");
                } else {
                    devPref.setSummary("Deep packet capture, TLS decryption, Wireshark & developer tools");
                }
            }

            if(mHasStartedMitmWizard && !MitmAddon.needsSetup(requireContext())) {
                Log.d(TAG, "mitm setup complete, enabling");
                mTlsDecryption.setChecked(true);
                mFullPayloadEnabled.setChecked(true);
            }
            mHasStartedMitmWizard = false;
        }

        private @NonNull <T extends Preference> T requirePreference(String key) {
            T pref = findPreference(key);
            if(pref == null)
                throw new IllegalStateException();
            return pref;
        }

        private void setupSearchPref() {
            Preference searchPref = findPreference("pref_search_settings");
            if (searchPref != null) {
                searchPref.setOnPreferenceClickListener(p -> {
                    if (getActivity() instanceof SettingsActivity) {
                        ((SettingsActivity) getActivity()).openSearchDialog();
                    }
                    return true;
                });
            }
        }

        private boolean isAdvancedMode() {
            return mAdvancedFeaturesSwitch != null && mAdvancedFeaturesSwitch.isChecked();
        }

        private void setupAdvancedFeaturesMode() {
            mAdvancedFeaturesSwitch = findPreference(Prefs.PREF_ENABLE_ADVANCED_FEATURES);
            mEnableAllAdvancedPref = findPreference("pref_enable_all_advanced_now");

            if (mAdvancedFeaturesSwitch != null) {
                mAdvancedFeaturesSwitch.setOnPreferenceChangeListener((preference, newValue) -> {
                    boolean enabled = (Boolean) newValue;
                    updateAdvancedFeaturesVisibility(enabled);
                    return true;
                });
            }

            if (mEnableAllAdvancedPref != null) {
                mEnableAllAdvancedPref.setOnPreferenceClickListener(pref -> {
                    showEnableAllAdvancedDialog();
                    return true;
                });
            }
        }

        private void updateAdvancedFeaturesVisibility(boolean isAdvanced) {
            if (mEnableAllAdvancedPref != null) {
                mEnableAllAdvancedPref.setVisible(isAdvanced);
            }

            // 1. Capture Engine low-level options
            if (mRootCaptureEnabled != null) {
                mRootCaptureEnabled.setVisible(isAdvanced && Utils.isRootAvailable());
            }
            if (mCapInterface != null) {
                mCapInterface.setVisible(isAdvanced && rootCaptureEnabled());
            }
            if (mIpMode != null) {
                mIpMode.setVisible(isAdvanced && !rootCaptureEnabled());
            }
            if (mRestartOnDisconnect != null) {
                mRestartOnDisconnect.setVisible(isAdvanced && VpnReconnectService.isAvailable());
            }

            // 2. Traffic Inspection & Decryption category
            androidx.preference.PreferenceCategory trafficCat = findPreference("traffic_inspection");
            if (trafficCat != null) {
                trafficCat.setVisible(isAdvanced);
            }

            // 3. Threat Intel APIs & Custom detection rules
            Preference threatIntel = findPreference("threat_intel_settings");
            if (threatIntel != null) {
                threatIntel.setVisible(isAdvanced);
            }
            Preference detectionRules = findPreference("pref_detection_rules_enabled");
            if (detectionRules != null) {
                detectionRules.setVisible(isAdvanced);
            }

            // 4. Streaming, Proxies & Mesh (Keep P2P Exit Node visible for normal users, hide advanced network daemons)
            if (mSocks5Settings != null) {
                mSocks5Settings.setVisible(isAdvanced && !mTlsDecryption.isChecked() && !rootCaptureEnabled());
            }
            Preference httpPort = findPreference(Prefs.PREF_HTTP_SERVER_PORT);
            if (httpPort != null) httpPort.setVisible(isAdvanced);

            Preference colHost = findPreference(Prefs.PREF_COLLECTOR_HOST_KEY);
            if (colHost != null) colHost.setVisible(isAdvanced);

            Preference colPort = findPreference(Prefs.PREF_COLLECTOR_PORT_KEY);
            if (colPort != null) colPort.setVisible(isAdvanced);

            if (mPortMapping != null) {
                mPortMapping.setVisible(isAdvanced && !rootCaptureEnabled());
            }

            // 5. Backup & PCAP format internals
            if (mPcapngEnabled != null) {
                mPcapngEnabled.setVisible(isAdvanced && mIab.isPurchased(Billing.PCAPNG_SKU));
            }
            if (mDumpExtensions != null) {
                mDumpExtensions.setVisible(isAdvanced && !isPcapngEnabled());
            }
            Preference dumpHowTo = findPreference("dump_extensions_how_to");
            if (dumpHowTo != null) dumpHowTo.setVisible(isAdvanced);

            Preference filePrefix = findPreference(Prefs.PREF_FILENAME_PREFIX);
            if (filePrefix != null) filePrefix.setVisible(isAdvanced);

            Preference ctrlPerm = findPreference("control_permissions");
            if (ctrlPerm != null) ctrlPerm.setVisible(isAdvanced);

            // 6. Low-level storage dump manager
            Preference storageMgmt = findPreference("storage_management");
            if (storageMgmt != null) storageMgmt.setVisible(isAdvanced);
        }

        private void showEnableAllAdvancedDialog() {
            new AlertDialog.Builder(requireContext())
                    .setTitle(R.string.advanced_mode_dialog_title)
                    .setMessage(R.string.advanced_mode_dialog_msg)
                    .setPositiveButton(R.string.advanced_mode_enable_all, (dialog, which) -> {
                        SharedPreferences p = PreferenceManager.getDefaultSharedPreferences(requireContext());
                        p.edit()
                                .putBoolean(Prefs.PREF_FULL_PAYLOAD, true)
                                .putBoolean(Prefs.PREF_PCAPNG_ENABLED, true)
                                .putBoolean(Prefs.PREF_DUMP_EXTENSIONS, true)
                                .putBoolean(Prefs.PREF_AUTO_BLOCK_PRIVATE_DNS, true)
                                .putString(Prefs.PREF_BLOCK_QUIC, "always")
                                .putBoolean("pref_auto_daily_deep_scan", true)
                                .putBoolean("pref_detection_rules_enabled", true)
                                .apply();

                        if (mFullPayloadEnabled != null) mFullPayloadEnabled.setChecked(true);
                        if (mPcapngEnabled != null) mPcapngEnabled.setChecked(true);
                        if (mDumpExtensions != null) mDumpExtensions.setChecked(true);
                        if (mAutoBlockPrivateDNS != null) mAutoBlockPrivateDNS.setChecked(true);
                        if (mBlockQuic != null) mBlockQuic.setValue("always");

                        SwitchPreference dailyScan = findPreference("pref_auto_daily_deep_scan");
                        if (dailyScan != null) dailyScan.setChecked(true);

                        SwitchPreference detectRules = findPreference("pref_detection_rules_enabled");
                        if (detectRules != null) detectRules.setChecked(true);

                        Toast.makeText(requireContext(), R.string.advanced_mode_all_enabled_toast, Toast.LENGTH_LONG).show();
                    })
                    .setNegativeButton(android.R.string.cancel, null)
                    .show();
        }

        @SuppressWarnings("deprecation")
        private void setupExporterPrefs() {
            /* Collector host validation (IP address or domain name) */
            EditTextPreference mRemoteCollectorHost = requirePreference(Prefs.PREF_COLLECTOR_HOST_KEY);
            mRemoteCollectorHost.setOnPreferenceChangeListener((preference, newValue) -> Utils.validateHostOrIp(newValue.toString()));

            /* Collector port validation */
            EditTextPreference mRemoteCollectorPort = requirePreference(Prefs.PREF_COLLECTOR_PORT_KEY);
            mRemoteCollectorPort.setOnBindEditTextListener(editText -> editText.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_FLAG_SIGNED));
            mRemoteCollectorPort.setOnPreferenceChangeListener((preference, newValue) -> Utils.validatePort(newValue.toString()));
        }

        private void setupHttpServerPrefs() {
            /* HTTP Server port validation */
            EditTextPreference mHttpServerPort = requirePreference(Prefs.PREF_HTTP_SERVER_PORT);
            mHttpServerPort.setOnPreferenceChangeListener((preference, newValue) -> Utils.validatePort(newValue.toString()));
        }

        private boolean rootCaptureEnabled() {
            return Utils.isRootAvailable() && mRootCaptureEnabled.isChecked();
        }

        private boolean isPcapngEnabled() {
            return mIab.isPurchased(Billing.PCAPNG_SKU) && mPcapngEnabled.isChecked();
        }

        private void dumpExtensionsHideShow(boolean pcapngEnabled) {
            // the KotSafe extensions are implicitly enabled with the pcapng format
            mDumpExtensions.setVisible(isAdvancedMode() && !pcapngEnabled);
        }

        private void refreshInterfaces() {
            ArrayList<String> labels = new ArrayList<>();
            ArrayList<String> values = new ArrayList<>();

            labels.add(getString(R.string.internet));
            values.add("@inet");
            labels.add(getString(R.string.all_interfaces));
            values.add("any");

            try {
                Enumeration<NetworkInterface> ifaces = Utils.getNetworkInterfaces();

                while (ifaces.hasMoreElements()) {
                    NetworkInterface iface = ifaces.nextElement();
                    if(!iface.isUp())
                        continue;

                    String name = iface.getName();
                    labels.add(name);
                    values.add(name);
                }
            } catch (SocketException e) {
                e.printStackTrace();
            }

            mCapInterface.setEntryValues(values.toArray(new String[0]));
            mCapInterface.setEntries(labels.toArray(new String[0]));
        }

        private void setupCapturePrefs() {
            mCapInterface = requirePreference(Prefs.PREF_CAPTURE_INTERFACE);
            refreshInterfaces();

            mRootCaptureEnabled = requirePreference(Prefs.PREF_ROOT_CAPTURE);
            if(Utils.isRootAvailable()) {
                mRootCaptureEnabled.setOnPreferenceChangeListener((preference, newValue) -> {
                    rootCaptureHideShow((Boolean) newValue);
                    return checkDecrpytionWithRoot((Boolean) newValue, mTlsDecryption.isChecked());
                });
            } else
                mRootCaptureEnabled.setVisible(false);

            mRestartOnDisconnect = requirePreference(Prefs.PREF_RESTART_ON_DISCONNECT);
            mRestartOnDisconnect.setVisible(VpnReconnectService.isAvailable());

            mDnsSettings = requirePreference("dns_settings");;
            mVpnExceptions = requirePreference(Prefs.PREF_VPN_EXCEPTIONS);
            mVpnExceptions.setOnPreferenceClickListener(preference -> {
                Intent intent = new Intent(requireContext(), VpnExemptionsActivity.class);
                startActivity(intent);
                return true;
            });
        }

        private void setupSecurityPrefs() {
            mMalwareDetectionEnabled = requirePreference(Prefs.PREF_MALWARE_DETECTION);

            Preference secPerm = findPreference("security_permissions_setup");
            if(secPerm != null) {
                secPerm.setOnPreferenceClickListener(pref -> {
                    Intent intent = new Intent(requireContext(), com.kotsafe.security.activities.AppPermissionsActivity.class);
                    startActivity(intent);
                    return true;
                });
            }

            Preference wifiSec = findPreference("wifi_security_settings");
            if(wifiSec != null) {
                wifiSec.setOnPreferenceClickListener(pref -> {
                    Intent intent = new Intent(requireContext(), com.kotsafe.security.activities.WifiSecurityActivity.class);
                    startActivity(intent);
                    return true;
                });
            }

            Preference avScan = findPreference("antivirus_scan_action");
            if(avScan != null) {
                avScan.setOnPreferenceClickListener(pref -> {
                    Intent intent = new Intent(requireContext(), com.kotsafe.security.activities.AntivirusScanActivity.class);
                    startActivity(intent);
                    return true;
                });
            }

            Preference physSec = findPreference("physical_security_settings");
            if(physSec != null) {
                physSec.setVisible(true);
                physSec.setOnPreferenceClickListener(pref -> {
                    Intent intent = new Intent(requireContext(), com.kotsafe.security.activities.PhysicalSecurityActivity.class);
                    startActivity(intent);
                    return true;
                });
            }

            Preference qVault = findPreference("quarantine_vault_settings");
            if(qVault != null) {
                qVault.setVisible(true);
                int count = com.kotsafe.security.model.QuarantineVaultManager.getInstance(requireContext()).getQuarantinedCount();
                if (count > 0) {
                    qVault.setSummary(count + " isolated threat artifact" + (count > 1 ? "s" : "") + " in vault");
                }
                qVault.setOnPreferenceClickListener(pref -> {
                    Intent intent = new Intent(requireContext(), com.kotsafe.security.activities.QuarantineActivity.class);
                    startActivity(intent);
                    return true;
                });
            }

            Preference storageMgmt = findPreference("storage_management");
            if(storageMgmt != null) {
                storageMgmt.setOnPreferenceClickListener(pref -> {
                    Intent intent = new Intent(requireContext(), com.kotsafe.security.activities.StorageManagementActivity.class);
                    startActivity(intent);
                    return true;
                });
            }

            if(!mIab.isPurchased(Billing.MALWARE_DETECTION_SKU) && !mIab.isAvailable(Billing.MALWARE_DETECTION_SKU)) {
                androidx.preference.PreferenceCategory secCat = findPreference("security");
                if(secCat != null) {
                    secCat.removePreference(mMalwareDetectionEnabled);
                    Preference docs = findPreference("malware_detection_docs");
                    if(docs != null) secCat.removePreference(docs);
                }
                return;
            }

            // Billing code here
        }

        @SuppressWarnings("deprecation")
        private void setupTrafficInspectionPrefs() {
            mAutoBlockPrivateDNS = requirePreference("auto_block_private_dns");

            mTlsDecryption = requirePreference(Prefs.PREF_TLS_DECRYPTION_KEY);
            if(!MitmAddon.isSupportedTarget()) {
                // The mitm addon dropped support for armv7/x86 and Android < 7
                mTlsDecryption.setChecked(false);
                mTlsDecryption.setEnabled(false);
                mTlsDecryption.setSummary(R.string.tls_decryption_unsupported_target);
            } else
                mTlsDecryption.setOnPreferenceChangeListener((preference, newValue) -> {
                    boolean enabled = (boolean) newValue;
                    Context ctx = requireContext();

                    if(!checkDecrpytionWithRoot(rootCaptureEnabled(), (boolean) newValue))
                        return false;

                    if(enabled) {
                        MitmAddon.setDecryptionSetupDone(ctx, true);
                        MitmAddon.setCAInstallationSkipped(ctx, true);
                        com.kotsafe.security.tls.TlsCaManager.getInstance(ctx).autoInstallCaWithRoot();
                    }

                    mMitmWizard.setVisible(enabled);
                    mMitmproxyOpts.setVisible(enabled);
                    socks5ProxyHideShow(enabled, rootCaptureEnabled());
                    return true;
                });

            mPcapngEnabled = requirePreference(Prefs.PREF_PCAPNG_ENABLED);
            mDumpExtensions = requirePreference(Prefs.PREF_DUMP_EXTENSIONS);

            if(mIab.isPurchased(Billing.PCAPNG_SKU) || mIab.isAvailable(Billing.PCAPNG_SKU)) {
                mPcapngEnabled.setOnPreferenceClickListener((preference -> {
                    // Billing code here

                    return false;
                }));
                if(!mIab.isPurchased(Billing.PCAPNG_SKU))
                    mPcapngEnabled.setChecked(false);
            } else
                mPcapngEnabled.setVisible(false);

            mPcapngEnabled.setOnPreferenceChangeListener((preference, newValue) -> {
                dumpExtensionsHideShow((boolean) newValue);
                return true;
            });

            dumpExtensionsHideShow(isPcapngEnabled());

            mFullPayloadEnabled = requirePreference(Prefs.PREF_FULL_PAYLOAD);
            mBlockQuic = requirePreference(Prefs.PREF_BLOCK_QUIC);
            mMitmproxyOpts = requirePreference(Prefs.PREF_MITMPROXY_OPTS);
            mMitmproxyOpts.setVisible(mTlsDecryption.isChecked());
            mMitmWizard = requirePreference("mitm_setup_wizard");
            mMitmWizard.setVisible(mTlsDecryption.isChecked());
            mMitmWizard.setOnPreferenceClickListener(preference -> {
                mHasStartedMitmWizard = true;
                Intent intent = new Intent(requireContext(), MitmSetupWizard.class);
                startActivity(intent);
                return true;
            });

            mSocks5Settings = requirePreference("socks5_settings");

            setupConnectionsLogSizePref();
        }

        private void setupConnectionsLogSizePref() {
            mConnectionsLogSize = requirePreference(Prefs.PREF_CONNECTIONS_LOG_SIZE);
            updateConnectionsLogSizeSummary();

            mConnectionsLogSize.setOnPreferenceClickListener(preference -> {
                ConnectionsLogSizeDialog dialog = ConnectionsLogSizeDialog.newInstance();
                dialog.setListener(newSize -> updateConnectionsLogSizeSummary());
                dialog.show(getChildFragmentManager(), ConnectionsLogSizeDialog.TAG);
                return true;
            });
        }

        void updateConnectionsLogSizeSummary() {
            if (mConnectionsLogSize == null || !isAdded()) return;
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(requireContext());
            int size = Prefs.getConnectionsLogSize(prefs);
            int mb = (int) (((long) size * 2L) / 1024);

            String profileName;
            if (size == 2048) {
                profileName = getString(R.string.connections_preset_eco);
            } else if (size == 8192) {
                profileName = getString(R.string.connections_preset_standard);
            } else if (size == 16384) {
                profileName = getString(R.string.connections_preset_high);
            } else if (size == 32768) {
                profileName = getString(R.string.connections_preset_forensic);
            } else if (size == 65536) {
                profileName = getString(R.string.connections_preset_vault);
            } else {
                profileName = getString(R.string.connections_custom_size);
            }

            mConnectionsLogSize.setSummary(getString(R.string.connections_log_size_summary_format,
                    NumberFormat.getInstance().format(size), mb, profileName));
        }

        private void socks5ProxyHideShow(boolean tlsDecryption, boolean rootEnabled) {
            mSocks5Settings.setVisible(isAdvancedMode() && !tlsDecryption && !rootEnabled);
        }

        private void setupAppLanguagePref() {
            Preference appLang = findPreference(Prefs.PREF_APP_LANGUAGE);
            if (appLang != null) {
                SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(requireContext());
                String currentLang = prefs.getString(Prefs.PREF_APP_LANGUAGE, "system");
                appLang.setSummary(LanguagePickerDialog.getLanguageDisplayName(requireContext(), currentLang));

                if (SettingsActivity.ACTION_LANG_RESTART.equals(requireActivity().getIntent().getAction())) {
                    scrollToPreference(appLang);
                }

                appLang.setOnPreferenceClickListener(preference -> {
                    if (getActivity() instanceof SettingsActivity) {
                        ((SettingsActivity) getActivity()).openLanguagePickerDialog();
                    }
                    return true;
                });
            }

            Preference appLangExternal = findPreference("app_language_external");
            if (appLangExternal != null) {
                appLangExternal.setVisible(false);
            }
        }

        private void setupThemePref() {
            DropDownPreference themePref = findPreference(Prefs.PREF_THEME_MODE);
            if (themePref != null) {
                themePref.setOnPreferenceChangeListener((preference, newValue) -> {
                    String mode = newValue.toString();
                    Prefs.applyThemeMode(mode);
                    return true;
                });
            }
        }

        private void setupAnalyticsAndLogsPrefs() {
            Preference prefStats = findPreference("pref_traffic_stats");
            if (prefStats != null) {
                prefStats.setOnPreferenceClickListener(preference -> {
                    Intent intent = new Intent(requireContext(), StatsActivity.class);
                    startActivity(intent);
                    return true;
                });
            }

            Preference prefLog = findPreference("pref_app_log");
            if (prefLog != null) {
                prefLog.setOnPreferenceClickListener(preference -> {
                    Intent intent = new Intent(requireContext(), LogviewActivity.class);
                    intent.putExtra(LogviewActivity.EXTRA_INITIAL_TAB, LogviewActivity.POS_APP_LOG);
                    startActivity(intent);
                    return true;
                });
            }
        }

        private void setupOtherPrefs() {
            setupThemePref();
            setupAppLanguagePref();

            mPortMapping = requirePreference(Prefs.PREF_PORT_MAPPING);
            mPortMapping.setOnPreferenceClickListener(preference -> {
                Intent intent = new Intent(requireContext(), PortMapActivity.class);
                startActivity(intent);
                return true;
            });

            mIpMode = requirePreference(Prefs.PREF_IP_MODE);

            Preference ctrlPerm = requirePreference("control_permissions");
            ctrlPerm.setOnPreferenceClickListener(preference -> {
                Intent intent = new Intent(requireContext(), EditCtrlPermissions.class);
                startActivity(intent);
                return true;
            });
        }

        private void setupBackupPrefs() {
            Preference exportSettings = requirePreference("export_settings");
            exportSettings.setOnPreferenceClickListener(preference -> {
                mBackupHandler.startExport();
                return true;
            });

            Preference importSettings = requirePreference("import_settings");
            importSettings.setOnPreferenceClickListener(preference -> {
                mBackupHandler.startImport();
                return true;
            });
        }

        private void rootCaptureHideShow(boolean enabled) {
            boolean isAdv = isAdvancedMode();
            if(enabled) {
                mAutoBlockPrivateDNS.setVisible(false);
                mBlockQuic.setVisible(false);
                mSocks5Settings.setVisible(false);
            } else {
                mAutoBlockPrivateDNS.setVisible(isAdv);
                mBlockQuic.setVisible(isAdv);
                socks5ProxyHideShow(mTlsDecryption.isChecked(), false);
            }

            if (VpnReconnectService.isAvailable())
                mRestartOnDisconnect.setVisible(isAdv && !enabled);

            mIpMode.setVisible(isAdv && !enabled);
            mCapInterface.setVisible(isAdv && enabled);
            mVpnExceptions.setVisible(!enabled);
            mDnsSettings.setVisible(!enabled);
            mPortMapping.setVisible(isAdv && !enabled);
        }

        private boolean checkDecrpytionWithRoot(boolean rootEnabled, boolean tlsDecryption) {
            if(mRootDecryptionNoticeShown || !rootEnabled || !tlsDecryption)
                return true;

            new AlertDialog.Builder(requireContext())
                    .setMessage(R.string.tls_decryption_with_root_msg)
                    .setPositiveButton(R.string.ok, (dialog, whichButton) -> {
                        mRootCaptureEnabled.setChecked(true);
                        mTlsDecryption.setChecked(true);

                        mRootDecryptionNoticeShown = true;
                    })
                    .show();

            return false;
        }
    }
}
