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

package com.kotsafe.security.fragments.prefs;

import android.os.Bundle;
import android.text.InputType;
import android.text.TextUtils;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.preference.EditTextPreference;
import androidx.preference.Preference;
import androidx.preference.PreferenceFragmentCompat;

import com.kotsafe.security.R;
import com.kotsafe.security.ThreatIntelApiClient;

/**
 * Settings fragment for Threat Intel API keys (OTX / VirusTotal).
 *
 * Security design — API keys are "write-only" after initial save:
 *  - The EditText dialog is always cleared before display; the raw key is NEVER
 *    shown to the user again (even via the text field).
 *  - The summary shows only a masked version: ••••••••••••XXXX (last 4 chars).
 *  - The stored SharedPreference value is the full key so the app can use it,
 *    but the UI never reveals it.
 *  - Users can type a new key at any time to replace; leaving blank keeps the old key.
 */
public class ThreatIntelApiSettings extends PreferenceFragmentCompat {
    private EditTextPreference mOtxKeyPref;
    private EditTextPreference mVtKeyPref;
    private Preference mOtxTestPref;
    private Preference mVtTestPref;

    private final androidx.activity.result.ActivityResultLauncher<String[]> mLocationPermissionLauncher =
            registerForActivityResult(new androidx.activity.result.contract.ActivityResultContracts.RequestMultiplePermissions(), result -> {
                // Permission callback handled
            });

    @Override
    public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
        setPreferencesFromResource(R.xml.threat_intel_preferences, rootKey);

        mOtxKeyPref = findPreference(ThreatIntelApiClient.PREF_OTX_KEY);
        mVtKeyPref  = findPreference(ThreatIntelApiClient.PREF_VT_KEY);
        EditTextPreference urlhausKeyPref = findPreference(com.kotsafe.security.model.URLhausProvider.PREF_URLHAUS_KEY);
        EditTextPreference threatFoxKeyPref = findPreference(com.kotsafe.security.model.ThreatFoxProvider.PREF_THREATFOX_KEY);

        mOtxTestPref = findPreference("otx_test_connection");
        mVtTestPref  = findPreference("virustotal_test_connection");
        Preference urlhausTestPref = findPreference("urlhaus_test_connection");
        Preference threatFoxTestPref = findPreference("threatfox_test_connection");
        Preference syncNowPref = findPreference("threat_feed_sync_now");

        EditTextPreference mbKeyPref = findPreference(com.kotsafe.security.model.MalwareBazaarProvider.PREF_MB_KEY);
        EditTextPreference siemTokenPref = findPreference(com.kotsafe.security.model.SiemTelemetryForwarder.PREF_SIEM_AUTH_TOKEN);
        Preference mbTestPref = findPreference("malwarebazaar_test_connection");
        Preference siemTestPref = findPreference("siem_test_connection");

        configureKeyPref(mOtxKeyPref);
        configureKeyPref(mVtKeyPref);
        configureKeyPref(urlhausKeyPref);
        configureKeyPref(threatFoxKeyPref);
        configureKeyPref(mbKeyPref);
        configureKeyPref(siemTokenPref);

        updateMaskedSummary(mOtxKeyPref);
        updateMaskedSummary(mVtKeyPref);
        updateMaskedSummary(urlhausKeyPref);
        updateMaskedSummary(threatFoxKeyPref);
        updateMaskedSummary(mbKeyPref);
        updateMaskedSummary(siemTokenPref);

        // ── Test connection buttons ──────────────────────────────────────────
        if (mOtxTestPref != null) {
            mOtxTestPref.setOnPreferenceClickListener(preference -> {
                String key = ThreatIntelApiClient.getInstance(requireContext()).getOtxKey();
                if (key.isEmpty()) {
                    Toast.makeText(requireContext(), "Please enter an OTX API Key first", Toast.LENGTH_SHORT).show();
                    return true;
                }
                testConnection("AlienVault OTX", () ->
                        ThreatIntelApiClient.getInstance(requireContext()).testOtxConnection(key,
                                buildCallback("AlienVault OTX")));
                return true;
            });
        }

        if (mVtTestPref != null) {
            mVtTestPref.setOnPreferenceClickListener(preference -> {
                String key = ThreatIntelApiClient.getInstance(requireContext()).getVtKey();
                if (key.isEmpty()) {
                    Toast.makeText(requireContext(), "Please enter a VirusTotal API Key first", Toast.LENGTH_SHORT).show();
                    return true;
                }
                testConnection("VirusTotal", () ->
                        ThreatIntelApiClient.getInstance(requireContext()).testVirusTotalConnection(key,
                                buildCallback("VirusTotal")));
                return true;
            });
        }

        if (urlhausTestPref != null) {
            urlhausTestPref.setOnPreferenceClickListener(preference -> {
                String key = androidx.preference.PreferenceManager.getDefaultSharedPreferences(requireContext())
                        .getString(com.kotsafe.security.model.URLhausProvider.PREF_URLHAUS_KEY, "");
                testConnection("URLhaus", () ->
                        ThreatIntelApiClient.getInstance(requireContext()).testUrlhausConnection(key,
                                buildCallback("URLhaus (Abuse.ch)")));
                return true;
            });
        }

        if (threatFoxTestPref != null) {
            threatFoxTestPref.setOnPreferenceClickListener(preference -> {
                String key = androidx.preference.PreferenceManager.getDefaultSharedPreferences(requireContext())
                        .getString(com.kotsafe.security.model.ThreatFoxProvider.PREF_THREATFOX_KEY, "");
                testConnection("ThreatFox", () ->
                        ThreatIntelApiClient.getInstance(requireContext()).testThreatFoxConnection(key,
                                buildCallback("ThreatFox (Abuse.ch)")));
                return true;
            });
        }

        if (mbTestPref != null) {
            mbTestPref.setOnPreferenceClickListener(preference -> {
                String key = androidx.preference.PreferenceManager.getDefaultSharedPreferences(requireContext())
                        .getString(com.kotsafe.security.model.MalwareBazaarProvider.PREF_MB_KEY, "");
                testConnection("MalwareBazaar", () ->
                        ThreatIntelApiClient.getInstance(requireContext()).testMalwareBazaarConnection(key,
                                buildCallback("MalwareBazaar (Abuse.ch)")));
                return true;
            });
        }

        if (siemTestPref != null) {
            siemTestPref.setOnPreferenceClickListener(preference -> {
                String endpoint = com.kotsafe.security.model.SiemTelemetryForwarder.getInstance(requireContext()).getEndpointUrl();
                String token = com.kotsafe.security.model.SiemTelemetryForwarder.getInstance(requireContext()).getAuthToken();
                if (endpoint.isEmpty()) {
                    Toast.makeText(requireContext(), "Please configure SIEM Ingestion Endpoint URL first", Toast.LENGTH_SHORT).show();
                    return true;
                }
                testConnection("Enterprise SIEM", () ->
                        ThreatIntelApiClient.getInstance(requireContext()).testSiemConnection(endpoint, token,
                                buildCallback("Enterprise SIEM Ingest")));
                return true;
            });
        }

        // ── Enterprise Live Location & Geofencing ────────────────────────────
        Preference shareLocationPref = findPreference("pref_action_share_live_location");
        if (shareLocationPref != null) {
            shareLocationPref.setOnPreferenceClickListener(preference -> {
                com.kotsafe.security.model.DeviceLocationManager.getInstance(requireContext())
                        .shareLiveLocation(requireActivity());
                return true;
            });
        }

        androidx.preference.SwitchPreference locationEnabledPref =
                findPreference(com.kotsafe.security.model.DeviceLocationManager.PREF_LOCATION_ENABLED);
        if (locationEnabledPref != null) {
            locationEnabledPref.setOnPreferenceChangeListener((preference, newValue) -> {
                boolean enabled = Boolean.TRUE.equals(newValue);
                if (enabled && !com.kotsafe.security.model.DeviceLocationManager.getInstance(requireContext()).hasLocationPermission()) {
                    mLocationPermissionLauncher.launch(new String[]{
                            android.Manifest.permission.ACCESS_FINE_LOCATION,
                            android.Manifest.permission.ACCESS_COARSE_LOCATION
                    });
                }
                return true;
            });
        }

        // ── Threat Feed Sync Now ─────────────────────────────────────────────
        if (syncNowPref != null) {
            syncNowPref.setOnPreferenceClickListener(preference -> {
                Toast.makeText(requireContext(), "Starting Live Threat Feed Sync…", Toast.LENGTH_SHORT).show();
                com.kotsafe.security.model.ThreatFeedSyncManager.getInstance(requireContext())
                        .syncNow(new com.kotsafe.security.model.ThreatFeedSyncManager.SyncCallback() {
                            @Override
                            public void onProgress(String status) {
                                if (isAdded()) {
                                    requireActivity().runOnUiThread(() ->
                                            Toast.makeText(requireContext(), status, Toast.LENGTH_SHORT).show());
                                }
                            }

                            @Override
                            public void onSuccess(int totalRulesAdded) {
                                if (isAdded()) {
                                    requireActivity().runOnUiThread(() ->
                                            new AlertDialog.Builder(requireContext())
                                                    .setTitle("Threat Feeds Synchronized")
                                                    .setMessage("Successfully downloaded and cached " + totalRulesAdded + " active malware, C2, and hash rules from URLhaus, ThreatFox, and MalwareBazaar into local offline storage.")
                                                    .setIcon(R.drawable.ic_check_solid)
                                                    .setPositiveButton(android.R.string.ok, null)
                                                    .show());
                                }
                            }

                            @Override
                            public void onError(String errorMessage) {
                                if (isAdded()) {
                                    requireActivity().runOnUiThread(() ->
                                            new AlertDialog.Builder(requireContext())
                                                    .setTitle("Sync Failed")
                                                    .setMessage("Threat Feed Sync Error: " + errorMessage)
                                                    .setIcon(R.drawable.ic_exclamation_triangle_solid)
                                                    .setPositiveButton(android.R.string.ok, null)
                                                    .show());
                                }
                            }
                        });
                return true;
            });
        }
    }

    // ── Key Preference Configuration ────────────────────────────────────────

    /**
     * Configures an API key EditTextPreference for write-only behaviour:
     *  - Input type = password (masked while typing)
     *  - Dialog is always cleared (raw key never shown)
     *  - After save, updates the masked summary
     */
    private void configureKeyPref(EditTextPreference pref) {
        if (pref == null) return;

        // Mask input while typing
        pref.setOnBindEditTextListener(editText -> {
            editText.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
            // Always clear so the real key is never pre-populated in the dialog
            editText.setText("");
            editText.setHint("Enter new key to replace current");
        });

        // After the user saves: if blank, keep existing key, otherwise store new one
        pref.setOnPreferenceChangeListener((preference, newValue) -> {
            String typed = (String) newValue;
            if (TextUtils.isEmpty(typed.trim())) {
                // User left blank → keep the old stored key, just refresh summary
                updateMaskedSummary((EditTextPreference) preference);
                return false; // Don't overwrite stored value with blank
            }
            updateMaskedSummaryFromKey((EditTextPreference) preference, typed);
            return true; // Store the new key
        });
    }

    // ── Summary helpers ──────────────────────────────────────────────────────

    /** Updates summary from the currently stored preference value. */
    private void updateMaskedSummary(EditTextPreference pref) {
        if (pref == null) return;
        updateMaskedSummaryFromKey(pref, pref.getText());
    }

    /** Renders a masked summary from a given key string. Raw key is never shown. */
    private void updateMaskedSummaryFromKey(EditTextPreference pref, String key) {
        if (!TextUtils.isEmpty(key) && !key.trim().isEmpty()) {
            String masked = (key.length() > 4)
                    ? "••••••••••••" + key.substring(key.length() - 4)
                    : "••••••••";
            pref.setSummary("🔑 Configured  " + masked + "  •  Tap to replace");
        } else {
            pref.setSummary("Not configured — tap to enter your API key");
        }
    }

    // ── Connection test helpers ──────────────────────────────────────────────

    private void testConnection(String serviceName, Runnable task) {
        Toast.makeText(requireContext(), "Testing " + serviceName + "…", Toast.LENGTH_SHORT).show();
        task.run();
    }

    private ThreatIntelApiClient.ApiCallback<String> buildCallback(String serviceName) {
        return new ThreatIntelApiClient.ApiCallback<String>() {
            @Override
            public void onSuccess(String result) {
                if (!isAdded()) return;
                requireActivity().runOnUiThread(() ->
                        new AlertDialog.Builder(requireContext())
                                .setTitle(serviceName)
                                .setMessage(result)
                                .setIcon(R.drawable.ic_check_solid)
                                .setPositiveButton(android.R.string.ok, null)
                                .show());
            }

            @Override
            public void onError(String message) {
                if (!isAdded()) return;
                requireActivity().runOnUiThread(() ->
                        new AlertDialog.Builder(requireContext())
                                .setTitle("Connection Error")
                                .setMessage(message)
                                .setIcon(R.drawable.ic_exclamation_triangle_solid)
                                .setPositiveButton(android.R.string.ok, null)
                                .show());
            }
        };
    }
}
