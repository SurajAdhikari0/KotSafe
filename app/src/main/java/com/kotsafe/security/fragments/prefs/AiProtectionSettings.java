/*
 * This file is part of KotSafe / KotSafe Cyber Security Project.
 * Apache License, Version 2.0 — see <http://www.apache.org/licenses/LICENSE-2.0>
 */

package com.kotsafe.security.fragments.prefs;

import android.content.Intent;
import android.os.Bundle;
import android.text.InputType;
import android.text.TextUtils;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.preference.EditTextPreference;
import androidx.preference.ListPreference;
import androidx.preference.Preference;
import androidx.preference.PreferenceCategory;
import androidx.preference.PreferenceFragmentCompat;
import androidx.preference.SwitchPreference;

import com.kotsafe.security.R;
import com.kotsafe.security.activities.AiAssistantActivity;
import com.kotsafe.security.ai.AiClientEngine;
import com.kotsafe.security.ai.AiConfig;
import com.kotsafe.security.ai.GemmaModelDownloadManager;

/**
 * Preference fragment managing AI Protection, LLM provider credentials,
 * connection tests, and granular data access levels.
 */
public class AiProtectionSettings extends PreferenceFragmentCompat {

    private SwitchPreference mMasterPref;
    private ListPreference mProviderPref;
    private EditTextPreference mApiKeyPref;
    private EditTextPreference mModelPref;
    private EditTextPreference mEndpointPref;
    private Preference mTestConnPref;
    private Preference mOpenAssistantPref;

    private PreferenceCategory mProviderCat;
    private PreferenceCategory mAccessCat;

    private AiConfig mConfig;

    @Override
    public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
        setPreferencesFromResource(R.xml.ai_protection_preferences, rootKey);
        mConfig = new AiConfig(requireContext());

        mMasterPref = findPreference(AiConfig.PREF_AI_ENABLED);
        mProviderPref = findPreference(AiConfig.PREF_AI_PROVIDER);
        mApiKeyPref = findPreference(AiConfig.PREF_AI_API_KEY);
        mModelPref = findPreference(AiConfig.PREF_AI_MODEL);
        mEndpointPref = findPreference(AiConfig.PREF_AI_ENDPOINT);
        mTestConnPref = findPreference("pref_ai_test_connection");
        mOpenAssistantPref = findPreference("pref_ai_open_assistant");

        mProviderCat = findPreference("cat_ai_provider_config");
        mAccessCat = findPreference("cat_ai_access_levels");
        mGemmaDownloadPref = findPreference("pref_ai_gemma_download");
        mFullPowerPref = findPreference("pref_ai_full_power_mode");

        setupApiKeyField();
        setupProviderChange();
        setupTestConnection();
        setupAssistantLaunch();
        setupGemmaDownload();
        setupFullPowerToggle();

        if (mMasterPref != null) {
            mMasterPref.setOnPreferenceChangeListener((preference, newValue) -> {
                boolean enabled = (Boolean) newValue;
                updateControlsState(enabled);
                return true;
            });
            updateControlsState(mMasterPref.isChecked());
        }

        updateProviderSummaries();
    }

    private Preference mGemmaDownloadPref;
    private SwitchPreference mFullPowerPref;

    private void updateControlsState(boolean enabled) {
        if (mProviderCat != null) mProviderCat.setEnabled(enabled);
        if (mAccessCat != null) mAccessCat.setEnabled(enabled);
        if (mOpenAssistantPref != null) mOpenAssistantPref.setEnabled(enabled);
    }

    private void setupApiKeyField() {
        if (mApiKeyPref == null) return;

        mApiKeyPref.setOnBindEditTextListener(editText -> {
            editText.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
            editText.setText("");
        });

        mApiKeyPref.setOnPreferenceChangeListener((preference, newValue) -> {
            String newKey = ((String) newValue).trim();
            if (TextUtils.isEmpty(newKey)) {
                updateKeySummary("");
                return true;
            }
            mConfig.setApiKey(newKey);
            updateKeySummary(newKey);
            return false;
        });

        updateKeySummary(mConfig.getApiKey());
    }

    private void updateKeySummary(String key) {
        if (mApiKeyPref == null) return;
        if (TextUtils.isEmpty(key)) {
            mApiKeyPref.setSummary("Not configured (tap to set API key)");
        } else if (key.length() <= 4) {
            mApiKeyPref.setSummary("•••• (Configured)");
        } else {
            String last4 = key.substring(key.length() - 4);
            mApiKeyPref.setSummary("••••••••••••" + last4);
        }
    }

    private void setupProviderChange() {
        if (mProviderPref == null) return;

        mProviderPref.setOnPreferenceChangeListener((preference, newValue) -> {
            AiConfig.Provider p = AiConfig.Provider.fromString((String) newValue);
            if (mModelPref != null && (mModelPref.getText() == null || mModelPref.getText().isEmpty())) {
                mModelPref.setText(p.defaultModel);
            }
            if (mEndpointPref != null && (mEndpointPref.getText() == null || mEndpointPref.getText().isEmpty())) {
                mEndpointPref.setText(p.defaultEndpoint);
            }
            updateProviderSummaries();
            return true;
        });
    }

    private void updateProviderSummaries() {
        AiConfig.Provider p = mConfig.getProvider();
        boolean isOnDevice = p.isOnDevice();
        boolean isLocalCustom = (p == AiConfig.Provider.LOCAL_CUSTOM);

        if (mApiKeyPref != null) {
            mApiKeyPref.setVisible(!isOnDevice && !isLocalCustom);
        }
        if (mEndpointPref != null) {
            mEndpointPref.setVisible(isLocalCustom);
        }
        if (mGemmaDownloadPref != null) {
            mGemmaDownloadPref.setVisible(isOnDevice || isLocalCustom);
            updateModelPrefSummary();
        }
        if (mModelPref != null) {
            mModelPref.setSummary("Current: " + mConfig.getModel() + " (Default: " + p.defaultModel + ")");
        }
        if (mEndpointPref != null) {
            mEndpointPref.setSummary("Target: " + mConfig.getEndpoint());
        }
    }

    private void updateModelPrefSummary() {
        if (mGemmaDownloadPref == null) return;
        boolean qwenInstalled = AiConfig.isQwenDownloaded(requireContext());
        boolean smolInstalled = AiConfig.isSmolLmDownloaded(requireContext());
        boolean gemmaInstalled = AiConfig.isGemmaDownloaded(requireContext());

        if (qwenInstalled && mConfig.getProvider() == AiConfig.Provider.LOCAL_QWEN_0_5B) {
            java.io.File file = AiConfig.getQwenModelFile(requireContext());
            long mb = file.length() / (1024 * 1024);
            mGemmaDownloadPref.setSummary("🌟 Qwen 2.5 0.5B Active (" + mb + " MB) — Tap to manage");
        } else if (smolInstalled && mConfig.getProvider() == AiConfig.Provider.LOCAL_SMOLLM_135M) {
            java.io.File file = AiConfig.getSmolLmModelFile(requireContext());
            long mb = file.length() / (1024 * 1024);
            mGemmaDownloadPref.setSummary("⚡ SmolLM-135M Active (" + mb + " MB) — Tap to manage");
        } else if (qwenInstalled || smolInstalled || gemmaInstalled) {
            mGemmaDownloadPref.setSummary("On-Device Models Installed — Tap to manage or switch");
        } else {
            mGemmaDownloadPref.setSummary("Tap to download: Qwen 2.5 0.5B (Recommended, ~350 MB) or SmolLM (~90 MB)");
        }
    }

    private void setupFullPowerToggle() {
        if (mFullPowerPref == null) return;
        mFullPowerPref.setChecked(mConfig.isFullPowerMode());

        mFullPowerPref.setOnPreferenceChangeListener((preference, newValue) -> {
            boolean enabled = (Boolean) newValue;
            mConfig.setFullPowerMode(enabled);

            // Sync visual state of all child switches
            syncAccessSwitch(AiConfig.PREF_ACCESS_STATUS, enabled);
            syncAccessSwitch(AiConfig.PREF_ACCESS_CONNECTIONS, enabled);
            syncAccessSwitch(AiConfig.PREF_ACCESS_HTTP, enabled);
            syncAccessSwitch(AiConfig.PREF_ACCESS_REPEATER, enabled);
            syncAccessSwitch(AiConfig.PREF_ACCESS_FIREWALL, enabled);
            syncAccessSwitch(AiConfig.PREF_ACCESS_ANTIVIRUS, enabled);
            syncAccessSwitch(AiConfig.PREF_ACCESS_LOGS, enabled);

            Toast.makeText(requireContext(),
                    enabled ? "⚡ Full Power Mode Activated (Max Intelligence)" : "Restricted Privacy Mode Activated",
                    Toast.LENGTH_SHORT).show();
            return true;
        });
    }

    private void syncAccessSwitch(String key, boolean val) {
        SwitchPreference pref = findPreference(key);
        if (pref != null) pref.setChecked(val);
    }

    private void setupGemmaDownload() {
        if (mGemmaDownloadPref == null) return;

        mGemmaDownloadPref.setOnPreferenceClickListener(pref -> {
            showModelSelectionDialog();
            return true;
        });
    }

    private void showModelSelectionDialog() {
        GemmaModelDownloadManager mgr = GemmaModelDownloadManager.getInstance(requireContext());
        boolean qwenInstalled = AiConfig.isQwenDownloaded(requireContext());
        boolean smolInstalled = AiConfig.isSmolLmDownloaded(requireContext());
        boolean gemmaInstalled = AiConfig.isGemmaDownloaded(requireContext());

        String[] items = new String[]{
                "🌟 Qwen 2.5 0.5B (Recommended, ~350 MB) " + (qwenInstalled ? "— Installed ✅" : "— Download ⬇️"),
                "⚡ SmolLM-135M (Ultra-Light, ~90 MB) " + (smolInstalled ? "— Installed ✅" : "— Download ⬇️"),
                "Google Gemma 2B (Heavy, ~1.35 GB) " + (gemmaInstalled ? "— Installed ✅" : "— Download ⬇️")
        };

        new AlertDialog.Builder(requireContext())
                .setTitle("On-Device AI Models")
                .setItems(items, (dialog, which) -> {
                    GemmaModelDownloadManager.ModelTarget target;
                    if (which == 0) {
                        target = GemmaModelDownloadManager.ModelTarget.QWEN_0_5B;
                    } else if (which == 1) {
                        target = GemmaModelDownloadManager.ModelTarget.SMOLLM_135M;
                    } else {
                        target = GemmaModelDownloadManager.ModelTarget.GEMMA_2B;
                    }
                    showModelActionDialog(mgr, target);
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void showModelActionDialog(GemmaModelDownloadManager mgr, GemmaModelDownloadManager.ModelTarget target) {
        boolean downloaded = target.isDownloaded(requireContext());

        String desc;
        if (target == GemmaModelDownloadManager.ModelTarget.QWEN_0_5B) {
            desc = "🌟 **Recommended: Qwen 2.5 0.5B**\n\n"
                    + "Qwen 2.5 0.5B (~350 MB) is the Goldilocks size: small enough to run with zero lag on low RAM, but smart enough to generate rich, professional cybersecurity analysis.\n\n"
                    + "• In-depth forensic assessments & MITRE ATT&CK mapping\n"
                    + "• Firewall rule synthesis & exploit behavior reasoning\n"
                    + "• Memory footprint: ~500 MB RAM\n"
                    + "• Download size: ~350 MB (INT4 quantized)";
        } else if (target == GemmaModelDownloadManager.ModelTarget.SMOLLM_135M) {
            desc = "⚡ **SmolLM-135M (Ultra-Light Micro AI)**\n\n"
                    + "SmolLM-135M is great for 1-sentence answers or binary classifications (\"SAFE\" vs \"MALICIOUS\"), but cannot write rich forensic assessments.\n\n"
                    + "• Ultra-fast verdicts & zero battery drain\n"
                    + "• Ideal for low-RAM or older devices\n"
                    + "• Memory footprint: ~150 MB RAM\n"
                    + "• Download size: ~90 MB (INT4 quantized)";
        } else {
            desc = "Google Gemma 2B (Legacy Heavy Model)\n\n"
                    + "• Memory footprint: ~1.5 GB RAM\n"
                    + "• Download size: ~1.35 GB\n"
                    + "• Hardware: Requires high-end device with 8GB+ RAM";
        }

        AlertDialog.Builder builder = new AlertDialog.Builder(requireContext())
                .setTitle(target.title)
                .setMessage(desc);

        if (downloaded) {
            builder.setPositiveButton("Set as Active AI", (d, w) -> {
                setActiveModelProvider(target);
            });
            builder.setNegativeButton("Delete Model", (d, w) -> {
                mgr.deleteModel(target);
                updateModelPrefSummary();
                Toast.makeText(requireContext(), target.title + " deleted. Storage reclaimed.", Toast.LENGTH_SHORT).show();
            });
            builder.setNeutralButton("Keep", null);
        } else if (mgr.isDownloading()) {
            builder.setPositiveButton("Download in Progress...", null);
        } else {
            builder.setPositiveButton("Download Now", (d, w) -> {
                startModelDownloadFlow(mgr, target);
            });
            builder.setNeutralButton("Custom URL", (d, w) -> {
                showCustomUrlDialog(mgr, target);
            });
            builder.setNegativeButton("Cancel", null);
        }
        builder.show();
    }

    private void setActiveModelProvider(GemmaModelDownloadManager.ModelTarget target) {
        AiConfig.Provider provider;
        if (target == GemmaModelDownloadManager.ModelTarget.SMOLLM_135M) {
            provider = AiConfig.Provider.LOCAL_SMOLLM_135M;
        } else if (target == GemmaModelDownloadManager.ModelTarget.GEMMA_2B) {
            provider = AiConfig.Provider.LOCAL_GEMMA_2B;
        } else {
            provider = AiConfig.Provider.LOCAL_QWEN_0_5B;
        }

        mConfig.setProvider(provider);
        if (mProviderPref != null) {
            mProviderPref.setValue(provider.name());
        }
        updateProviderSummaries();
        Toast.makeText(requireContext(), "Active AI set to " + target.title, Toast.LENGTH_SHORT).show();
    }

    private void showCustomUrlDialog(GemmaModelDownloadManager mgr, GemmaModelDownloadManager.ModelTarget target) {
        android.widget.LinearLayout layout = new android.widget.LinearLayout(requireContext());
        layout.setOrientation(android.widget.LinearLayout.VERTICAL);
        layout.setPadding(60, 30, 60, 30);

        android.widget.TextView urlLabel = new android.widget.TextView(requireContext());
        urlLabel.setText("Mirror / Download URL for " + target.title + ":");
        urlLabel.setTextSize(14f);
        layout.addView(urlLabel);

        android.widget.EditText inputUrl = new android.widget.EditText(requireContext());
        String prefKey = "custom_model_url_" + target.name().toLowerCase();
        String currentUrl = androidx.preference.PreferenceManager.getDefaultSharedPreferences(requireContext())
                .getString(prefKey, target.mirrors.length > 0 ? target.mirrors[0] : "");
        inputUrl.setText(currentUrl);
        inputUrl.setHint("https://huggingface.co/...");
        layout.addView(inputUrl);

        new AlertDialog.Builder(requireContext())
                .setTitle(target.title + " Download URL")
                .setView(layout)
                .setPositiveButton("Save & Download", (dialog, which) -> {
                    String custom = inputUrl.getText().toString().trim();
                    androidx.preference.PreferenceManager.getDefaultSharedPreferences(requireContext())
                            .edit()
                            .putString(prefKey, custom)
                            .apply();
                    startModelDownloadFlow(mgr, target);
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void startModelDownloadFlow(GemmaModelDownloadManager mgr, GemmaModelDownloadManager.ModelTarget target) {
        android.widget.ProgressBar pb = new android.widget.ProgressBar(requireContext(), null, android.R.attr.progressBarStyleHorizontal);
        pb.setIndeterminate(false);
        pb.setMax(100);
        pb.setProgress(0);
        pb.setPadding(48, 24, 48, 24);

        AlertDialog progressDialog = new AlertDialog.Builder(requireContext())
                .setTitle("Downloading " + target.title + "...")
                .setMessage("Connecting to mirror CDN...")
                .setView(pb)
                .setNegativeButton("Cancel", (dialog, which) -> {
                    mgr.cancelDownload();
                })
                .setCancelable(false)
                .show();

        mgr.startDownload(target, new GemmaModelDownloadManager.DownloadListener() {
            @Override
            public void onProgress(long bytesDownloaded, long totalBytes, int percent) {
                pb.setProgress(percent);
                long mbDownloaded = bytesDownloaded / (1024 * 1024);
                long mbTotal = totalBytes / (1024 * 1024);
                progressDialog.setMessage("Downloaded: " + mbDownloaded + " MB / " + mbTotal + " MB (" + percent + "%)");
            }

            @Override
            public void onCompleted(java.io.File modelFile) {
                progressDialog.dismiss();
                setActiveModelProvider(target);
                new AlertDialog.Builder(requireContext())
                        .setTitle(target.title + " Installed! 🚀")
                        .setMessage("Model weights downloaded successfully. Active provider updated to " + target.title + " for 100% on-device AI protection!")
                        .setPositiveButton("OK", null)
                        .show();
            }

            @Override
            public void onError(String errorMessage) {
                progressDialog.dismiss();
                updateModelPrefSummary();
                new AlertDialog.Builder(requireContext())
                        .setTitle("Download Failed")
                        .setMessage("Error:\n" + errorMessage + "\n\nKotSafe will continue using its built-in offline security expert.")
                        .setPositiveButton("OK", null)
                        .show();
            }

            @Override
            public void onCancelled() {
                progressDialog.dismiss();
                updateModelPrefSummary();
                Toast.makeText(requireContext(), "Download cancelled.", Toast.LENGTH_SHORT).show();
            }
        });
    }

    private void setupTestConnection() {
        if (mTestConnPref == null) return;

        mTestConnPref.setOnPreferenceClickListener(pref -> {
            if (!mConfig.isAiEnabled()) {
                Toast.makeText(requireContext(), "Please enable AI Protection first", Toast.LENGTH_SHORT).show();
                return true;
            }

            android.widget.ProgressBar progressBar = new android.widget.ProgressBar(requireContext());
            progressBar.setPadding(48, 48, 48, 48);
            AlertDialog dialog = new AlertDialog.Builder(requireContext())
                    .setTitle("Testing AI Connection")
                    .setMessage("Pinging " + mConfig.getProvider().displayName + " (" + mConfig.getModel() + ")...")
                    .setView(progressBar)
                    .setCancelable(false)
                    .show();

            AiClientEngine.getInstance(requireContext()).testConnection(new AiClientEngine.Callback() {
                @Override
                public void onSuccess(String responseText) {
                    dialog.dismiss();
                    new AlertDialog.Builder(requireContext())
                            .setTitle("AI Connection Successful! ✅")
                            .setMessage("Provider: " + mConfig.getProvider().displayName
                                    + "\nModel: " + mConfig.getModel()
                                    + "\n\nResponse:\n" + responseText)
                            .setPositiveButton("OK", null)
                            .show();
                }

                @Override
                public void onError(String errorMessage) {
                    dialog.dismiss();
                    new AlertDialog.Builder(requireContext())
                            .setTitle("AI Connection Failed ❌")
                            .setMessage("Error:\n" + errorMessage)
                            .setPositiveButton("OK", null)
                            .show();
                }
            });
            return true;
        });
    }

    private void setupAssistantLaunch() {
        if (mOpenAssistantPref == null) return;

        mOpenAssistantPref.setOnPreferenceClickListener(pref -> {
            if (!mConfig.isAiEnabled()) {
                Toast.makeText(requireContext(), "Enable AI Protection before launching Assistant", Toast.LENGTH_SHORT).show();
                return true;
            }
            startActivity(new Intent(requireContext(), AiAssistantActivity.class));
            return true;
        });
    }
}
