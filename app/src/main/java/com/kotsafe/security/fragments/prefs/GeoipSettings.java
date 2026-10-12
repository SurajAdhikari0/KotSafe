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

package com.kotsafe.security.fragments.prefs;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.preference.Preference;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.Geolocation;
import com.kotsafe.security.Log;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.Geomodel;

import java.net.InetAddress;
import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class GeoipSettings extends SettingsSubFragment {
    private static final String TAG = "GeoipSettings";
    private Preference mCountryStatus;
    private Preference mAsnStatus;
    private Preference mDelete;
    private AlertDialog mAlertDialog;

    private ActivityResultLauncher<String> mImportCountryLauncher;
    private ActivityResultLauncher<String> mImportAsnLauncher;

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mImportCountryLauncher = registerForActivityResult(
                new ActivityResultContracts.GetContent(),
                uri -> handleImportResult(uri, false)
        );

        mImportAsnLauncher = registerForActivityResult(
                new ActivityResultContracts.GetContent(),
                uri -> handleImportResult(uri, true)
        );
    }

    @Override
    public void onCreatePreferences(@Nullable Bundle savedInstanceState, @Nullable String rootKey) {
        setPreferencesFromResource(R.xml.geoip_preferences, rootKey);
        Context context = requireContext();

        mCountryStatus = requirePreference("country_status");
        mAsnStatus = requirePreference("asn_status");
        mDelete = requirePreference("delete");

        refreshStatus(context);

        mDelete.setOnPreferenceClickListener(preference -> {
            new AlertDialog.Builder(context)
                    .setTitle(R.string.delete)
                    .setMessage(R.string.geo_db_delete)
                    .setPositiveButton(R.string.delete, (dialog, which) -> {
                        Geolocation.deleteDb(context);
                        refreshStatus(context);
                        Toast.makeText(context, "Databases deleted", Toast.LENGTH_SHORT).show();
                    })
                    .setNegativeButton(android.R.string.cancel, null)
                    .show();
            return true;
        });

        requirePreference("download").setOnPreferenceClickListener(preference -> {
            downloadDatabases();
            return true;
        });

        requirePreference("import_country_db").setOnPreferenceClickListener(preference -> {
            mImportCountryLauncher.launch("*/*");
            return true;
        });

        requirePreference("import_asn_db").setOnPreferenceClickListener(preference -> {
            mImportAsnLauncher.launch("*/*");
            return true;
        });

        requirePreference("custom_mirror").setOnPreferenceClickListener(preference -> {
            showCustomMirrorDialog();
            return true;
        });

        requirePreference("test_ip_lookup").setOnPreferenceClickListener(preference -> {
            showTestIpDialog();
            return true;
        });
    }

    @Override
    public void onDestroyView() {
        if(mAlertDialog != null)
            mAlertDialog.dismiss();

        super.onDestroyView();
    }

    private void handleImportResult(@Nullable Uri uri, boolean isAsn) {
        if (uri == null) return;
        Context context = requireContext();
        boolean success = Geolocation.importDbFromUri(context, uri, isAsn);
        if (success) {
            Toast.makeText(context, R.string.geo_import_success, Toast.LENGTH_SHORT).show();
        } else {
            Toast.makeText(context, R.string.geo_import_failed, Toast.LENGTH_LONG).show();
        }
        refreshStatus(context);
    }

    private void refreshStatus(Context context) {
        Date countryDate = Geolocation.getCountryDbDate(context);
        if(countryDate != null) {
            String dateStr = Utils.formatEpochFull(context, countryDate.getTime() / 1000);
            String sizeStr = Utils.formatBytes(Geolocation.getCountryDbSize(context));
            mCountryStatus.setSummary(String.format(context.getString(R.string.geo_db_active), dateStr, sizeStr));
            mCountryStatus.setEnabled(true);
        } else {
            mCountryStatus.setSummary(R.string.geo_db_not_installed);
            mCountryStatus.setEnabled(false);
        }

        Date asnDate = Geolocation.getAsnDbDate(context);
        if(asnDate != null) {
            String dateStr = Utils.formatEpochFull(context, asnDate.getTime() / 1000);
            String sizeStr = Utils.formatBytes(Geolocation.getAsnDbSize(context));
            mAsnStatus.setSummary(String.format(context.getString(R.string.geo_db_active), dateStr, sizeStr));
            mAsnStatus.setEnabled(true);
        } else {
            mAsnStatus.setSummary(R.string.geo_db_not_installed);
            mAsnStatus.setEnabled(false);
        }

        mDelete.setVisible(countryDate != null || asnDate != null);
    }

    private void downloadDatabases() {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Handler handler = new Handler(Looper.getMainLooper());

        AlertDialog.Builder builder = new AlertDialog.Builder(requireContext());
        builder.setTitle(R.string.downloading);
        builder.setMessage(R.string.download_in_progress);

        mAlertDialog = builder.create();
        mAlertDialog.setCanceledOnTouchOutside(false);
        mAlertDialog.show();

        mAlertDialog.setOnCancelListener(dialogInterface -> {
            Log.i(TAG, "Abort download");
            executor.shutdownNow();
        });
        mAlertDialog.setOnDismissListener(dialog -> mAlertDialog = null);

        final Context context = requireContext();
        executor.execute(() -> {
            boolean result = Geolocation.downloadDb(context);

            handler.post(() -> {
                if(result) {
                    Utils.showToastLong(context, R.string.download_success);
                } else {
                    Utils.showToastLong(context, R.string.download_failed);
                }

                if(mAlertDialog != null)
                    mAlertDialog.dismiss();
                refreshStatus(context);
            });
        });
    }

    private void showCustomMirrorDialog() {
        Context context = requireContext();
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);

        AlertDialog.Builder builder = new AlertDialog.Builder(context);
        builder.setTitle(R.string.custom_mirror_title);

        LinearLayout layout = new LinearLayout(context);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(48, 24, 48, 24);

        TextView tvCountry = new TextView(context);
        tvCountry.setText("Custom Country MMDB URL (.gz or .mmdb):");
        tvCountry.setTextSize(13);
        layout.addView(tvCountry);

        final EditText etCountry = new EditText(context);
        etCountry.setInputType(InputType.TYPE_TEXT_VARIATION_URI);
        etCountry.setText(prefs.getString(Geolocation.PREF_CUSTOM_COUNTRY_URL, ""));
        etCountry.setHint("https://example.com/country.mmdb.gz");
        layout.addView(etCountry);

        TextView tvAsn = new TextView(context);
        tvAsn.setText("Custom ASN MMDB URL (.gz or .mmdb):");
        tvAsn.setTextSize(13);
        tvAsn.setPadding(0, 16, 0, 0);
        layout.addView(tvAsn);

        final EditText etAsn = new EditText(context);
        etAsn.setInputType(InputType.TYPE_TEXT_VARIATION_URI);
        etAsn.setText(prefs.getString(Geolocation.PREF_CUSTOM_ASN_URL, ""));
        etAsn.setHint("https://example.com/asn.mmdb.gz");
        layout.addView(etAsn);

        builder.setView(layout);

        builder.setPositiveButton(android.R.string.ok, (dialog, which) -> {
            prefs.edit()
                    .putString(Geolocation.PREF_CUSTOM_COUNTRY_URL, etCountry.getText().toString().trim())
                    .putString(Geolocation.PREF_CUSTOM_ASN_URL, etAsn.getText().toString().trim())
                    .apply();
            Toast.makeText(context, "Mirror settings saved", Toast.LENGTH_SHORT).show();
        });

        builder.setNeutralButton("Reset Default", (dialog, which) -> {
            prefs.edit()
                    .remove(Geolocation.PREF_CUSTOM_COUNTRY_URL)
                    .remove(Geolocation.PREF_CUSTOM_ASN_URL)
                    .apply();
            Toast.makeText(context, "Reset to standard mirrors", Toast.LENGTH_SHORT).show();
        });

        builder.setNegativeButton(android.R.string.cancel, null);
        builder.show();
    }

    private void showTestIpDialog() {
        Context context = requireContext();
        Geolocation geo = new Geolocation(context);

        AlertDialog.Builder builder = new AlertDialog.Builder(context);
        builder.setTitle(R.string.test_ip_lookup_title);

        LinearLayout root = new LinearLayout(context);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(48, 24, 48, 24);

        final EditText etIp = new EditText(context);
        etIp.setHint("Enter IP (e.g. 1.1.1.1 or 8.8.8.8)");
        etIp.setText("1.1.1.1");
        root.addView(etIp);

        // Preset quick buttons
        LinearLayout presets = new LinearLayout(context);
        presets.setOrientation(LinearLayout.HORIZONTAL);
        presets.setPadding(0, 8, 0, 16);

        String[] sampleIps = new String[]{"1.1.1.1", "8.8.8.8", "9.9.9.9"};
        for (String ip : sampleIps) {
            Button btn = new Button(context, null, android.R.attr.buttonStyleSmall);
            btn.setText(ip);
            btn.setOnClickListener(v -> etIp.setText(ip));
            presets.addView(btn);
        }
        root.addView(presets);

        final TextView tvResult = new TextView(context);
        tvResult.setTextSize(14);
        tvResult.setPadding(16, 16, 16, 16);
        tvResult.setBackgroundColor(0x1A00E676);
        tvResult.setTextColor(0xFFFFFFFF);
        root.addView(tvResult);

        Runnable performResolve = () -> {
            String ipStr = etIp.getText().toString().trim();
            if (ipStr.isEmpty()) {
                tvResult.setText("Please enter a valid IP address");
                return;
            }
            try {
                InetAddress addr = InetAddress.getByName(ipStr);
                Geomodel.GeoInfo info = geo.lookup(addr);

                StringBuilder sb = new StringBuilder();
                sb.append("🌐 IP: ").append(ipStr).append("\n\n");
                if (info.hasCountry()) {
                    sb.append("📍 Country: ").append(info.flagEmoji).append(" ")
                            .append(info.countryName).append(" (").append(info.countryCode).append(")\n");
                } else {
                    sb.append("📍 Country: Unknown (Country DB missing or IP unmapped)\n");
                }

                if (info.hasAsn()) {
                    sb.append("🏢 ASN: AS").append(info.asnNumber);
                    if (!info.asnName.isEmpty()) {
                        sb.append(" — ").append(info.asnName);
                    }
                    sb.append("\n");
                } else {
                    sb.append("🏢 ASN: Unknown (ASN DB missing or unmapped)\n");
                }

                tvResult.setText(sb.toString());
            } catch (Exception e) {
                tvResult.setText("Invalid IP address: " + e.getMessage());
            }
        };

        // Perform initial resolve
        performResolve.run();

        builder.setView(root);
        builder.setPositiveButton("Resolve", (dialog, which) -> {});
        builder.setNegativeButton("Close", null);

        AlertDialog dialog = builder.create();
        dialog.show();

        // Prevent auto-dismiss on "Resolve" click so user can test multiple IPs
        Button positiveBtn = dialog.getButton(AlertDialog.BUTTON_POSITIVE);
        if (positiveBtn != null) {
            positiveBtn.setOnClickListener(v -> performResolve.run());
        }
    }

    private @NonNull
    <T extends Preference> T requirePreference(String key) {
        T pref = findPreference(key);
        if(pref == null)
            throw new IllegalStateException();
        return pref;
    }
}
