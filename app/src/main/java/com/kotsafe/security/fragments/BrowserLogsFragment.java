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
 *
 * Copyright 2026 - KotSafe
 */

package com.kotsafe.security.fragments;

import android.content.Context;
import android.content.Intent;
import android.provider.Settings;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.SearchView;
import androidx.appcompat.widget.SwitchCompat;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.kotsafe.security.CaptureService;
import com.kotsafe.security.ConnectionsRegister;
import com.kotsafe.security.R;
import com.kotsafe.security.adapters.BrowserLogsAdapter;
import com.kotsafe.security.dialogs.BrowserUrlTrackingTermsDialog;
import com.kotsafe.security.interfaces.ConnectionsListener;
import com.kotsafe.security.model.BrowserActivityManager;
import com.kotsafe.security.model.BrowserActivityManager.BrowserLogEntry;
import com.kotsafe.security.model.Prefs;
import com.kotsafe.security.model.ConnectionDescriptor;
import com.kotsafe.security.views.BrowserLogDetailsDialog;

import java.util.ArrayList;
import java.util.List;

/**
 * Fragment displaying web browser activity logs.
 * Shows encrypted TLS streams when decryption/decoder is disabled,
 * and cleartext HTTP/DoH/Protobuf when decryption/decoder is enabled.
 */
public class BrowserLogsFragment extends Fragment implements ConnectionsListener {
    public static final String TAG = "BrowserLogsFragment";

    private BrowserActivityManager mBrowserManager;
    private BrowserLogsAdapter mAdapter;
    private RecyclerView mRecyclerView;
    private View mEmptyState;

    private TextView mTvDecryptorPill;
    private TextView mTvDecryptorDesc;
    private SwitchCompat mSwitchMode;
    private SearchView mSearchView;

    private boolean mForceDecrypted = false;
    private String mCurrentFilter = "";
    private final Handler mHandler = new Handler(Looper.getMainLooper());
    private final java.util.concurrent.ExecutorService mBgExecutor = java.util.concurrent.Executors.newSingleThreadExecutor();
    private boolean mRegisteredListener = false;
    private boolean mUpdateScheduled = false;

    private View mLayoutCaTrust;
    private Button mBtnTrustCa;
    private View mLayoutAccessibility;
    private TextView mTvAccessibilityMsg;
    private Button mBtnEnableAccessibility;

    public static BrowserLogsFragment newInstance() {
        return new BrowserLogsFragment();
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_browser_logs, container, false);
    }

    private String mActiveChipFilter = "ALL";

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        Context ctx = requireContext();
        mBrowserManager = BrowserActivityManager.getInstance(ctx);
        mAdapter = new BrowserLogsAdapter(ctx);
        mAdapter.setOnLogItemClickListener(entry -> {
            if (!isAdded() || isStateSaved()) return;
            BrowserLogDetailsDialog.newInstance(entry)
                    .show(getParentFragmentManager(), BrowserLogDetailsDialog.TAG);
        });

        mRecyclerView = view.findViewById(R.id.recycler_view);
        mEmptyState = view.findViewById(R.id.layout_empty_state);

        mTvDecryptorPill = view.findViewById(R.id.tv_decryptor_status_pill);
        mTvDecryptorDesc = view.findViewById(R.id.tv_decryptor_description);
        mSwitchMode = view.findViewById(R.id.switch_force_decrypted);
        mSearchView = view.findViewById(R.id.search_view);
        mLayoutCaTrust = view.findViewById(R.id.layout_ca_trust_banner);
        mBtnTrustCa = view.findViewById(R.id.btn_trust_ca);
        if (mBtnTrustCa != null) {
            mBtnTrustCa.setOnClickListener(v -> installCaCertificate());
        }
        mLayoutAccessibility = view.findViewById(R.id.layout_accessibility_banner);
        mTvAccessibilityMsg = view.findViewById(R.id.tv_accessibility_msg);
        mBtnEnableAccessibility = view.findViewById(R.id.btn_enable_accessibility);
        if (mBtnEnableAccessibility != null) {
            mBtnEnableAccessibility.setOnClickListener(v -> showTermsAndEnable());
        }
        if (mLayoutAccessibility != null) {
            mLayoutAccessibility.setOnClickListener(v -> showTermsAndEnable());
        }

        View btnPrivacyTerms = view.findViewById(R.id.btn_browser_privacy_terms);
        if (btnPrivacyTerms != null) {
            btnPrivacyTerms.setOnClickListener(v -> showTermsDialogOnly());
        }

        com.google.android.material.chip.ChipGroup chipGroup = view.findViewById(R.id.browser_filter_chip_group);
        if (chipGroup != null) {
            chipGroup.setOnCheckedStateChangeListener((group, checkedIds) -> {
                if (checkedIds.isEmpty()) return;
                int id = checkedIds.get(0);
                if (id == R.id.chip_browser_decrypted) {
                    mActiveChipFilter = "DECRYPTED";
                } else if (id == R.id.chip_browser_encrypted) {
                    mActiveChipFilter = "ENCRYPTED";
                } else if (id == R.id.chip_browser_trackers) {
                    mActiveChipFilter = "TRACKERS";
                } else if (id == R.id.chip_browser_cleartext) {
                    mActiveChipFilter = "CLEARTEXT";
                } else {
                    mActiveChipFilter = "ALL";
                }
                loadLogs();
            });
        }

        mRecyclerView.setLayoutManager(new LinearLayoutManager(requireContext()));
        mRecyclerView.setAdapter(mAdapter);

        // Initial mode state
        boolean isDecryptionActive = mBrowserManager.isTlsDecryptionActive();
        mForceDecrypted = !isDecryptionActive;
        mSwitchMode.setChecked(true);

        mSwitchMode.setOnCheckedChangeListener((buttonView, isChecked) -> {
            mForceDecrypted = isChecked;
            loadLogs();
        });

        mSearchView.setOnQueryTextListener(new SearchView.OnQueryTextListener() {
            @Override
            public boolean onQueryTextSubmit(String query) {
                mCurrentFilter = query != null ? query.trim() : "";
                loadLogs();
                return true;
            }

            @Override
            public boolean onQueryTextChange(String newText) {
                mCurrentFilter = newText != null ? newText.trim() : "";
                scheduleReload();
                return true;
            }
        });

        loadLogs();
    }

    @Override
    public void onResume() {
        super.onResume();
        registerListener();
        loadLogs();
    }

    @Override
    public void onPause() {
        super.onPause();
        unregisterListener();
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        mHandler.removeCallbacksAndMessages(null);
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        mBgExecutor.shutdownNow();
    }

    private void registerListener() {
        ConnectionsRegister reg = CaptureService.getConnsRegister();
        if (reg != null && !mRegisteredListener) {
            reg.addListener(this);
            mRegisteredListener = true;
        }
    }

    private void unregisterListener() {
        ConnectionsRegister reg = CaptureService.getConnsRegister();
        if (reg != null && mRegisteredListener) {
            reg.removeListener(this);
            mRegisteredListener = false;
        }
    }

    private void scheduleReload() {
        if (!mUpdateScheduled && isAdded()) {
            mUpdateScheduled = true;
            mHandler.postDelayed(() -> {
                mUpdateScheduled = false;
                loadLogs();
            }, 300);
        }
    }

    private void showTermsAndEnable() {
        if (!isAdded()) return;
        Context ctx = requireContext();
        if (!Prefs.isBrowserUrlTermsAccepted(ctx)) {
            BrowserUrlTrackingTermsDialog.show(ctx, () -> {
                BrowserUrlTrackingTermsDialog.launchAccessibilitySettings(ctx);
            });
        } else {
            BrowserUrlTrackingTermsDialog.launchAccessibilitySettings(ctx);
        }
    }

    private void showTermsDialogOnly() {
        if (!isAdded()) return;
        Context ctx = requireContext();
        BrowserUrlTrackingTermsDialog.show(ctx, () -> {
            BrowserUrlTrackingTermsDialog.launchAccessibilitySettings(ctx);
        });
    }

    private void openAccessibilitySettings() {
        if (!isAdded()) return;
        BrowserUrlTrackingTermsDialog.launchAccessibilitySettings(requireContext());
    }

    private void loadLogs() {
        Context ctx = getContext();
        if (ctx == null || !isAdded()) return;
        final Context appContext = ctx.getApplicationContext();

        boolean isDecryptionActive = mBrowserManager.isTlsDecryptionActive();

        if (isDecryptionActive) {
            mTvDecryptorPill.setText("DECRYPTOR: ACTIVE");
            mTvDecryptorPill.setBackgroundResource(R.drawable.badge_pill_active);
            mTvDecryptorPill.setTextColor(ContextCompat.getColor(appContext, R.color.badgeActiveFg));
            mTvDecryptorDesc.setText("Deep TLS Decryption active: Inspecting cleartext payloads and headers.");
        } else {
            mTvDecryptorPill.setText("KOTSAFE MODE: ACTIVE");
            mTvDecryptorPill.setBackgroundResource(R.drawable.badge_pill_active);
            mTvDecryptorPill.setTextColor(ContextCompat.getColor(appContext, R.color.badgeActiveFg));
            mTvDecryptorDesc.setText("Monitoring live browser activity cleanly without certificates or security warnings.");
        }

        // CA Trust Warning: ONLY shown if user explicitly enabled TLS Decryption in Settings and CA is not installed
        boolean caInstalled = com.kotsafe.security.tls.TlsCaManager.getInstance(appContext).isCaInstalled();
        if (mLayoutCaTrust != null) {
            mLayoutCaTrust.setVisibility((isDecryptionActive && !caInstalled) ? View.VISIBLE : View.GONE);
        }

        // Defender Accessibility Banner: Prompt user or show active status for full URL tracking
        boolean isAccessEnabled = com.kotsafe.security.services.BrowserAccessibilityService.isAccessibilityServiceEnabled(appContext);
        if (mLayoutAccessibility != null) {
            mLayoutAccessibility.setVisibility(View.VISIBLE);
            if (isAccessEnabled) {
                if (mTvAccessibilityMsg != null) {
                    mTvAccessibilityMsg.setText("Full URL Tracking is Active: Deep paths captured via KotSafe Web Protection.");
                }
                if (mBtnEnableAccessibility != null) {
                    mBtnEnableAccessibility.setText("Settings");
                }
            } else {
                if (mTvAccessibilityMsg != null) {
                    mTvAccessibilityMsg.setText("Enable Full URL tracking to capture deep paths (KotSafe mode).");
                }
                if (mBtnEnableAccessibility != null) {
                    mBtnEnableAccessibility.setText("Enable");
                }
            }
        }

        final String chipFilter = mActiveChipFilter;
        mBgExecutor.execute(() -> {
            List<BrowserLogEntry> rawLogs = mBrowserManager.getBrowserLogs(mForceDecrypted, mCurrentFilter);
            List<BrowserLogEntry> filteredLogs = new ArrayList<>();
            for (BrowserLogEntry entry : rawLogs) {
                if ("DECRYPTED".equals(chipFilter)) {
                    if (entry.isDecrypted) filteredLogs.add(entry);
                } else if ("ENCRYPTED".equals(chipFilter)) {
                    if (!entry.isDecrypted) filteredLogs.add(entry);
                } else if ("TRACKERS".equals(chipFilter)) {
                    if (entry.parsedUrl != null && (entry.parsedUrl.hasTrackingParams() ||
                            (entry.parsedUrl.riskAssessment != null && (entry.parsedUrl.riskAssessment.isKnownTracker ||
                             entry.parsedUrl.riskAssessment.riskLevel == com.kotsafe.security.model.parser.AdvancedLogParser.RiskLevel.SUSPICIOUS ||
                             entry.parsedUrl.riskAssessment.riskLevel == com.kotsafe.security.model.parser.AdvancedLogParser.RiskLevel.HIGH_RISK)))) {
                        filteredLogs.add(entry);
                    }
                } else if ("CLEARTEXT".equals(chipFilter)) {
                    if (entry.isCleartextHttp || entry.remotePort == 80 || (entry.url != null && entry.url.startsWith("http://"))) {
                        filteredLogs.add(entry);
                    }
                } else {
                    filteredLogs.add(entry);
                }
            }

            mHandler.post(() -> {
                if (!isAdded()) return;
                mAdapter.setEntries(filteredLogs);

                if (filteredLogs.isEmpty()) {
                    mEmptyState.setVisibility(View.VISIBLE);
                    mRecyclerView.setVisibility(View.GONE);
                } else {
                    mEmptyState.setVisibility(View.GONE);
                    mRecyclerView.setVisibility(View.VISIBLE);
                }
            });
        });
    }

    private void installCaCertificate() {
        Context ctx = requireContext();
        com.kotsafe.security.tls.TlsCaManager caManager = com.kotsafe.security.tls.TlsCaManager.getInstance(ctx);
        String pem = caManager.getCaCertificatePem();

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
            // Android 11+ blocks direct CA installation via KeyChain intent. Save cert to Downloads and guide user.
            boolean saved = false;
            try {
                android.content.ContentValues values = new android.content.ContentValues();
                values.put(android.provider.MediaStore.MediaColumns.DISPLAY_NAME, "KotSafe_CA.crt");
                values.put(android.provider.MediaStore.MediaColumns.MIME_TYPE, "application/x-x509-ca-cert");
                values.put(android.provider.MediaStore.MediaColumns.RELATIVE_PATH, android.os.Environment.DIRECTORY_DOWNLOADS);
                android.net.Uri uri = ctx.getContentResolver().insert(android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI, values);
                if (uri != null) {
                    try (java.io.OutputStream os = ctx.getContentResolver().openOutputStream(uri)) {
                        if (os != null) {
                            os.write(pem.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                            saved = true;
                        }
                    }
                }
            } catch (Exception ignored) {}

            new androidx.appcompat.app.AlertDialog.Builder(ctx)
                    .setTitle("Trust KotSafe Root CA")
                    .setMessage((saved ? "Root CA saved to your Downloads as KotSafe_CA.crt.\n\n" : "")
                            + "To decrypt HTTPS on Android 11+, install the certificate:\n\n"
                            + "1. Tap 'Open Security Settings' below.\n"
                            + "2. Go to 'Encryption & credentials' > 'Install a certificate' > 'CA certificate'.\n"
                            + "3. Tap 'Install anyway' and pick 'KotSafe_CA.crt' from Downloads.")
                    .setPositiveButton("Open Settings", (d, which) -> {
                        try {
                            startActivity(new Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS));
                        } catch (Exception e) {
                            try {
                                startActivity(new Intent(android.provider.Settings.ACTION_SETTINGS));
                            } catch (Exception ignored) {}
                        }
                    })
                    .setNegativeButton("Cancel", null)
                    .show();
        } else {
            try {
                Intent intent = android.security.KeyChain.createInstallIntent();
                intent.putExtra(android.security.KeyChain.EXTRA_NAME, "KotSafe CA");
                intent.putExtra(android.security.KeyChain.EXTRA_CERTIFICATE, pem.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                startActivity(intent);
            } catch (Exception e) {
                try {
                    Intent intent = new Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS);
                    startActivity(intent);
                    android.widget.Toast.makeText(ctx, "Please install the KotSafe CA certificate under Security > Encryption & Credentials", android.widget.Toast.LENGTH_LONG).show();
                } catch (Exception ignored) {}
            }
        }
    }

    @Override
    public void connectionsChanges(int num_connections) {
        scheduleReload();
    }

    @Override
    public void connectionsAdded(int start, ConnectionDescriptor[] conns) {
        scheduleReload();
    }

    @Override
    public void connectionsRemoved(int start, ConnectionDescriptor[] conns) {
        scheduleReload();
    }

    @Override
    public void connectionsUpdated(int[] positions) {
        scheduleReload();
    }
}
