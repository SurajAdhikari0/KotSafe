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

package com.kotsafe.security.fragments;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.text.format.Formatter;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.kotsafe.security.Log;
import com.kotsafe.security.MitmAddon;
import com.kotsafe.security.R;
import com.kotsafe.security.ReversedLinesFileReader;
import com.kotsafe.security.Utils;
import com.kotsafe.security.activities.MitmSetupWizard;
import com.kotsafe.security.activities.prefs.SettingsActivity;
import com.kotsafe.security.adapters.AppLogsAdapter;
import com.kotsafe.security.model.AppLogEntry;
import com.kotsafe.security.views.LogEntryDetailsDialog;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.chip.ChipGroup;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class LogviewFragment extends Fragment {
    private static final String TAG = "LogviewFragment";
    public static final int MAX_LINES = 1000;

    private String mLogPath;
    private String mLogText = "";

    // Views
    private ScrollView mScrollView;
    private TextView mLogView;
    private RecyclerView mRecyclerView;
    private View mLayoutEmpty;
    private View mLayoutFilters;
    private TextView mTvLogCount;

    // Status Banner views
    private ImageView mIvStatusIcon;
    private TextView mTvStatusTitle;
    private TextView mTvStatusDesc;
    private MaterialButton mBtnStatusAction;

    // Search and filter
    private EditText mSearchInput;
    private ImageView mBtnClearSearch;
    private ChipGroup mLevelChipGroup;
    private ChipGroup mModeChipGroup;

    // Adapter & Data
    private AppLogsAdapter mAdapter;
    private final List<AppLogEntry> mAllEntries = new ArrayList<>();
    private final List<AppLogEntry> mFilteredEntries = new ArrayList<>();

    private boolean mIsParsedMode = true;
    private AppLogEntry.Level mSelectedLevel = null; // null = all
    private String mSearchQuery = "";

    private final ExecutorService mExecutor = Executors.newSingleThreadExecutor();
    private final Handler mMainHandler = new Handler(Looper.getMainLooper());

    public static LogviewFragment newInstance(String path) {
        LogviewFragment fragment = new LogviewFragment();
        Bundle args = new Bundle();
        args.putSerializable("path", path);
        fragment.setArguments(args);
        return fragment;
    }

    @Override
    public View onCreateView(LayoutInflater inflater,
                             ViewGroup container, Bundle savedInstanceState) {
        return inflater.inflate(R.layout.logview_fragment, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        Bundle args = getArguments();
        assert args != null;
        mLogPath = args.getString("path");
        assert(mLogPath != null);

        mScrollView = view.findViewById(R.id.scrollView);
        mLogView = view.findViewById(R.id.log);
        mRecyclerView = view.findViewById(R.id.recycler_log_entries);
        mLayoutEmpty = view.findViewById(R.id.layout_empty_state);
        mLayoutFilters = view.findViewById(R.id.layout_filters_container);
        mTvLogCount = view.findViewById(R.id.tv_log_count);

        mIvStatusIcon = view.findViewById(R.id.iv_status_icon);
        mTvStatusTitle = view.findViewById(R.id.tv_status_title);
        mTvStatusDesc = view.findViewById(R.id.tv_status_desc);
        mBtnStatusAction = view.findViewById(R.id.btn_status_action);

        mSearchInput = view.findViewById(R.id.search_log_input);
        mBtnClearSearch = view.findViewById(R.id.btn_clear_search_input);
        mLevelChipGroup = view.findViewById(R.id.level_filter_chip_group);
        mModeChipGroup = view.findViewById(R.id.mode_chip_group);

        // RecyclerView setup
        mAdapter = new AppLogsAdapter(requireContext());
        mAdapter.setOnLogClickListener(entry -> {
            if (!isAdded() || isStateSaved()) return;
            LogEntryDetailsDialog.newInstance(entry).show(getParentFragmentManager(), LogEntryDetailsDialog.TAG);
        });
        mRecyclerView.setLayoutManager(new LinearLayoutManager(requireContext()));
        mRecyclerView.setAdapter(mAdapter);

        // Window Insets & TV compatibility
        ViewCompat.setOnApplyWindowInsetsListener(mScrollView, (v, windowInsets) -> {
            Insets insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars() |
                    WindowInsetsCompat.Type.displayCutout());
            v.setPadding(0, 0, 0, insets.bottom);
            return WindowInsetsCompat.CONSUMED;
        });
        mScrollView.setClipToPadding(false);

        if (Utils.isTv(view.getContext())) {
            mScrollView.setDescendantFocusability(ViewGroup.FOCUS_BLOCK_DESCENDANTS);
        }

        setupStatusBanner();
        setupModeSelector();
        setupLevelFilter();
        setupSearch();
        setupActionButtons(view);

        reloadLog();
    }

    private void setupStatusBanner() {
        Context ctx = getContext();
        if (ctx == null) return;

        if (mLogPath.contains(Log.ROOT_LOGGER_PATH)) {
            // Root Capture Log
            mIvStatusIcon.setImageResource(R.drawable.ic_pref_root_capture);
            boolean rootAvailable = Utils.isRootAvailable();

            if (rootAvailable) {
                mTvStatusTitle.setText("KotEngine (Root Available)");
                mTvStatusDesc.setText("Root access detected. Capture runs through the KotEngine VpnService engine.");
                mBtnStatusAction.setText("Settings");
                mBtnStatusAction.setVisibility(View.VISIBLE);
                mBtnStatusAction.setOnClickListener(v -> {
                    startActivity(new Intent(ctx, SettingsActivity.class));
                });
            } else {
                mTvStatusTitle.setText("Standard VPN Service (Non-Root)");
                mTvStatusDesc.setText("Traffic is routed via Android VpnService and the KotEngine native engine.");
                mBtnStatusAction.setVisibility(View.GONE);
            }
        } else if (mLogPath.contains(Log.MITM_LOGGER_PATH)) {
            // MITM Addon Log
            mIvStatusIcon.setImageResource(R.drawable.ic_pref_tls);
            boolean installed = MitmAddon.isInstalled(ctx);

            if (installed) {
                String ver = MitmAddon.getInstalledVersionName(ctx);
                mTvStatusTitle.setText("MITM Add-on Proxy (v" + ver + ")");
                mTvStatusDesc.setText("Companion TLS decryptor is installed and configured.");
                mBtnStatusAction.setText("Wizard");
                mBtnStatusAction.setVisibility(View.VISIBLE);
                mBtnStatusAction.setOnClickListener(v -> {
                    startActivity(new Intent(ctx, MitmSetupWizard.class));
                });
            } else {
                mTvStatusTitle.setText("MITM Add-on Not Detected");
                mTvStatusDesc.setText("Install the companion add-on to intercept and inspect TLS traffic.");
                mBtnStatusAction.setText("Install Addon");
                mBtnStatusAction.setVisibility(View.VISIBLE);
                mBtnStatusAction.setOnClickListener(v -> {
                    startActivity(new Intent(ctx, MitmSetupWizard.class));
                });
            }
        } else {
            // App Log (kotsafe.log)
            mIvStatusIcon.setImageResource(R.drawable.ic_pref_logs);
            mTvStatusTitle.setText("KotSafe System Log");
            File f = new File(mLogPath);
            String sizeStr = f.exists() ? Formatter.formatFileSize(ctx, f.length()) : "0 B";
            mTvStatusDesc.setText("Active engine telemetry • " + sizeStr);
            mBtnStatusAction.setVisibility(View.GONE);
        }
    }

    private void setupModeSelector() {
        if (mModeChipGroup == null) return;
        mModeChipGroup.setOnCheckedStateChangeListener((group, checkedIds) -> {
            int checkedId = checkedIds.isEmpty() ? View.NO_ID : checkedIds.get(0);
            if (checkedId == R.id.chip_mode_raw) {
                mIsParsedMode = false;
                mScrollView.setVisibility(View.VISIBLE);
                mRecyclerView.setVisibility(View.GONE);
                mLayoutFilters.setVisibility(View.GONE);
                updateEmptyStateVisibility(mLogText.trim().isEmpty());
            } else {
                mIsParsedMode = true;
                mScrollView.setVisibility(View.GONE);
                mRecyclerView.setVisibility(View.VISIBLE);
                mLayoutFilters.setVisibility(View.VISIBLE);
                filterAndDisplay();
            }
        });
    }

    private void setupLevelFilter() {
        if (mLevelChipGroup == null) return;
        mLevelChipGroup.setOnCheckedStateChangeListener((group, checkedIds) -> {
            int checkedId = checkedIds.isEmpty() ? View.NO_ID : checkedIds.get(0);
            if (checkedId == R.id.chip_lvl_error) {
                mSelectedLevel = AppLogEntry.Level.ERROR;
            } else if (checkedId == R.id.chip_lvl_warn) {
                mSelectedLevel = AppLogEntry.Level.WARN;
            } else if (checkedId == R.id.chip_lvl_info) {
                mSelectedLevel = AppLogEntry.Level.INFO;
            } else if (checkedId == R.id.chip_lvl_debug) {
                mSelectedLevel = AppLogEntry.Level.DEBUG;
            } else {
                mSelectedLevel = null; // All
            }
            filterAndDisplay();
        });
    }

    private void setupSearch() {
        if (mSearchInput == null) return;
        mSearchInput.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                mSearchQuery = s.toString().trim().toLowerCase();
                mBtnClearSearch.setVisibility(mSearchQuery.isEmpty() ? View.GONE : View.VISIBLE);
                filterAndDisplay();
            }

            @Override
            public void afterTextChanged(Editable s) {}
        });

        if (mBtnClearSearch != null) {
            mBtnClearSearch.setOnClickListener(v -> mSearchInput.setText(""));
        }
    }

    private void setupActionButtons(View root) {
        View btnRefresh = root.findViewById(R.id.btn_action_refresh);
        if (btnRefresh != null) {
            btnRefresh.setOnClickListener(v -> reloadLog());
        }

        View btnClear = root.findViewById(R.id.btn_action_clear);
        if (btnClear != null) {
            btnClear.setOnClickListener(v -> confirmClearLog());
        }

        View btnCopyAll = root.findViewById(R.id.btn_action_copy_all);
        if (btnCopyAll != null) {
            btnCopyAll.setOnClickListener(v -> copyAllLogs());
        }
    }

    private void confirmClearLog() {
        if (!isAdded()) return;
        new AlertDialog.Builder(requireContext())
                .setTitle("Clear Log File?")
                .setMessage("Are you sure you want to clear this log file? All recorded entries will be erased.")
                .setPositiveButton("Clear", (dialog, which) -> {
                    try {
                        new FileOutputStream(mLogPath).close();
                        Toast.makeText(requireContext(), "Log file cleared", Toast.LENGTH_SHORT).show();
                        reloadLog();
                    } catch (IOException e) {
                        Toast.makeText(requireContext(), "Error clearing file: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                    }
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void copyAllLogs() {
        if (!isAdded()) return;
        ClipboardManager cm = (ClipboardManager) requireContext().getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm != null) {
            String textToCopy;
            if (mIsParsedMode) {
                StringBuilder sb = new StringBuilder();
                for (AppLogEntry entry : mFilteredEntries) {
                    sb.append(entry.rawLine).append("\n");
                }
                textToCopy = sb.toString();
            } else {
                textToCopy = mLogText;
            }

            if (textToCopy.isEmpty()) {
                Toast.makeText(requireContext(), "No logs to copy", Toast.LENGTH_SHORT).show();
                return;
            }

            cm.setPrimaryClip(ClipData.newPlainText("Logs", textToCopy));
            Toast.makeText(requireContext(), "Copied all logs to clipboard", Toast.LENGTH_SHORT).show();
        }
    }

    public void reloadLog() {
        final Context appContext = getContext() != null ? getContext().getApplicationContext() : null;

        mExecutor.execute(() -> {
            File logFile = new File(mLogPath);
            StringBuilder rawBuilder = new StringBuilder();
            List<AppLogEntry> parsedList = new ArrayList<>();

            if (logFile.exists() && logFile.length() > 0) {
                try (ReversedLinesFileReader reader = new ReversedLinesFileReader(logFile, StandardCharsets.US_ASCII)) {
                    String line;
                    int count = 0;
                    List<String> reversedLines = new ArrayList<>();

                    while ((line = reader.readLine()) != null && count < MAX_LINES) {
                        reversedLines.add(line);
                        count++;
                    }

                    // Reconstruct chronological order from reversed read
                    for (int i = reversedLines.size() - 1; i >= 0; i--) {
                        String l = reversedLines.get(i);
                        rawBuilder.append(l).append("\n");
                        parsedList.add(AppLogEntry.parse(l));
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

            final String fullRawText = rawBuilder.toString();
            final long fileSize = logFile.exists() ? logFile.length() : 0;

            mMainHandler.post(() -> {
                if (!isAdded()) return;

                mLogText = fullRawText;
                mLogView.setText(!mLogText.isEmpty() ? mLogText : getString(R.string.no_data));

                mAllEntries.clear();
                mAllEntries.addAll(parsedList);

                // Update status banner file size
                if (appContext != null && mTvStatusDesc != null && mLogPath.contains(Log.DEFAULT_LOGGER_PATH)) {
                    mTvStatusDesc.setText("Active engine telemetry • " + Formatter.formatFileSize(appContext, fileSize));
                }

                if (mIsParsedMode) {
                    filterAndDisplay();
                } else {
                    updateEmptyStateVisibility(mLogText.trim().isEmpty());
                }
            });
        });
    }

    private void filterAndDisplay() {
        mFilteredEntries.clear();

        for (AppLogEntry entry : mAllEntries) {
            // Level filter
            if (mSelectedLevel != null) {
                if (mSelectedLevel == AppLogEntry.Level.ERROR) {
                    if (entry.level != AppLogEntry.Level.ERROR && entry.level != AppLogEntry.Level.FATAL) {
                        continue;
                    }
                } else if (entry.level != mSelectedLevel) {
                    continue;
                }
            }

            // Search query filter
            if (!mSearchQuery.isEmpty()) {
                boolean matchTag = entry.tag != null && entry.tag.toLowerCase().contains(mSearchQuery);
                boolean matchMsg = entry.message != null && entry.message.toLowerCase().contains(mSearchQuery);
                boolean matchRaw = entry.rawLine != null && entry.rawLine.toLowerCase().contains(mSearchQuery);
                if (!matchTag && !matchMsg && !matchRaw) {
                    continue;
                }
            }

            mFilteredEntries.add(entry);
        }

        mAdapter.setEntries(mFilteredEntries);
        mTvLogCount.setText(mFilteredEntries.size() + " entries");
        updateEmptyStateVisibility(mFilteredEntries.isEmpty());
    }

    private void updateEmptyStateVisibility(boolean isEmpty) {
        if (mLayoutEmpty != null) {
            mLayoutEmpty.setVisibility(isEmpty ? View.VISIBLE : View.GONE);
        }
    }

    public String getLog() {
        return mLogText;
    }
}
