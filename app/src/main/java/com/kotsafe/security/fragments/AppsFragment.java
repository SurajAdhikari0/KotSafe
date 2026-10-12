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

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.ContextMenu;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.core.graphics.Insets;
import androidx.core.view.MenuProvider;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.Lifecycle;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.CaptureService;
import com.kotsafe.security.ConnectionsRegister;
import com.kotsafe.security.Log;
import com.kotsafe.security.KotSafe;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.activities.AppDetailsActivity;
import com.kotsafe.security.adapters.AppsManagerAdapter;
import com.kotsafe.security.interfaces.ConnectionsListener;
import com.kotsafe.security.model.AppDescriptor;
import com.kotsafe.security.model.Blocklist;
import com.kotsafe.security.model.ConnectionDescriptor;
import com.kotsafe.security.model.MatchList;
import com.kotsafe.security.model.Prefs;
import com.kotsafe.security.views.EmptyRecyclerView;
import com.google.android.material.chip.Chip;
import com.google.android.material.chip.ChipGroup;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class AppsFragment extends Fragment implements ConnectionsListener, MenuProvider {
    private static final String TAG = "AppsFragment";

    private EmptyRecyclerView mRecyclerView;
    private AppsManagerAdapter mAdapter;
    private ProgressBar mLoadingProgress;
    private View mEmptyView;
    private TextView mNoAppsText;

    private ChipGroup mChipGroup;
    private Chip mChipUserApps;
    private Chip mChipSystemApps;
    private Chip mChipAllPackages;

    private EditText mEtSearch;
    private ImageView mBtnClearSearch;
    private TextView mTvSummary;
    private TextView mTvCaptureStatus;

    private Handler mHandler;
    private boolean mRefreshScheduled;
    private boolean mListenerSet;

    @Override
    public void onPause() {
        super.onPause();
        unregisterConnsListener();
    }

    @Override
    public void onResume() {
        super.onResume();
        registerConnsListener();
        refreshLiveStats();
    }

    @Override
    public View onCreateView(@NonNull LayoutInflater inflater,
                             ViewGroup container, Bundle savedInstanceState) {
        requireActivity().addMenuProvider(this, getViewLifecycleOwner(), Lifecycle.State.RESUMED);
        return inflater.inflate(R.layout.fragment_apps_manager, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        mRecyclerView = view.findViewById(R.id.recycler_view);
        mRecyclerView.setLayoutManager(new EmptyRecyclerView.MyLinearLayoutManager(getContext()));
        registerForContextMenu(mRecyclerView);

        // Remove the unwanted top inset margin applied by EmptyRecyclerView so the list sits cleanly below the search bar
        ViewCompat.setOnApplyWindowInsetsListener(mRecyclerView, (v, windowInsets) -> {
            Insets imeInsets = windowInsets.getInsets(WindowInsetsCompat.Type.ime());
            Insets navInsets = windowInsets.getInsets(WindowInsetsCompat.Type.navigationBars());
            boolean isImeOpen = imeInsets.bottom > 0;
            int bottomInset = isImeOpen ? imeInsets.bottom : navInsets.bottom;

            ViewGroup.MarginLayoutParams mlp = (ViewGroup.MarginLayoutParams) v.getLayoutParams();
            if (mlp != null) {
                mlp.topMargin = 0;
                mlp.bottomMargin = isImeOpen ? imeInsets.bottom : 0;
                mlp.leftMargin = 0;
                mlp.rightMargin = 0;
                v.setLayoutParams(mlp);
            }

            v.setPadding(0, 0, 0, !isImeOpen ? bottomInset : 0);
            return windowInsets;
        });

        // Immediately zero out any existing top margin
        ViewGroup.MarginLayoutParams initialMlp = (ViewGroup.MarginLayoutParams) mRecyclerView.getLayoutParams();
        if (initialMlp != null) {
            initialMlp.topMargin = 0;
            mRecyclerView.setLayoutParams(initialMlp);
        }

        mLoadingProgress = view.findViewById(R.id.loading_progress);
        mEmptyView = view.findViewById(R.id.empty_view);
        mNoAppsText = view.findViewById(R.id.no_apps);

        mChipGroup = view.findViewById(R.id.chip_group_categories);
        mChipUserApps = view.findViewById(R.id.chip_user_apps);
        mChipSystemApps = view.findViewById(R.id.chip_system_apps);
        mChipAllPackages = view.findViewById(R.id.chip_all_packages);

        mEtSearch = view.findViewById(R.id.et_search);
        mBtnClearSearch = view.findViewById(R.id.btn_clear_search);
        mTvSummary = view.findViewById(R.id.tv_category_summary);
        mTvCaptureStatus = view.findViewById(R.id.tv_capture_status);

        mHandler = new Handler(Looper.getMainLooper());
        mAdapter = new AppsManagerAdapter(requireContext());
        mRecyclerView.setAdapter(mAdapter);
        mRecyclerView.setEmptyView(mEmptyView);

        setupClickListeners();
        setupFiltersAndSearch();

        // Load all packages from device
        loadDeviceAppsAsync();

        // Service observation
        CaptureService.observeStatus(this, serviceStatus -> {
            updateCaptureStatusVisuals();
            if (serviceStatus == CaptureService.ServiceStatus.STARTED) {
                if (mListenerSet) {
                    unregisterConnsListener();
                    registerConnsListener();
                }
            }
            refreshLiveStats();
        });
    }

    private void setupClickListeners() {
        mAdapter.setOnAppClickListener(app -> {
            Intent intent = new Intent(getActivity(), AppDetailsActivity.class);
            intent.putExtra(AppDetailsActivity.APP_UID_EXTRA, app.getUid());
            startActivity(intent);
        });
    }

    private void setupFiltersAndSearch() {
        mChipGroup.setOnCheckedStateChangeListener((group, checkedIds) -> {
            if (checkedIds.isEmpty()) return;
            int checkedId = checkedIds.get(0);

            if (checkedId == R.id.chip_user_apps) {
                mAdapter.setFilterMode(AppsManagerAdapter.FILTER_USER_APPS);
            } else if (checkedId == R.id.chip_system_apps) {
                mAdapter.setFilterMode(AppsManagerAdapter.FILTER_SYSTEM_APPS);
            } else if (checkedId == R.id.chip_all_packages) {
                mAdapter.setFilterMode(AppsManagerAdapter.FILTER_ALL_PACKAGES);
            }
            updateSummaryText();
        });

        mEtSearch.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                String query = (s != null) ? s.toString() : "";
                mAdapter.setSearchQuery(query);
                mBtnClearSearch.setVisibility(query.isEmpty() ? View.GONE : View.VISIBLE);
                updateSummaryText();
            }

            @Override
            public void afterTextChanged(Editable s) {}
        });

        mBtnClearSearch.setOnClickListener(v -> mEtSearch.setText(""));
    }

    private void updateSummaryText() {
        int filter = mAdapter.getFilterMode();
        int count = mAdapter.getItemCount();
        String summary;

        if (filter == AppsManagerAdapter.FILTER_USER_APPS) {
            summary = getString(R.string.tab_user_apps) + ": " + count + " apps";
        } else if (filter == AppsManagerAdapter.FILTER_SYSTEM_APPS) {
            summary = getString(R.string.tab_system_apps) + ": " + count + " apps";
        } else {
            summary = getString(R.string.tab_all_packages) + ": " + count + " packages";
        }

        mTvSummary.setText(summary);
    }

    private void updateCaptureStatusVisuals() {
        boolean active = CaptureService.isServiceActive();
        if (active) {
            mTvCaptureStatus.setText("● Capture Active");
            mTvCaptureStatus.setTextColor(requireContext().getColor(R.color.statusOpen));
        } else {
            mTvCaptureStatus.setText("○ Capture Idle");
            mTvCaptureStatus.setTextColor(requireContext().getColor(R.color.metricTextSecondary));
        }
    }

    private void loadDeviceAppsAsync() {
        mLoadingProgress.setVisibility(View.VISIBLE);

        new Thread(() -> {
            Context ctx = getContext();
            if (ctx == null) return;

            PackageManager pm = ctx.getPackageManager();
            List<PackageInfo> packs = Utils.getInstalledPackages(pm, 0);
            List<AppDescriptor> appList = new ArrayList<>();

            for (PackageInfo p : packs) {
                try {
                    appList.add(new AppDescriptor(pm, p));
                } catch (Exception e) {
                    Log.w(TAG, "Error resolving app: " + p.packageName + ": " + e.getMessage());
                }
            }

            Collections.sort(appList);

            mHandler.post(() -> {
                if (!isAdded()) return;

                mLoadingProgress.setVisibility(View.GONE);
                mAdapter.setApps(appList);

                mChipUserApps.setText(getString(R.string.tab_user_apps) + " (" + mAdapter.getUserAppsCount() + ")");
                mChipSystemApps.setText(getString(R.string.tab_system_apps) + " (" + mAdapter.getSystemAppsCount() + ")");
                mChipAllPackages.setText(getString(R.string.tab_all_packages) + " (" + mAdapter.getAllPackagesCount() + ")");

                updateSummaryText();
                updateCaptureStatusVisuals();
                refreshLiveStats();
            });
        }).start();
    }

    private void refreshLiveStats() {
        ConnectionsRegister reg = CaptureService.getConnsRegister();
        if (reg != null) {
            mAdapter.setAppStats(reg.getAppsStats());
        }
    }

    private void registerConnsListener() {
        if (!mListenerSet) {
            ConnectionsRegister reg = CaptureService.getConnsRegister();
            if (reg != null) {
                reg.addListener(this);
                mListenerSet = true;
            }
        }
    }

    private void unregisterConnsListener() {
        if (mListenerSet) {
            ConnectionsRegister reg = CaptureService.getConnsRegister();
            if (reg != null) {
                reg.removeListener(this);
            }
            mListenerSet = false;
        }
    }

    private void refreshLiveStatsAsync() {
        if (!mRefreshScheduled) {
            mRefreshScheduled = true;
            mHandler.postDelayed(() -> {
                mRefreshScheduled = false;
                refreshLiveStats();
            }, 250);
        }
    }

    @Override
    public void onCreateContextMenu(@NonNull ContextMenu menu, @NonNull View v,
                                    @Nullable ContextMenu.ContextMenuInfo menuInfo) {
        super.onCreateContextMenu(menu, v, menuInfo);

        MenuInflater inflater = requireActivity().getMenuInflater();
        inflater.inflate(R.menu.app_context_menu, menu);

        AppDescriptor app = mAdapter.getSelectedApp();
        if (app == null) return;

        int uid = app.getUid();
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(requireContext());
        boolean isBlocked = KotSafe.getInstance().getBlocklist().matchesApp(uid);

        menu.findItem(R.id.block_app).setVisible(!isBlocked);

        if (Prefs.isFirewallWhitelistMode(prefs)) {
            boolean isWhitelisted = KotSafe.getInstance().getFirewallWhitelist().matchesApp(uid);
            menu.findItem(R.id.add_to_fw_whitelist).setVisible(!isWhitelisted);
            menu.findItem(R.id.remove_from_fw_whitelist).setVisible(isWhitelisted);
        }

        menu.findItem(R.id.unblock_app_permanently).setVisible(isBlocked);
        menu.findItem(R.id.unblock_app_10m).setVisible(isBlocked)
                .setTitle(getString(R.string.unblock_for_n_minutes, 10));
        menu.findItem(R.id.unblock_app_1h).setVisible(isBlocked)
                .setTitle(getString(R.string.unblock_for_n_hours, 1));
        menu.findItem(R.id.unblock_app_8h).setVisible(isBlocked)
                .setTitle(getString(R.string.unblock_for_n_hours, 8));
    }

    @Override
    public boolean onContextItemSelected(@NonNull MenuItem item) {
        int id = item.getItemId();
        Blocklist blocklist = KotSafe.getInstance().getBlocklist();
        MatchList whitelist = KotSafe.getInstance().getFirewallWhitelist();
        boolean whitelistChanged = false;
        AppDescriptor app = mAdapter.getSelectedApp();

        if (app == null)
            return super.onContextItemSelected(item);

        int uid = app.getUid();

        if (id == R.id.block_app)
            blocklist.addApp(uid);
        else if (id == R.id.unblock_app_permanently)
            blocklist.removeApp(uid);
        else if (id == R.id.unblock_app_10m)
            blocklist.unblockAppForMinutes(uid, 10);
        else if (id == R.id.unblock_app_1h)
            blocklist.unblockAppForMinutes(uid, 60);
        else if (id == R.id.unblock_app_8h)
            blocklist.unblockAppForMinutes(uid, 480);
        else if (id == R.id.add_to_fw_whitelist) {
            whitelist.addApp(uid);
            whitelistChanged = true;
        } else if (id == R.id.remove_from_fw_whitelist) {
            whitelist.removeApp(uid);
            whitelistChanged = true;
        } else
            return super.onContextItemSelected(item);

        if (whitelistChanged) {
            whitelist.save();
            if (CaptureService.isServiceActive())
                CaptureService.requireInstance().reloadFirewallWhitelist();
        } else {
            blocklist.saveAndReload();
        }

        mAdapter.notifyDataSetChanged();
        return true;
    }

    @Override
    public void onCreateMenu(@NonNull Menu menu, @NonNull MenuInflater menuInflater) {
        // App options menu can be extended here
    }

    @Override
    public boolean onMenuItemSelected(@NonNull MenuItem menuItem) {
        return false;
    }

    @Override
    public void connectionsChanges(int num_connections) {
        refreshLiveStatsAsync();
    }

    @Override
    public void connectionsAdded(int start, ConnectionDescriptor[] conns) {
        refreshLiveStatsAsync();
    }

    @Override
    public void connectionsRemoved(int start, ConnectionDescriptor[] conns) {
        refreshLiveStatsAsync();
    }

    @Override
    public void connectionsUpdated(int[] positions) {
        refreshLiveStatsAsync();
    }
}
