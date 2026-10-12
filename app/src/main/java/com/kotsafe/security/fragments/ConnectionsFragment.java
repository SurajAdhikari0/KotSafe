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

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.ContextMenu;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.HorizontalScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.OnBackPressedCallback;
import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.view.ActionMode;
import androidx.appcompat.widget.SearchView;
import androidx.core.graphics.Insets;
import androidx.core.view.MenuProvider;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.Lifecycle;
import androidx.recyclerview.widget.DividerItemDecoration;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.SimpleItemAnimator;
import androidx.preference.PreferenceManager;
import java.util.ArrayList;
import java.util.List;

import com.kotsafe.security.model.ConnectionRefreshCoordinator;
import com.kotsafe.security.model.ConnectionScreenMetrics;
import com.kotsafe.security.model.ConnectionScreenState;
import com.kotsafe.security.model.ConnectionScreenStateBuilder;
import com.kotsafe.security.util.ConnectionsTimingTrace;

import com.kotsafe.security.AppsResolver;
import com.kotsafe.security.Billing;
import com.kotsafe.security.CaptureService;
import com.kotsafe.security.Cidr;
import com.kotsafe.security.ConnectionsRegister;
import com.kotsafe.security.Log;
import com.kotsafe.security.KotSafe;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.activities.AppDetailsActivity;
import com.kotsafe.security.model.AppDescriptor;
import com.kotsafe.security.model.Blocklist;
import com.kotsafe.security.model.ConnectionDescriptor;
import com.kotsafe.security.model.ConnectionRow;
import com.kotsafe.security.activities.ConnectionDetailsActivity;
import com.kotsafe.security.adapters.ConnectionsAdapter;
import com.kotsafe.security.model.FilterDescriptor;
import com.kotsafe.security.model.MatchList;
import com.kotsafe.security.model.MatchList.RuleType;
import com.kotsafe.security.model.Prefs;
import com.kotsafe.security.model.TrafficTimeSeriesCollector;
import com.kotsafe.security.views.GlassWireTrafficGraphView;
import com.kotsafe.security.views.EmptyRecyclerView;
import com.kotsafe.security.interfaces.ConnectionsListener;
import com.kotsafe.security.activities.EditFilterActivity;
import com.google.android.material.chip.Chip;
import com.google.android.material.chip.ChipGroup;
import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.google.android.material.slider.LabelFormatter;
import com.google.android.material.slider.Slider;
import com.kotsafe.security.views.ConnectionAiFlowDialog;
import com.kotsafe.security.views.QuickConnectionActionDialog;
import com.kotsafe.security.model.AppNetworkRule;
import com.kotsafe.security.model.AppNetworkRulesManager;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.ArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ConnectionsFragment extends Fragment implements ConnectionsListener, MenuProvider, SearchView.OnQueryTextListener {
    private static final String TAG = "ConnectionsFragment";
    private static boolean maliciousWarningShown = false;
    public static final String FILTER_EXTRA = "filter";
    public static final String QUERY_EXTRA = "query";
    private Handler mHandler;
    private ConnectionsAdapter mAdapter;
    private FloatingActionButton mFabDown;
    private int mFabDownMargin = 0;
    private EmptyRecyclerView mRecyclerView;
    private TextView mEmptyText;
    private TextView mOldConnectionsText;
    private TextView mSummaryActivePill;
    private TextView mSummaryTotalPill;
    private TextView mSummaryClosedPill;
    private TextView mSummaryBlockedPill;
    private boolean autoScroll;
    private boolean listenerSet;
    private ChipGroup mActiveFilter;
    private ChipGroup mCategoryChipGroup;
    private Chip mChipCatAll, mChipCatUser, mChipCatSystem, mChipCatDns, mChipCatActive, mChipCatClosed, mChipCatBlocked, mChipCatWeb;
    private Slider mSizeSlider;
    private boolean mSizeSliderActive = false;
    private MenuItem mMenuFilter;
    private MenuItem mMenuItemSearch;
    private MenuItem mSave;
    private Uri mCsvFname;
    private AppsResolver mApps;
    private SearchView mSearchView;
    private String mQueryToApply;
    private String mUnblockCidr;
    private String mDecRemoveCidr;
    private ActionMode mActionMode;
    private AlertDialog mAlertDialog;
    private OnBackPressedCallback mBackCallback;
    private final Runnable mUpdateMetricsRunnable = this::doUpdateSummaryMetrics;
    private ConnectionRefreshCoordinator mCoordinator;

    private boolean canBlockAppWide(int uid) {
        return uid >= android.os.Process.FIRST_APPLICATION_UID
                && uid != android.os.Process.myUid();
    }

    private View mGraphContainer;
    private GlassWireTrafficGraphView mTrafficGraph;
    private TrafficTimeSeriesCollector.OnLiveTrafficListener mTrafficListener;

    private void setupLiveTrafficGraph() {
        if (mGraphContainer == null || mTrafficGraph == null) return;
        boolean enabled = Prefs.isTrafficGraphsEnabled(getContext());
        mGraphContainer.setVisibility(enabled ? View.VISIBLE : View.GONE);
        if (enabled) {
            TrafficTimeSeriesCollector collector = TrafficTimeSeriesCollector.getInstance();
            mTrafficGraph.setDataPoints(collector.getRollingSnapshot());
            if (mTrafficListener == null) {
                mTrafficListener = (point, snapshot) -> {
                    if (isAdded() && mTrafficGraph != null && mHandler != null) {
                        mHandler.post(() -> mTrafficGraph.setDataPoints(snapshot));
                    }
                };
                collector.addListener(mTrafficListener);
            }
        } else if (mTrafficListener != null) {
            TrafficTimeSeriesCollector.getInstance().removeListener(mTrafficListener);
            mTrafficListener = null;
        }
    }

    private final ActivityResultLauncher<Intent> csvFileLauncher =
            registerForActivityResult(new StartActivityForResult(), this::csvFileResult);
    private final ActivityResultLauncher<Intent> filterLauncher =
            registerForActivityResult(new StartActivityForResult(), this::filterResult);

    @Override
    public void onResume() {
        super.onResume();
        ConnectionsTimingTrace.onConnectionsScreenFirstVisible();

        refreshEmptyText();

        ConnectionsRegister reg = CaptureService.getConnsRegister();
        if (mCoordinator != null) {
            mCoordinator.setConnectionsRegister(reg);
            if (mAdapter != null) {
                mCoordinator.updateFilter(mAdapter.mFilter, false);
            }
        }

        ConnectionScreenState cached = (reg != null) ? reg.getCachedScreenState() : null;
        boolean cacheValid = cached != null && (mAdapter == null || cached.category == mAdapter.mFilter.appCategory);
        if (cacheValid) {
            applyScreenState(cached);
        } else if (CaptureService.isServiceActive()) {
            if (mEmptyText != null) {
                mEmptyText.setText(R.string.loading_live_connections);
            }
        }

        registerConnsListener();
        mRecyclerView.setEmptyView(mEmptyText); // after registerConnsListener, when the adapter is populated

        refreshMenuIcons();

        // Only request a refresh if no valid cached data was already rendered
        if (!cacheValid && mCoordinator != null) {
            mCoordinator.requestRefresh(true);
        }

        if (mAdapter != null) {
            boolean visible = mAdapter.mFilter.minSize >= 1024;
            mSizeSlider.setVisibility(visible ? View.VISIBLE : View.GONE);
            mSizeSlider.setLabelBehavior(visible ? LabelFormatter.LABEL_VISIBLE : LabelFormatter.LABEL_GONE);
        }

        setupLiveTrafficGraph();
    }

    @Override
    public void onPause() {
        super.onPause();

        if (mTrafficListener != null) {
            TrafficTimeSeriesCollector.getInstance().removeListener(mTrafficListener);
            mTrafficListener = null;
        }

        unregisterConnsListener();
        mHandler.removeCallbacksAndMessages(null);
        mRecyclerView.setEmptyView(null);

        if(mSearchView != null)
            mQueryToApply = mSearchView.getQuery().toString();
    }

    @Override
    public void onDestroyView() {
        if(mAlertDialog != null)
            mAlertDialog.dismiss();

        if (mCoordinator != null) {
            mCoordinator.shutdown();
            mCoordinator = null;
        }

        if (mTrafficListener != null) {
            TrafficTimeSeriesCollector.getInstance().removeListener(mTrafficListener);
            mTrafficListener = null;
        }

        super.onDestroyView();
    }

    @Override
    public void onHiddenChanged(boolean hidden) {
        super.onHiddenChanged(hidden);

        if (hidden) {
            if(mActionMode != null)
                mActionMode.finish();
            clearFilters();
        } else {
            if (mRecyclerView != null) {
                mRecyclerView.scrollToPosition(0);
            }
        }
    }

    @Override
    public void onSaveInstanceState(@NonNull Bundle outState) {
        super.onSaveInstanceState(outState);

        if(mSearchView != null)
            outState.putString("search", mSearchView.getQuery().toString());
        if(mAdapter != null)
            outState.putSerializable("filter_desc", mAdapter.mFilter);
    }

    @Override
    public View onCreateView(LayoutInflater inflater,
                             ViewGroup container, Bundle savedInstanceState) {
        if (!(getParentFragment() instanceof DataViewContainerFragment)) {
            requireActivity().addMenuProvider(this, getViewLifecycleOwner(), Lifecycle.State.RESUMED);
        }
        return inflater.inflate(R.layout.connections, container, false);
    }

    private void refreshEmptyText() {
        if((CaptureService.getConnsRegister() != null) || CaptureService.isServiceActive()) {
            if (mAdapter != null && mAdapter.mFilter != null &&
                    (mAdapter.mFilter.filteringStatus == ConnectionDescriptor.FilteringStatus.BLOCKED ||
                     mAdapter.mFilter.appCategory == FilterDescriptor.AppCategory.BLOCKED_ONLY)) {
                mEmptyText.setText(R.string.no_blocked_connections_desc);
            } else {
                mEmptyText.setText(mAdapter.hasFilter() ? R.string.no_matches_found : R.string.no_connections);
            }
        } else {
            mEmptyText.setText(R.string.capture_not_running_status);
        }
    }

    private void registerConnsListener() {
        if (!listenerSet) {
            ConnectionsRegister reg = CaptureService.getConnsRegister();

            if (reg != null) {
                reg.addListener(this);
                listenerSet = true;
            }
        }
    }

    private void unregisterConnsListener() {
        if(listenerSet) {
            ConnectionsRegister reg = CaptureService.getConnsRegister();
            if (reg != null)
                reg.removeListener(this);

            listenerSet = false;
        }
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        mHandler = new Handler(Looper.getMainLooper());
        mFabDown = view.findViewById(R.id.fabDown);
        mRecyclerView = view.findViewById(R.id.connections_view);
        mOldConnectionsText = view.findViewById(R.id.old_connections_notice);
        EmptyRecyclerView.MyLinearLayoutManager layoutMan = new EmptyRecyclerView.MyLinearLayoutManager(requireContext());
        mRecyclerView.setLayoutManager(layoutMan);

        // Ensure zero top inset margin so connections list sits flush right under filter headers
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

        mApps = new AppsResolver(requireContext());

        mEmptyText = view.findViewById(R.id.no_connections);
        mSummaryActivePill = view.findViewById(R.id.summary_active_pill);
        mSummaryTotalPill = view.findViewById(R.id.summary_total_pill);
        mSummaryClosedPill = view.findViewById(R.id.summary_closed_pill);
        mSummaryBlockedPill = view.findViewById(R.id.summary_blocked_pill);

        mGraphContainer = view.findViewById(R.id.graph_container);
        mTrafficGraph = view.findViewById(R.id.connections_traffic_graph);
        if (mTrafficGraph != null) {
            mTrafficGraph.setCompactMode(true);
        }
        setupLiveTrafficGraph();

        if (mSummaryBlockedPill != null) {
            mSummaryBlockedPill.setOnClickListener(v -> {
                if (mCategoryChipGroup != null && mChipCatBlocked != null) {
                    mCategoryChipGroup.check(mChipCatBlocked.getId());
                    scrollToChip(mChipCatBlocked);
                }
            });
        }
        if (mSummaryActivePill != null) {
            mSummaryActivePill.setOnClickListener(v -> {
                if (mCategoryChipGroup != null && mChipCatActive != null) {
                    mCategoryChipGroup.check(mChipCatActive.getId());
                    scrollToChip(mChipCatActive);
                }
            });
        }
        if (mSummaryClosedPill != null) {
            mSummaryClosedPill.setOnClickListener(v -> {
                if (mCategoryChipGroup != null && mChipCatClosed != null) {
                    mCategoryChipGroup.check(mChipCatClosed.getId());
                    scrollToChip(mChipCatClosed);
                }
            });
        }
        if (mSummaryTotalPill != null) {
            mSummaryTotalPill.setOnClickListener(v -> {
                if (mCategoryChipGroup != null && mChipCatAll != null) {
                    mCategoryChipGroup.check(mChipCatAll.getId());
                    scrollToChip(mChipCatAll);
                }
            });
        }
        mSizeSlider = view.findViewById(R.id.size_slider);
        mSizeSlider.setLabelFormatter(value -> Utils.formatBytes(((long) value) * 1024));
        mSizeSlider.addOnChangeListener((slider, value, fromUser) -> {
            if (mAdapter != null) {
                mAdapter.mFilter.minSize = ((long) value) * 1024;
                refreshFilteredConnections();
            }
        });
        mSizeSlider.addOnSliderTouchListener(new Slider.OnSliderTouchListener() {
            @Override
            public void onStartTrackingTouch(@NonNull Slider slider) {
                mSizeSliderActive = true;
            }

            @Override
            public void onStopTrackingTouch(@NonNull Slider slider) {
                if (slider.getValue() == 0) {
                    // NOTE: setting LABEL_GONE is also necessary to
                    // prevent the label from being still visible in some cases
                    slider.setVisibility(View.GONE);
                    slider.setLabelBehavior(LabelFormatter.LABEL_GONE);
                }

                mSizeSliderActive = false;
                recheckMaxConnectionSize();
            }
        });

        mActiveFilter = view.findViewById(R.id.active_filter);
        mActiveFilter.setOnCheckedStateChangeListener((group, checkedIds) -> {
            if(mAdapter != null) {
                for(int checkedId: checkedIds)
                    mAdapter.mFilter.clear(checkedId);
                refreshFilteredConnections();
            }
        });

        mCategoryChipGroup = view.findViewById(R.id.category_chip_group);
        mChipCatAll = view.findViewById(R.id.chip_cat_all);
        mChipCatUser = view.findViewById(R.id.chip_cat_user);
        mChipCatSystem = view.findViewById(R.id.chip_cat_system);
        mChipCatDns = view.findViewById(R.id.chip_cat_dns);
        mChipCatActive = view.findViewById(R.id.chip_cat_active);
        mChipCatClosed = view.findViewById(R.id.chip_cat_closed);
        mChipCatBlocked = view.findViewById(R.id.chip_cat_blocked);
        mChipCatWeb = view.findViewById(R.id.chip_cat_web);

        if (mCategoryChipGroup != null) {
            mCategoryChipGroup.setOnCheckedStateChangeListener((group, checkedIds) -> {
                if (mAdapter == null) return;
                if (checkedIds.isEmpty() || checkedIds.contains(R.id.chip_cat_all)) {
                    mAdapter.mFilter.appCategory = FilterDescriptor.AppCategory.ALL;
                } else if (checkedIds.contains(R.id.chip_cat_user)) {
                    mAdapter.mFilter.appCategory = FilterDescriptor.AppCategory.USER;
                } else if (checkedIds.contains(R.id.chip_cat_system)) {
                    mAdapter.mFilter.appCategory = FilterDescriptor.AppCategory.SYSTEM;
                } else if (checkedIds.contains(R.id.chip_cat_dns)) {
                    mAdapter.mFilter.appCategory = FilterDescriptor.AppCategory.DNS;
                } else if (checkedIds.contains(R.id.chip_cat_active)) {
                    mAdapter.mFilter.appCategory = FilterDescriptor.AppCategory.ACTIVE_ONLY;
                } else if (checkedIds.contains(R.id.chip_cat_closed)) {
                    mAdapter.mFilter.appCategory = FilterDescriptor.AppCategory.CLOSED;
                } else if (checkedIds.contains(R.id.chip_cat_blocked)) {
                    mAdapter.mFilter.appCategory = FilterDescriptor.AppCategory.BLOCKED_ONLY;
                } else if (checkedIds.contains(R.id.chip_cat_web)) {
                    mAdapter.mFilter.appCategory = FilterDescriptor.AppCategory.WEB_ONLY;
                }
                refreshFilteredConnections();
            });
        }

        mAdapter = new ConnectionsAdapter(requireContext(), mApps);
        mAdapter.mFilter.appCategory = FilterDescriptor.getDefaultAppCategory();
        mRecyclerView.setAdapter(mAdapter);

        if (mCategoryChipGroup != null && mChipCatAll != null) {
            mCategoryChipGroup.check(mChipCatAll.getId());
        }

        RecyclerView.ItemAnimator animator = mRecyclerView.getItemAnimator();
        if (animator instanceof SimpleItemAnimator) {
            ((SimpleItemAnimator) animator).setSupportsChangeAnimations(false);
        }

        mCoordinator = new ConnectionRefreshCoordinator(
                new ConnectionScreenStateBuilder(requireContext(), mApps),
                mHandler
        );
        mCoordinator.setListener(this::applyScreenState);
        mCoordinator.updateFilter(mAdapter.mFilter, false);

        listenerSet = false;
        registerForContextMenu(mRecyclerView);
        updateSummaryMetrics();

        mAdapter.setClickListener(v -> {
            int pos = mRecyclerView.getChildLayoutPosition(v);
            if (pos == RecyclerView.NO_POSITION) return;

            if(mActionMode != null) {
                toggleSelection(pos);
                return;
            }

            ConnectionRow row = mAdapter.getRow(pos);
            if (row != null && row.rowType == ConnectionRow.ROW_TYPE_APP_GROUP_HEADER) {
                mAdapter.toggleAppExpansion(row.uid);
                return;
            }

            ConnectionDescriptor item = mAdapter.getItem(pos);

            if(item != null) {
                if(mAdapter.mFilter != null && mAdapter.mFilter.appCategory == FilterDescriptor.AppCategory.ALL && item.isDns()) {
                    if (mChipCatDns != null) {
                        mChipCatDns.setChecked(true);
                        return;
                    }
                }
                Intent intent = new Intent(requireContext(), ConnectionDetailsActivity.class);
                intent.putExtra(ConnectionDetailsActivity.CONN_ID_KEY, item.incr_id);

                if(mAdapter.hasFilter()) {
                    ArrayList<Integer> filteredIds = mAdapter.getFilteredConnectionIds();
                    if(filteredIds != null)
                        intent.putIntegerArrayListExtra(ConnectionDetailsActivity.FILTERED_IDS_KEY, filteredIds);
                }

                startActivity(intent);
            }
        });

        mAdapter.setSelectionLongClickListener(v -> {
            int pos = mRecyclerView.getChildLayoutPosition(v);
            if (mActionMode != null) {
                // Multi-select mode: toggle selection
                toggleSelection(pos);
                return true;
            }
            // Normal mode: show Quick Action dialog
            ConnectionDescriptor item = mAdapter.getItem(pos);
            if (item != null && isAdded() && getParentFragmentManager() != null) {
                AppDescriptor app = mApps.getAppByUid(item.uid, 0);
                String pkg  = app != null ? app.getPackageName() : null;
                String name = app != null ? app.getName() : ("UID " + item.uid);
                QuickConnectionActionDialog dlg = QuickConnectionActionDialog.newInstance(item, pkg, name);
                dlg.setActionListener(new QuickConnectionActionDialog.ActionListener() {
                    @Override
                    public void onBlockApp(int uid, String packageName) {
                        if (uid == android.os.Process.myUid() || (packageName != null && (packageName.equalsIgnoreCase(requireContext().getPackageName()) || packageName.contains("kotsafe")))) {
                            Toast.makeText(requireContext(),
                                    "KotSafe core security service is protected and cannot be blocked.",
                                    Toast.LENGTH_SHORT).show();
                            return;
                        }
                        if (!canBlockAppWide(uid)) {
                            Toast.makeText(requireContext(),
                                    "Android system services cannot be blocked app-wide.",
                                    Toast.LENGTH_SHORT).show();
                            return;
                        }
                        AppNetworkRulesManager mgr = AppNetworkRulesManager.getInstance(requireContext());
                        AppNetworkRule rule = mgr.getRule(uid);
                        if (rule == null) rule = new AppNetworkRule(packageName != null ? packageName : "", uid);
                        rule.setWifiBlocked(true);
                        rule.setMobileBlocked(true);
                        mgr.setRule(rule);
                        Toast.makeText(requireContext(),
                                requireContext().getString(R.string.app_blocked) + ": " + name,
                                Toast.LENGTH_SHORT).show();
                    }
                    @Override
                    public void onOpenAiAudit(int connId) {
                        if (isAdded() && getParentFragmentManager() != null) {
                            ConnectionAiFlowDialog.newInstance(connId)
                                    .show(getParentFragmentManager(), "ai_flow");
                        }
                    }

                    @Override
                    public void onOpenTimeline(int uid, int connId) {
                        if (isAdded() && getParentFragmentManager() != null) {
                            com.kotsafe.security.views.AppTimelineDialog.newInstance(uid, connId)
                                    .show(getParentFragmentManager(), "app_timeline");
                        }
                    }
                });
                dlg.show(getParentFragmentManager(), "quick_action");
            }
            return true;
        });

        autoScroll = true;
        showFabDown(false);

        ViewCompat.setOnApplyWindowInsetsListener(view.findViewById(R.id.linearlayout), (v, windowInsets) -> {
            Insets insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars() |
                    WindowInsetsCompat.Type.displayCutout());

            // Avoid adding top inset padding here; Toolbar / AppBarLayout handles top insets.
            // Eliminates the black gap below the toolbar.
            v.setPadding(insets.left, 0, insets.right, 0);

            return windowInsets.inset(insets.left, insets.top, insets.right, 0);
        });

        mFabDown.setOnClickListener(v -> scrollToBottom());
        ViewCompat.setOnApplyWindowInsetsListener(mFabDown, (v, windowInsets) -> {
            Insets insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars() |
                    WindowInsetsCompat.Type.displayCutout() | WindowInsetsCompat.Type.ime());

            ViewGroup.MarginLayoutParams mlp = (ViewGroup.MarginLayoutParams) v.getLayoutParams();
            if (mFabDownMargin == 0)
                // save base margin from the layout
                mFabDownMargin = mlp.bottomMargin;

            mlp.bottomMargin = mFabDownMargin + insets.bottom;
            v.setLayoutParams(mlp);

            return WindowInsetsCompat.CONSUMED;
        });

        mRecyclerView.addOnScrollListener(new RecyclerView.OnScrollListener() {
            @Override
            public void onScrolled(@NonNull RecyclerView recyclerView, int dx, int dy) {
                recheckScroll();
            }
        });

        refreshMenuIcons();

        String search = "";
        boolean fromIntent = false;
        Intent intent = requireActivity().getIntent();
        FilterDescriptor filter = null;
        if (getArguments() != null) {
            filter = Utils.getSerializable(getArguments(), FILTER_EXTRA, FilterDescriptor.class);
        }
        if (filter == null && intent != null) {
            filter = Utils.getSerializableExtra(intent, FILTER_EXTRA, FilterDescriptor.class);
        }

        if(filter != null) {
            mAdapter.mFilter = filter;
            fromIntent = true;
            syncCategoryChips(filter.appCategory);

            if (filter.onlyBlacklisted && !maliciousWarningShown) {
                new AlertDialog.Builder(requireContext())
                        .setTitle(R.string.malicious_connections)
                        .setMessage(R.string.malicious_connections_notice)
                        .setPositiveButton(R.string.ok, (dialogInterface, i) -> {})
                        .show();

                maliciousWarningShown = true;
            }
        }

        if(intent != null) {
            search = intent.getStringExtra(QUERY_EXTRA);
            if((search != null) && !search.isEmpty()) {
                // Avoid hiding the interesting items
                mAdapter.mFilter.showMasked = true;
                fromIntent = true;
            }
        }

        if(savedInstanceState != null) {
            if((search == null) || search.isEmpty())
                search = savedInstanceState.getString("search");

            if(!fromIntent && savedInstanceState.containsKey("filter_desc")) {
                mAdapter.mFilter = Utils.getSerializable(savedInstanceState, "filter_desc", FilterDescriptor.class);
                if (mAdapter.mFilter != null) {
                    syncCategoryChips(mAdapter.mFilter.appCategory);
                }
            }
        }
        refreshActiveFilter();

        if((search != null) && !search.isEmpty())
            mQueryToApply = search;

        // Register for service status
        CaptureService.observeStatus(this, serviceStatus -> {
            if(serviceStatus == CaptureService.ServiceStatus.STARTED) {
                // register the new connection register
                unregisterConnsListener();
                registerConnsListener();

                autoScroll = true;
                showFabDown(false);
                mOldConnectionsText.setVisibility(View.GONE);
                mEmptyText.setText(R.string.no_connections);
                mApps.clear();
            }

            refreshMenuIcons();
        });

        mBackCallback = new OnBackPressedCallback(false) {
            @Override
            public void handleOnBackPressed() {
                if (mActionMode != null) {
                    mActionMode.finish();
                    return;
                }
                mMenuItemSearch.collapseActionView();
            }
        };
        requireActivity().getOnBackPressedDispatcher().addCallback(getViewLifecycleOwner(), mBackCallback);
    }

    private void updateBackCallback() {
        if (mBackCallback == null)
            return;

        boolean searchExpanded = (mSearchView != null) && !mSearchView.isIconified();
        mBackCallback.setEnabled((mActionMode != null) || searchExpanded);
    }

    private void scrollToChip(View chip) {
        if (chip != null && getView() != null) {
            HorizontalScrollView scroll = getView().findViewById(R.id.category_filters_bar);
            if (scroll != null) {
                scroll.post(() -> scroll.smoothScrollTo(chip.getLeft(), 0));
            }
        }
    }

    private void syncCategoryChips(FilterDescriptor.AppCategory cat) {
        if (mCategoryChipGroup == null || cat == null) return;
        int targetId;
        switch (cat) {
            case ALL:
                targetId = R.id.chip_cat_all;
                break;
            case SYSTEM:
                targetId = R.id.chip_cat_system;
                break;
            case DNS:
                targetId = R.id.chip_cat_dns;
                break;
            case ACTIVE_ONLY:
                targetId = R.id.chip_cat_active;
                break;
            case CLOSED:
                targetId = R.id.chip_cat_closed;
                break;
            case BLOCKED_ONLY:
                targetId = R.id.chip_cat_blocked;
                break;
            case WEB_ONLY:
                targetId = R.id.chip_cat_web;
                break;
            case USER:
            default:
                targetId = R.id.chip_cat_user;
                break;
        }
        mCategoryChipGroup.check(targetId);
        View chip = mCategoryChipGroup.findViewById(targetId);
        if (chip != null) {
            scrollToChip(chip);
        }
    }

    @Override
    public void onCreateContextMenu(@NonNull ContextMenu menu, @NonNull View v,
                                    @Nullable ContextMenu.ContextMenuInfo menuInfo) {
        super.onCreateContextMenu(menu, v, menuInfo);

        MenuInflater inflater = requireActivity().getMenuInflater();
        inflater.inflate(R.menu.connection_context_menu, menu);
        int max_length = 32;

        ConnectionDescriptor conn = mAdapter.getSelectedItem();
        if(conn == null)
            return;

        AppDescriptor app = mApps.getAppByUid(conn.uid, 0);
        Context ctx = requireContext();
        MenuItem item;

        Billing billing = Billing.newInstance(ctx);
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ctx);

        boolean firewallVisible = billing.isFirewallVisible();
        boolean whitelistMode = Prefs.isFirewallWhitelistMode(prefs);
        boolean showPurchaseFirewall = (!billing.isPurchased(Billing.FIREWALL_SKU) && billing.isAvailable(Billing.FIREWALL_SKU)) && !CaptureService.isCapturingAsRoot();
        boolean blockVisible = false;
        boolean unblockVisible = false;
        boolean decryptVisible = false;
        boolean dontDecryptVisible = false;
        Blocklist blocklist = KotSafe.getInstance().getBlocklist();
        MatchList fwWhitelist = KotSafe.getInstance().getFirewallWhitelist();
        MatchList decryptionList = KotSafe.getInstance().getDecryptionList();

        // App allowlist: only meaningful when the app is known and blocked
        boolean appBlocked = (app != null) && blocklist.matchesApp(app.getUid());
        MatchList appAllowlist = (appBlocked) ? blocklist.findAppAllowlist(app.getPackageName()) : null;

        if(app != null) {
            blockVisible = canBlockAppWide(conn.uid) && !appBlocked;
            unblockVisible = appBlocked;

            boolean decryptApp = decryptionList.matchesApp(app.getUid());
            decryptVisible = !decryptApp;
            dontDecryptVisible = decryptApp;

            item = menu.findItem(R.id.hide_app);
            String label = Utils.shorten(MatchList.getRuleLabel(ctx, RuleType.APP, app.getPackageName()), max_length);
            item.setTitle(label);
            item.setVisible(true);

            item = menu.findItem(R.id.search_app);
            item.setTitle(label);
            item.setVisible(true);

            item = menu.findItem(R.id.block_app);
            item.setTitle(label);
            item.setVisible(canBlockAppWide(conn.uid) && !appBlocked);

            item = menu.findItem(R.id.unblock_app);
            item.setTitle(label);
            item.setVisible(appBlocked);

            item = menu.findItem(R.id.dec_add_app);
            item.setTitle(label);
            item.setVisible(!decryptApp);

            item = menu.findItem(R.id.dec_rem_app);
            item.setTitle(label);
            item.setVisible(decryptApp);

            menu.findItem(R.id.unblock_app_10m).setTitle(getString(R.string.unblock_for_n_minutes, 10));
            menu.findItem(R.id.unblock_app_1h).setTitle(getString(R.string.unblock_for_n_hours, 1));
            menu.findItem(R.id.unblock_app_8h).setTitle(getString(R.string.unblock_for_n_hours, 8));

            if(conn.isBlacklisted()) {
                item = menu.findItem(R.id.mw_whitelist_app);
                item.setTitle(label);
                item.setVisible(true);
            }

            if(firewallVisible && whitelistMode) {
                boolean whitelisted = fwWhitelist.matchesApp(app.getUid());
                menu.findItem(R.id.add_to_fw_whitelist).setVisible(!whitelisted);
                menu.findItem(R.id.remove_from_fw_whitelist).setVisible(whitelisted);
            }
        }

        if((conn.info != null) && (!conn.info.isEmpty())) {
            boolean hostBlocked = blocklist.matchesExactHost(conn.info);
            String label = Utils.shorten(MatchList.getRuleLabel(ctx, RuleType.HOST, conn.info), max_length);
            blockVisible |= !hostBlocked;
            unblockVisible |= hostBlocked;

            if(appBlocked) {
                boolean hostAllowed = (appAllowlist != null) && appAllowlist.matchesExactHost(conn.info);
                item = menu.findItem(R.id.allow_host);
                item.setTitle(getString(R.string.allowlist_allow, label));
                item.setVisible(!hostAllowed);
                item = menu.findItem(R.id.deny_host);
                item.setTitle(getString(R.string.allowlist_remove, label));
                item.setVisible(hostAllowed);
            }

            boolean decryptHost = decryptionList.matchesExactHost(conn.info);
            decryptVisible |= !decryptHost;
            dontDecryptVisible |= decryptHost;

            item = menu.findItem(R.id.hide_host);
            item.setTitle(label);
            item.setVisible(true);

            item = menu.findItem(R.id.block_host);
            item.setTitle(label);
            item.setVisible(!hostBlocked);

            item = menu.findItem(R.id.unblock_host);
            item.setTitle(label);
            item.setVisible(hostBlocked);

            item = menu.findItem(R.id.search_host);
            item.setTitle(label);
            item.setVisible(true);

            item = menu.findItem(R.id.copy_host);
            item.setTitle(label);
            item.setVisible(true);

            item = menu.findItem(R.id.dec_add_host);
            item.setTitle(label);
            item.setVisible(!decryptHost);

            item = menu.findItem(R.id.dec_rem_host);
            item.setTitle(label);
            item.setVisible(decryptHost);

            String dm_clean = Utils.cleanDomain(conn.info);
            String domain = Utils.getSecondLevelDomain(dm_clean);

            if(!domain.equals(dm_clean)) {
                boolean domainBlocked = blocklist.matchesExactHost(domain);
                label = Utils.shorten(MatchList.getRuleLabel(ctx, RuleType.HOST, domain), max_length);
                blockVisible |= !domainBlocked;
                unblockVisible |= domainBlocked;

                item = menu.findItem(R.id.hide_domain);
                item.setTitle(label);
                item.setVisible(true);

                item = menu.findItem(R.id.block_domain);
                item.setTitle(label);
                item.setVisible(!domainBlocked);

                item = menu.findItem(R.id.unblock_domain);
                item.setTitle(label);
                item.setVisible(domainBlocked);

                if(appBlocked) {
                    boolean domainAllowed = (appAllowlist != null) && appAllowlist.matchesExactHost(domain);
                    item = menu.findItem(R.id.allow_domain);
                    item.setTitle(getString(R.string.allowlist_allow, label));
                    item.setVisible(!domainAllowed);
                    item = menu.findItem(R.id.deny_domain);
                    item.setTitle(getString(R.string.allowlist_remove, label));
                    item.setVisible(domainAllowed);
                }
            }

            if(conn.isBlacklistedHost()) {
                item = menu.findItem(R.id.mw_whitelist_host);
                item.setTitle(label);
                item.setVisible(true);
            }
        } // conn.info

        if((conn.url != null) && !(conn.url.isEmpty())) {
            item = menu.findItem(R.id.copy_url);
            item.setTitle(Utils.shorten(String.format(getString(R.string.url_val), conn.url), max_length));
            item.setVisible(true);
        }

        if(!conn.country.isEmpty()) {
            boolean countryBlocked = blocklist.matchesCountry(conn.country);
            String label = Utils.shorten(String.format(getString(R.string.country_val), Utils.getCountryName(ctx, conn.country)), max_length);
            blockVisible |= !countryBlocked;
            unblockVisible |= countryBlocked;

            item = menu.findItem(R.id.block_country);
            item.setTitle(label);
            item.setVisible(!countryBlocked);

            item = menu.findItem(R.id.unblock_country);
            item.setTitle(label);
            item.setVisible(countryBlocked);

            item = menu.findItem(R.id.hide_country);
            item.setTitle(label);
            item.setVisible(true);
        }

        String label = MatchList.getRuleLabel(ctx, RuleType.IP, conn.dst_ip);
        menu.findItem(R.id.hide_ip).setTitle(label);
        menu.findItem(R.id.copy_ip).setTitle(label);
        menu.findItem(R.id.search_ip).setTitle(label);
        String unblockIpLabel = label;
        String decRemoveIpLabel = label;
        mUnblockCidr = null;
        mDecRemoveCidr = null;

        boolean ipBlocked = blocklist.matchesExactIP(conn.dst_ip);
        if (!ipBlocked) {
            Cidr blockedCidr = blocklist.matchesCidr(conn.dst_ip);
            if (blockedCidr != null) {
                ipBlocked = true;
                mUnblockCidr = blockedCidr.toString();
                unblockIpLabel = MatchList.getCidrLabel(ctx, blockedCidr);
            }
        }
        blockVisible |= !ipBlocked;
        unblockVisible |= ipBlocked;

        boolean decryptIp = decryptionList.matchesExactIP(conn.dst_ip);
        if (!decryptIp) {
            Cidr decryptCidr = decryptionList.matchesCidr(conn.dst_ip);
            if (decryptCidr != null) {
                decryptIp = true;
                mDecRemoveCidr = decryptCidr.toString();
                decRemoveIpLabel = MatchList.getCidrLabel(ctx, decryptCidr);
            }
        }
        decryptVisible |= !decryptIp;
        dontDecryptVisible |= decryptIp;

        menu.findItem(R.id.block_ip)
                .setTitle(label)
                .setVisible(!ipBlocked);
        menu.findItem(R.id.unblock_ip)
                .setTitle(unblockIpLabel)
                .setVisible(ipBlocked);

        if(appBlocked) {
            // Allowlist only tracks exact IPs (no CIDR ranges in the per-app allowlist UI)
            boolean ipAllowed = (appAllowlist != null) && appAllowlist.matchesExactIP(conn.dst_ip);
            menu.findItem(R.id.allow_ip).setTitle(getString(R.string.allowlist_allow, label)).setVisible(!ipAllowed);
            menu.findItem(R.id.deny_ip).setTitle(getString(R.string.allowlist_remove, label)).setVisible(ipAllowed);
        }

        menu.findItem(R.id.dec_add_ip)
                .setTitle(label)
                .setVisible(!decryptIp);
        menu.findItem(R.id.dec_rem_ip)
                .setTitle(decRemoveIpLabel)
                .setVisible(decryptIp);

        if(conn.isBlacklistedIp())
            menu.findItem(R.id.mw_whitelist_ip).setTitle(label).setVisible(true);

        if(conn.hasHttpRequest())
            menu.findItem(R.id.copy_http_request).setVisible(true);
        if(conn.hasHttpResponse())
            menu.findItem(R.id.copy_http_response).setVisible(true);

        label = MatchList.getRuleLabel(ctx, RuleType.PROTOCOL, conn.l7proto);
        menu.findItem(R.id.hide_proto).setTitle(label);
        menu.findItem(R.id.search_proto).setTitle(label);

        menu.findItem(R.id.block_menu).setVisible((firewallVisible || showPurchaseFirewall) && blockVisible);
        menu.findItem(R.id.unblock_menu).setVisible(firewallVisible && unblockVisible);

        // The per-app allowlist (exceptions to a blocked app) is scoped to the app, unlike the
        // global Block/Unblock lists
        MenuItem allowlistMenu = menu.findItem(R.id.app_allowlist_menu);
        allowlistMenu.setVisible(firewallVisible && appBlocked);
        if(app != null)
            allowlistMenu.setTitle(getString(R.string.allow_for_app, Utils.shorten(app.getName(), max_length)));

        if(!conn.isBlacklisted())
            menu.findItem(R.id.mw_whitelist_menu).setVisible(false);

        boolean decryptionEnabled = CaptureService.isDecryptionListEnabled();
        boolean canDecryptConnection = !conn.isNotDecryptable() && !conn.isCleartext();
        menu.findItem(R.id.decrypt_menu).setVisible(decryptionEnabled && canDecryptConnection && decryptVisible);
        menu.findItem(R.id.dont_decrypt_menu).setVisible(decryptionEnabled && canDecryptConnection && dontDecryptVisible);
    }

    @Override
    public boolean onContextItemSelected(@NonNull MenuItem item) {
        Context ctx = requireContext();
        ConnectionDescriptor conn = mAdapter.getSelectedItem();
        MatchList whitelist = KotSafe.getInstance().getMalwareWhitelist();
        MatchList fwWhitelist = KotSafe.getInstance().getFirewallWhitelist();
        MatchList decryptionList = KotSafe.getInstance().getDecryptionList();
        Blocklist blocklist = KotSafe.getInstance().getBlocklist();
        boolean firewallPurchased = Billing.newInstance(ctx).isPurchased(Billing.FIREWALL_SKU);
        boolean mask_changed = false;
        boolean whitelist_changed = false;
        boolean blocklist_changed = false;
        boolean firewall_wl_changed = false;
        boolean decryption_list_changed = false;
        MatchList app_allowlist_changed = null;

        if(conn == null)
            return super.onContextItemSelected(item);

        int id = item.getItemId();

        if(id == R.id.select_connection) {
            startSelectionMode(conn);
            return true;
        } else if(id == R.id.hide_app) {
            mAdapter.mMask.addApp(conn.uid);
            mask_changed = true;
        } else if(id == R.id.hide_host) {
            mAdapter.mMask.addHost(conn.info);
            mask_changed = true;
        } else if(id == R.id.hide_ip) {
            mAdapter.mMask.addIp(conn.dst_ip);
            mask_changed = true;
        } else if(id == R.id.hide_proto) {
            mAdapter.mMask.addProto(conn.l7proto);
            mask_changed = true;
        } else if(id == R.id.hide_domain) {
            mAdapter.mMask.addHost(Utils.getSecondLevelDomain(conn.info));
            mask_changed = true;
        } else if(id == R.id.hide_country) {
            mAdapter.mMask.addCountry(conn.country);
            mask_changed = true;
        } else if(id == R.id.search_app) {
            AppDescriptor app = mApps.getAppByUid(conn.uid, 0);
            if(app != null)
                setQuery(app.getPackageName());
            else
                return super.onContextItemSelected(item);
        } else if(id == R.id.search_host)
            setQuery(conn.info);
        else if(id == R.id.search_ip)
            setQuery(conn.dst_ip);
        else if(id == R.id.search_proto)
            setQuery(conn.l7proto);
        else if(id == R.id.mw_whitelist_app)  {
            whitelist.addApp(conn.uid);
            whitelist_changed = true;
        } else if(id == R.id.mw_whitelist_ip)  {
            whitelist.addIp(conn.dst_ip);
            whitelist_changed = true;
        } else if(id == R.id.mw_whitelist_host) {
            whitelist.addHost(conn.info);
            whitelist_changed = true;
        } else if(id == R.id.dec_add_app)  {
            decryptionList.addApp(conn.uid);
            decryption_list_changed = true;
        } else if(id == R.id.dec_add_ip)  {
            decryptionList.addIp(conn.dst_ip);
            decryption_list_changed = true;
        } else if(id == R.id.dec_add_host)  {
            decryptionList.addHost(conn.info);
            decryption_list_changed = true;
        } else if(id == R.id.dec_rem_app)  {
            decryptionList.removeApp(conn.uid);
            decryption_list_changed = true;
        } else if(id == R.id.dec_rem_ip)  {
            decryptionList.removeIp((mDecRemoveCidr != null) ? mDecRemoveCidr : conn.dst_ip);
            decryption_list_changed = true;
        } else if(id == R.id.dec_rem_host)  {
            decryptionList.removeHost(conn.info);
            decryption_list_changed = true;
        } else if(id == R.id.block_app) {
            if (!canBlockAppWide(conn.uid)) {
                Toast.makeText(ctx, "Android system services cannot be blocked app-wide.", Toast.LENGTH_SHORT).show();
                return true;
            }
            if(firewallPurchased) {
                blocklist.addApp(conn.uid);
                blocklist_changed = true;
            } else
                showFirewallPurchaseDialog();
        } else if(id == R.id.block_ip) {
            if(firewallPurchased) {
                blocklist.addIp(conn.dst_ip);
                blocklist_changed = true;
            } else
                showFirewallPurchaseDialog();
        } else if(id == R.id.block_host) {
            if(firewallPurchased) {
                blocklist.addHost(conn.info);
                blocklist_changed = true;
            } else
                showFirewallPurchaseDialog();
        } else if(id == R.id.block_domain) {
            if(firewallPurchased) {
                blocklist.addHost(Utils.getSecondLevelDomain(conn.info));
                blocklist_changed = true;
            } else
                showFirewallPurchaseDialog();
        } else if(id == R.id.block_country) {
            if(firewallPurchased) {
                blocklist.addCountry(conn.country);
                blocklist_changed = true;
            } else
                showFirewallPurchaseDialog();
        } else if(id == R.id.unblock_app_permanently) {
            blocklist.removeApp(conn.uid);
            blocklist_changed = true;
        } else if(id == R.id.unblock_app_10m) {
            blocklist_changed = blocklist.unblockAppForMinutes(conn.uid, 10);
        } else if(id == R.id.unblock_app_1h) {
            blocklist_changed = blocklist.unblockAppForMinutes(conn.uid, 60);
        } else if(id == R.id.unblock_app_8h) {
            blocklist_changed = blocklist.unblockAppForMinutes(conn.uid, 480);
        } else if(id == R.id.unblock_ip) {
            blocklist.removeIp((mUnblockCidr != null) ? mUnblockCidr : conn.dst_ip);
            blocklist_changed = true;
        } else if(id == R.id.unblock_host) {
            blocklist.removeHost(conn.info);
            blocklist_changed = true;
        } else if(id == R.id.unblock_domain) {
            blocklist.removeHost(Utils.getSecondLevelDomain(conn.info));
            blocklist_changed = true;
        } else if(id == R.id.unblock_country) {
            blocklist.removeCountry(conn.country);
            blocklist_changed = true;
        } else if(id == R.id.add_to_fw_whitelist) {
            fwWhitelist.addApp(conn.uid);
            firewall_wl_changed = true;
        } else if(id == R.id.remove_from_fw_whitelist) {
            fwWhitelist.removeApp(conn.uid);
            firewall_wl_changed = true;
        } else if(id == R.id.allow_host) {
            AppDescriptor app = mApps.getAppByUid(conn.uid, 0);
            if(app != null) {
                app_allowlist_changed = blocklist.getAppAllowlist(app.getPackageName());
                app_allowlist_changed.addHost(conn.info);
            }
        } else if(id == R.id.allow_ip) {
            AppDescriptor app = mApps.getAppByUid(conn.uid, 0);
            if(app != null) {
                app_allowlist_changed = blocklist.getAppAllowlist(app.getPackageName());
                app_allowlist_changed.addIp(conn.dst_ip);
            }
        } else if(id == R.id.allow_domain) {
            AppDescriptor app = mApps.getAppByUid(conn.uid, 0);
            if(app != null) {
                app_allowlist_changed = blocklist.getAppAllowlist(app.getPackageName());
                app_allowlist_changed.addHost(Utils.getSecondLevelDomain(conn.info));
            }
        } else if(id == R.id.deny_host) {
            AppDescriptor app = mApps.getAppByUid(conn.uid, 0);
            if(app != null) {
                app_allowlist_changed = blocklist.getAppAllowlist(app.getPackageName());
                app_allowlist_changed.removeHost(conn.info);
            }
        } else if(id == R.id.deny_ip) {
            AppDescriptor app = mApps.getAppByUid(conn.uid, 0);
            if(app != null) {
                app_allowlist_changed = blocklist.getAppAllowlist(app.getPackageName());
                app_allowlist_changed.removeIp(conn.dst_ip);
            }
        } else if(id == R.id.deny_domain) {
            AppDescriptor app = mApps.getAppByUid(conn.uid, 0);
            if(app != null) {
                app_allowlist_changed = blocklist.getAppAllowlist(app.getPackageName());
                app_allowlist_changed.removeHost(Utils.getSecondLevelDomain(conn.info));
            }
        } else if(id == R.id.open_app_details) {
            Intent intent = new Intent(requireContext(), AppDetailsActivity.class);
            intent.putExtra(AppDetailsActivity.APP_UID_EXTRA, conn.uid);
            startActivity(intent);
        } else if(id == R.id.copy_ip)
            Utils.copyToClipboard(ctx, conn.dst_ip);
        else if(id == R.id.copy_host)
            Utils.copyToClipboard(ctx, conn.info);
        else if(id == R.id.copy_url)
            Utils.copyToClipboard(ctx, conn.url);
        else if(id == R.id.copy_http_request)
            Utils.copyToClipboard(ctx, conn.getHttpRequest());
        else if(id == R.id.copy_http_response)
            Utils.copyToClipboard(ctx, conn.getHttpResponse());
        else
            return super.onContextItemSelected(item);

        if(mask_changed) {
            mAdapter.mMask.save();
            mAdapter.mFilter.showMasked = false;
            refreshFilteredConnections();
        } else if(whitelist_changed) {
            whitelist.save();
            CaptureService.reloadMalwareWhitelist();
        } else if(firewall_wl_changed) {
            fwWhitelist.save();
            if(CaptureService.isServiceActive())
                CaptureService.requireInstance().reloadFirewallWhitelist();
        } else if(decryption_list_changed) {
            decryptionList.save();
            CaptureService.reloadDecryptionList();
        } else if(app_allowlist_changed != null)
            blocklist.saveAndReload();
        else if(blocklist_changed)
            blocklist.saveAndReload();

        return true;
    }

    private void showFirewallPurchaseDialog() {
        new AlertDialog.Builder(requireContext())
                .setTitle(R.string.paid_feature)
                .setMessage(Utils.getText(requireContext(), R.string.firewall_purchase_msg, getString(R.string.no_root_firewall)))
                .setPositiveButton(R.string.show_me, (dialogInterface, i) -> {
                    // Billing code here
                })
                .setNegativeButton(R.string.cancel_action, (dialogInterface, i) -> {})
                .show();
    }

    private void setQuery(String query) {
        Utils.setSearchQuery(mSearchView, mMenuItemSearch, query);
    }

    private void recheckScroll() {
        final EmptyRecyclerView.MyLinearLayoutManager layoutMan = (EmptyRecyclerView.MyLinearLayoutManager) mRecyclerView.getLayoutManager();
        assert layoutMan != null;
        int first_visibile_pos = layoutMan.findFirstCompletelyVisibleItemPosition();
        int last_visible_pos = layoutMan.findLastCompletelyVisibleItemPosition();
        int last_pos = mAdapter.getItemCount() - 1;
        boolean reached_bottom = (last_visible_pos >= last_pos);
        boolean is_scrolling = (first_visibile_pos != 0) || (!reached_bottom);

        if(is_scrolling) {
            if(reached_bottom) {
                autoScroll = true;
                showFabDown(false);
            } else {
                autoScroll = false;
                showFabDown(true);
            }
        } else
            showFabDown(false);
    }

    private void showFabDown(boolean visible) {
        // compared to setVisibility, .show/.hide provide animations and also properly clear the AnchorId
        if(visible)
            mFabDown.show();
        else
            mFabDown.hide();
    }

    private void scrollToBottom() {
        if (mAdapter != null && mAdapter.getSortMode() == ConnectionsAdapter.SortMode.RECENT) {
            mRecyclerView.scrollToPosition(0);
        } else {
            int last_pos = mAdapter != null ? mAdapter.getItemCount() - 1 : 0;
            if (last_pos >= 0) mRecyclerView.scrollToPosition(last_pos);
        }

        showFabDown(false);
    }

    private void refreshActiveFilter() {
        if(mAdapter == null)
            return;

        mActiveFilter.removeAllViews();
        mAdapter.mFilter.toChips(getLayoutInflater(), mActiveFilter);

        // minSize slider
        long minSizeKB = mAdapter.mFilter.minSize / 1024;
        boolean sliderVisible = false;
        ConnectionsRegister reg = CaptureService.getConnsRegister();

        if ((reg != null) && (minSizeKB > 0)) {
            long maxSizeKb = reg.getMaxBytes() / 1024;
            maxSizeKb = Math.max(maxSizeKb, minSizeKB);

            if (maxSizeKb >= 2) {
                // NOTE: visible -> hidden transition is performed in onStopTrackingTouch
                mSizeSlider.setValueTo(maxSizeKb);
                mSizeSlider.setValue(minSizeKB);
                sliderVisible = true;
            }
        }

        if (sliderVisible && (mSizeSlider.getVisibility() != View.VISIBLE)) {
            mSizeSlider.setVisibility(View.VISIBLE);
            mSizeSlider.setLabelBehavior(LabelFormatter.LABEL_VISIBLE);
        }
    }

    private void recheckMaxConnectionSize() {
        if ((mSizeSlider.getVisibility() == View.VISIBLE) && !mSizeSliderActive) {
            ConnectionsRegister reg = CaptureService.getConnsRegister();
            if (reg != null) {
                long maxSizeKB = reg.getMaxBytes() / 1024;

                if (maxSizeKB > mSizeSlider.getValueTo())
                    mSizeSlider.setValueTo(maxSizeKB);
            }
        }
    }

    public void applyScreenState(@NonNull ConnectionScreenState state) {
        if (!isAdded() || getContext() == null) return;

        if (mAdapter != null) {
            mAdapter.setConnectionRows(state.rows);
        }

        ConnectionsRegister reg = CaptureService.getConnsRegister();
        if (reg != null) {
            reg.setCachedScreenState(state);
        }

        assignMetrics(state.metrics);

        if (state.metrics != null && state.metrics.untrackedCount > 0 && mOldConnectionsText != null) {
            String info = String.format(getString(R.string.older_connections_notice), state.metrics.untrackedCount);
            mOldConnectionsText.setText(info);
            mOldConnectionsText.setVisibility(View.VISIBLE);
        } else if (mOldConnectionsText != null) {
            mOldConnectionsText.setVisibility(View.GONE);
        }

        refreshEmptyText();
        refreshMenuIcons();
        refreshActiveFilter();
        recheckScroll();

        if (autoScroll) {
            scrollToBottom();
        }
    }

    private void assignMetrics(@Nullable ConnectionScreenMetrics metrics) {
        if (metrics == null || !isAdded() || getContext() == null) return;

        if (mSummaryActivePill != null)
            mSummaryActivePill.setText(getString(R.string.summary_active_format, metrics.activeCount));
        if (mSummaryTotalPill != null)
            mSummaryTotalPill.setText(getString(R.string.summary_total_format, metrics.totalCount));
        if (mSummaryClosedPill != null)
            mSummaryClosedPill.setText(getString(R.string.summary_closed_format, metrics.closedCount));
        if (mSummaryBlockedPill != null) {
            mSummaryBlockedPill.setText(getString(R.string.summary_blocked_format, metrics.blockedCount));
            mSummaryBlockedPill.setVisibility(metrics.blockedCount > 0 ? View.VISIBLE : View.GONE);
        }

        if (mChipCatAll != null) mChipCatAll.setText(getString(R.string.connection_all_count, metrics.countAll));
        if (mChipCatUser != null) mChipCatUser.setText(getString(R.string.connection_user_count, metrics.countUser));
        if (mChipCatSystem != null) mChipCatSystem.setText(getString(R.string.connection_system_count, metrics.countSystem));
        if (mChipCatDns != null) mChipCatDns.setText(getString(R.string.connection_dns_count, metrics.countDns));
        if (mChipCatActive != null) mChipCatActive.setText(getString(R.string.connection_active_count, metrics.countActiveOnly));
        if (mChipCatClosed != null) mChipCatClosed.setText(getString(R.string.connection_closed_count, metrics.countClosedOnly));
        if (mChipCatBlocked != null) mChipCatBlocked.setText(getString(R.string.connection_blocked_count, metrics.countBlockedOnly));
        if (mChipCatWeb != null) mChipCatWeb.setText(getString(R.string.connection_web_count, metrics.countWebOnly));

        if (mSizeSlider != null && !mSizeSliderActive) {
            long maxSizeKB = metrics.maxBytes / 1024;
            if (maxSizeKB > mSizeSlider.getValueTo()) {
                mSizeSlider.setValueTo(maxSizeKB);
            }
        }
    }

    private void refreshFilteredConnections() {
        if (mCoordinator != null && mAdapter != null) {
            mCoordinator.updateFilter(mAdapter.mFilter, true);
        } else if (mAdapter != null) {
            mAdapter.refreshFilteredConnections();
            refreshMenuIcons();
            refreshActiveFilter();
            recheckScroll();
            updateSummaryMetrics();
        }
    }

    private void updateSummaryMetrics() {
        if (mCoordinator != null) {
            ConnectionsRegister reg = CaptureService.getConnsRegister();
            ConnectionScreenState cached = (reg != null) ? reg.getCachedScreenState() : null;
            if (cached != null) {
                assignMetrics(cached.metrics);
                return;
            }
            mCoordinator.requestRefresh(false);
            return;
        }

        if (mHandler != null) {
            mHandler.removeCallbacks(mUpdateMetricsRunnable);
            mHandler.postDelayed(mUpdateMetricsRunnable, 300);
        } else {
            doUpdateSummaryMetrics();
        }
    }

    private void doUpdateSummaryMetrics() {
        if (!isAdded() || getContext() == null)
            return;
        int total = (mAdapter != null) ? mAdapter.getItemCount() : 0;
        int active = 0;
        int blocked = 0;
        ConnectionsRegister reg = CaptureService.getConnsRegister();
        if (reg != null) {
            blocked = reg.getNumBlockedConnections() + reg.getNumMaliciousConnections();
        }
        if (mAdapter != null) {
            int count = mAdapter.getItemCount();
            for (int i = 0; i < count; i++) {
                ConnectionDescriptor conn = mAdapter.getItem(i);
                if (conn != null && conn.status < ConnectionDescriptor.CONN_STATUS_CLOSED)
                    active++;
            }
        }
        int closed = 0;
        ConnectionsRegister regAll = CaptureService.getConnsRegister();
        if (regAll != null) {
            int n = regAll.getConnCount();
            int act = 0, cls = 0;
            for (int i = 0; i < n; i++) {
                ConnectionDescriptor c = regAll.getConn(i);
                if (c == null) continue;
                if (c.status < ConnectionDescriptor.CONN_STATUS_CLOSED) act++; else cls++;
            }
            active = act;
            closed = cls;
            total = n;
        } else {
            closed = Math.max(0, total - active);
        }
        if (mSummaryActivePill != null)
            mSummaryActivePill.setText(getString(R.string.summary_active_format, active));
        if (mSummaryTotalPill != null)
            mSummaryTotalPill.setText(getString(R.string.summary_total_format, total));
        if (mSummaryClosedPill != null)
            mSummaryClosedPill.setText(getString(R.string.summary_closed_format, closed));
        if (mSummaryBlockedPill != null) {
            mSummaryBlockedPill.setText(getString(R.string.summary_blocked_format, blocked));
            mSummaryBlockedPill.setVisibility(blocked > 0 ? View.VISIBLE : View.GONE);
        }

        if (mCategoryChipGroup != null && reg != null) {
            FilterDescriptor.AppCategory[] cats = FilterDescriptor.AppCategory.values();
            FilterDescriptor[] probes = new FilterDescriptor[cats.length];
            int[] counts = new int[cats.length];
            for (int k = 0; k < cats.length; k++) {
                probes[k] = new FilterDescriptor();
                probes[k].appCategory = cats[k];
            }
            int regTotal = reg.getConnCount();
            boolean singleSocketMode = Prefs.isSingleSocketDiagnostics(requireContext());

            @SuppressWarnings("unchecked")
            java.util.Set<String>[] seenKeys = new java.util.Set[cats.length];
            for (int k = 0; k < cats.length; k++) {
                seenKeys[k] = new java.util.HashSet<>();
            }

            for (int i = 0; i < regTotal; i++) {
                ConnectionDescriptor c = reg.getConn(i);
                if (c == null) continue;
                for (int k = 0; k < cats.length; k++) {
                    if (probes[k].matches(c)) {
                        if (singleSocketMode) {
                            counts[k]++;
                        } else {
                            String key;
                            if (c.isDns()) {
                                String resolver = (c.dst_port == 53 || c.dst_port == 5353) ? c.dst_ip : c.src_ip;
                                String domain = (c.info != null && !c.info.isEmpty()) ? c.info : ((c.url != null) ? c.url : "");
                                while (domain.endsWith(".")) domain = domain.substring(0, domain.length() - 1);
                                key = "DNS:" + c.uid + ":" + resolver + ":" + domain.toLowerCase(Locale.ROOT);
                            } else {
                                String target = ConnectionsAdapter.getCanonicalTarget(c);
                                int dstPort = (c.dst_port == 123 || c.src_port == 123) ? 123
                                        : ((c.ipproto == 1 || c.ipproto == 58) ? 0 : c.dst_port);

                                if (c.is_blocked || c.isBlacklisted()) {
                                    key = "BLOCKED:" + c.uid + ":" + c.ipproto + ":" + target + ":" + dstPort;
                                } else if (cats[k] == FilterDescriptor.AppCategory.ACTIVE_ONLY) {
                                    key = "ACTIVE:" + c.uid + ":" + c.ipproto + ":" + target + ":" + dstPort;
                                } else if (cats[k] == FilterDescriptor.AppCategory.CLOSED) {
                                    key = "CLOSED:" + c.uid + ":" + c.ipproto + ":" + target + ":" + dstPort;
                                } else {
                                    key = "FLOW:" + c.uid + ":" + c.ipproto + ":" + target + ":" + dstPort;
                                }
                            }

                            if (seenKeys[k].add(key)) {
                                counts[k]++;
                            }
                        }
                    }
                }
            }
            if (!singleSocketMode) {
                active = counts[FilterDescriptor.AppCategory.ACTIVE_ONLY.ordinal()];
                closed = counts[FilterDescriptor.AppCategory.CLOSED.ordinal()];
                total = counts[FilterDescriptor.AppCategory.ALL.ordinal()];
                blocked = counts[FilterDescriptor.AppCategory.BLOCKED_ONLY.ordinal()];
                if (mSummaryActivePill != null)
                    mSummaryActivePill.setText(getString(R.string.summary_active_format, active));
                if (mSummaryTotalPill != null)
                    mSummaryTotalPill.setText(getString(R.string.summary_total_format, total));
                if (mSummaryClosedPill != null)
                    mSummaryClosedPill.setText(getString(R.string.summary_closed_format, closed));
                if (mSummaryBlockedPill != null) {
                    mSummaryBlockedPill.setText(getString(R.string.summary_blocked_format, blocked));
                    mSummaryBlockedPill.setVisibility(blocked > 0 ? View.VISIBLE : View.GONE);
                }
            }
            if (mChipCatAll != null) mChipCatAll.setText(getString(R.string.connection_all_count, counts[FilterDescriptor.AppCategory.ALL.ordinal()]));
            if (mChipCatUser != null) mChipCatUser.setText(getString(R.string.connection_user_count, counts[FilterDescriptor.AppCategory.USER.ordinal()]));
            if (mChipCatSystem != null) mChipCatSystem.setText(getString(R.string.connection_system_count, counts[FilterDescriptor.AppCategory.SYSTEM.ordinal()]));
            if (mChipCatDns != null) mChipCatDns.setText(getString(R.string.connection_dns_count, counts[FilterDescriptor.AppCategory.DNS.ordinal()]));
            if (mChipCatActive != null) mChipCatActive.setText(getString(R.string.connection_active_count, counts[FilterDescriptor.AppCategory.ACTIVE_ONLY.ordinal()]));
            if (mChipCatClosed != null) mChipCatClosed.setText(getString(R.string.connection_closed_count, counts[FilterDescriptor.AppCategory.CLOSED.ordinal()]));
            if (mChipCatBlocked != null) mChipCatBlocked.setText(getString(R.string.connection_blocked_count, counts[FilterDescriptor.AppCategory.BLOCKED_ONLY.ordinal()]));
            if (mChipCatWeb != null) mChipCatWeb.setText(getString(R.string.connection_web_count, counts[FilterDescriptor.AppCategory.WEB_ONLY.ordinal()]));
        }
    }

    private void recheckUntrackedConnections() {
        ConnectionsRegister reg = CaptureService.requireConnsRegister();
        if(reg.getUntrackedConnCount() > 0) {
            String info = String.format(getString(R.string.older_connections_notice), reg.getUntrackedConnCount());
            mOldConnectionsText.setText(info);
            mOldConnectionsText.setVisibility(View.VISIBLE);
        } else
            mOldConnectionsText.setVisibility(View.GONE);
    }

    @Override
    public void connectionsChanges(int num_connections) {
        if (mCoordinator != null) {
            mCoordinator.requestRefresh(false);
        } else {
            Utils.runOnUi(() -> {
                Log.d(TAG, "New connections size: " + num_connections);
                mAdapter.connectionsChanges(num_connections);
                recheckScroll();
                if(autoScroll)
                    scrollToBottom();
                recheckUntrackedConnections();
                updateSummaryMetrics();
            }, mHandler);
        }
    }

    @Override
    public void connectionsAdded(int start, ConnectionDescriptor []conns) {
        if (mCoordinator != null) {
            mCoordinator.requestRefresh(false);
        } else {
            mHandler.post(() -> {
                Log.d(TAG, "Add " + conns.length + " connections at " + start);
                mAdapter.connectionsAdded(start, conns);
                if(autoScroll)
                    scrollToBottom();
                recheckUntrackedConnections();
                recheckMaxConnectionSize();
                updateSummaryMetrics();
            });
        }
    }

    @Override
    public void connectionsRemoved(int start, ConnectionDescriptor []conns) {
        if (mCoordinator != null) {
            mCoordinator.requestRefresh(false);
        } else {
            mHandler.post(() -> {
                Log.d(TAG, "Remove " + conns.length + " connections at " + start);
                mAdapter.connectionsRemoved(start, conns);
                updateSummaryMetrics();
            });
        }
    }

    @Override
    public void connectionsUpdated(int[] positions) {
        if (mCoordinator != null) {
            mCoordinator.requestRefresh(false);
        } else {
            mHandler.post(() -> {
                mAdapter.connectionsUpdated(positions);
                recheckMaxConnectionSize();
                updateSummaryMetrics();
            });
        }
    }

    @Override
    public void onCreateMenu(@NonNull Menu menu, MenuInflater menuInflater) {
        menuInflater.inflate(R.menu.connections_menu, menu);

        mSave = menu.findItem(R.id.save);
        mMenuFilter = menu.findItem(R.id.edit_filter);
        mMenuItemSearch = menu.findItem(R.id.search);

        mSearchView = (SearchView) mMenuItemSearch.getActionView();
        mSearchView.setOnQueryTextListener(this);

        mMenuItemSearch.setOnActionExpandListener(new MenuItem.OnActionExpandListener() {
            @Override
            public boolean onMenuItemActionExpand(@NonNull MenuItem item) {
                mBackCallback.setEnabled(true);
                return true;
            }

            @Override
            public boolean onMenuItemActionCollapse(@NonNull MenuItem item) {
                mBackCallback.setEnabled(mActionMode != null);
                return true;
            }
        });

        if((mQueryToApply != null) && (!mQueryToApply.isEmpty())) {
            String query = mQueryToApply;
            mQueryToApply = null;
            setQuery(query);
        }

        MenuItem groupByAppItem = menu.findItem(R.id.toggle_group_by_app);
        if (groupByAppItem != null) {
            groupByAppItem.setChecked(Prefs.isGroupByApp(PreferenceManager.getDefaultSharedPreferences(requireContext())));
        }

        MenuItem singleSocketItem = menu.findItem(R.id.toggle_single_socket_mode);
        if (singleSocketItem != null) {
            singleSocketItem.setChecked(Prefs.isSingleSocketDiagnostics(requireContext()));
        }

        MenuItem hideSystemItem = menu.findItem(R.id.toggle_hide_system_traffic);
        if (hideSystemItem != null) {
            hideSystemItem.setChecked(Prefs.isHideSystemTraffic(PreferenceManager.getDefaultSharedPreferences(requireContext())));
        }

        MenuItem autoMoveItem = menu.findItem(R.id.toggle_auto_move_closed);
        if (autoMoveItem != null) {
            autoMoveItem.setChecked(Prefs.isAutoMoveClosed(PreferenceManager.getDefaultSharedPreferences(requireContext())));
        }

        refreshMenuIcons();
    }

    @Override
    public boolean onMenuItemSelected(@NonNull MenuItem item) {
        int id = item.getItemId();

        if(id == R.id.save) {
            openFileSelector();
            return true;
        } else if(id == R.id.sort_connections) {
            showSortDialog();
            return true;
        } else if(id == R.id.edit_filter) {
            Intent intent = new Intent(requireContext(), EditFilterActivity.class);
            intent.putExtra(EditFilterActivity.FILTER_DESCRIPTOR, mAdapter.mFilter);
            filterLauncher.launch(intent);
            return true;
        } else if(id == R.id.toggle_group_by_app) {
            SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(requireContext());
            boolean current = Prefs.isGroupByApp(sp);
            boolean newState = !current;
            sp.edit().putBoolean(Prefs.PREF_GROUP_BY_APP, newState).apply();
            item.setChecked(newState);
            if (mAdapter != null) {
                mAdapter.setGroupByApp(newState);
            }
            Toast.makeText(requireContext(), newState ? "Grouping connections by app" : "Showing all connections", Toast.LENGTH_SHORT).show();
            return true;
        } else if(id == R.id.toggle_single_socket_mode) {
            boolean current = Prefs.isSingleSocketDiagnostics(requireContext());
            boolean newState = !current;
            Prefs.setSingleSocketDiagnostics(requireContext(), newState);
            item.setChecked(newState);
            Utils.showToast(requireContext(), newState ? R.string.single_socket_mode_enabled : R.string.single_socket_mode_disabled);
            return true;
        } else if(id == R.id.toggle_hide_system_traffic) {
            SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(requireContext());
            boolean current = Prefs.isHideSystemTraffic(sp);
            boolean newState = !current;
            sp.edit().putBoolean(Prefs.PREF_HIDE_SYSTEM_TRAFFIC, newState).apply();
            item.setChecked(newState);
            refreshFilteredConnections();
            Toast.makeText(requireContext(), newState ? "Android system services hidden" : "Android system services visible", Toast.LENGTH_SHORT).show();
            return true;
        } else if(id == R.id.toggle_auto_move_closed) {
            SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(requireContext());
            boolean newState = !Prefs.isAutoMoveClosed(sp);
            sp.edit().putBoolean(Prefs.PREF_AUTO_MOVE_CLOSED, newState).apply();
            item.setChecked(newState);
            refreshFilteredConnections();
            Toast.makeText(requireContext(), newState ? "Closed services move to the Closed tab" : "Closed services stay in the main list", Toast.LENGTH_SHORT).show();
            return true;
        } else if (id == R.id.simulate_test_traffic) {
            simulateConnectionsAllCategories();
            return true;
        }

        return false;
    }

    private void simulateConnectionsAllCategories() {
        Context ctx = requireContext();
        ConnectionsRegister simReg = new ConnectionsRegister(ctx, 250);
        long now = System.currentTimeMillis();
        int incr = 1;
        List<ConnectionDescriptor> conns = new ArrayList<>();

        int chromeUid = 10273; // Google Docs (Installed User App)
        int waUid = 10282;     // WhatsApp (Installed User App)
        int ytUid = 10276;     // YouTube Music (Installed User App)
        int spUid = 10263;     // DocVault (Installed User App)
        int systemUid = 1000;  // Android OS System

        // 1. DNS Requests (Category: DNS) - Multiple duplicate queries
        for (int i = 0; i < 6; i++) {
            ConnectionDescriptor c = new ConnectionDescriptor(incr++, 4, 17, "10.0.0.2", "8.8.8.8", "US",
                    54000 + i, 53, 0, waUid, 1, false, now - (6 - i) * 2000L);
            c.info = "api.whatsapp.com";
            c.url = "api.whatsapp.com";
            c.l7proto = "DNS";
            c.sent_bytes = 68;
            c.rcvd_bytes = 142;
            c.status = ConnectionDescriptor.CONN_STATUS_CONNECTED;
            conns.add(c);
        }

        for (int i = 0; i < 4; i++) {
            ConnectionDescriptor c = new ConnectionDescriptor(incr++, 4, 17, "10.0.0.2", "1.1.1.1", "US",
                    54100 + i, 53, 0, chromeUid, 1, false, now - (4 - i) * 3000L);
            c.info = "www.google.com";
            c.url = "www.google.com";
            c.l7proto = "DNS";
            c.sent_bytes = 72;
            c.rcvd_bytes = 160;
            c.status = ConnectionDescriptor.CONN_STATUS_CONNECTED;
            conns.add(c);
        }

        for (int i = 0; i < 7; i++) {
            ConnectionDescriptor c = new ConnectionDescriptor(incr++, 4, 17, "10.0.0.2", "8.8.8.8", "US",
                    54200 + i, 53, 0, chromeUid, 1, false, now - (7 - i) * 1500L);
            c.info = "ads.admob.com";
            c.url = "ads.admob.com";
            c.l7proto = "DNS";
            c.sent_bytes = 64;
            c.rcvd_bytes = 0;
            c.is_blocked = true;
            c.block_reason = "Ad Tracker";
            c.status = ConnectionDescriptor.CONN_STATUS_CLOSED;
            conns.add(c);
        }

        // 2. User Apps & Web (Active sockets to google.com)
        for (int i = 0; i < 5; i++) {
            ConnectionDescriptor c = new ConnectionDescriptor(incr++, 4, 6, "10.0.0.2", "142.250.190.46", "US",
                    55000 + i, 443, 0, chromeUid, 1, false, now - (5 - i) * 4000L);
            c.info = "google.com";
            c.url = "google.com";
            c.l7proto = "HTTPS";
            c.sent_bytes = 2400;
            c.rcvd_bytes = 18500;
            c.status = ConnectionDescriptor.CONN_STATUS_CONNECTED;
            conns.add(c);
        }

        for (int i = 0; i < 4; i++) {
            ConnectionDescriptor c = new ConnectionDescriptor(incr++, 4, 6, "10.0.0.2", "157.240.241.60", "US",
                    55100 + i, 443, 0, waUid, 1, false, now - (4 - i) * 5000L);
            c.info = "api.whatsapp.com";
            c.url = "api.whatsapp.com";
            c.l7proto = "HTTPS";
            c.sent_bytes = 1200;
            c.rcvd_bytes = 4300;
            c.status = ConnectionDescriptor.CONN_STATUS_CONNECTED;
            conns.add(c);
        }

        for (int i = 0; i < 3; i++) {
            ConnectionDescriptor c = new ConnectionDescriptor(incr++, 4, 6, "10.0.0.2", "172.217.16.206", "US",
                    55200 + i, 443, 0, ytUid, 1, false, now - (3 - i) * 1000L);
            c.info = "rr1---sn-4g5ednks.googlevideo.com";
            c.url = "rr1---sn-4g5ednks.googlevideo.com";
            c.l7proto = "HTTPS";
            c.sent_bytes = 8500;
            c.rcvd_bytes = 154200;
            c.status = ConnectionDescriptor.CONN_STATUS_CONNECTED;
            conns.add(c);
        }

        // 3. System Services (UID 1000)
        for (int i = 0; i < 8; i++) {
            ConnectionDescriptor c = new ConnectionDescriptor(incr++, 4, 17, "10.0.0.2", "216.239.35.0", "US",
                    56000 + i, 123, 0, systemUid, 1, false, now - (8 - i) * 6000L);
            c.info = "time.android.com";
            c.url = "time.android.com";
            c.l7proto = "NTP";
            c.sent_bytes = 48;
            c.rcvd_bytes = 48;
            c.status = ConnectionDescriptor.CONN_STATUS_CLOSED;
            conns.add(c);
        }

        for (int i = 0; i < 4; i++) {
            ConnectionDescriptor c = new ConnectionDescriptor(incr++, 4, 6, "10.0.0.2", "172.217.16.195", "US",
                    56100 + i, 80, 0, systemUid, 1, false, now - (4 - i) * 8000L);
            c.info = "connectivitycheck.gstatic.com";
            c.url = "connectivitycheck.gstatic.com";
            c.l7proto = "HTTP";
            c.sent_bytes = 350;
            c.rcvd_bytes = 520;
            c.status = ConnectionDescriptor.CONN_STATUS_CLOSED;
            conns.add(c);
        }

        // 4. Closed flows (Spotify audio CDN)
        for (int i = 0; i < 6; i++) {
            ConnectionDescriptor c = new ConnectionDescriptor(incr++, 4, 6, "10.0.0.2", "104.154.127.126", "SE",
                    57000 + i, 443, 0, spUid, 1, false, now - (6 - i) * 10000L);
            c.info = "audio-ak.spotify.com";
            c.url = "audio-ak.spotify.com";
            c.l7proto = "HTTPS";
            c.sent_bytes = 3200;
            c.rcvd_bytes = 89000;
            c.status = ConnectionDescriptor.CONN_STATUS_CLOSED;
            conns.add(c);
        }

        // 5. Blocked flows (Malware / C2 Botnet)
        for (int i = 0; i < 15; i++) {
            ConnectionDescriptor c = new ConnectionDescriptor(incr++, 4, 6, "10.0.0.2", "185.220.101.5", "RU",
                    58000 + i, 443, 0, chromeUid, 1, false, now - (15 - i) * 1000L);
            c.info = "tracker.c2server.org";
            c.url = "tracker.c2server.org";
            c.l7proto = "HTTPS";
            c.is_blocked = true;
            c.block_reason = "Malware/C2 Botnet";
            c.status = ConnectionDescriptor.CONN_STATUS_CLOSED;
            conns.add(c);
        }

        for (int i = 0; i < 9; i++) {
            ConnectionDescriptor c = new ConnectionDescriptor(incr++, 4, 6, "10.0.0.2", "142.250.180.14", "US",
                    58100 + i, 443, 0, chromeUid, 1, false, now - (9 - i) * 1200L);
            c.info = "ads.doubleclick.net";
            c.url = "ads.doubleclick.net";
            c.l7proto = "HTTPS";
            c.is_blocked = true;
            c.block_reason = "Ad Tracker";
            c.status = ConnectionDescriptor.CONN_STATUS_CLOSED;
            conns.add(c);
        }

        // 6. Web traffic (Wikipedia & GitHub)
        for (int i = 0; i < 5; i++) {
            ConnectionDescriptor c = new ConnectionDescriptor(incr++, 4, 6, "10.0.0.2", "198.35.26.96", "US",
                    59000 + i, 443, 0, chromeUid, 1, false, now - (5 - i) * 7000L);
            c.info = "en.wikipedia.org";
            c.url = "en.wikipedia.org";
            c.l7proto = "HTTPS";
            c.sent_bytes = 1500;
            c.rcvd_bytes = 24000;
            c.status = ConnectionDescriptor.CONN_STATUS_CLOSED;
            conns.add(c);
        }
        for (int i = 0; i < 3; i++) {
            ConnectionDescriptor c = new ConnectionDescriptor(incr++, 4, 6, "10.0.0.2", "140.82.121.4", "US",
                    59100 + i, 443, 0, chromeUid, 1, false, now - (3 - i) * 2000L);
            c.info = "github.com";
            c.url = "github.com";
            c.l7proto = "HTTPS";
            c.sent_bytes = 2100;
            c.rcvd_bytes = 12000;
            c.status = ConnectionDescriptor.CONN_STATUS_CONNECTED;
            conns.add(c);
        }

        CaptureService.setSimulatedConnsRegister(simReg);
        simReg.newConnections(conns.toArray(new ConnectionDescriptor[0]));

        if (mCoordinator != null) {
            mCoordinator.setConnectionsRegister(simReg);
            mCoordinator.requestRefresh(true);
        } else {
            refreshFilteredConnections();
        }
        refreshEmptyText();
        Toast.makeText(ctx, "Simulated 79 connections across all 7 categories (merged)", Toast.LENGTH_SHORT).show();
    }

    private void showSortDialog() {
        if (mAdapter == null) return;
        String[] options = new String[] {
            getString(R.string.sort_recent_first),
            getString(R.string.sort_active_first),
            getString(R.string.sort_traffic_first),
            getString(R.string.sort_app_name)
        };
        int selectedIndex = mAdapter.getSortMode().ordinal();
        new com.google.android.material.dialog.MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.sort_by)
            .setSingleChoiceItems(options, selectedIndex, (dialog, which) -> {
                ConnectionsAdapter.SortMode[] modes = ConnectionsAdapter.SortMode.values();
                if (which >= 0 && which < modes.length) {
                    ConnectionsAdapter.SortMode selected = modes[which];
                    mAdapter.setSortMode(selected, mCoordinator == null);
                    if (mCoordinator != null) {
                        ConnectionScreenStateBuilder.SortMode bMode;
                        switch (selected) {
                            case ACTIVE: bMode = ConnectionScreenStateBuilder.SortMode.ACTIVE; break;
                            case BYTES: bMode = ConnectionScreenStateBuilder.SortMode.BYTES; break;
                            case NAME: bMode = ConnectionScreenStateBuilder.SortMode.NAME; break;
                            case RECENT:
                            default: bMode = ConnectionScreenStateBuilder.SortMode.RECENT; break;
                        }
                        mCoordinator.updateSortMode(bMode, true);
                    }
                }
                dialog.dismiss();
            })
            .setNegativeButton(android.R.string.cancel, null)
            .show();
    }

    private void refreshMenuIcons() {
        if(mSave == null)
            return;

        boolean is_enabled = (CaptureService.getConnsRegister() != null);

        mMenuItemSearch.setEnabled(is_enabled);
        mSave.setEnabled(is_enabled);
    }

    private void dumpCsv() {
        if(mCsvFname == null)
            return;

        Log.d(TAG, "Writing CSV file: " + mCsvFname);
        String dump = mAdapter.dumpConnectionsCsv(mActionMode != null);

        ExecutorService executor = Executors.newSingleThreadExecutor();
        Handler handler = new Handler(Looper.getMainLooper());
        final boolean[] cancelled = {false};

        AlertDialog.Builder builder = new AlertDialog.Builder(requireContext());
        builder.setTitle(R.string.exporting);
        builder.setMessage(R.string.export_in_progress);
        builder.setNegativeButton(android.R.string.cancel, (dialog, which) -> {
            Log.i(TAG, "Abort CSV export");
            cancelled[0] = true;
            executor.shutdownNow();
        });

        mAlertDialog = builder.create();
        mAlertDialog.setCanceledOnTouchOutside(false);
        mAlertDialog.show();

        mAlertDialog.setOnCancelListener(dialog -> {
            Log.i(TAG, "Abort CSV export (back button)");
            cancelled[0] = true;
            executor.shutdownNow();
        });
        mAlertDialog.setOnDismissListener(dialog -> mAlertDialog = null);

        final Uri csvFname = mCsvFname;
        mCsvFname = null;

        executor.execute(() -> {
            boolean success = false;

            try {
                OutputStream stream = requireActivity().getContentResolver().openOutputStream(csvFname, "rwt");

                if(stream != null) {
                    stream.write(dump.getBytes(StandardCharsets.UTF_8));
                    stream.close();
                    success = true;
                }
            } catch (IOException e) {
                if(!cancelled[0])
                    e.printStackTrace();
            }

            if(cancelled[0])
                return;

            final boolean result = success;
            final Utils.UriStat stat = result ? Utils.getUriStat(requireContext(), csvFname) : null;

            handler.post(() -> {
                if(mAlertDialog != null)
                    mAlertDialog.dismiss();

                if(result) {
                    if(stat != null) {
                        String msg = String.format(getString(R.string.file_saved_with_name), stat.name);
                        Toast.makeText(requireContext(), msg, Toast.LENGTH_SHORT).show();
                    } else
                        Utils.showToast(requireContext(), R.string.save_ok);
                } else
                    Utils.showToast(requireContext(), R.string.cannot_write_file);

                if(mActionMode != null)
                    mActionMode.finish();
            });
        });
    }

    public void openFileSelector() {
        boolean noFileDialog = false;
        String fname = Utils.getExportFileName(requireContext(), "csv");
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        intent.putExtra(Intent.EXTRA_TITLE, fname);

        if(Utils.supportsFileDialog(requireContext(), intent)) {
            try {
                csvFileLauncher.launch(intent);
            } catch (ActivityNotFoundException e) {
                noFileDialog = true;
            }
        } else
            noFileDialog = true;

        if(noFileDialog) {
            Log.w(TAG, "No app found to handle file selection");

            // Pick default path
            Uri uri = Utils.getDownloadsUri(requireContext(), fname);

            if(uri != null) {
                mCsvFname = uri;
                dumpCsv();
            } else
                Utils.showToastLong(requireContext(), R.string.no_activity_file_selection);
        }
    }

    private void csvFileResult(final ActivityResult result) {
        if (result.getResultCode() == Activity.RESULT_OK && result.getData() != null) {
            mCsvFname = result.getData().getData();
            dumpCsv();
        } else {
            mCsvFname = null;
        }
    }

    private void filterResult(final ActivityResult result) {
        if(result.getResultCode() == Activity.RESULT_OK && result.getData() != null) {
            FilterDescriptor descriptor = Utils.getSerializableExtra(result.getData(), EditFilterActivity.FILTER_DESCRIPTOR, FilterDescriptor.class);
            if(descriptor != null) {
                mAdapter.mFilter = descriptor;
                refreshFilteredConnections();
                refreshActiveFilter();
            }
        }
    }

    @Override
    public boolean onQueryTextSubmit(String query) { return true; }

    @Override
    public boolean onQueryTextChange(String newText) {
        if (mCoordinator != null) {
            mAdapter.setSearch(newText, false);
            mCoordinator.updateSearchQuery(newText, false);
        } else if (mAdapter != null) {
            mAdapter.setSearch(newText);
        }
        recheckScroll();
        refreshEmptyText();
        return true;
    }

    private void startSelectionMode(ConnectionDescriptor conn) {
        if(mActionMode != null)
            return;

        mActionMode = ((AppCompatActivity) requireActivity()).startSupportActionMode(mActionModeCallback);

        // find position of the connection and select it
        for(int i = 0; i < mAdapter.getItemCount(); i++) {
            ConnectionDescriptor c = mAdapter.getItem(i);
            if((c != null) && (c.incr_id == conn.incr_id)) {
                mAdapter.selectItem(i);
                break;
            }
        }

        updateActionModeTitle();
        updateBackCallback();
    }

    private void toggleSelection(int pos) {
        mAdapter.toggleSelection(pos);

        if(mAdapter.getSelectedCount() == 0) {
            if(mActionMode != null)
                mActionMode.finish();
        } else
            updateActionModeTitle();
    }

    private void updateActionModeTitle() {
        if(mActionMode != null)
            mActionMode.setTitle(getString(R.string.n_selected, mAdapter.getSelectedCount()));
    }

    private final ActionMode.Callback mActionModeCallback = new ActionMode.Callback() {
        @Override
        public boolean onCreateActionMode(ActionMode mode, Menu menu) {
            mode.getMenuInflater().inflate(R.menu.connections_cab, menu);
            return true;
        }

        @Override
        public boolean onPrepareActionMode(ActionMode mode, Menu menu) {
            return false;
        }

        @Override
        public boolean onActionItemClicked(ActionMode mode, MenuItem item) {
            int id = item.getItemId();

            if(id == R.id.select_all) {
                if(mAdapter.getSelectedCount() == mAdapter.getItemCount())
                    mode.finish();
                else {
                    mAdapter.selectAll();
                    updateActionModeTitle();
                }
                return true;
            } else if(id == R.id.save) {
                openFileSelector();
                return true;
            }

            return false;
        }

        @Override
        public void onDestroyActionMode(ActionMode mode) {
            mAdapter.clearSelection();
            mActionMode = null;
            updateBackCallback();
        }
    };

    public void clearFilters() {
        if(mAdapter != null) {
            mAdapter.mFilter = new FilterDescriptor();
            refreshFilteredConnections();
            refreshActiveFilter();
        }
    }
}
