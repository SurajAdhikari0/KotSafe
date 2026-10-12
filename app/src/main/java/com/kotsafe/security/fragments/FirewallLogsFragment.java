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

package com.kotsafe.security.fragments;

import android.content.Context;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.kotsafe.security.R;
import com.kotsafe.security.adapters.FirewallLogsAdapter;
import com.kotsafe.security.model.FirewallLogDbHelper;
import com.kotsafe.security.model.FirewallLogEntry;
import com.kotsafe.security.model.FirewallLogManager;
import com.kotsafe.security.model.ThreatIntelManager;
import com.kotsafe.security.views.FirewallLogDetailsDialog;
import com.google.android.material.chip.ChipGroup;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class FirewallLogsFragment extends Fragment implements FirewallLogManager.OnNewLogListener, FirewallLogsAdapter.OnLogItemClickListener {
    private static final String TAG = "FirewallLogsFragment";

    private RecyclerView mRecyclerView;
    private FirewallLogsAdapter mAdapter;
    private View mEmptyState;
    private EditText mSearchInput;
    private ImageView mBtnClearSearch;
    private ChipGroup mChipGroup;

    private String mCurrentFilter = "ALL";
    private String mCurrentQuery = "";
    private final ExecutorService mExecutor = Executors.newSingleThreadExecutor();

    public static final String ARG_INITIAL_FILTER = "initial_filter";

    public static FirewallLogsFragment newInstance() {
        return newInstance("ALL");
    }

    public static FirewallLogsFragment newInstance(String initialFilter) {
        FirewallLogsFragment fragment = new FirewallLogsFragment();
        Bundle args = new Bundle();
        args.putString(ARG_INITIAL_FILTER, initialFilter != null ? initialFilter : "ALL");
        fragment.setArguments(args);
        return fragment;
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        View root = inflater.inflate(R.layout.fragment_firewall_logs, container, false);

        mRecyclerView = root.findViewById(R.id.recycler_firewall_logs);
        mEmptyState = root.findViewById(R.id.empty_state_logs);
        mSearchInput = root.findViewById(R.id.search_logs);
        mBtnClearSearch = root.findViewById(R.id.btn_clear_search);
        mChipGroup = root.findViewById(R.id.filter_chip_group);

        mAdapter = new FirewallLogsAdapter(requireContext(), this);
        mRecyclerView.setLayoutManager(new LinearLayoutManager(requireContext()));
        mRecyclerView.setAdapter(mAdapter);

        setupFilters(root);
        setupSearch();

        TextView btnClearAll = root.findViewById(R.id.btn_clear_all_logs);
        btnClearAll.setOnClickListener(v -> confirmClearLogs());

        FirewallLogManager.getInstance(requireContext()).addListener(this);
        loadLogs();

        return root;
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        Context ctx = getContext();
        if (ctx != null) {
            FirewallLogManager.getInstance(ctx).removeListener(this);
        }
    }

    private void setupFilters(View root) {
        mChipGroup.setOnCheckedStateChangeListener((group, checkedIds) -> {
            if(checkedIds.isEmpty()) return;
            int id = checkedIds.get(0);
            if(id == R.id.chip_blocked) {
                mCurrentFilter = "BLOCKED";
            } else if(id == R.id.chip_allowed) {
                mCurrentFilter = "ALLOWED";
            } else if(id == R.id.chip_threats) {
                mCurrentFilter = "THREATS";
            } else if(id == R.id.chip_background) {
                mCurrentFilter = "BACKGROUND";
            } else if(id == R.id.chip_services) {
                mCurrentFilter = "SERVICES";
            } else {
                mCurrentFilter = "ALL";
            }
            loadLogs();
        });

        Bundle args = getArguments();
        if (args != null && args.containsKey(ARG_INITIAL_FILTER)) {
            String initFilter = args.getString(ARG_INITIAL_FILTER, "ALL");
            if ("BLOCKED".equalsIgnoreCase(initFilter)) {
                mCurrentFilter = "BLOCKED";
                mChipGroup.check(R.id.chip_blocked);
            } else if ("ALLOWED".equalsIgnoreCase(initFilter)) {
                mCurrentFilter = "ALLOWED";
                mChipGroup.check(R.id.chip_allowed);
            } else if ("THREATS".equalsIgnoreCase(initFilter)) {
                mCurrentFilter = "THREATS";
                mChipGroup.check(R.id.chip_threats);
            } else if ("BACKGROUND".equalsIgnoreCase(initFilter)) {
                mCurrentFilter = "BACKGROUND";
                mChipGroup.check(R.id.chip_background);
            } else if ("SERVICES".equalsIgnoreCase(initFilter)) {
                mCurrentFilter = "SERVICES";
                mChipGroup.check(R.id.chip_services);
            } else {
                mCurrentFilter = "ALL";
                mChipGroup.check(R.id.chip_all);
            }
        }
    }

    private void setupSearch() {
        mSearchInput.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                mCurrentQuery = s.toString();
                mBtnClearSearch.setVisibility(mCurrentQuery.isEmpty() ? View.GONE : View.VISIBLE);
                loadLogs();
            }

            @Override
            public void afterTextChanged(Editable s) {}
        });

        mBtnClearSearch.setOnClickListener(v -> mSearchInput.setText(""));
    }

    private void loadLogs() {
        Context ctx = getContext();
        if (ctx == null || !isAdded()) return;
        final Context appContext = ctx.getApplicationContext();

        mExecutor.execute(() -> {
            FirewallLogDbHelper db = FirewallLogDbHelper.getInstance(appContext);
            List<FirewallLogEntry> list = db.queryLogs(mCurrentFilter, mCurrentQuery, 300, 0);

            if(getActivity() != null) {
                getActivity().runOnUiThread(() -> {
                    if (!isAdded()) return;
                    mAdapter.setLogs(list);
                    updateEmptyState(list.isEmpty());
                });
            }
        });
    }

    private void updateEmptyState(boolean isEmpty) {
        mEmptyState.setVisibility(isEmpty ? View.VISIBLE : View.GONE);
        mRecyclerView.setVisibility(isEmpty ? View.GONE : View.VISIBLE);
    }

    private void confirmClearLogs() {
        new AlertDialog.Builder(requireContext())
                .setTitle("Clear Firewall Logs")
                .setMessage("Are you sure you want to delete all recorded firewall and security activity logs?")
                .setPositiveButton("Clear", (d, w) -> {
                    FirewallLogManager.getInstance(requireContext()).clearLogs();
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    @Override
    public void onNewLog(FirewallLogEntry entry) {
        if(getActivity() == null) return;
        getActivity().runOnUiThread(() -> {
            // Check if matches filter
            boolean matchesFilter = true;
            if("BLOCKED".equals(mCurrentFilter) && !entry.isBlocked()) matchesFilter = false;
            else if("ALLOWED".equals(mCurrentFilter) && entry.isBlocked()) matchesFilter = false;
            else if("THREATS".equals(mCurrentFilter) && !entry.isMalicious()) matchesFilter = false;
            else if("BACKGROUND".equals(mCurrentFilter) && !entry.isBackground) matchesFilter = false;
            else if("SERVICES".equals(mCurrentFilter) && !entry.isServiceApp) matchesFilter = false;

            if(matchesFilter && (mCurrentQuery.isEmpty() ||
                    (entry.appName != null && entry.appName.toLowerCase().contains(mCurrentQuery.toLowerCase())) ||
                    (entry.dstIp != null && entry.dstIp.contains(mCurrentQuery)) ||
                    (entry.domainOrUrl != null && entry.domainOrUrl.toLowerCase().contains(mCurrentQuery.toLowerCase())))) {
                mAdapter.addLogAtTop(entry);
                updateEmptyState(false);
                mRecyclerView.scrollToPosition(0);
            }
        });
    }

    @Override
    public void onLogsCleared() {
        if(getActivity() == null) return;
        getActivity().runOnUiThread(() -> {
            mAdapter.clear();
            updateEmptyState(true);
        });
    }

    @Override
    public void onLogItemClick(FirewallLogEntry entry) {
        if (!isAdded() || isStateSaved()) return;
        FirewallLogDetailsDialog dialog = FirewallLogDetailsDialog.newInstance(entry);
        dialog.show(getParentFragmentManager(), "firewall_log_details");
    }

    @Override
    public void onQuickThreatAnalyze(FirewallLogEntry entry) {
        onLogItemClick(entry);
    }
}
