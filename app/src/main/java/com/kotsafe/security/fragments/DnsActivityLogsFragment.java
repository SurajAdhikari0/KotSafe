/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
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

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.kotsafe.security.R;
import com.kotsafe.security.adapters.DnsActivityLogsAdapter;
import com.kotsafe.security.model.DnsActivityDbHelper;
import com.kotsafe.security.model.DnsActivityEntry;
import com.kotsafe.security.views.DnsDomainActionDialog;
import com.google.android.material.chip.ChipGroup;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class DnsActivityLogsFragment extends Fragment implements DnsActivityLogsAdapter.OnDnsItemClickListener, DnsDomainActionDialog.OnRuleChangedListener {
    private static final String TAG = "DnsActivityLogsFragment";

    private RecyclerView mRecyclerView;
    private DnsActivityLogsAdapter mAdapter;
    private View mEmptyState;
    private EditText mSearchInput;
    private ImageView mBtnClearSearch;
    private ChipGroup mChipGroup;

    private String mCurrentFilter = null; // null = ALL, "BLOCKED", "ALLOWED"
    private String mCurrentQuery = "";
    private final ExecutorService mExecutor = Executors.newSingleThreadExecutor();

    public static DnsActivityLogsFragment newInstance() {
        return new DnsActivityLogsFragment();
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        View root = inflater.inflate(R.layout.fragment_dns_activity_logs, container, false);

        mRecyclerView = root.findViewById(R.id.recycler_dns_logs);
        mEmptyState = root.findViewById(R.id.empty_state_dns);
        mSearchInput = root.findViewById(R.id.search_dns);
        mBtnClearSearch = root.findViewById(R.id.btn_clear_search_dns);
        mChipGroup = root.findViewById(R.id.dns_filter_chip_group);

        mAdapter = new DnsActivityLogsAdapter(requireContext(), this);
        mRecyclerView.setLayoutManager(new LinearLayoutManager(requireContext()));
        mRecyclerView.setAdapter(mAdapter);

        setupFilters();
        setupSearch();

        return root;
    }

    @Override
    public void onResume() {
        super.onResume();
        loadLogs();
    }

    private void setupFilters() {
        mChipGroup.setOnCheckedStateChangeListener((group, checkedIds) -> {
            if (checkedIds.isEmpty()) return;
            int id = checkedIds.get(0);
            if (id == R.id.chip_dns_blocked) {
                mCurrentFilter = DnsActivityEntry.STATUS_BLOCKED;
            } else if (id == R.id.chip_dns_allowed) {
                mCurrentFilter = DnsActivityEntry.STATUS_ALLOWED;
            } else {
                mCurrentFilter = null; // All
            }
            loadLogs();
        });
    }

    private void setupSearch() {
        mSearchInput.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                mCurrentQuery = s.toString().trim();
                mBtnClearSearch.setVisibility(mCurrentQuery.isEmpty() ? View.GONE : View.VISIBLE);
                loadLogs();
            }

            @Override
            public void afterTextChanged(Editable s) {}
        });

        mBtnClearSearch.setOnClickListener(v -> mSearchInput.setText(""));
    }

    public void loadLogs() {
        Context ctx = getContext();
        if (ctx == null || !isAdded()) return;
        final Context appContext = ctx.getApplicationContext();

        mExecutor.execute(() -> {
            DnsActivityDbHelper db = DnsActivityDbHelper.getInstance(appContext);
            List<DnsActivityEntry> results = db.queryLogs(mCurrentFilter, mCurrentQuery, 200, 0);

            if (getActivity() != null) {
                getActivity().runOnUiThread(() -> {
                    if (!isAdded()) return;
                    mAdapter.setLogs(results);
                    boolean empty = results.isEmpty();
                    mEmptyState.setVisibility(empty ? View.VISIBLE : View.GONE);
                    mRecyclerView.setVisibility(empty ? View.GONE : View.VISIBLE);
                });
            }
        });
    }

    @Override
    public void onDnsItemClick(DnsActivityEntry entry) {
        if (!isAdded() || isStateSaved()) return;
        DnsDomainActionDialog dialog = DnsDomainActionDialog.newInstance(entry);
        dialog.setOnRuleChangedListener(this);
        dialog.show(getParentFragmentManager(), DnsDomainActionDialog.TAG);
    }

    @Override
    public void onRuleChanged() {
        loadLogs();
    }
}
