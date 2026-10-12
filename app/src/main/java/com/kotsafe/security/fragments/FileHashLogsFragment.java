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

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.kotsafe.security.R;
import com.kotsafe.security.adapters.FileHashLogsAdapter;
import com.kotsafe.security.model.FileHashDbHelper;
import com.kotsafe.security.model.FileHashEntry;
import com.kotsafe.security.model.FileHashScanner;
import com.kotsafe.security.views.FileHashDetailsDialog;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.chip.ChipGroup;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class FileHashLogsFragment extends Fragment {
    private FileHashDbHelper mDbHelper;
    private FileHashScanner mScanner;
    private FileHashLogsAdapter mAdapter;
    private final ExecutorService mExecutor = Executors.newSingleThreadExecutor();
    private final Handler mMainHandler = new Handler(Looper.getMainLooper());

    private EditText mSearchBox;
    private ImageView mBtnClearSearch;
    private ChipGroup mChipGroup;
    private TextView mTextStatus;
    private MaterialButton mBtnScanNow;
    private LinearLayout mLayoutScanProgress;
    private ProgressBar mScanProgressBar;
    private TextView mTextScanProgress;
    private TextView mEmptyText;
    private RecyclerView mRecyclerView;

    private String mCurrentCategory = "ALL";
    private String mSearchQuery = "";

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_file_hash_logs, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        mDbHelper = FileHashDbHelper.getInstance(requireContext());
        mScanner = FileHashScanner.getInstance(requireContext());

        mSearchBox = view.findViewById(R.id.search_box);
        mBtnClearSearch = view.findViewById(R.id.btn_clear_search);
        mChipGroup = view.findViewById(R.id.chip_group_filters);
        mTextStatus = view.findViewById(R.id.text_status);
        mBtnScanNow = view.findViewById(R.id.btn_scan_now);
        mLayoutScanProgress = view.findViewById(R.id.layout_scan_progress);
        mScanProgressBar = view.findViewById(R.id.scan_progress_bar);
        mTextScanProgress = view.findViewById(R.id.text_scan_progress);
        mEmptyText = view.findViewById(R.id.empty_text);
        mRecyclerView = view.findViewById(R.id.recycler_file_hashes);

        mAdapter = new FileHashLogsAdapter(requireContext());
        mAdapter.setOnItemClickListener(entry -> {
            FileHashDetailsDialog dialog = FileHashDetailsDialog.newInstance(entry);
            dialog.show(getChildFragmentManager(), FileHashDetailsDialog.TAG);
        });

        mRecyclerView.setLayoutManager(new LinearLayoutManager(requireContext()));
        mRecyclerView.setAdapter(mAdapter);

        // Search Input
        mSearchBox.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {}
            @Override
            public void afterTextChanged(Editable s) {
                mSearchQuery = s.toString().trim();
                mBtnClearSearch.setVisibility(mSearchQuery.isEmpty() ? View.GONE : View.VISIBLE);
                loadHashes();
            }
        });

        mBtnClearSearch.setOnClickListener(v -> mSearchBox.setText(""));

        // Chip Filters
        mChipGroup.setOnCheckedStateChangeListener((group, checkedIds) -> {
            if (checkedIds.isEmpty()) return;
            int id = checkedIds.get(0);
            if (id == R.id.chip_services) {
                mCurrentCategory = "SERVICES";
            } else if (id == R.id.chip_user) {
                mCurrentCategory = "USER";
            } else if (id == R.id.chip_system) {
                mCurrentCategory = "SYSTEM";
            } else if (id == R.id.chip_threats) {
                mCurrentCategory = "THREATS";
            } else {
                mCurrentCategory = "ALL";
            }
            loadHashes();
        });

        // Scan Action
        mBtnScanNow.setOnClickListener(v -> triggerScan());

        loadHashes();

        // If database is empty, automatically kick off an initial background scan
        mExecutor.execute(() -> {
            if (mDbHelper.getCount() == 0) {
                mMainHandler.post(this::triggerScan);
            }
        });
    }

    private void triggerScan() {
        if (mScanner.isScanning()) {
            Toast.makeText(requireContext(), "Scan already running...", Toast.LENGTH_SHORT).show();
            return;
        }

        mLayoutScanProgress.setVisibility(View.VISIBLE);
        mBtnScanNow.setEnabled(false);

        mScanner.startFullScan(new FileHashScanner.ScanListener() {
            @Override
            public void onScanProgress(int current, int total, String currentItem) {
                mScanProgressBar.setMax(Math.max(total, 1));
                mScanProgressBar.setProgress(current);
                mTextScanProgress.setText("Hashing " + currentItem + " (" + current + "/" + total + ")...");
            }

            @Override
            public void onScanCompleted(int totalScanned, int skipped, int servicesCount) {
                mLayoutScanProgress.setVisibility(View.GONE);
                mBtnScanNow.setEnabled(true);
                Toast.makeText(requireContext(),
                        "Scan complete: " + totalScanned + " hashed, " + skipped + " skipped (" + servicesCount + " services)",
                        Toast.LENGTH_SHORT).show();
                loadHashes();
            }
        });
    }

    private void loadHashes() {
        mExecutor.execute(() -> {
            List<FileHashEntry> list = mDbHelper.queryHashes(mSearchQuery, mCurrentCategory, 200, 0);
            long totalCount = mDbHelper.getCount();
            long serviceCount = mDbHelper.getServiceCount();

            mMainHandler.post(() -> {
                if (!isAdded()) return;
                mAdapter.setEntries(list);
                mEmptyText.setVisibility(list.isEmpty() ? View.VISIBLE : View.GONE);
                mTextStatus.setText(totalCount + " apps hashed (" + serviceCount + " background services)");
            });
        });
    }
}
