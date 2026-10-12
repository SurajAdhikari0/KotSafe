/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 *
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.activities;

import android.annotation.SuppressLint;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.chip.Chip;
import com.google.android.material.chip.ChipGroup;
import com.kotsafe.security.R;
import com.kotsafe.security.dialogs.MitreRemediationBottomSheet;
import com.kotsafe.security.model.MitreMobileCatalog;
import com.kotsafe.security.model.MitreTechnique;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class MitreAttackActivity extends AppCompatActivity {

    private MitreAdapter mListAdapter;
    private MatrixColumnsAdapter mMatrixAdapter;
    private List<MitreTechnique> mAll = new ArrayList<>();
    private final List<MitreTechnique> mFiltered = new ArrayList<>();
    private final List<MatrixColumnData> mMatrixColumns = new ArrayList<>();

    private TextView mDetectedLabel, mTotalLabel, mMappingPercentLabel;
    private TextView mBadgeActiveThreats, mBadgeAnomalies, mBadgeDefended;
    private ProgressBar mMappingProgress;
    private View mEmptyState;
    private EditText mSearchInput;
    private ImageView mBtnClearSearch;
    private ChipGroup mChipGroup;
    private MaterialButton mBtnToggleViewMode;
    private RecyclerView mMatrixRecycler;
    private RecyclerView mListRecycler;

    private boolean mIsMatrixMode = true;
    private String mSearchQuery = "";
    private String mTacticFilter = null;        // null = all tactics
    private Boolean mDetectedFilter = null;     // null = all, true = mapped only, false = unmapped only

    public static class MatrixColumnData {
        public final MitreTechnique.Tactic tactic;
        public final int orderIndex;
        public final List<MitreTechnique> techniques = new ArrayList<>();

        public MatrixColumnData(MitreTechnique.Tactic tactic, int orderIndex) {
            this.tactic = tactic;
            this.orderIndex = orderIndex;
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_mitre_attack);

        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        if (getSupportActionBar() != null) getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        mDetectedLabel       = findViewById(R.id.detected_count_label);
        mTotalLabel          = findViewById(R.id.total_count_label);
        mMappingPercentLabel = findViewById(R.id.mapping_percent_label);
        mMappingProgress     = findViewById(R.id.mapping_progress);
        mBadgeActiveThreats  = findViewById(R.id.badge_active_threats);
        mBadgeAnomalies      = findViewById(R.id.badge_anomalies);
        mBadgeDefended       = findViewById(R.id.badge_defended);
        mEmptyState          = findViewById(R.id.empty_state);
        mSearchInput         = findViewById(R.id.search_input);
        mBtnClearSearch      = findViewById(R.id.btn_clear_search);
        mChipGroup           = findViewById(R.id.tactic_chips);
        mBtnToggleViewMode   = findViewById(R.id.btn_toggle_view_mode);
        mMatrixRecycler      = findViewById(R.id.matrix_columns_recycler);
        mListRecycler        = findViewById(R.id.attack_list);

        // Setup Matrix Columns RecyclerView (Horizontal scrolling)
        mMatrixRecycler.setLayoutManager(new LinearLayoutManager(this, LinearLayoutManager.HORIZONTAL, false));
        mMatrixAdapter = new MatrixColumnsAdapter(mMatrixColumns);
        mMatrixRecycler.setAdapter(mMatrixAdapter);

        // Setup List RecyclerView (Vertical scrolling)
        mListRecycler.setLayoutManager(new LinearLayoutManager(this));
        mListAdapter = new MitreAdapter(mFiltered);
        mListRecycler.setAdapter(mListAdapter);

        // View Mode Toggle
        updateViewModeDisplay();
        mBtnToggleViewMode.setOnClickListener(v -> {
            mIsMatrixMode = !mIsMatrixMode;
            updateViewModeDisplay();
        });

        // Search text watcher
        mSearchInput.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {
                mSearchQuery = s.toString();
                mBtnClearSearch.setVisibility(mSearchQuery.isEmpty() ? View.GONE : View.VISIBLE);
                applyFilter();
            }
            @Override public void afterTextChanged(Editable s) {}
        });

        mBtnClearSearch.setOnClickListener(v -> {
            mSearchInput.setText("");
            mSearchQuery = "";
        });

        // Filter chips listener
        mChipGroup.setOnCheckedStateChangeListener((group, checked) -> {
            if (checked.isEmpty()) return;
            int id = checked.get(0);

            mTacticFilter = null;
            mDetectedFilter = null;

            if (id == R.id.chip_filter_all) {
                // all
            } else if (id == R.id.chip_filter_mapped) {
                mDetectedFilter = Boolean.TRUE;
            } else if (id == R.id.chip_filter_unmapped) {
                mDetectedFilter = Boolean.FALSE;
            } else if (id == R.id.chip_tactic_c2) {
                mTacticFilter = MitreTechnique.Tactic.C2.name();
            } else if (id == R.id.chip_tactic_exfil) {
                mTacticFilter = MitreTechnique.Tactic.EXFIL.name();
            } else if (id == R.id.chip_tactic_defense) {
                mTacticFilter = MitreTechnique.Tactic.DEFENSE_EVADE.name();
            } else if (id == R.id.chip_tactic_discovery) {
                mTacticFilter = MitreTechnique.Tactic.DISCOVERY.name();
            } else if (id == R.id.chip_tactic_initial) {
                mTacticFilter = MitreTechnique.Tactic.INITIAL_ACCESS.name();
            } else if (id == R.id.chip_tactic_execution) {
                mTacticFilter = MitreTechnique.Tactic.EXECUTION.name();
            } else if (id == R.id.chip_tactic_persistence) {
                mTacticFilter = MitreTechnique.Tactic.PERSISTENCE.name();
            } else if (id == R.id.chip_tactic_privesc) {
                mTacticFilter = MitreTechnique.Tactic.PRIVILEGE_ESC.name();
            } else if (id == R.id.chip_tactic_credential) {
                mTacticFilter = MitreTechnique.Tactic.CREDENTIAL.name();
            } else if (id == R.id.chip_tactic_collection) {
                mTacticFilter = MitreTechnique.Tactic.COLLECTION.name();
            } else if (id == R.id.chip_tactic_impact) {
                mTacticFilter = MitreTechnique.Tactic.IMPACT.name();
            }

            applyFilter();
        });

        // Reset filters button
        findViewById(R.id.btn_reset_filters).setOnClickListener(v -> {
            mSearchInput.setText("");
            mSearchQuery = "";
            Chip allChip = findViewById(R.id.chip_filter_all);
            if (allChip != null) allChip.setChecked(true);
        });

        loadTechniques();
        applyFilter();
    }

    private void updateViewModeDisplay() {
        if (mIsMatrixMode) {
            mMatrixRecycler.setVisibility(View.VISIBLE);
            mListRecycler.setVisibility(View.GONE);
            mBtnToggleViewMode.setText("📋 List Mode");
        } else {
            mMatrixRecycler.setVisibility(View.GONE);
            mListRecycler.setVisibility(View.VISIBLE);
            mBtnToggleViewMode.setText("🗺️ Matrix Mode");
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        loadTechniques();
        applyFilter();
    }

    private void loadTechniques() {
        mAll = MitreTechnique.getTechniquesWithMappedAlerts(this);
    }

    @SuppressLint("NotifyDataSetChanged")
    private void applyFilter() {
        mFiltered.clear();
        for (MitreTechnique t : mAll) {
            if (t.matchesFilter(mSearchQuery, mTacticFilter, mDetectedFilter)) {
                mFiltered.add(t);
            }
        }
        mListAdapter.notifyDataSetChanged();

        // Populate Matrix columns
        mMatrixColumns.clear();
        MitreTechnique.Tactic[] orderedTactics = {
                MitreTechnique.Tactic.INITIAL_ACCESS,
                MitreTechnique.Tactic.EXECUTION,
                MitreTechnique.Tactic.PERSISTENCE,
                MitreTechnique.Tactic.PRIVILEGE_ESC,
                MitreTechnique.Tactic.DEFENSE_EVADE,
                MitreTechnique.Tactic.CREDENTIAL,
                MitreTechnique.Tactic.DISCOVERY,
                MitreTechnique.Tactic.COLLECTION,
                MitreTechnique.Tactic.C2,
                MitreTechnique.Tactic.EXFIL,
                MitreTechnique.Tactic.IMPACT
        };

        int colIdx = 1;
        for (MitreTechnique.Tactic tac : orderedTactics) {
            MatrixColumnData col = new MatrixColumnData(tac, colIdx++);
            for (MitreTechnique t : mFiltered) {
                if (t.tactic == tac) {
                    col.techniques.add(t);
                }
            }
            if (!col.techniques.isEmpty() || (mSearchQuery.isEmpty() && mTacticFilter == null && mDetectedFilter == null)) {
                mMatrixColumns.add(col);
            }
        }
        mMatrixAdapter.notifyDataSetChanged();

        // Calculate Posture Metrics
        int total = mAll.size();
        int activeThreats = 0;
        int anomalies = 0;
        int defended = 0;

        for (MitreTechnique t : mAll) {
            if (t.statusLevel == MitreTechnique.STATUS_ACTIVE_THREAT) {
                activeThreats++;
            } else if (t.statusLevel == MitreTechnique.STATUS_SUSPICIOUS) {
                anomalies++;
            } else if (t.statusLevel == MitreTechnique.STATUS_DEFENDED) {
                defended++;
            }
        }

        int score = 100 - (activeThreats * 15) - (anomalies * 5);
        if (score < 10) score = 10;

        mBadgeActiveThreats.setText("🔴 " + activeThreats + " Threats");
        mBadgeAnomalies.setText("🟡 " + anomalies + " Anomalies");
        mBadgeDefended.setText("🟢 " + (defended > 0 ? defended : total) + " Defended");

        if (activeThreats > 0) {
            mDetectedLabel.setText("DEFENSIVE POSTURE: CRITICAL THREATS (" + activeThreats + ")");
            mDetectedLabel.setTextColor(0xFFEF4444);
            mMappingProgress.setProgressTintList(ColorStateList.valueOf(0xFFEF4444));
        } else if (anomalies > 0) {
            mDetectedLabel.setText("DEFENSIVE POSTURE: ELEVATED ANOMALIES (" + anomalies + ")");
            mDetectedLabel.setTextColor(0xFFF59E0B);
            mMappingProgress.setProgressTintList(ColorStateList.valueOf(0xFFF59E0B));
        } else {
            mDetectedLabel.setText("DEFENSIVE POSTURE: HARDENED (ALL SAFE)");
            mDetectedLabel.setTextColor(0xFF10B981);
            mMappingProgress.setProgressTintList(ColorStateList.valueOf(0xFF10B981));
        }

        mTotalLabel.setText(mFiltered.size() + " shown / " + total + " total");
        mMappingPercentLabel.setText(score + "% Posture");
        mMappingProgress.setProgress(score);

        if (mFiltered.isEmpty()) {
            mEmptyState.setVisibility(View.VISIBLE);
            mMatrixRecycler.setVisibility(View.GONE);
            mListRecycler.setVisibility(View.GONE);
        } else {
            mEmptyState.setVisibility(View.GONE);
            updateViewModeDisplay();
        }
    }

    private void openRemediationSheet(MitreTechnique t) {
        MitreRemediationBottomSheet.show(this, t, updated -> applyFilter());
    }

    // ── Adapter for Horizontal Matrix Columns ────────────────────────────────

    private class MatrixColumnsAdapter extends RecyclerView.Adapter<MatrixColumnsAdapter.ColViewHolder> {
        private final List<MatrixColumnData> mCols;

        MatrixColumnsAdapter(List<MatrixColumnData> cols) {
            mCols = cols;
        }

        @NonNull
        @Override
        public ColViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View v = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_mitre_matrix_column, parent, false);
            return new ColViewHolder(v);
        }

        @Override
        public void onBindViewHolder(@NonNull ColViewHolder h, int position) {
            MatrixColumnData col = mCols.get(position);
            h.tvTitle.setText(col.tactic.label);
            h.tvOrder.setText(String.valueOf(col.orderIndex));
            h.tvCount.setText(String.valueOf(col.techniques.size()));

            try {
                h.headerContainer.setBackgroundColor(Color.parseColor(col.tactic.color));
            } catch (Exception ignored) {}

            h.rvColumnCards.setLayoutManager(new LinearLayoutManager(h.itemView.getContext()));
            h.rvColumnCards.setAdapter(new MatrixCardsAdapter(col.techniques));
        }

        @Override
        public int getItemCount() {
            return mCols.size();
        }

        class ColViewHolder extends RecyclerView.ViewHolder {
            View headerContainer;
            TextView tvOrder, tvTitle, tvCount;
            RecyclerView rvColumnCards;

            ColViewHolder(@NonNull View itemView) {
                super(itemView);
                headerContainer = itemView.findViewById(R.id.column_header_container);
                tvOrder = itemView.findViewById(R.id.column_tactic_order);
                tvTitle = itemView.findViewById(R.id.column_tactic_title);
                tvCount = itemView.findViewById(R.id.column_technique_count);
                rvColumnCards = itemView.findViewById(R.id.column_recycler_view);
            }
        }
    }

    // ── Adapter for Techniques inside a Column ───────────────────────────────

    private class MatrixCardsAdapter extends RecyclerView.Adapter<MatrixCardsAdapter.CardViewHolder> {
        private final List<MitreTechnique> mCards;

        MatrixCardsAdapter(List<MitreTechnique> cards) {
            mCards = cards;
        }

        @NonNull
        @Override
        public CardViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View v = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_mitre_matrix_card, parent, false);
            return new CardViewHolder(v);
        }

        @Override
        public void onBindViewHolder(@NonNull CardViewHolder h, int position) {
            MitreTechnique t = mCards.get(position);
            h.tvId.setText(t.id);
            h.tvName.setText(t.name);
            h.tvD3fend.setText("🛡️ " + t.d3fendId + " " + t.d3fendName);
            h.tvStatus.setText(t.getStatusBadgeLabel());
            h.tvStatus.setBackgroundTintList(ColorStateList.valueOf(t.getStatusColor()));

            if (t.getMappedAlertCount() > 0) {
                h.tvAlertCount.setVisibility(View.VISIBLE);
                h.tvAlertCount.setText("⚠️ " + t.getMappedAlertCount() + " INCIDENT" + (t.getMappedAlertCount() > 1 ? "S" : ""));
            } else {
                h.tvAlertCount.setVisibility(View.GONE);
            }

            h.itemView.setOnClickListener(v -> openRemediationSheet(t));
        }

        @Override
        public int getItemCount() {
            return mCards.size();
        }

        class CardViewHolder extends RecyclerView.ViewHolder {
            TextView tvId, tvName, tvD3fend, tvStatus, tvAlertCount;

            CardViewHolder(@NonNull View itemView) {
                super(itemView);
                tvId = itemView.findViewById(R.id.matrix_technique_id);
                tvName = itemView.findViewById(R.id.matrix_technique_name);
                tvD3fend = itemView.findViewById(R.id.matrix_d3fend_chip);
                tvStatus = itemView.findViewById(R.id.matrix_status_pill);
                tvAlertCount = itemView.findViewById(R.id.matrix_alert_count_badge);
            }
        }
    }

    // ── Adapter for Standard List Mode ───────────────────────────────────────

    private class MitreAdapter extends RecyclerView.Adapter<MitreAdapter.VH> {
        private final List<MitreTechnique> mData;

        MitreAdapter(List<MitreTechnique> data) {
            mData = data;
        }

        @NonNull
        @Override
        public VH onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View v = LayoutInflater.from(parent.getContext()).inflate(R.layout.mitre_attack_item, parent, false);
            return new VH(v);
        }

        @Override
        public void onBindViewHolder(@NonNull VH h, int position) {
            MitreTechnique t = mData.get(position);
            h.bind(t);
        }

        @Override
        public int getItemCount() {
            return mData.size();
        }

        class VH extends RecyclerView.ViewHolder {
            TextView tvTactic, tvId, tvName, tvDesc, tvMitigation, tvEvidence, tvMappedPill;

            VH(@NonNull View itemView) {
                super(itemView);
                tvTactic     = itemView.findViewById(R.id.tactic_badge);
                tvId         = itemView.findViewById(R.id.technique_id);
                tvName       = itemView.findViewById(R.id.technique_name);
                tvDesc       = itemView.findViewById(R.id.technique_desc);
                tvMitigation = itemView.findViewById(R.id.mitigation_text);
                tvEvidence   = itemView.findViewById(R.id.evidence_text);
                tvMappedPill = itemView.findViewById(R.id.mapped_pill);
            }

            void bind(MitreTechnique t) {
                tvTactic.setText(t.tactic.label);
                try {
                    tvTactic.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor(t.tactic.color)));
                } catch (Exception ignored) {}

                tvId.setText(t.id);
                tvName.setText(t.name);
                tvDesc.setText(t.description);

                if (tvMitigation != null) {
                    tvMitigation.setText("Mitigation: " + t.mitigation + " [D3FEND: " + t.d3fendId + "]");
                }

                if (tvEvidence != null) {
                    tvEvidence.setText(t.evidence);
                }

                if (tvMappedPill != null) {
                    tvMappedPill.setVisibility(t.isDetected ? View.VISIBLE : View.GONE);
                    tvMappedPill.setText(t.getStatusBadgeLabel());
                    tvMappedPill.setBackgroundTintList(ColorStateList.valueOf(t.getStatusColor()));
                }

                itemView.setOnClickListener(v -> openRemediationSheet(t));
            }
        }
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
}
