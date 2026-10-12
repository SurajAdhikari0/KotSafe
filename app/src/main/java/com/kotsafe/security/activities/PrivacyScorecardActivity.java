package com.kotsafe.security.activities;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.widget.Toolbar;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.chip.ChipGroup;
import com.kotsafe.security.CaptureService;
import com.kotsafe.security.ConnectionsRegister;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.AppPrivacyScorecardEngine;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class PrivacyScorecardActivity extends BaseActivity {

    private static final String TAG = "PrivacyScorecardAct";

    private ProgressBar mScanProgress;
    private TextView mTvFleetGrade;
    private TextView mTvFleetScore;
    private TextView mTvCountApps;
    private TextView mTvCountTrackers;
    private TextView mTvCountCleartext;
    private TextView mTvCountHighRisk;
    private RecyclerView mRvScorecards;
    private TextView mTvEmpty;
    private ChipGroup mChipGroupFilter;

    private final List<AppScoreItem> mAllItems = new ArrayList<>();
    private final List<AppScoreItem> mDisplayedItems = new ArrayList<>();
    private ScorecardAdapter mAdapter;
    private final ExecutorService mExecutor = Executors.newSingleThreadExecutor();
    private final Handler mMainHandler = new Handler(Looper.getMainLooper());

    private String mCurrentFilter = "ALL";

    public static class AppScoreItem {
        public final int uid;
        public final String packageName;
        public final String label;
        public final Drawable icon;
        public final AppPrivacyScorecardEngine.ScorecardResult result;

        public AppScoreItem(int uid, String packageName, String label, Drawable icon,
                            AppPrivacyScorecardEngine.ScorecardResult result) {
            this.uid = uid;
            this.packageName = packageName;
            this.label = label;
            this.icon = icon;
            this.result = result;
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_privacy_scorecard);

        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
            getSupportActionBar().setTitle("Privacy Health Scorecard");
        }

        initViews();
        loadScorecards();
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void initViews() {
        mScanProgress = findViewById(R.id.scan_progress);
        mTvFleetGrade = findViewById(R.id.tv_fleet_grade);
        mTvFleetScore = findViewById(R.id.tv_fleet_score);
        mTvCountApps = findViewById(R.id.tv_count_apps);
        mTvCountTrackers = findViewById(R.id.tv_count_trackers);
        mTvCountCleartext = findViewById(R.id.tv_count_cleartext);
        mTvCountHighRisk = findViewById(R.id.tv_count_high_risk);
        mTvEmpty = findViewById(R.id.tv_empty);

        mRvScorecards = findViewById(R.id.rv_scorecards);
        mRvScorecards.setLayoutManager(new LinearLayoutManager(this));
        mAdapter = new ScorecardAdapter(mDisplayedItems, item -> {
            Intent intent = new Intent(PrivacyScorecardActivity.this, AppDetailsActivity.class);
            intent.putExtra(AppDetailsActivity.APP_UID_EXTRA, item.uid);
            startActivity(intent);
        });
        mRvScorecards.setAdapter(mAdapter);

        mChipGroupFilter = findViewById(R.id.chip_group_filter);
        mChipGroupFilter.setOnCheckedChangeListener((group, checkedId) -> {
            if (checkedId == R.id.chip_high_risk) {
                mCurrentFilter = "HIGH_RISK";
            } else if (checkedId == R.id.chip_invasive) {
                mCurrentFilter = "INVASIVE";
            } else if (checkedId == R.id.chip_moderate) {
                mCurrentFilter = "MODERATE";
            } else if (checkedId == R.id.chip_excellent) {
                mCurrentFilter = "EXCELLENT";
            } else {
                mCurrentFilter = "ALL";
            }
            applyFilter();
        });
    }

    private void loadScorecards() {
        mScanProgress.setVisibility(View.VISIBLE);
        mExecutor.execute(() -> {
            PackageManager pm = getPackageManager();
            List<ApplicationInfo> installedApps = pm.getInstalledApplications(PackageManager.GET_META_DATA);
            List<AppScoreItem> items = new ArrayList<>();
            ConnectionsRegister reg = CaptureService.getConnsRegister();

            int totalScore = 0;
            int totalTrackers = 0;
            int totalCleartext = 0;
            int totalHighRisk = 0;

            for (ApplicationInfo appInfo : installedApps) {
                // Filter out non-launchable background system packages to highlight apps user cares about
                if (Utils.classifyAppInstall(appInfo) == Utils.AppInstallClass.SYSTEM
                    && pm.getLaunchIntentForPackage(appInfo.packageName) == null) {
                    continue;
                }

                String label;
                try {
                    label = pm.getApplicationLabel(appInfo).toString();
                } catch (Exception e) {
                    label = appInfo.packageName;
                }

                Drawable icon;
                try {
                    icon = pm.getApplicationIcon(appInfo);
                } catch (Exception e) {
                    icon = ContextCompat.getDrawable(this, R.drawable.ic_apps);
                }

                List<AppPrivacyScorecardEngine.ConnectionRecord> records = (reg != null)
                        ? reg.getPrivacyRecordsForUid(appInfo.uid) : new ArrayList<>();

                AppPrivacyScorecardEngine.ScorecardResult res =
                        AppPrivacyScorecardEngine.evaluate(this, appInfo.packageName, records);

                totalScore += res.score;
                totalTrackers += res.trackerDomainsFound;
                if (res.hasCleartextHttp) totalCleartext++;
                if (res.score < 40) totalHighRisk++;

                items.add(new AppScoreItem(appInfo.uid, appInfo.packageName, label, icon, res));
            }

            // Sort from lowest score (highest risk) to highest score
            Collections.sort(items, (a, b) -> Integer.compare(a.result.score, b.result.score));

            final int appCount = items.size();
            final int avgScore = (appCount > 0) ? (totalScore / appCount) : 100;
            final int finalTrackers = totalTrackers;
            final int finalCleartext = totalCleartext;
            final int finalHighRisk = totalHighRisk;

            mMainHandler.post(() -> {
                mScanProgress.setVisibility(View.GONE);
                mAllItems.clear();
                mAllItems.addAll(items);

                mTvFleetScore.setText(avgScore + "/100");
                if (avgScore >= 85) {
                    mTvFleetGrade.setText("🟢 EXCELLENT");
                    mTvFleetGrade.setTextColor(ContextCompat.getColor(this, R.color.ok));
                    mTvFleetScore.setTextColor(ContextCompat.getColor(this, R.color.ok));
                } else if (avgScore >= 65) {
                    mTvFleetGrade.setText("🟡 MODERATE");
                    mTvFleetGrade.setTextColor(ContextCompat.getColor(this, R.color.warning));
                    mTvFleetScore.setTextColor(ContextCompat.getColor(this, R.color.warning));
                } else if (avgScore >= 40) {
                    mTvFleetGrade.setText("🟠 INVASIVE");
                    mTvFleetGrade.setTextColor(Color.parseColor("#FB8C00"));
                    mTvFleetScore.setTextColor(Color.parseColor("#FB8C00"));
                } else {
                    mTvFleetGrade.setText("🔴 HIGH RISK");
                    mTvFleetGrade.setTextColor(ContextCompat.getColor(this, R.color.statusError));
                    mTvFleetScore.setTextColor(ContextCompat.getColor(this, R.color.statusError));
                }

                mTvCountApps.setText(String.valueOf(appCount));
                mTvCountTrackers.setText(String.valueOf(finalTrackers));
                mTvCountCleartext.setText(String.valueOf(finalCleartext));
                mTvCountHighRisk.setText(String.valueOf(finalHighRisk));

                applyFilter();
            });
        });
    }

    private void applyFilter() {
        mDisplayedItems.clear();
        for (AppScoreItem item : mAllItems) {
            if ("ALL".equals(mCurrentFilter)) {
                mDisplayedItems.add(item);
            } else if (mCurrentFilter.equals(item.result.grade)) {
                mDisplayedItems.add(item);
            }
        }
        mAdapter.notifyDataSetChanged();
        mTvEmpty.setVisibility(mDisplayedItems.isEmpty() ? View.VISIBLE : View.GONE);
    }

    // ── Adapter ───────────────────────────────────────────────────────────────

    public interface OnItemClickListener {
        void onItemClick(AppScoreItem item);
    }

    private static class ScorecardAdapter extends RecyclerView.Adapter<ScorecardAdapter.ViewHolder> {
        private final List<AppScoreItem> mItems;
        private final OnItemClickListener mListener;

        ScorecardAdapter(List<AppScoreItem> items, OnItemClickListener listener) {
            this.mItems = items;
            this.mListener = listener;
        }

        @NonNull
        @Override
        public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View v = LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.item_privacy_scorecard_app, parent, false);
            return new ViewHolder(v);
        }

        @Override
        public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
            AppScoreItem item = mItems.get(position);
            Context ctx = holder.itemView.getContext();

            holder.ivIcon.setImageDrawable(item.icon);
            holder.tvLabel.setText(item.label);
            holder.tvPackage.setText(item.packageName);

            holder.tvScoreNumber.setText(String.valueOf(item.result.score));
            holder.tvScoreGrade.setText(item.result.grade);

            if (item.result.score >= 85) {
                holder.tvScoreNumber.setTextColor(ContextCompat.getColor(ctx, R.color.ok));
                holder.tvScoreGrade.setTextColor(ContextCompat.getColor(ctx, R.color.ok));
            } else if (item.result.score >= 65) {
                holder.tvScoreNumber.setTextColor(ContextCompat.getColor(ctx, R.color.warning));
                holder.tvScoreGrade.setTextColor(ContextCompat.getColor(ctx, R.color.warning));
            } else if (item.result.score >= 40) {
                holder.tvScoreNumber.setTextColor(Color.parseColor("#FB8C00"));
                holder.tvScoreGrade.setTextColor(Color.parseColor("#FB8C00"));
            } else {
                holder.tvScoreNumber.setTextColor(ContextCompat.getColor(ctx, R.color.statusError));
                holder.tvScoreGrade.setTextColor(ContextCompat.getColor(ctx, R.color.statusError));
            }

            if (item.result.trackerDomainsFound > 0) {
                holder.tagTrackers.setText(item.result.trackerDomainsFound + " Trackers");
                holder.tagTrackers.setVisibility(View.VISIBLE);
            } else {
                holder.tagTrackers.setVisibility(View.GONE);
            }

            if (item.result.hasCleartextHttp) {
                holder.tagCleartext.setVisibility(View.VISIBLE);
            } else {
                holder.tagCleartext.setVisibility(View.GONE);
            }

            if (item.result.dangerousPermissions > 0) {
                holder.tagPerms.setText(item.result.dangerousPermissions + " Sensitive Perms");
                holder.tagPerms.setVisibility(View.VISIBLE);
            } else {
                holder.tagPerms.setVisibility(View.GONE);
            }

            holder.itemView.setOnClickListener(v -> mListener.onItemClick(item));
        }

        @Override
        public int getItemCount() {
            return mItems.size();
        }

        static class ViewHolder extends RecyclerView.ViewHolder {
            ImageView ivIcon;
            TextView tvLabel;
            TextView tvPackage;
            TextView tagTrackers;
            TextView tagCleartext;
            TextView tagPerms;
            TextView tvScoreNumber;
            TextView tvScoreGrade;

            ViewHolder(@NonNull View itemView) {
                super(itemView);
                ivIcon = itemView.findViewById(R.id.app_icon);
                tvLabel = itemView.findViewById(R.id.app_label);
                tvPackage = itemView.findViewById(R.id.app_package);
                tagTrackers = itemView.findViewById(R.id.tag_trackers);
                tagCleartext = itemView.findViewById(R.id.tag_cleartext);
                tagPerms = itemView.findViewById(R.id.tag_perms);
                tvScoreNumber = itemView.findViewById(R.id.tv_score_number);
                tvScoreGrade = itemView.findViewById(R.id.tv_score_grade);
            }
        }
    }
}
