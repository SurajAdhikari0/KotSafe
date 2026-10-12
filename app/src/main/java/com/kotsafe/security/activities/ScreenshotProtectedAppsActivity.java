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

package com.kotsafe.security.activities;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.AsyncTask;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.PhysicalSecurityManager;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Activity that lets the user pick which installed apps should have
 * per-app screenshot / screen-recording blocking enforced by the
 * FLAG_SECURE overlay injected via ScreenshotBlockOverlayService.
 */
public class ScreenshotProtectedAppsActivity extends AppCompatActivity {

    private static final String TAG = "ScreenshotProtectedApps";

    private PhysicalSecurityManager mManager;
    private Set<String> mProtectedPackages;

    private RecyclerView mRecycler;
    private ProgressBar mProgress;
    private EditText mSearch;
    private AppAdapter mAdapter;
    private final List<AppEntry> mAllApps = new ArrayList<>();
    private final List<AppEntry> mFiltered = new ArrayList<>();

    // ── Entry model ──────────────────────────────────────────────────────────

    private static class AppEntry {
        final String packageName;
        final String label;
        final android.graphics.drawable.Drawable icon;
        boolean checked;

        AppEntry(String pkg, String lbl, android.graphics.drawable.Drawable ic, boolean chk) {
            packageName = pkg;
            label = lbl;
            icon = ic;
            checked = chk;
        }
    }

    // ── RecyclerView Adapter ──────────────────────────────────────────────────

    private class AppAdapter extends RecyclerView.Adapter<AppAdapter.VH> {

        class VH extends RecyclerView.ViewHolder {
            ImageView icon;
            TextView name;
            TextView pkg;
            CheckBox check;

            VH(View v) {
                super(v);
                icon  = v.findViewById(R.id.iv_app_icon);
                name  = v.findViewById(R.id.tv_app_name);
                pkg   = v.findViewById(R.id.tv_app_package);
                check = v.findViewById(R.id.cb_app_check);
            }
        }

        @NonNull
        @Override
        public VH onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View v = getLayoutInflater().inflate(R.layout.item_screenshot_app, parent, false);
            return new VH(v);
        }

        @Override
        public void onBindViewHolder(@NonNull VH h, int pos) {
            AppEntry e = mFiltered.get(pos);
            h.icon.setImageDrawable(e.icon);
            h.name.setText(e.label);
            h.pkg.setText(e.packageName);
            h.check.setOnCheckedChangeListener(null);
            h.check.setChecked(e.checked);
            h.check.setOnCheckedChangeListener((btn, chk) -> {
                e.checked = chk;
                if (chk) {
                    mProtectedPackages.add(e.packageName);
                } else {
                    mProtectedPackages.remove(e.packageName);
                }
                mManager.setScreenshotProtectedPackages(mProtectedPackages);
            });
            h.itemView.setOnClickListener(v -> h.check.setChecked(!h.check.isChecked()));
        }

        @Override
        public int getItemCount() { return mFiltered.size(); }

        void applyFilter(String q) {
            mFiltered.clear();
            if (q == null || q.isEmpty()) {
                mFiltered.addAll(mAllApps);
            } else {
                String lo = q.toLowerCase();
                for (AppEntry e : mAllApps) {
                    if (e.label.toLowerCase().contains(lo) || e.packageName.toLowerCase().contains(lo)) {
                        mFiltered.add(e);
                    }
                }
            }
            notifyDataSetChanged();
        }
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_screenshot_protected_apps);

        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
            getSupportActionBar().setTitle("Per-App Screenshot Block");
        }

        mManager = PhysicalSecurityManager.getInstance(this);
        mProtectedPackages = mManager.getScreenshotProtectedPackages();

        mProgress = findViewById(R.id.progress_loading);
        mSearch   = findViewById(R.id.et_search);
        mRecycler = findViewById(R.id.recycler_apps);
        mRecycler.setLayoutManager(new LinearLayoutManager(this));
        mRecycler.setItemViewCacheSize(8);
        mAdapter  = new AppAdapter();
        mRecycler.setAdapter(mAdapter);

        mSearch.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int st, int c, int a) {}
            @Override public void onTextChanged(CharSequence s, int st, int b, int c) {
                mAdapter.applyFilter(s.toString());
            }
            @Override public void afterTextChanged(Editable s) {}
        });

        loadAppsAsync();
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        if (item.getItemId() == android.R.id.home) { finish(); return true; }
        return super.onOptionsItemSelected(item);
    }

    // ── App loading (background thread) ──────────────────────────────────────

    @SuppressWarnings("deprecation")
    private void loadAppsAsync() {
        mProgress.setVisibility(View.VISIBLE);
        new AsyncTask<Void, Void, List<AppEntry>>() {
            @Override
            protected List<AppEntry> doInBackground(Void... v) {
                PackageManager pm = getPackageManager();
                List<ApplicationInfo> apps = pm.getInstalledApplications(PackageManager.GET_META_DATA);
                List<AppEntry> result = new ArrayList<>();
                for (ApplicationInfo ai : apps) {
                    // Skip system packages without launcher intent (only user-launchable apps)
                    if (pm.getLaunchIntentForPackage(ai.packageName) == null
                            && Utils.classifyAppInstall(ai) == Utils.AppInstallClass.SYSTEM) {
                        continue;
                    }
                    String label;
                    try {
                        label = pm.getApplicationLabel(ai).toString();
                    } catch (Exception e) {
                        label = ai.packageName;
                    }
                    android.graphics.drawable.Drawable icon;
                    try {
                        icon = pm.getApplicationIcon(ai);
                    } catch (Exception e) {
                        icon = pm.getDefaultActivityIcon();
                    }
                    boolean checked = mProtectedPackages.contains(ai.packageName);
                    result.add(new AppEntry(ai.packageName, label, icon, checked));
                }
                // Sort: checked first, then alphabetical
                Collections.sort(result, (a, b) -> {
                    if (a.checked != b.checked) return a.checked ? -1 : 1;
                    return a.label.compareToIgnoreCase(b.label);
                });
                return result;
            }

            @Override
            protected void onPostExecute(List<AppEntry> entries) {
                mProgress.setVisibility(View.GONE);
                mAllApps.clear();
                mAllApps.addAll(entries);
                mAdapter.applyFilter(mSearch.getText().toString());
            }
        }.execute();
    }
}
