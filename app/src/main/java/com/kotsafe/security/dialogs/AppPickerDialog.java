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
 * Copyright 2026 - KotSafe Team
 */

package com.kotsafe.security.dialogs;

import android.annotation.SuppressLint;
import android.app.Dialog;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.DialogFragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.kotsafe.security.R;
import com.kotsafe.security.model.AppDescriptor;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class AppPickerDialog extends DialogFragment {
    public static final String TAG = "AppPickerDialog";

    public interface OnAppSelectedListener {
        void onAppSelected(@NonNull AppDescriptor app);
    }

    private OnAppSelectedListener mListener;
    private final List<AppItem> mAllApps = new ArrayList<>();
    private final List<AppItem> mFilteredApps = new ArrayList<>();
    private AppPickerAdapter mAdapter;
    private ProgressBar mProgressBar;
    private TextView mTvNoApps;
    private static final ExecutorService sExecutor = Executors.newSingleThreadExecutor();

    public static class AppItem {
        public final AppDescriptor descriptor;
        public final Drawable icon;

        public AppItem(AppDescriptor descriptor, Drawable icon) {
            this.descriptor = descriptor;
            this.icon = icon;
        }
    }

    public static AppPickerDialog newInstance() {
        return new AppPickerDialog();
    }

    public AppPickerDialog setOnAppSelectedListener(OnAppSelectedListener listener) {
        mListener = listener;
        return this;
    }

    @NonNull
    @Override
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        LayoutInflater inflater = getLayoutInflater();
        View view = inflater.inflate(R.layout.dialog_app_picker, null);

        EditText etSearch = view.findViewById(R.id.et_search_apps);
        RecyclerView rvApps = view.findViewById(R.id.rv_apps);
        mProgressBar = view.findViewById(R.id.progress_loading);
        mTvNoApps = view.findViewById(R.id.tv_no_apps);

        rvApps.setLayoutManager(new LinearLayoutManager(requireContext()));
        mAdapter = new AppPickerAdapter();
        rvApps.setAdapter(mAdapter);

        etSearch.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                filter(s.toString());
            }

            @Override
            public void afterTextChanged(Editable s) {}
        });

        loadApps();

        return new MaterialAlertDialogBuilder(requireContext())
                .setTitle("Select Application")
                .setIcon(R.drawable.ic_apps)
                .setView(view)
                .setNegativeButton(R.string.cancel_action, (d, w) -> d.dismiss())
                .create();
    }

    @SuppressLint("QueryPermissionsNeeded")
    private void loadApps() {
        mProgressBar.setVisibility(View.VISIBLE);
        Context context = requireContext().getApplicationContext();

        sExecutor.execute(() -> {
            PackageManager pm = context.getPackageManager();
            List<PackageInfo> installed = pm.getInstalledPackages(0);
            List<AppItem> loaded = new ArrayList<>();

            for (PackageInfo pi : installed) {
                if (pi.applicationInfo == null) continue;
                String pkg = pi.packageName;
                String name = pi.applicationInfo.loadLabel(pm).toString();
                AppDescriptor desc = new AppDescriptor(pm, pi);
                loaded.add(new AppItem(desc, desc.getIcon()));
            }

            Collections.sort(loaded, (a, b) -> a.descriptor.getName().compareToIgnoreCase(b.descriptor.getName()));

            if (getActivity() != null) {
                getActivity().runOnUiThread(() -> {
                    mAllApps.clear();
                    mAllApps.addAll(loaded);
                    mFilteredApps.clear();
                    mFilteredApps.addAll(loaded);
                    mProgressBar.setVisibility(View.GONE);
                    mAdapter.notifyDataSetChanged();
                });
            }
        });
    }

    private void filter(String query) {
        mFilteredApps.clear();
        if (query == null || query.trim().isEmpty()) {
            mFilteredApps.addAll(mAllApps);
        } else {
            String lower = query.toLowerCase(Locale.getDefault()).trim();
            for (AppItem item : mAllApps) {
                if (item.descriptor.getName().toLowerCase(Locale.getDefault()).contains(lower) ||
                    item.descriptor.getPackageName().toLowerCase(Locale.getDefault()).contains(lower)) {
                    mFilteredApps.add(item);
                }
            }
        }
        mTvNoApps.setVisibility(mFilteredApps.isEmpty() ? View.VISIBLE : View.GONE);
        mAdapter.notifyDataSetChanged();
    }

    private class AppPickerAdapter extends RecyclerView.Adapter<AppPickerAdapter.ViewHolder> {
        @NonNull
        @Override
        public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View v = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_app_picker, parent, false);
            return new ViewHolder(v);
        }

        @Override
        public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
            AppItem item = mFilteredApps.get(position);
            holder.tvName.setText(item.descriptor.getName());
            holder.tvPackage.setText(item.descriptor.getPackageName());
            if (item.icon != null) {
                holder.ivIcon.setImageDrawable(item.icon);
            } else {
                holder.ivIcon.setImageResource(R.drawable.ic_launcher_foreground);
            }

            holder.itemView.setOnClickListener(v -> {
                dismiss();
                if (mListener != null) {
                    mListener.onAppSelected(item.descriptor);
                }
            });
        }

        @Override
        public int getItemCount() {
            return mFilteredApps.size();
        }

        class ViewHolder extends RecyclerView.ViewHolder {
            final ImageView ivIcon;
            final TextView tvName;
            final TextView tvPackage;

            ViewHolder(@NonNull View itemView) {
                super(itemView);
                ivIcon = itemView.findViewById(R.id.iv_app_icon);
                tvName = itemView.findViewById(R.id.tv_app_name);
                tvPackage = itemView.findViewById(R.id.tv_package_name);
            }
        }
    }
}
