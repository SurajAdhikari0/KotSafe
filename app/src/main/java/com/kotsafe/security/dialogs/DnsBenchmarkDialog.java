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

package com.kotsafe.security.dialogs;

import android.app.Dialog;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.kotsafe.security.R;
import com.kotsafe.security.adapters.DnsProviderAdapter;
import com.kotsafe.security.model.DnsLatencyBenchmark;
import com.kotsafe.security.model.DnsProvider;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.google.android.material.bottomsheet.BottomSheetDialog;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;
import com.google.android.material.button.MaterialButton;

import java.util.List;
import java.util.Map;

public class DnsBenchmarkDialog extends BottomSheetDialogFragment {
    public static final String TAG = "DnsBenchmarkDialog";

    public interface OnDnsProviderSelectedListener {
        void onDnsProviderSelected(@NonNull DnsProvider provider);
    }

    private OnDnsProviderSelectedListener mListener;
    private DnsProviderAdapter mAdapter;
    private DnsLatencyBenchmark mBenchmark;
    private View mLayoutProgress;
    private TextView mTvStatus;
    private String mInitialSelectedId = "cloudflare";

    public static DnsBenchmarkDialog newInstance(@Nullable String selectedProviderId) {
        DnsBenchmarkDialog dialog = new DnsBenchmarkDialog();
        Bundle args = new Bundle();
        if (selectedProviderId != null) {
            args.putString("selected_id", selectedProviderId);
        }
        dialog.setArguments(args);
        return dialog;
    }

    public void setOnDnsProviderSelectedListener(@Nullable OnDnsProviderSelectedListener listener) {
        mListener = listener;
    }

    @NonNull
    @Override
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        Dialog dialog = super.onCreateDialog(savedInstanceState);
        dialog.setOnShowListener(d -> {
            BottomSheetDialog bsd = (BottomSheetDialog) d;
            FrameLayout bottomSheet = bsd.findViewById(com.google.android.material.R.id.design_bottom_sheet);
            if (bottomSheet != null) {
                BottomSheetBehavior<FrameLayout> behavior = BottomSheetBehavior.from(bottomSheet);
                behavior.setState(BottomSheetBehavior.STATE_EXPANDED);
                behavior.setSkipCollapsed(true);
            }
        });
        return dialog;
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.dialog_dns_benchmark, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        if (getArguments() != null) {
            mInitialSelectedId = getArguments().getString("selected_id", "cloudflare");
        }

        mBenchmark = new DnsLatencyBenchmark();

        view.findViewById(R.id.btn_dialog_close).setOnClickListener(v -> dismiss());

        mLayoutProgress = view.findViewById(R.id.layout_benchmark_progress);
        mTvStatus = view.findViewById(R.id.tv_benchmark_status);

        RecyclerView rv = view.findViewById(R.id.rv_dns_providers);
        rv.setLayoutManager(new LinearLayoutManager(requireContext()));

        List<DnsProvider> providers = DnsProvider.getPresets();
        mAdapter = new DnsProviderAdapter(providers, mInitialSelectedId, null);
        rv.setAdapter(mAdapter);

        setupCategoryChips(view);

        MaterialButton btnBenchmark = view.findViewById(R.id.btn_benchmark_speed);
        btnBenchmark.setOnClickListener(v -> startBenchmark(providers));

        MaterialButton btnApply = view.findViewById(R.id.btn_apply_dns);
        btnApply.setOnClickListener(v -> {
            DnsProvider selected = mAdapter.getSelectedProvider();
            if (selected != null && mListener != null) {
                mListener.onDnsProviderSelected(selected);
            }
            dismiss();
        });

        // Run benchmark once automatically on dialog open
        startBenchmark(providers);
    }

    private void setupCategoryChips(@NonNull View view) {
        TextView chipAll = view.findViewById(R.id.chip_cat_all);
        TextView chipSpeed = view.findViewById(R.id.chip_cat_speed);
        TextView chipSecurity = view.findViewById(R.id.chip_cat_security);
        TextView chipAdblock = view.findViewById(R.id.chip_cat_adblock);
        TextView chipFamily = view.findViewById(R.id.chip_cat_family);

        TextView[] chips = new TextView[]{chipAll, chipSpeed, chipSecurity, chipAdblock, chipFamily};
        DnsProvider.Category[] categories = new DnsProvider.Category[]{
                DnsProvider.Category.ALL,
                DnsProvider.Category.SPEED_PRIVACY,
                DnsProvider.Category.SECURITY,
                DnsProvider.Category.ADBLOCK,
                DnsProvider.Category.FAMILY
        };

        for (int i = 0; i < chips.length; i++) {
            final int index = i;
            chips[i].setOnClickListener(v -> {
                for (int j = 0; j < chips.length; j++) {
                    boolean active = (j == index);
                    chips[j].setTextColor(active ? Color.WHITE : Color.parseColor("#94A3B8"));
                    chips[j].setBackgroundTintList(ColorStateList.valueOf(
                            active ? Color.parseColor("#3B82F6") : Color.parseColor("#20808080")
                    ));
                }
                mAdapter.setCategoryFilter(categories[index]);
            });
        }
    }

    private void startBenchmark(@NonNull List<DnsProvider> providers) {
        if (mBenchmark == null) return;

        mLayoutProgress.setVisibility(View.VISIBLE);
        mTvStatus.setText(R.string.dns_running_benchmark);

        mBenchmark.runBenchmark(providers, new DnsLatencyBenchmark.BenchmarkListener() {
            @Override
            public void onProviderTested(@NonNull DnsProvider provider, int latencyMs) {
                if (!isAdded()) return;
                mAdapter.updateLatency(provider.getId(), latencyMs);
            }

            @Override
            public void onBenchmarkFinished(@NonNull Map<String, Integer> results) {
                if (!isAdded()) return;
                mLayoutProgress.setVisibility(View.GONE);
                mAdapter.setAllLatencies(results);
            }
        });
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        if (mBenchmark != null) {
            mBenchmark.cancel();
            mBenchmark = null;
        }
    }
}
