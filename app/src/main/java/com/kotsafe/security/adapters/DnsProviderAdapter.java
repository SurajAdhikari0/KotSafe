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

package com.kotsafe.security.adapters;

import android.content.res.ColorStateList;
import android.graphics.Color;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.RadioButton;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;

import com.kotsafe.security.R;
import com.kotsafe.security.model.DnsProvider;
import com.google.android.material.card.MaterialCardView;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DnsProviderAdapter extends RecyclerView.Adapter<DnsProviderAdapter.ViewHolder> {
    public interface OnProviderClickListener {
        void onProviderClick(@NonNull DnsProvider provider);
    }

    private final List<DnsProvider> mAllProviders = new ArrayList<>();
    private final List<DnsProvider> mFilteredList = new ArrayList<>();
    private final Map<String, Integer> mLatencies = new HashMap<>();
    private String mSelectedProviderId = "cloudflare";
    private DnsProvider.Category mCurrentCategory = DnsProvider.Category.ALL;
    private OnProviderClickListener mListener;

    public DnsProviderAdapter(@NonNull List<DnsProvider> providers,
                              @Nullable String currentSelectedId,
                              @Nullable OnProviderClickListener listener) {
        mAllProviders.addAll(providers);
        if (currentSelectedId != null) {
            mSelectedProviderId = currentSelectedId;
        }
        mListener = listener;
        applyFilter();
    }

    public void setSelectedProviderId(@NonNull String providerId) {
        mSelectedProviderId = providerId;
        notifyDataSetChanged();
    }

    @Nullable
    public DnsProvider getSelectedProvider() {
        for (DnsProvider p : mAllProviders) {
            if (p.getId().equalsIgnoreCase(mSelectedProviderId)) {
                return p;
            }
        }
        return mAllProviders.isEmpty() ? null : mAllProviders.get(0);
    }

    public void setCategoryFilter(@NonNull DnsProvider.Category category) {
        mCurrentCategory = category;
        applyFilter();
    }

    public void updateLatency(@NonNull String providerId, int latencyMs) {
        mLatencies.put(providerId, latencyMs);
        for (int i = 0; i < mFilteredList.size(); i++) {
            if (mFilteredList.get(i).getId().equalsIgnoreCase(providerId)) {
                notifyItemChanged(i);
                break;
            }
        }
    }

    public void setAllLatencies(@NonNull Map<String, Integer> latencies) {
        mLatencies.clear();
        mLatencies.putAll(latencies);
        notifyDataSetChanged();
    }

    private void applyFilter() {
        mFilteredList.clear();
        if (mCurrentCategory == DnsProvider.Category.ALL) {
            mFilteredList.addAll(mAllProviders);
        } else {
            for (DnsProvider p : mAllProviders) {
                if (p.getCategory() == mCurrentCategory) {
                    mFilteredList.add(p);
                }
            }
        }
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_dns_provider, parent, false);
        return new ViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        DnsProvider provider = mFilteredList.get(position);
        holder.bind(provider, provider.getId().equalsIgnoreCase(mSelectedProviderId), mLatencies.get(provider.getId()));
    }

    @Override
    public int getItemCount() {
        return mFilteredList.size();
    }

    class ViewHolder extends RecyclerView.ViewHolder {
        private final MaterialCardView card;
        private final RadioButton rbSelected;
        private final TextView tvName;
        private final TextView tvCategory;
        private final TextView tvDesc;
        private final TextView tvLatency;
        private final TextView tvIp;
        private final TextView tvIpv6;
        private final TextView tvBadgeDoh;
        private final TextView tvBadgeAdblock;

        ViewHolder(@NonNull View itemView) {
            super(itemView);
            card = itemView.findViewById(R.id.card_dns_provider);
            rbSelected = itemView.findViewById(R.id.rb_selected);
            tvName = itemView.findViewById(R.id.tv_provider_name);
            tvCategory = itemView.findViewById(R.id.tv_provider_category);
            tvDesc = itemView.findViewById(R.id.tv_provider_desc);
            tvLatency = itemView.findViewById(R.id.tv_provider_latency);
            tvIp = itemView.findViewById(R.id.tv_provider_ip);
            tvIpv6 = itemView.findViewById(R.id.tv_provider_ipv6);
            tvBadgeDoh = itemView.findViewById(R.id.tv_badge_doh);
            tvBadgeAdblock = itemView.findViewById(R.id.tv_badge_adblock);
        }

        void bind(DnsProvider provider, boolean isSelected, @Nullable Integer latencyMs) {
            tvName.setText(provider.getName());
            tvDesc.setText(provider.getDescription());
            tvIp.setText(provider.getPrimaryIpv4());

            rbSelected.setChecked(isSelected);
            card.setStrokeColor(isSelected ? Color.parseColor("#3B82F6") : Color.parseColor("#33808080"));
            card.setStrokeWidth(isSelected ? 3 : 1);

            // Category Pill
            tvCategory.setText(provider.getCategory().getTitle());
            int catColor;
            switch (provider.getCategory()) {
                case SECURITY:
                    catColor = Color.parseColor("#10B981");
                    break;
                case ADBLOCK:
                    catColor = Color.parseColor("#EC4899");
                    break;
                case FAMILY:
                    catColor = Color.parseColor("#F59E0B");
                    break;
                case SPEED_PRIVACY:
                default:
                    catColor = Color.parseColor("#6366F1");
                    break;
            }
            tvCategory.setBackgroundTintList(ColorStateList.valueOf(catColor));

            // Features badges
            tvIpv6.setVisibility((provider.getPrimaryIpv6() != null && !provider.getPrimaryIpv6().isEmpty()) ? View.VISIBLE : View.GONE);
            tvBadgeDoh.setVisibility(provider.hasDoH() ? View.VISIBLE : View.GONE);
            tvBadgeAdblock.setVisibility(provider.hasAdBlock() ? View.VISIBLE : View.GONE);

            // Latency indicator
            if (latencyMs == null) {
                tvLatency.setText("⏱️ --");
                tvLatency.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor("#64748B")));
            } else if (latencyMs == -1) {
                tvLatency.setText("Timeout");
                tvLatency.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor("#EF4444")));
            } else {
                tvLatency.setText(latencyMs + " ms");
                if (latencyMs < 40) {
                    tvLatency.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor("#10B981"))); // Green
                } else if (latencyMs < 90) {
                    tvLatency.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor("#F59E0B"))); // Amber
                } else {
                    tvLatency.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor("#F97316"))); // Orange
                }
            }

            card.setOnClickListener(v -> {
                mSelectedProviderId = provider.getId();
                notifyDataSetChanged();
                if (mListener != null) {
                    mListener.onProviderClick(provider);
                }
            });
        }
    }
}
