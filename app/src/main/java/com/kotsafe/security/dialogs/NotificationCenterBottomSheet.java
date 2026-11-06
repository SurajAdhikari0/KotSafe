/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 *
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.dialogs;

import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.bottomsheet.BottomSheetDialog;
import com.google.android.material.button.MaterialButton;
import com.kotsafe.security.R;
import com.kotsafe.security.model.NotificationBulletin;
import com.kotsafe.security.model.NotificationCenterManager;

import java.util.ArrayList;
import java.util.List;

/**
 * BottomSheet Dialog displaying real-time security bulletins, emergency advisories,
 * and announcements broadcasted from the KotSafe Admin Console.
 */
public class NotificationCenterBottomSheet {

    public static void show(@NonNull Context context, Runnable onDismissListener) {
        BottomSheetDialog dialog = new BottomSheetDialog(context);
        View view = LayoutInflater.from(context).inflate(R.layout.dialog_notification_center, null);
        dialog.setContentView(view);

        TextView tvBadgeUnread     = view.findViewById(R.id.badge_unread_count);
        MaterialButton btnMarkAll  = view.findViewById(R.id.btn_mark_all_read);
        ProgressBar progressBar    = view.findViewById(R.id.progress_loading);
        View layoutEmpty           = view.findViewById(R.id.layout_empty_state);
        RecyclerView recycler      = view.findViewById(R.id.recycler_bulletins);

        recycler.setLayoutManager(new LinearLayoutManager(context));
        BulletinAdapter adapter = new BulletinAdapter(context, (bulletin) -> {
            NotificationCenterManager.getInstance(context).markAsRead(bulletin.getId());
            updateUnreadBadge(tvBadgeUnread, NotificationCenterManager.getInstance(context).getCachedUnreadCount());
        });
        recycler.setAdapter(adapter);

        // Populate with cached bulletins immediately if available
        List<NotificationBulletin> cached = NotificationCenterManager.getInstance(context).getCachedBulletins();
        if (!cached.isEmpty()) {
            adapter.setBulletins(cached);
            updateUnreadBadge(tvBadgeUnread, NotificationCenterManager.getInstance(context).getCachedUnreadCount());
            layoutEmpty.setVisibility(View.GONE);
            recycler.setVisibility(View.VISIBLE);
        } else {
            progressBar.setVisibility(View.VISIBLE);
        }

        // Fetch fresh notifications from server
        NotificationCenterManager.getInstance(context).fetchNotifications(new NotificationCenterManager.NotificationCallback() {
            @Override
            public void onSuccess(List<NotificationBulletin> bulletins, int unreadCount) {
                progressBar.setVisibility(View.GONE);
                adapter.setBulletins(bulletins);
                updateUnreadBadge(tvBadgeUnread, unreadCount);

                if (bulletins.isEmpty()) {
                    layoutEmpty.setVisibility(View.VISIBLE);
                    recycler.setVisibility(View.GONE);
                } else {
                    layoutEmpty.setVisibility(View.GONE);
                    recycler.setVisibility(View.VISIBLE);
                }
            }

            @Override
            public void onError(String error) {
                progressBar.setVisibility(View.GONE);
                if (adapter.getItemCount() == 0) {
                    layoutEmpty.setVisibility(View.VISIBLE);
                    recycler.setVisibility(View.GONE);
                }
            }
        });

        // Mark all as read button
        btnMarkAll.setOnClickListener(v -> {
            NotificationCenterManager.getInstance(context).markAllAsRead();
            adapter.markAllRead();
            tvBadgeUnread.setVisibility(View.GONE);
            Toast.makeText(context, "All bulletins marked as read", Toast.LENGTH_SHORT).show();
        });

        if (onDismissListener != null) {
            dialog.setOnDismissListener(d -> onDismissListener.run());
        }

        dialog.show();
    }

    private static void updateUnreadBadge(TextView badgeView, int count) {
        if (count > 0) {
            badgeView.setText(String.valueOf(count));
            badgeView.setVisibility(View.VISIBLE);
        } else {
            badgeView.setVisibility(View.GONE);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // RecyclerView Adapter
    // ─────────────────────────────────────────────────────────────────────────────

    private static class BulletinAdapter extends RecyclerView.Adapter<BulletinAdapter.ViewHolder> {

        public interface OnItemReadListener {
            void onRead(NotificationBulletin bulletin);
        }

        private final Context mContext;
        private final List<NotificationBulletin> mItems = new ArrayList<>();
        private final OnItemReadListener mReadListener;

        BulletinAdapter(Context context, OnItemReadListener listener) {
            mContext = context;
            mReadListener = listener;
        }

        void setBulletins(List<NotificationBulletin> list) {
            mItems.clear();
            if (list != null) {
                mItems.addAll(list);
            }
            notifyDataSetChanged();
        }

        void markAllRead() {
            for (NotificationBulletin b : mItems) {
                b.setRead(true);
            }
            notifyDataSetChanged();
        }

        @NonNull
        @Override
        public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_notification_bulletin, parent, false);
            return new ViewHolder(view);
        }

        @Override
        public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
            NotificationBulletin item = mItems.get(position);

            holder.tvTitle.setText(item.getTitle());
            holder.tvDescription.setText(item.getDescription());
            holder.tvTimeAgo.setText(item.getTimeAgo());
            holder.tvSender.setText("KotSafe SOC · " + item.getAdminName());

            // Severity styling
            String type = item.getType();
            if ("critical".equalsIgnoreCase(type)) {
                holder.tvSeverity.setText("CRITICAL THREAT");
                holder.tvSeverity.setBackgroundResource(R.drawable.ks_bg_badge_red);
            } else if ("warning".equalsIgnoreCase(type)) {
                holder.tvSeverity.setText("SECURITY ALERT");
                holder.tvSeverity.setBackgroundResource(R.drawable.ks_bg_badge_amber);
            } else if ("update".equalsIgnoreCase(type)) {
                holder.tvSeverity.setText("ENGINE UPDATE");
                holder.tvSeverity.setBackgroundResource(R.drawable.ks_bg_badge_green);
            } else if ("announcement".equalsIgnoreCase(type)) {
                holder.tvSeverity.setText("ANNOUNCEMENT");
                holder.tvSeverity.setBackgroundResource(R.drawable.ks_bg_badge_purple);
            } else {
                holder.tvSeverity.setText("ADVISORY");
                holder.tvSeverity.setBackgroundResource(R.drawable.ks_bg_badge_blue);
            }

            // Target audience badge
            String audience = item.getTargetAudience();
            if ("android".equalsIgnoreCase(audience)) {
                holder.tvAudience.setText("MOBILE");
                holder.tvAudience.setVisibility(View.VISIBLE);
            } else if ("all".equalsIgnoreCase(audience) || audience == null || audience.isEmpty()) {
                holder.tvAudience.setText("ALL FLEET");
                holder.tvAudience.setVisibility(View.VISIBLE);
            } else {
                holder.tvAudience.setText(audience.toUpperCase());
                holder.tvAudience.setVisibility(View.VISIBLE);
            }

            // Unread indicator dot
            holder.dotUnread.setVisibility(item.isRead() ? View.GONE : View.VISIBLE);

            // Action URL button
            String actionUrl = item.getActionUrl();
            if (actionUrl != null && !actionUrl.trim().isEmpty()) {
                holder.btnAction.setVisibility(View.VISIBLE);
                holder.btnAction.setOnClickListener(v -> {
                    try {
                        Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(actionUrl));
                        mContext.startActivity(intent);
                    } catch (Exception e) {
                        Toast.makeText(mContext, "Could not open link: " + actionUrl, Toast.LENGTH_SHORT).show();
                    }
                });
            } else {
                holder.btnAction.setVisibility(View.GONE);
            }

            // Clicking card marks as read
            holder.itemView.setOnClickListener(v -> {
                if (!item.isRead()) {
                    item.setRead(true);
                    holder.dotUnread.setVisibility(View.GONE);
                    if (mReadListener != null) {
                        mReadListener.onRead(item);
                    }
                }
            });
        }

        @Override
        public int getItemCount() {
            return mItems.size();
        }

        static class ViewHolder extends RecyclerView.ViewHolder {
            final TextView tvSeverity;
            final TextView tvAudience;
            final TextView tvTimeAgo;
            final View dotUnread;
            final TextView tvTitle;
            final TextView tvDescription;
            final MaterialButton btnAction;
            final TextView tvSender;

            ViewHolder(@NonNull View itemView) {
                super(itemView);
                tvSeverity    = itemView.findViewById(R.id.bulletin_severity_badge);
                tvAudience    = itemView.findViewById(R.id.bulletin_audience_badge);
                tvTimeAgo     = itemView.findViewById(R.id.bulletin_time_ago);
                dotUnread     = itemView.findViewById(R.id.bulletin_unread_dot);
                tvTitle       = itemView.findViewById(R.id.bulletin_title);
                tvDescription = itemView.findViewById(R.id.bulletin_description);
                btnAction     = itemView.findViewById(R.id.btn_bulletin_action);
                tvSender      = itemView.findViewById(R.id.bulletin_sender);
            }
        }
    }
}

