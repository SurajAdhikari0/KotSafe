/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.adapters;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.res.ColorStateList;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.kotsafe.security.R;
import com.kotsafe.security.model.AppLogEntry;

import java.util.ArrayList;
import java.util.List;

public class AppLogsAdapter extends RecyclerView.Adapter<AppLogsAdapter.LogViewHolder> {

    public interface OnLogClickListener {
        void onLogClick(AppLogEntry entry);
    }

    private final Context mContext;
    private final List<AppLogEntry> mEntries = new ArrayList<>();
    private OnLogClickListener mListener;

    public AppLogsAdapter(Context context) {
        mContext = context;
    }

    public void setOnLogClickListener(OnLogClickListener listener) {
        mListener = listener;
    }

    public void setEntries(List<AppLogEntry> entries) {
        mEntries.clear();
        if (entries != null) {
            mEntries.addAll(entries);
        }
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public LogViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_app_log, parent, false);
        return new LogViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull LogViewHolder holder, int position) {
        AppLogEntry entry = mEntries.get(position);

        // Level Badge
        holder.tvLevel.setText(entry.getLevelLabel());
        holder.tvLevel.setBackgroundTintList(ColorStateList.valueOf(entry.getLevelBadgeColor()));

        // Tag Chip
        if (entry.tag != null && !entry.tag.isEmpty()) {
            holder.tvTag.setVisibility(View.VISIBLE);
            holder.tvTag.setText(entry.tag);
        } else {
            holder.tvTag.setVisibility(View.GONE);
        }

        // Timestamp
        if (entry.timestamp != null && !entry.timestamp.isEmpty()) {
            holder.tvTimestamp.setVisibility(View.VISIBLE);
            holder.tvTimestamp.setText(entry.timestamp);
        } else {
            holder.tvTimestamp.setVisibility(View.GONE);
        }

        // Message
        holder.tvMessage.setText(entry.message);

        // Copy button
        holder.btnCopy.setOnClickListener(v -> {
            ClipboardManager cm = (ClipboardManager) mContext.getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null) {
                cm.setPrimaryClip(ClipData.newPlainText("Log entry", entry.rawLine));
                Toast.makeText(mContext, "Copied log line", Toast.LENGTH_SHORT).show();
            }
        });

        // Item tap
        holder.itemView.setOnClickListener(v -> {
            if (mListener != null) {
                mListener.onLogClick(entry);
            }
        });
    }

    @Override
    public int getItemCount() {
        return mEntries.size();
    }

    static class LogViewHolder extends RecyclerView.ViewHolder {
        final TextView tvLevel;
        final TextView tvTag;
        final TextView tvTimestamp;
        final TextView tvMessage;
        final ImageView btnCopy;

        LogViewHolder(@NonNull View itemView) {
            super(itemView);
            tvLevel = itemView.findViewById(R.id.tv_log_level);
            tvTag = itemView.findViewById(R.id.tv_log_tag);
            tvTimestamp = itemView.findViewById(R.id.tv_log_timestamp);
            tvMessage = itemView.findViewById(R.id.tv_log_message);
            btnCopy = itemView.findViewById(R.id.btn_copy_line);
        }
    }
}
