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

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.FileHashEntry;

import java.util.ArrayList;
import java.util.List;

public class FileHashLogsAdapter extends RecyclerView.Adapter<FileHashLogsAdapter.ViewHolder> {
    public interface OnItemClickListener {
        void onItemClick(FileHashEntry entry);
    }

    private final Context mContext;
    private final PackageManager mPackageManager;
    private final List<FileHashEntry> mEntries = new ArrayList<>();
    private OnItemClickListener mListener;

    public FileHashLogsAdapter(Context context) {
        mContext = context;
        mPackageManager = context.getPackageManager();
    }

    public void setOnItemClickListener(OnItemClickListener listener) {
        mListener = listener;
    }

    public void setEntries(List<FileHashEntry> entries) {
        mEntries.clear();
        if (entries != null) {
            mEntries.addAll(entries);
        }
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(mContext).inflate(R.layout.file_hash_item, parent, false);
        return new ViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        FileHashEntry entry = mEntries.get(position);

        holder.appName.setText(entry.appName);
        holder.packageName.setText(entry.packageName);
        holder.filePath.setText(entry.filePath);
        holder.fileSize.setText(Utils.formatBytes(entry.fileSize));
        holder.fileHash.setText(entry.sha256 != null && !entry.sha256.isEmpty() ? entry.sha256 : "Not Computed");

        // Service badge
        if (entry.isServiceApp) {
            holder.badgeService.setVisibility(View.VISIBLE);
        } else {
            holder.badgeService.setVisibility(View.GONE);
        }

        // Threat badge
        if (FileHashEntry.THREAT_MALICIOUS.equals(entry.threatStatus)) {
            holder.badgeThreat.setText("MALICIOUS");
            holder.badgeThreat.setBackgroundResource(R.drawable.bg_badge_threat);
            holder.badgeThreat.setVisibility(View.VISIBLE);
        } else if (FileHashEntry.THREAT_SUSPICIOUS.equals(entry.threatStatus)) {
            holder.badgeThreat.setText("SUSPICIOUS");
            holder.badgeThreat.setBackgroundResource(R.drawable.bg_badge_threat);
            holder.badgeThreat.setVisibility(View.VISIBLE);
        } else {
            holder.badgeThreat.setVisibility(View.GONE);
        }

        // App icon
        try {
            Drawable icon = mPackageManager.getApplicationIcon(entry.packageName);
            holder.appIcon.setImageDrawable(icon);
        } catch (Exception e) {
            holder.appIcon.setImageResource(R.drawable.ic_apps);
        }

        holder.btnCopyHash.setOnClickListener(v -> {
            if (entry.sha256 != null && !entry.sha256.isEmpty()) {
                ClipboardManager cm = (ClipboardManager) mContext.getSystemService(Context.CLIPBOARD_SERVICE);
                ClipData clip = ClipData.newPlainText("SHA-256 Hash", entry.sha256);
                cm.setPrimaryClip(clip);
                Toast.makeText(mContext, "SHA-256 copied", Toast.LENGTH_SHORT).show();
            }
        });

        holder.itemView.setOnClickListener(v -> {
            if (mListener != null) {
                mListener.onItemClick(entry);
            }
        });
    }

    @Override
    public int getItemCount() {
        return mEntries.size();
    }

    static class ViewHolder extends RecyclerView.ViewHolder {
        ImageView appIcon, btnCopyHash;
        TextView appName, packageName, fileSize, filePath, fileHash;
        TextView badgeService, badgeThreat;

        ViewHolder(@NonNull View itemView) {
            super(itemView);
            appIcon = itemView.findViewById(R.id.app_icon);
            appName = itemView.findViewById(R.id.app_name);
            packageName = itemView.findViewById(R.id.package_name);
            fileSize = itemView.findViewById(R.id.file_size);
            filePath = itemView.findViewById(R.id.file_path);
            fileHash = itemView.findViewById(R.id.file_hash);
            badgeService = itemView.findViewById(R.id.badge_service);
            badgeThreat = itemView.findViewById(R.id.badge_threat);
            btnCopyHash = itemView.findViewById(R.id.btn_copy_hash);
        }
    }
}
