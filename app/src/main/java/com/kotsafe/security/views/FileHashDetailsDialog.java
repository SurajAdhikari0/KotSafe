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

package com.kotsafe.security.views;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.activities.AppDetailsActivity;
import com.kotsafe.security.model.FileHashEntry;
import com.kotsafe.security.model.ThreatIntelManager;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;
import com.google.android.material.button.MaterialButton;

public class FileHashDetailsDialog extends BottomSheetDialogFragment {
    public static final String TAG = "FileHashDetailsDialog";
    private static final String ARG_ENTRY = "arg_entry";

    private FileHashEntry mEntry;

    public static FileHashDetailsDialog newInstance(FileHashEntry entry) {
        FileHashDetailsDialog dialog = new FileHashDetailsDialog();
        Bundle args = new Bundle();
        args.putSerializable(ARG_ENTRY, entry);
        dialog.setArguments(args);
        return dialog;
    }

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (getArguments() != null) {
            mEntry = (FileHashEntry) getArguments().getSerializable(ARG_ENTRY);
        }
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.dialog_file_hash_details, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        if (mEntry == null) {
            dismiss();
            return;
        }

        ImageView appIcon = view.findViewById(R.id.dialog_app_icon);
        TextView appName = view.findViewById(R.id.dialog_app_name);
        TextView packageName = view.findViewById(R.id.dialog_package_name);
        TextView threatBadge = view.findViewById(R.id.dialog_threat_badge);

        TextView fileName = view.findViewById(R.id.dialog_file_name);
        TextView filePath = view.findViewById(R.id.dialog_file_path);
        TextView sha256 = view.findViewById(R.id.dialog_sha256);
        TextView md5 = view.findViewById(R.id.dialog_md5);
        TextView serviceNote = view.findViewById(R.id.dialog_service_note);

        ImageView btnCopySha256 = view.findViewById(R.id.dialog_btn_copy_sha256);
        ImageView btnCopyMd5 = view.findViewById(R.id.dialog_btn_copy_md5);
        MaterialButton btnVt = view.findViewById(R.id.btn_vt_lookup);
        MaterialButton btnOtx = view.findViewById(R.id.btn_otx_lookup);
        MaterialButton btnManageAccess = view.findViewById(R.id.btn_manage_access);

        // Load Icon
        try {
            PackageManager pm = requireContext().getPackageManager();
            Drawable icon = pm.getApplicationIcon(mEntry.packageName);
            appIcon.setImageDrawable(icon);
        } catch (Exception e) {
            appIcon.setImageResource(R.drawable.ic_apps);
        }

        appName.setText(mEntry.appName);
        packageName.setText(mEntry.packageName);

        // Threat badge
        if (FileHashEntry.THREAT_MALICIOUS.equals(mEntry.threatStatus)) {
            threatBadge.setText("MALICIOUS");
            threatBadge.setBackgroundResource(R.drawable.bg_badge_threat);
            threatBadge.setVisibility(View.VISIBLE);
        } else if (FileHashEntry.THREAT_SUSPICIOUS.equals(mEntry.threatStatus)) {
            threatBadge.setText("SUSPICIOUS");
            threatBadge.setBackgroundResource(R.drawable.bg_badge_threat);
            threatBadge.setVisibility(View.VISIBLE);
        } else {
            threatBadge.setText("CLEAN");
            threatBadge.setBackgroundResource(R.drawable.bg_badge_service);
            threatBadge.setVisibility(View.VISIBLE);
        }

        fileName.setText(mEntry.fileName + " (" + Utils.formatBytes(mEntry.fileSize) + ")");
        filePath.setText(mEntry.filePath);
        sha256.setText(mEntry.sha256 != null && !mEntry.sha256.isEmpty() ? mEntry.sha256 : "Not Computed");
        md5.setText(mEntry.md5 != null && !mEntry.md5.isEmpty() ? mEntry.md5 : "Not Computed");

        StringBuilder note = new StringBuilder();
        if (mEntry.isServiceApp) note.append("• Active Background Service\n");
        if (mEntry.isSystemApp) note.append("• System Application / Firmware Binary\n");
        if (mEntry.threatDetails != null && !mEntry.threatDetails.isEmpty()) {
            note.append("• Notice: ").append(mEntry.threatDetails);
        }
        serviceNote.setText(note.toString().trim());

        btnCopySha256.setOnClickListener(v -> copyToClipboard("SHA-256 Hash", mEntry.sha256));
        btnCopyMd5.setOnClickListener(v -> copyToClipboard("MD5 Hash", mEntry.md5));

        btnVt.setOnClickListener(v -> {
            if (mEntry.sha256 != null && !mEntry.sha256.isEmpty()) {
                ThreatIntelManager.openVirusTotalFile(requireContext(), mEntry.sha256);
            } else {
                Toast.makeText(requireContext(), "No hash available for lookup", Toast.LENGTH_SHORT).show();
            }
        });

        btnOtx.setOnClickListener(v -> {
            if (mEntry.sha256 != null && !mEntry.sha256.isEmpty()) {
                ThreatIntelManager.openOtxFile(requireContext(), mEntry.sha256);
            } else {
                Toast.makeText(requireContext(), "No hash available for lookup", Toast.LENGTH_SHORT).show();
            }
        });

        btnManageAccess.setOnClickListener(v -> {
            try {
                PackageManager pm = requireContext().getPackageManager();
                int uid = Utils.getPackageUid(pm, mEntry.packageName, 0);
                Intent intent = new Intent(requireContext(), AppDetailsActivity.class);
                intent.putExtra(AppDetailsActivity.APP_UID_EXTRA, uid);
                startActivity(intent);
                dismiss();
            } catch (Exception e) {
                Toast.makeText(requireContext(), "Could not open app details", Toast.LENGTH_SHORT).show();
            }
        });
    }

    private void copyToClipboard(String label, String text) {
        if (text == null || text.isEmpty()) return;
        ClipboardManager cm = (ClipboardManager) requireContext().getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData clip = ClipData.newPlainText(label, text);
        cm.setPrimaryClip(clip);
        Toast.makeText(requireContext(), label + " copied to clipboard", Toast.LENGTH_SHORT).show();
    }
}
