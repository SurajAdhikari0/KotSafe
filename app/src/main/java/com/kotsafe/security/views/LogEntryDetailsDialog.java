/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.views;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.res.ColorStateList;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.kotsafe.security.R;
import com.kotsafe.security.model.AppLogEntry;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;

public class LogEntryDetailsDialog extends BottomSheetDialogFragment {
    public static final String TAG = "LogEntryDetailsDialog";
    private static final String ARG_ENTRY = "log_entry";

    public static LogEntryDetailsDialog newInstance(AppLogEntry entry) {
        LogEntryDetailsDialog dialog = new LogEntryDetailsDialog();
        Bundle args = new Bundle();
        args.putSerializable(ARG_ENTRY, entry);
        dialog.setArguments(args);
        return dialog;
    }

    @Override
    public int getTheme() {
        return R.style.Theme_MaterialComponents_DayNight_BottomSheetDialog;
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.dialog_log_entry_details, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        Bundle args = getArguments();
        if (args == null) {
            dismiss();
            return;
        }

        AppLogEntry entry = (AppLogEntry) args.getSerializable(ARG_ENTRY);
        if (entry == null) {
            dismiss();
            return;
        }

        TextView tvLevel = view.findViewById(R.id.dialog_log_level);
        TextView tvTag = view.findViewById(R.id.dialog_log_tag);
        TextView tvTimestamp = view.findViewById(R.id.dialog_log_timestamp);
        TextView tvMessage = view.findViewById(R.id.dialog_log_message);

        tvLevel.setText(entry.getLevelLabel());
        tvLevel.setBackgroundTintList(ColorStateList.valueOf(entry.getLevelBadgeColor()));

        if (entry.tag != null && !entry.tag.isEmpty()) {
            tvTag.setVisibility(View.VISIBLE);
            tvTag.setText(entry.tag);
        } else {
            tvTag.setVisibility(View.GONE);
        }

        if (entry.timestamp != null && !entry.timestamp.isEmpty()) {
            tvTimestamp.setVisibility(View.VISIBLE);
            tvTimestamp.setText(entry.timestamp);
        } else {
            tvTimestamp.setVisibility(View.GONE);
        }

        tvMessage.setText(entry.message);

        view.findViewById(R.id.dialog_btn_copy_msg).setOnClickListener(v -> {
            copyText("Log Message", entry.message);
            dismiss();
        });

        view.findViewById(R.id.dialog_btn_copy_raw).setOnClickListener(v -> {
            copyText("Full Log Line", entry.rawLine);
            dismiss();
        });
    }

    private void copyText(String label, String text) {
        if (!isAdded()) return;
        ClipboardManager cm = (ClipboardManager) requireContext().getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm != null) {
            cm.setPrimaryClip(ClipData.newPlainText(label, text));
            Toast.makeText(requireContext(), "Copied to clipboard", Toast.LENGTH_SHORT).show();
        }
    }
}
