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

import android.app.Dialog;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.DialogFragment;

import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;

public class CtrlPermCodeDialog extends DialogFragment {
    public static final String TAG = "CtrlPermCodeDialog";
    private static final String ARG_API_KEY = "arg_api_key";

    public static CtrlPermCodeDialog newInstance(String apiKey) {
        CtrlPermCodeDialog dialog = new CtrlPermCodeDialog();
        Bundle args = new Bundle();
        args.putString(ARG_API_KEY, apiKey);
        dialog.setArguments(args);
        return dialog;
    }

    @NonNull
    @Override
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        String apiKey = getArguments() != null ? getArguments().getString(ARG_API_KEY, "") : "";
        if (apiKey == null || apiKey.isEmpty()) {
            apiKey = "<YOUR_API_KEY>";
        }

        LayoutInflater inflater = getLayoutInflater();
        View view = inflater.inflate(R.layout.dialog_ctrl_perm_code, null);

        TextView tvAdbStart = view.findViewById(R.id.code_adb_start);
        TextView tvAdbStop = view.findViewById(R.id.code_adb_stop);
        TextView tvAdbStatus = view.findViewById(R.id.code_adb_status);
        TextView tvTasker = view.findViewById(R.id.code_tasker);
        TextView tvBash = view.findViewById(R.id.code_bash);

        String cmdStart = "adb shell am broadcast -a com.kotsafe.security.Control -e action start -e api_key " + apiKey;
        String cmdStop = "adb shell am broadcast -a com.kotsafe.security.Control -e action stop -e api_key " + apiKey;
        String cmdStatus = "adb shell am broadcast -a com.kotsafe.security.Control -e action get_status -e api_key " + apiKey;
        String taskerText = "Action: com.kotsafe.security.Control\nExtra: action:start\nExtra: api_key:" + apiKey;
        String bashText = "#!/bin/bash\n# Start KotSafe Capture via Intent API\nam broadcast -a com.kotsafe.security.Control \\\n  -e action start \\\n  -e api_key \"" + apiKey + "\"";

        tvAdbStart.setText(cmdStart);
        tvAdbStop.setText(cmdStop);
        tvAdbStatus.setText(cmdStatus);
        tvTasker.setText(taskerText);
        tvBash.setText(bashText);

        view.findViewById(R.id.btn_copy_adb_start).setOnClickListener(v -> Utils.copyToClipboard(requireContext(), cmdStart));
        view.findViewById(R.id.btn_copy_adb_stop).setOnClickListener(v -> Utils.copyToClipboard(requireContext(), cmdStop));
        view.findViewById(R.id.btn_copy_adb_status).setOnClickListener(v -> Utils.copyToClipboard(requireContext(), cmdStatus));
        view.findViewById(R.id.btn_copy_tasker).setOnClickListener(v -> Utils.copyToClipboard(requireContext(), taskerText));
        view.findViewById(R.id.btn_copy_bash).setOnClickListener(v -> Utils.copyToClipboard(requireContext(), bashText));

        return new MaterialAlertDialogBuilder(requireContext())
                .setTitle("Control API Code & ADB Helper")
                .setIcon(R.drawable.ic_baseline_javascript)
                .setView(view)
                .setPositiveButton(R.string.ok, (d, w) -> d.dismiss())
                .create();
    }
}
