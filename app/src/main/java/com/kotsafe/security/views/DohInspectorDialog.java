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

package com.kotsafe.security.views;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;

import com.kotsafe.security.R;
import com.kotsafe.security.decoders.DohDecoder;
import com.kotsafe.security.decoders.DohDecoder.DohResult;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;

/**
 * BottomSheet dialog for inspecting decoded DNS-over-HTTPS (DoH) wireformat packets.
 */
public class DohInspectorDialog extends BottomSheetDialogFragment {
    public static final String TAG = "DohInspectorDialog";
    private static final String ARG_WIRE_DATA = "wire_dns_data";
    private static final String ARG_BASE64_URL = "base64_dns_url";

    private byte[] mWireData;
    private String mBase64Url;
    private DohResult mResult;

    public static DohInspectorDialog newInstance(@NonNull byte[] wireData) {
        DohInspectorDialog dialog = new DohInspectorDialog();
        Bundle args = new Bundle();
        args.putByteArray(ARG_WIRE_DATA, wireData);
        dialog.setArguments(args);
        return dialog;
    }

    public static DohInspectorDialog newInstanceFromBase64Url(@NonNull String base64Url) {
        DohInspectorDialog dialog = new DohInspectorDialog();
        Bundle args = new Bundle();
        args.putString(ARG_BASE64_URL, base64Url);
        dialog.setArguments(args);
        return dialog;
    }

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (getArguments() != null) {
            mWireData = getArguments().getByteArray(ARG_WIRE_DATA);
            mBase64Url = getArguments().getString(ARG_BASE64_URL);

            if (mWireData != null) {
                mResult = DohDecoder.decode(mWireData);
            } else if (mBase64Url != null) {
                mResult = DohDecoder.decodeBase64Url(mBase64Url);
            }
        }
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.dialog_doh_inspector, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        if (mResult == null) {
            Toast.makeText(requireContext(), "Could not decode as DNS wire format", Toast.LENGTH_SHORT).show();
            dismiss();
            return;
        }

        ImageView btnClose = view.findViewById(R.id.btn_close);
        TextView tvStatus = view.findViewById(R.id.tv_doh_status);
        TextView tvId = view.findViewById(R.id.tv_doh_id);
        TextView tvAnswersCount = view.findViewById(R.id.tv_doh_answers_count);
        TextView tvSummary = view.findViewById(R.id.tv_doh_summary);
        TextView tvJson = view.findViewById(R.id.tv_doh_json);

        Button btnCopySummary = view.findViewById(R.id.btn_copy_summary);
        Button btnCopyJson = view.findViewById(R.id.btn_copy_json);

        btnClose.setOnClickListener(v -> dismiss());

        // Header status styling
        if (mResult.isResponse) {
            tvStatus.setText("DNS RESP: " + mResult.rcodeName);
            if (mResult.rcode == 0) {
                tvStatus.setBackgroundResource(R.drawable.badge_pill_active);
                tvStatus.setTextColor(ContextCompat.getColor(requireContext(), R.color.badgeActiveFg));
            } else {
                tvStatus.setBackgroundResource(R.drawable.badge_pill_closed);
                tvStatus.setTextColor(ContextCompat.getColor(requireContext(), R.color.statusError));
            }
        } else {
            tvStatus.setText("DNS QUERY");
            tvStatus.setBackgroundResource(R.drawable.badge_pill_closed);
            tvStatus.setTextColor(ContextCompat.getColor(requireContext(), R.color.badgeClosedFg));
        }

        tvId.setText("ID: 0x" + Integer.toHexString(mResult.id).toUpperCase());
        tvAnswersCount.setText(mResult.answers.size() + " Answers");
        tvSummary.setText(mResult.summary);
        tvJson.setText(mResult.prettyJson);

        // Actions
        btnCopySummary.setOnClickListener(v -> {
            copyToClipboard("DNS Summary", mResult.summary);
            Toast.makeText(requireContext(), "DNS summary copied", Toast.LENGTH_SHORT).show();
        });

        btnCopyJson.setOnClickListener(v -> {
            copyToClipboard("DNS JSON", mResult.prettyJson);
            Toast.makeText(requireContext(), "DNS message JSON copied", Toast.LENGTH_SHORT).show();
        });
    }

    private void copyToClipboard(String label, String text) {
        ClipboardManager cm = (ClipboardManager) requireContext().getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm != null) {
            ClipData clip = ClipData.newPlainText(label, text);
            cm.setPrimaryClip(clip);
        }
    }
}
