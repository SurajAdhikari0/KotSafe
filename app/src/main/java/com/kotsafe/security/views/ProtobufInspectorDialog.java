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
import com.kotsafe.security.decoders.ProtobufDecoder;
import com.kotsafe.security.decoders.ProtobufDecoder.ProtobufResult;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;

/**
 * BottomSheet dialog for inspecting decoded Protocol Buffers and gRPC wire payloads.
 */
public class ProtobufInspectorDialog extends BottomSheetDialogFragment {
    public static final String TAG = "ProtobufInspectorDialog";
    private static final String ARG_PAYLOAD = "raw_protobuf_payload";

    private byte[] mPayload;
    private ProtobufResult mResult;

    public static ProtobufInspectorDialog newInstance(@NonNull byte[] payload) {
        ProtobufInspectorDialog dialog = new ProtobufInspectorDialog();
        Bundle args = new Bundle();
        args.putByteArray(ARG_PAYLOAD, payload);
        dialog.setArguments(args);
        return dialog;
    }

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (getArguments() != null) {
            mPayload = getArguments().getByteArray(ARG_PAYLOAD);
            if (mPayload != null) {
                mResult = ProtobufDecoder.detectAndDecode(mPayload);
            }
        }
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.dialog_protobuf_inspector, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        if (mResult == null) {
            Toast.makeText(requireContext(), "Could not decode as Protobuf / gRPC", Toast.LENGTH_SHORT).show();
            dismiss();
            return;
        }

        ImageView btnClose = view.findViewById(R.id.btn_close);
        TextView tvFormat = view.findViewById(R.id.tv_proto_format);
        TextView tvFields = view.findViewById(R.id.tv_proto_fields);
        TextView tvSize = view.findViewById(R.id.tv_proto_size);
        TextView tvDetail = view.findViewById(R.id.tv_proto_detail);

        TextView tvJson = view.findViewById(R.id.tv_proto_json);
        TextView tvHex = view.findViewById(R.id.tv_proto_hex);

        Button btnCopyHex = view.findViewById(R.id.btn_copy_hex);
        Button btnCopyJson = view.findViewById(R.id.btn_copy_json);

        btnClose.setOnClickListener(v -> dismiss());

        // Format pill
        if (mResult.isGrpc) {
            tvFormat.setText(mResult.isCompressed ? "gRPC (COMPRESSED)" : "gRPC FRAME");
            tvFormat.setBackgroundResource(R.drawable.badge_pill_active);
            tvFormat.setTextColor(ContextCompat.getColor(requireContext(), R.color.badgeActiveFg));
            tvDetail.setText("5-byte gRPC framing detected and stripped. Wire payload decoded.");
        } else {
            tvFormat.setText("PROTOBUF");
            tvFormat.setBackgroundResource(R.drawable.badge_pill_active);
            tvFormat.setTextColor(ContextCompat.getColor(requireContext(), R.color.badgeActiveFg));
            tvDetail.setText("Raw Protobuf wire-format decoded into structured fields.");
        }

        tvFields.setText(mResult.totalFields + " fields");
        tvSize.setText(mResult.payloadSize + " bytes");

        tvJson.setText(mResult.prettyJson);
        tvHex.setText(mResult.rawHex);

        // Actions
        btnCopyJson.setOnClickListener(v -> {
            copyToClipboard("Protobuf JSON", mResult.prettyJson);
            Toast.makeText(requireContext(), "JSON copied to clipboard", Toast.LENGTH_SHORT).show();
        });

        btnCopyHex.setOnClickListener(v -> {
            copyToClipboard("Protobuf Hex", mResult.rawHex);
            Toast.makeText(requireContext(), "Raw hex copied to clipboard", Toast.LENGTH_SHORT).show();
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
