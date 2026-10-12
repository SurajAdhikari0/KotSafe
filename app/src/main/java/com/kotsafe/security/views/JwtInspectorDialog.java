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
import com.kotsafe.security.decoders.JwtDecoder;
import com.kotsafe.security.decoders.JwtDecoder.JwtTokenInfo;
import com.kotsafe.security.decoders.JwtDecoder.TokenStatus;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;

/**
 * BottomSheet dialog for inspecting decoded JWT tokens, claims, and validation status.
 */
public class JwtInspectorDialog extends BottomSheetDialogFragment {
    public static final String TAG = "JwtInspectorDialog";
    private static final String ARG_RAW_JWT = "raw_jwt";

    private String mRawJwt;
    private JwtTokenInfo mTokenInfo;

    public static JwtInspectorDialog newInstance(@NonNull String rawJwt) {
        JwtInspectorDialog dialog = new JwtInspectorDialog();
        Bundle args = new Bundle();
        args.putString(ARG_RAW_JWT, rawJwt);
        dialog.setArguments(args);
        return dialog;
    }

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (getArguments() != null) {
            mRawJwt = getArguments().getString(ARG_RAW_JWT);
            if (mRawJwt != null) {
                mTokenInfo = JwtDecoder.findAndParseJwt(mRawJwt);
            }
        }
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.dialog_jwt_inspector, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        if (mTokenInfo == null) {
            Toast.makeText(requireContext(), "Invalid or malformed JWT token", Toast.LENGTH_SHORT).show();
            dismiss();
            return;
        }

        ImageView btnClose = view.findViewById(R.id.btn_close);
        TextView tvStatus = view.findViewById(R.id.tv_jwt_status);
        TextView tvAlg = view.findViewById(R.id.tv_jwt_algorithm);
        TextView tvType = view.findViewById(R.id.tv_jwt_type);
        TextView tvDetail = view.findViewById(R.id.tv_jwt_detail);

        TextView tvPayload = view.findViewById(R.id.tv_jwt_payload_json);
        TextView tvHeader = view.findViewById(R.id.tv_jwt_header_json);

        Button btnCopyJson = view.findViewById(R.id.btn_copy_json);
        Button btnCopyToken = view.findViewById(R.id.btn_copy_token);

        btnClose.setOnClickListener(v -> dismiss());

        // Status pill styling
        if (mTokenInfo.status == TokenStatus.VALID) {
            tvStatus.setText("ACTIVE");
            tvStatus.setBackgroundResource(R.drawable.badge_pill_active);
            tvStatus.setTextColor(ContextCompat.getColor(requireContext(), R.color.badgeActiveFg));
        } else if (mTokenInfo.status == TokenStatus.EXPIRED) {
            tvStatus.setText("EXPIRED");
            tvStatus.setBackgroundResource(R.drawable.badge_pill_closed);
            tvStatus.setTextColor(ContextCompat.getColor(requireContext(), R.color.statusError));
        } else if (mTokenInfo.status == TokenStatus.INSECURE_NONE) {
            tvStatus.setText("INSECURE NONE");
            tvStatus.setBackgroundResource(R.drawable.badge_pill_closed);
            tvStatus.setTextColor(ContextCompat.getColor(requireContext(), R.color.statusError));
        } else {
            tvStatus.setText(mTokenInfo.status.name());
        }

        tvAlg.setText("alg: " + mTokenInfo.algorithm);
        tvType.setText("typ: " + (mTokenInfo.tokenType != null ? mTokenInfo.tokenType : "JWT"));
        tvDetail.setText(mTokenInfo.statusDetail);

        tvPayload.setText(mTokenInfo.prettyPayload);
        tvHeader.setText(mTokenInfo.prettyHeader);

        // Copy Actions
        btnCopyJson.setOnClickListener(v -> {
            copyToClipboard("JWT Claims", mTokenInfo.prettyPayload);
            Toast.makeText(requireContext(), "Claims copied to clipboard", Toast.LENGTH_SHORT).show();
        });

        btnCopyToken.setOnClickListener(v -> {
            copyToClipboard("JWT Token", mTokenInfo.rawToken);
            Toast.makeText(requireContext(), "Raw token copied to clipboard", Toast.LENGTH_SHORT).show();
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
