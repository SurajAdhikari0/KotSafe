/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.dialogs;

import android.app.Dialog;
import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ProgressBar;
import android.widget.RadioButton;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.CaptureService;
import com.kotsafe.security.ConnectionsRegister;
import com.kotsafe.security.R;
import com.kotsafe.security.model.Prefs;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.google.android.material.bottomsheet.BottomSheetDialog;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;
import com.google.android.material.textfield.TextInputEditText;
import com.google.android.material.textfield.TextInputLayout;

import java.text.NumberFormat;

public class ConnectionsLogSizeDialog extends BottomSheetDialogFragment {
    public static final String TAG = "ConnectionsLogSizeDialog";

    public interface OnConnectionsLogSizeChangedListener {
        void onConnectionsLogSizeChanged(int newSize);
    }

    private static final int PRESET_ECO = 2048;
    private static final int PRESET_STANDARD = 8192;
    private static final int PRESET_HIGH = 16384;
    private static final int PRESET_FORENSIC = 32768;
    private static final int PRESET_VAULT = 65536;

    private int mSelectedSize = PRESET_STANDARD;
    private boolean mIsCustom = false;
    private int mMaxSupported = 65536;
    private OnConnectionsLogSizeChangedListener mListener;

    private MaterialCardView mCardEco, mCardStandard, mCardHigh, mCardForensic, mCardVault, mCardCustom;
    private RadioButton mRbEco, mRbStandard, mRbHigh, mRbForensic, mRbVault, mRbCustom;
    private View mLayoutCustomInput;
    private TextInputLayout mTilCustom;
    private TextInputEditText mEtCustom;
    private TextView mTvCustomCalc;
    private ProgressBar mPbMemory;
    private TextView mTvActiveConnections, mTvHeapHeadroom, mTvBufferRatioLabel;

    public static ConnectionsLogSizeDialog newInstance() {
        return new ConnectionsLogSizeDialog();
    }

    public void setListener(OnConnectionsLogSizeChangedListener listener) {
        mListener = listener;
    }

    @Override
    public int getTheme() {
        return R.style.Theme_MaterialComponents_DayNight_BottomSheetDialog;
    }

    @NonNull
    @Override
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        BottomSheetDialog dialog = (BottomSheetDialog) super.onCreateDialog(savedInstanceState);
        dialog.setOnShowListener(d -> {
            BottomSheetDialog bsd = (BottomSheetDialog) d;
            FrameLayout bottomSheet = bsd.findViewById(com.google.android.material.R.id.design_bottom_sheet);
            if (bottomSheet != null) {
                BottomSheetBehavior<FrameLayout> behavior = BottomSheetBehavior.from(bottomSheet);
                behavior.setState(BottomSheetBehavior.STATE_EXPANDED);
                behavior.setSkipCollapsed(true);
            }
        });
        return dialog;
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.dialog_connections_log_size, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        Context context = requireContext();
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        mSelectedSize = Prefs.getConnectionsLogSize(prefs);
        mMaxSupported = Prefs.getMaxConnectionsLogSize();

        // Bind views
        view.findViewById(R.id.btn_dialog_close).setOnClickListener(v -> dismiss());

        mTvActiveConnections = view.findViewById(R.id.tv_active_connections);
        mTvHeapHeadroom = view.findViewById(R.id.tv_heap_headroom);
        mPbMemory = view.findViewById(R.id.pb_memory_ratio);
        mTvBufferRatioLabel = view.findViewById(R.id.tv_buffer_ratio_label);

        mCardEco = view.findViewById(R.id.card_preset_eco);
        mCardStandard = view.findViewById(R.id.card_preset_standard);
        mCardHigh = view.findViewById(R.id.card_preset_high);
        mCardForensic = view.findViewById(R.id.card_preset_forensic);
        mCardVault = view.findViewById(R.id.card_preset_vault);
        mCardCustom = view.findViewById(R.id.card_preset_custom);

        mRbEco = view.findViewById(R.id.rb_preset_eco);
        mRbStandard = view.findViewById(R.id.rb_preset_standard);
        mRbHigh = view.findViewById(R.id.rb_preset_high);
        mRbForensic = view.findViewById(R.id.rb_preset_forensic);
        mRbVault = view.findViewById(R.id.rb_preset_vault);
        mRbCustom = view.findViewById(R.id.rb_preset_custom);

        mLayoutCustomInput = view.findViewById(R.id.layout_custom_input);
        mTilCustom = view.findViewById(R.id.til_custom_size);
        mEtCustom = view.findViewById(R.id.et_custom_size);
        mTvCustomCalc = view.findViewById(R.id.tv_custom_calc);

        MaterialButton btnApply = view.findViewById(R.id.btn_apply);
        MaterialButton btnCancel = view.findViewById(R.id.btn_cancel);

        // Hide vault card if device heap cannot support it
        if (mMaxSupported < PRESET_VAULT) {
            mCardVault.setVisibility(View.GONE);
        }

        // Hide forensic card if device heap cannot support it
        if (mMaxSupported < PRESET_FORENSIC) {
            mCardForensic.setVisibility(View.GONE);
        }

        // Setup memory status card
        setupMemoryStats();

        // Setup preset click listeners
        mCardEco.setOnClickListener(v -> selectPreset(PRESET_ECO));
        mCardStandard.setOnClickListener(v -> selectPreset(PRESET_STANDARD));
        mCardHigh.setOnClickListener(v -> selectPreset(PRESET_HIGH));
        mCardForensic.setOnClickListener(v -> selectPreset(PRESET_FORENSIC));
        mCardVault.setOnClickListener(v -> selectPreset(PRESET_VAULT));
        mCardCustom.setOnClickListener(v -> selectCustom());

        mEtCustom.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                if (!mIsCustom) return;
                updateCustomCalculation(s.toString().trim());
            }

            @Override
            public void afterTextChanged(Editable s) {}
        });

        // Initialize selection state
        if (mSelectedSize == PRESET_ECO) {
            selectPreset(PRESET_ECO);
        } else if (mSelectedSize == PRESET_STANDARD) {
            selectPreset(PRESET_STANDARD);
        } else if (mSelectedSize == PRESET_HIGH) {
            selectPreset(PRESET_HIGH);
        } else if (mSelectedSize == PRESET_FORENSIC) {
            selectPreset(PRESET_FORENSIC);
        } else if (mSelectedSize == PRESET_VAULT) {
            selectPreset(PRESET_VAULT);
        } else {
            selectCustom();
            mEtCustom.setText(String.valueOf(mSelectedSize));
        }

        btnCancel.setOnClickListener(v -> dismiss());

        btnApply.setOnClickListener(v -> applySelection());
    }

    private void setupMemoryStats() {
        ConnectionsRegister reg = CaptureService.getConnsRegister();
        int activeCount = (reg != null) ? reg.getConnCount() : 0;
        int currentLimit = (reg != null) ? reg.getSize() : mSelectedSize;

        mTvActiveConnections.setText(NumberFormat.getInstance().format(activeCount) + " / " + NumberFormat.getInstance().format(currentLimit));

        long maxMemory = Runtime.getRuntime().maxMemory();
        long totalMemory = Runtime.getRuntime().totalMemory();
        long freeMemory = Runtime.getRuntime().freeMemory();
        long usedMemory = totalMemory - freeMemory;
        long headroom = Math.max(0, maxMemory - usedMemory);

        int headroomMb = (int) (headroom / (1024 * 1024));
        mTvHeapHeadroom.setText(headroomMb + " MB free");

        updateBufferRatio(mSelectedSize);
    }

    private void updateBufferRatio(int connCount) {
        long estRamBytes = (long) connCount * 2L * 1024;
        int estRamMb = (int) (estRamBytes / (1024 * 1024));

        long maxMemory = Runtime.getRuntime().maxMemory();
        int progress = (int) Math.min(100, (estRamBytes * 100) / Math.max(1, maxMemory));

        mPbMemory.setProgress(progress);
        mTvBufferRatioLabel.setText("Estimated RAM usage: ~" + estRamMb + " MB (" + progress + "% of Java heap)");
    }

    private void selectPreset(int size) {
        mIsCustom = false;
        mSelectedSize = size;
        mLayoutCustomInput.setVisibility(View.GONE);

        mRbEco.setChecked(size == PRESET_ECO);
        mRbStandard.setChecked(size == PRESET_STANDARD);
        mRbHigh.setChecked(size == PRESET_HIGH);
        mRbForensic.setChecked(size == PRESET_FORENSIC);
        mRbVault.setChecked(size == PRESET_VAULT);
        mRbCustom.setChecked(false);

        updateCardStroke(mCardEco, size == PRESET_ECO);
        updateCardStroke(mCardStandard, size == PRESET_STANDARD);
        updateCardStroke(mCardHigh, size == PRESET_HIGH);
        updateCardStroke(mCardForensic, size == PRESET_FORENSIC);
        updateCardStroke(mCardVault, size == PRESET_VAULT);
        updateCardStroke(mCardCustom, false);

        updateBufferRatio(size);
    }

    private void selectCustom() {
        mIsCustom = true;
        mLayoutCustomInput.setVisibility(View.VISIBLE);

        mRbEco.setChecked(false);
        mRbStandard.setChecked(false);
        mRbHigh.setChecked(false);
        mRbForensic.setChecked(false);
        mRbVault.setChecked(false);
        mRbCustom.setChecked(true);

        updateCardStroke(mCardEco, false);
        updateCardStroke(mCardStandard, false);
        updateCardStroke(mCardHigh, false);
        updateCardStroke(mCardForensic, false);
        updateCardStroke(mCardVault, false);
        updateCardStroke(mCardCustom, true);

        String currentText = (mEtCustom.getText() != null) ? mEtCustom.getText().toString().trim() : "";
        if (currentText.isEmpty()) {
            mEtCustom.setText(String.valueOf(mSelectedSize));
            updateCustomCalculation(String.valueOf(mSelectedSize));
        } else {
            updateCustomCalculation(currentText);
        }
    }

    private void updateCustomCalculation(String text) {
        mTilCustom.setError(null);
        if (text.isEmpty()) {
            mTvCustomCalc.setText("Enter a value between 1,024 and " + NumberFormat.getInstance().format(mMaxSupported));
            return;
        }

        try {
            int val = Integer.parseInt(text);
            long mb = ((long) val * 2L) / 1024;
            if (val < Prefs.MIN_CONNECTIONS_LOG_SIZE) {
                mTilCustom.setError("Minimum value is " + Prefs.MIN_CONNECTIONS_LOG_SIZE);
            } else if (val > mMaxSupported) {
                mTilCustom.setError("Maximum supported for this device is " + NumberFormat.getInstance().format(mMaxSupported));
            } else {
                mSelectedSize = val;
                mTvCustomCalc.setText("Valid: " + NumberFormat.getInstance().format(val) + " connections ≈ " + mb + " MB RAM");
                updateBufferRatio(val);
            }
        } catch (NumberFormatException e) {
            mTilCustom.setError("Invalid number");
        }
    }

    private void updateCardStroke(MaterialCardView card, boolean isSelected) {
        if (card == null) return;
        int primaryColor = ContextCompat.getColor(requireContext(), R.color.colorPrimary);
        int strokeColor = isSelected ? primaryColor : Color.parseColor("#33888888");
        card.setStrokeColor(strokeColor);
        card.setStrokeWidth(isSelected ? 2 : 1);
    }

    private void applySelection() {
        if (mIsCustom) {
            String text = (mEtCustom.getText() != null) ? mEtCustom.getText().toString().trim() : "";
            try {
                int val = Integer.parseInt(text);
                if (val < Prefs.MIN_CONNECTIONS_LOG_SIZE || val > mMaxSupported) {
                    mTilCustom.setError("Must be between " + Prefs.MIN_CONNECTIONS_LOG_SIZE + " and " + NumberFormat.getInstance().format(mMaxSupported));
                    return;
                }
                mSelectedSize = val;
            } catch (NumberFormatException e) {
                mTilCustom.setError("Invalid number");
                return;
            }
        }

        Context ctx = requireContext();
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ctx);
        Prefs.setConnectionsLogSize(prefs, mSelectedSize);

        int mb = (int) (((long) mSelectedSize * 2L) / 1024);
        Toast.makeText(ctx, getString(R.string.connections_resized_toast, NumberFormat.getInstance().format(mSelectedSize), mb), Toast.LENGTH_SHORT).show();

        if (mListener != null) {
            mListener.onConnectionsLogSizeChanged(mSelectedSize);
        }

        dismiss();
    }
}
