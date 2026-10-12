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
 * * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.fragments;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.fragment.app.Fragment;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.CaptureService;
import com.kotsafe.security.HttpLog;
import com.kotsafe.security.Log;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.activities.ConnectionDetailsActivity;
import com.kotsafe.security.activities.HttpDetailsActivity;
import com.kotsafe.security.adapters.PayloadAdapter;
import com.kotsafe.security.interfaces.PayloadHostActivity;
import com.kotsafe.security.model.Prefs;
import com.kotsafe.security.views.EmptyRecyclerView;

public class HttpPayloadFragment extends Fragment implements PayloadHostActivity.ConnUpdateListener {
    private static final String TAG = "ConnectionPayload";
    private HttpDetailsActivity mActivity;
    private HttpLog.HttpRequest mHttpReq;
    private PayloadAdapter mAdapter;
    private EmptyRecyclerView mRecyclerView;

    public static HttpPayloadFragment newInstance(int req_pos, boolean show_reply) {
        HttpPayloadFragment fragment = new HttpPayloadFragment();
        Bundle args = new Bundle();
        args.putSerializable("show_reply", show_reply);
        args.putInt("req_pos", req_pos);
        fragment.setArguments(args);
        return fragment;
    }

    @Override
    public void onAttach(@NonNull Context context) {
        super.onAttach(context);

        mActivity = (HttpDetailsActivity) context;
        mActivity.addConnUpdateListener(this);

        if (mAdapter != null)
            mAdapter.setExportPayloadHandler(mActivity);
    }

    @Override
    public void onDetach() {
        super.onDetach();
        if (mActivity != null)
            mActivity.removeConnUpdateListener(this);
        mActivity = null;

        if (mAdapter != null)
            mAdapter.setExportPayloadHandler(null);
    }

    @Override
    public void connectionUpdated() {
        if (mAdapter != null && mHttpReq != null && getArguments() != null) {
            boolean show_reply = getArguments().getBoolean("show_reply");
            mAdapter.refreshHttpChunk(mHttpReq, show_reply);
        }
    }

    @Override
    public View onCreateView(LayoutInflater inflater,
                             ViewGroup container, Bundle savedInstanceState) {
        return inflater.inflate(R.layout.connection_payload, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        Bundle args = getArguments();
        assert args != null;

        HttpLog httpLog = CaptureService.getHttpLog();
        if (httpLog == null) {
            mActivity.finish();
            return;
        }

        mHttpReq = httpLog.getRequest(args.getInt("req_pos"));
        if(mHttpReq == null) {
            Utils.showToast(requireContext(), R.string.item_not_found);
            mActivity.finish();
            return;
        }

        mRecyclerView = view.findViewById(R.id.payload);
        EmptyRecyclerView.MyLinearLayoutManager layoutMan = new EmptyRecyclerView.MyLinearLayoutManager(requireContext());
        mRecyclerView.setLayoutManager(layoutMan);

        // Add window insets handling to prevent unwanted padding from propagated insets
        ViewCompat.setOnApplyWindowInsetsListener(mRecyclerView, (v, windowInsets) -> {
            Insets insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars() |
                    WindowInsetsCompat.Type.displayCutout());
            v.setPadding(0, 0, 0, insets.bottom);

            return WindowInsetsCompat.CONSUMED;
        });
        mRecyclerView.setClipToPadding(false);

        boolean show_reply = args.getBoolean("show_reply");
        mAdapter = new PayloadAdapter(requireContext(), mHttpReq, show_reply);
        mAdapter.setDisplayAsPrintableText(true);
        mAdapter.setExportPayloadHandler(mActivity);

        if (mHttpReq.decryptionError.isEmpty()) {
            View emptyView = view.findViewById(R.id.no_payload);
            if (emptyView != null)
                mRecyclerView.setEmptyView(emptyView);

            // only set adapter after acknowledged (see setMenuVisibility below)
            if (payloadNoticeAcknowledged(PreferenceManager.getDefaultSharedPreferences(requireContext())))
                mRecyclerView.setAdapter(mAdapter);
        } else {
            LinearLayout errorContainer = view.findViewById(R.id.decryption_error_container);
            TextView urlView = view.findViewById(R.id.request_url);
            TextView errorView = view.findViewById(R.id.decryption_error);
            Button showConnectionBtn = view.findViewById(R.id.show_connection_btn);

            urlView.setText(mHttpReq.getProtoAndHost());
            errorView.setText(mHttpReq.decryptionError);
            mRecyclerView.setEmptyView(errorContainer);

            showConnectionBtn.setOnClickListener(v -> {
                Intent intent = new Intent(requireContext(), ConnectionDetailsActivity.class);
                intent.putExtra(ConnectionDetailsActivity.CONN_ID_KEY, mHttpReq.conn.incr_id);
                startActivity(intent);
            });
        }
    }

    @Override
    public void setMenuVisibility(boolean menuVisible) {
        super.setMenuVisibility(menuVisible);

        Context context = getContext();
        if(context == null)
            return;

        Log.d(TAG, "setMenuVisibility : " + menuVisible);
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);

        if(menuVisible && !payloadNoticeAcknowledged(prefs)) {
            AlertDialog dialog = new AlertDialog.Builder(context)
                    .setTitle(R.string.warning)
                    .setMessage(R.string.payload_scams_notice)
                    .setOnCancelListener((d) -> requireActivity().finish())
                    .setNegativeButton(R.string.cancel_action, (d, b) -> requireActivity().finish())
                    .setPositiveButton(R.string.show_data_action, (d, whichButton) -> {
                        mRecyclerView.setAdapter(mAdapter);
                        prefs.edit().putBoolean(Prefs.PREF_PAYLOAD_NOTICE_ACK, true).apply();
                    }).show();

            dialog.setCanceledOnTouchOutside(false);
        }

        if(menuVisible && mActivity != null)
            mActivity.updateMenuVisibility();
    }

    private boolean payloadNoticeAcknowledged(SharedPreferences prefs) {
        return prefs.getBoolean(Prefs.PREF_PAYLOAD_NOTICE_ACK, false);
    }

    public void setDisplayMode(boolean showAsPrintable) {
        mAdapter.setDisplayAsPrintableText(showAsPrintable);
    }
}
