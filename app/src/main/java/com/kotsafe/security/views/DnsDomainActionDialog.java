/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.views;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.kotsafe.security.R;
import com.kotsafe.security.model.AdBlockSubscriptionManager;
import com.kotsafe.security.model.DnsActivityEntry;
import com.kotsafe.security.model.ThreatIntelManager;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;

public class DnsDomainActionDialog extends BottomSheetDialogFragment {
    public static final String TAG = "DnsDomainActionDialog";
    private static final String ARG_ENTRY = "dns_entry";

    public interface OnRuleChangedListener {
        void onRuleChanged();
    }

    private DnsActivityEntry mEntry;
    private OnRuleChangedListener mListener;

    public static DnsDomainActionDialog newInstance(DnsActivityEntry entry) {
        DnsDomainActionDialog dialog = new DnsDomainActionDialog();
        Bundle args = new Bundle();
        args.putSerializable(ARG_ENTRY, entry);
        dialog.setArguments(args);
        return dialog;
    }

    public void setOnRuleChangedListener(OnRuleChangedListener listener) {
        mListener = listener;
    }

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (getArguments() != null) {
            mEntry = (DnsActivityEntry) getArguments().getSerializable(ARG_ENTRY);
        }
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.dialog_dns_domain_action, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        if (mEntry == null) {
            dismiss();
            return;
        }

        TextView tvBadge = view.findViewById(R.id.tv_dns_status_badge);
        TextView tvDomain = view.findViewById(R.id.tv_dns_domain_name);
        TextView tvCaller = view.findViewById(R.id.tv_dns_caller_info);
        TextView tvReason = view.findViewById(R.id.tv_dns_reason);

        tvDomain.setText(mEntry.domain);
        String caller = (mEntry.callerApp != null && !mEntry.callerApp.isEmpty()) ? mEntry.callerApp : "Network Process";
        tvCaller.setText("App: " + caller + " • Query: " + mEntry.queryType);

        if (mEntry.isBlocked()) {
            tvBadge.setText("BLOCKED");
            tvBadge.setBackgroundColor(Color.parseColor("#E53935"));
            String r = (mEntry.blockReason != null && !mEntry.blockReason.isEmpty()) ? mEntry.blockReason : "Tracker / Ad Blocklist";
            tvReason.setText("Blocked by: " + r);
            tvReason.setVisibility(View.VISIBLE);
        } else {
            tvBadge.setText("ALLOWED");
            tvBadge.setBackgroundColor(Color.parseColor("#43A047"));
            tvReason.setVisibility(View.GONE);
        }

        // Action: Always Whitelist
        view.findViewById(R.id.btn_action_whitelist).setOnClickListener(v -> {
            AdBlockSubscriptionManager.getInstance(requireContext()).addToWhitelist(mEntry.domain);
            Toast.makeText(requireContext(), "Added to Whitelist: " + mEntry.domain, Toast.LENGTH_SHORT).show();
            if (mListener != null) mListener.onRuleChanged();
            dismiss();
        });

        // Action: Always Blacklist
        view.findViewById(R.id.btn_action_blacklist).setOnClickListener(v -> {
            AdBlockSubscriptionManager.getInstance(requireContext()).addToBlacklist(mEntry.domain);
            Toast.makeText(requireContext(), "Blocked via Blacklist: " + mEntry.domain, Toast.LENGTH_SHORT).show();
            if (mListener != null) mListener.onRuleChanged();
            dismiss();
        });

        // Action: Copy Domain
        view.findViewById(R.id.btn_action_copy).setOnClickListener(v -> {
            ClipboardManager cb = (ClipboardManager) requireContext().getSystemService(Context.CLIPBOARD_SERVICE);
            if (cb != null) {
                cb.setPrimaryClip(ClipData.newPlainText("domain", mEntry.domain));
                Toast.makeText(requireContext(), "Copied to clipboard", Toast.LENGTH_SHORT).show();
            }
            dismiss();
        });

        // Action: WHOIS / Threat Lookup
        view.findViewById(R.id.btn_action_whois).setOnClickListener(v -> {
            ThreatIntelManager.openVirusTotalAuto(requireContext(), mEntry.domain, "DOMAIN");
            dismiss();
        });
    }
}
