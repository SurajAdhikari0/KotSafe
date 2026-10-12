/*
 * This file is part of KotSafe / KotSafe Cyber Security Project.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.views;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.kotsafe.security.CaptureService;
import com.kotsafe.security.ConnectionsRegister;
import com.kotsafe.security.R;
import com.kotsafe.security.model.AppDescriptor;
import com.kotsafe.security.model.ConnectionDescriptor;
import com.kotsafe.security.model.SecurityRulesDb;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;

import java.util.Collections;
import java.util.List;

/**
 * 1-tap quick firewall action dialog.
 * Appears on long-press of any connection row in the Connections tab.
 * Provides instant Block App / Block Domain / Block IP / AI Audit actions.
 */
public class QuickConnectionActionDialog extends BottomSheetDialogFragment {

    private static final String ARG_CONN_ID = "conn_id";
    private static final String ARG_DST_IP   = "dst_ip";
    private static final String ARG_DST_HOST = "dst_host";
    private static final String ARG_DST_PORT = "dst_port";
    private static final String ARG_UID      = "uid";
    private static final String ARG_PKG      = "pkg";
    private static final String ARG_APP_NAME = "app_name";

    /** Listener for actions the parent fragment should handle. */
    public interface ActionListener {
        void onBlockApp(int uid, String packageName);
        void onOpenAiAudit(int connId);
        default void onOpenTimeline(int uid, int connId) {}
    }

    private ActionListener mListener;

    public static QuickConnectionActionDialog newInstance(
            @NonNull ConnectionDescriptor conn, @Nullable String packageName, @Nullable String appName) {
        QuickConnectionActionDialog dlg = new QuickConnectionActionDialog();
        Bundle args = new Bundle();
        args.putInt(ARG_CONN_ID, conn.incr_id);
        args.putString(ARG_DST_IP, conn.dst_ip);
        args.putString(ARG_DST_HOST, conn.info);
        args.putInt(ARG_DST_PORT, conn.dst_port);
        args.putInt(ARG_UID, conn.uid);
        args.putString(ARG_PKG, packageName != null ? packageName : "");
        args.putString(ARG_APP_NAME, appName != null ? appName : "UID " + conn.uid);
        dlg.setArguments(args);
        return dlg;
    }

    public void setActionListener(@Nullable ActionListener listener) {
        mListener = listener;
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater,
                             @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.dialog_quick_conn_action, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        Bundle args = getArguments();
        if (args == null) { dismiss(); return; }

        int connId   = args.getInt(ARG_CONN_ID, -1);
        String dstIp = args.getString(ARG_DST_IP, "");
        String host  = args.getString(ARG_DST_HOST, "");
        int port     = args.getInt(ARG_DST_PORT, 0);
        int uid      = args.getInt(ARG_UID, -1);
        String pkg   = args.getString(ARG_PKG, "");
        String appName = args.getString(ARG_APP_NAME, "App");

        // Header
        TextView tvTarget = view.findViewById(R.id.tv_quick_target);
        String target = (host != null && !host.isEmpty()) ? host : dstIp;
        tvTarget.setText(target + ":" + port);

        // Block App
        LinearLayout rowBlockApp = view.findViewById(R.id.row_block_app);
        TextView tvBlockAppDesc = view.findViewById(R.id.tv_block_app_desc);
        boolean isSelf = (uid == android.os.Process.myUid())
                || com.kotsafe.security.model.SecurityBlocklistManager.getInstance(requireContext()).isSelfOrKotSafe(pkg);
        boolean canBlockApp = uid >= android.os.Process.FIRST_APPLICATION_UID && !isSelf;
        if (canBlockApp) {
            tvBlockAppDesc.setText("Block all traffic from: " + appName);
            rowBlockApp.setOnClickListener(v -> {
                if (mListener != null) {
                    mListener.onBlockApp(uid, pkg);
                }
                dismiss();
            });
        } else {
            if (isSelf) {
                tvBlockAppDesc.setText("KotSafe core security system is protected");
                rowBlockApp.setEnabled(false);
                rowBlockApp.setAlpha(0.5f);
            } else if (uid == 1000 || port == 53) {
                ConnectionsRegister reg = null;
                try {
                    reg = CaptureService.requireConnsRegister();
                } catch (Exception ignored) {}
                ConnectionDescriptor conn = (reg != null && connId >= 0) ? reg.getConnById(connId) : null;
                long t = (conn != null && conn.last_seen > 0) ? conn.last_seen : System.currentTimeMillis();
                List<ConnectionsRegister.CorrelatedApp> correlated = (reg != null)
                        ? reg.getCorrelatedAppsForTimestamp(t, 5000)
                        : Collections.emptyList();
                if (!correlated.isEmpty()) {
                    AppDescriptor caller = correlated.get(0).app;
                    tvBlockAppDesc.setText("Android System Resolver (Likely caller: " + caller.getName() + ")\nTap to block " + caller.getName());
                    rowBlockApp.setEnabled(true);
                    rowBlockApp.setAlpha(1.0f);
                    rowBlockApp.setOnClickListener(v -> {
                        if (mListener != null) {
                            mListener.onBlockApp(caller.getUid(), caller.getPackageName());
                        }
                        dismiss();
                    });
                } else {
                    tvBlockAppDesc.setText("System DNS Resolver (Protected from app-wide block)");
                    rowBlockApp.setEnabled(false);
                    rowBlockApp.setAlpha(0.5f);
                }
            } else {
                // Core Android services keep connectivity, VPN routing, and time in sync. They
                // remain visible for investigation, but a one-tap app-wide block would be unsafe.
                tvBlockAppDesc.setText("System services are protected from app-wide blocking");
                rowBlockApp.setEnabled(false);
                rowBlockApp.setAlpha(0.5f);
            }
        }

        // Block Domain
        LinearLayout rowBlockDomain = view.findViewById(R.id.row_block_domain);
        LinearLayout rowBlockDomainGroup = view.findViewById(R.id.row_block_domain_group);
        if (host != null && !host.isEmpty()) {
            rowBlockDomainGroup.setVisibility(View.VISIBLE);
            TextView tvBlockDomainDesc = view.findViewById(R.id.tv_block_domain_desc);
            tvBlockDomainDesc.setText("Block domain: " + host);
            rowBlockDomain.setOnClickListener(v -> {
                if (getContext() != null) {
                    if (com.kotsafe.security.model.SecurityBlocklistManager.isOfficialDomain(host)
                            || com.kotsafe.security.model.SecurityBlocklistManager.isTrustedAdOrAnalyticsDomain(host)
                            || com.kotsafe.security.model.SecurityBlocklistManager.getInstance(requireContext()).isSystemWhitelisted(host)) {
                        Toast.makeText(requireContext(), host + " is a safe / trusted domain and cannot be blocked.", Toast.LENGTH_SHORT).show();
                        dismiss();
                        return;
                    }
                    SecurityRulesDb.getInstance(requireContext())
                            .blockDomain(host, "Blocked via Quick Action", SecurityRulesDb.SOURCE_USER);
                    Toast.makeText(requireContext(), "Domain " + host + " blocked", Toast.LENGTH_SHORT).show();
                }
                dismiss();
            });
        } else {
            rowBlockDomainGroup.setVisibility(View.GONE);
        }

        // Block IP
        LinearLayout rowBlockIp = view.findViewById(R.id.row_block_ip);
        TextView tvBlockIpDesc = view.findViewById(R.id.tv_block_ip_desc);
        if (dstIp != null && !dstIp.isEmpty()) {
            tvBlockIpDesc.setText("Block IP: " + dstIp);
            rowBlockIp.setOnClickListener(v -> {
                if (getContext() != null) {
                    if (com.kotsafe.security.model.SecurityBlocklistManager.getInstance(requireContext()).isSystemWhitelisted(dstIp)
                            || com.kotsafe.security.model.SecurityBlocklistManager.isCloudflareCdnIp(dstIp)) {
                        Toast.makeText(requireContext(), dstIp + " is a protected infrastructure IP and cannot be blocked.", Toast.LENGTH_SHORT).show();
                        dismiss();
                        return;
                    }
                    SecurityRulesDb.getInstance(requireContext())
                            .blockIp(dstIp, "Blocked via Quick Action", SecurityRulesDb.SOURCE_USER);
                    Toast.makeText(requireContext(), "IP " + dstIp + " blocked", Toast.LENGTH_SHORT).show();
                }
                dismiss();
            });
        } else {
            rowBlockIp.setVisibility(View.GONE);
        }

        // AI Security Audit
        LinearLayout rowAiAudit = view.findViewById(R.id.row_ai_audit);
        rowAiAudit.setOnClickListener(v -> {
            if (mListener != null && connId >= 0) {
                mListener.onOpenAiAudit(connId);
            }
            dismiss();
        });

        // App Activity Timeline
        LinearLayout rowTimeline = view.findViewById(R.id.row_app_timeline);
        if (rowTimeline != null) {
            rowTimeline.setOnClickListener(v -> {
                if (mListener != null && uid >= 0) {
                    mListener.onOpenTimeline(uid, connId);
                }
                dismiss();
            });
        }

        // Cancel
        view.findViewById(R.id.btn_cancel_quick).setOnClickListener(v -> dismiss());
    }
}
