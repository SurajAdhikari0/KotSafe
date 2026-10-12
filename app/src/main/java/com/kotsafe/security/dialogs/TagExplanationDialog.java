package com.kotsafe.security.dialogs;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.annotation.Nullable;

import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.kotsafe.security.R;
import com.kotsafe.security.model.ConnectionDescriptor;

public class TagExplanationDialog {

    public static void showForFlowBadge(
            Context context,
            ConnectionDescriptor conn,
            boolean isDns,
            int totalCount,
            @Nullable Runnable onInspectAction
    ) {
        if (context == null || conn == null) return;

        LayoutInflater inflater = LayoutInflater.from(context);
        View view = inflater.inflate(R.layout.dialog_tag_info, null);

        TextView badgePreview = view.findViewById(R.id.tag_badge_preview);
        TextView targetSubtitle = view.findViewById(R.id.tag_target_subtitle);
        TextView titleView = view.findViewById(R.id.tv_tag_title);
        TextView whatTitleView = view.findViewById(R.id.tv_tag_what_title);
        TextView bodyView = view.findViewById(R.id.tv_tag_body);
        TextView whyTitleView = view.findViewById(R.id.tv_tag_why_title);
        TextView whyBodyView = view.findViewById(R.id.tv_tag_why_body);
        LinearLayout reasonContainer = view.findViewById(R.id.container_reason);
        TextView reasonBody = view.findViewById(R.id.tv_tag_reason_body);
        TextView tipView = view.findViewById(R.id.tv_tag_tip);

        String targetStr = (conn.info != null && !conn.info.isEmpty()) ? conn.info : (conn.dst_ip + ":" + conn.dst_port);
        targetSubtitle.setText(targetStr);

        boolean isBlocked = conn.is_blocked || conn.isBlacklisted();
        String inspectBtnText = "Inspect";

        if (isBlocked) {
            badgePreview.setText("🔁 " + totalCount + " blocked");
            badgePreview.setTextColor(Color.parseColor("#F85149"));
            badgePreview.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor("#3B1219")));

            titleView.setText("Blocked Connection Retries (" + totalCount + ")");
            whatTitleView.setText("What does this tag mean?");
            whatTitleView.setTextColor(Color.parseColor("#F85149"));

            bodyView.setText("KotSafe's firewall or security shield blocked " + totalCount + " repeated connection attempts to this destination.");

            whyTitleView.setText("Why are they merged together?");
            whyBodyView.setText("When trackers, ad networks, or malicious hosts are blocked by KotSafe, client apps often retry continuously in bursts (sometimes 10–20 times in a few seconds). KotSafe combines these repeated retries into one alert card showing the total blocked attempt volume, keeping your screen uncluttered.");

            String reason = (conn.block_reason != null && !conn.block_reason.isEmpty()) ? conn.block_reason : conn.getBlockReasonLabel(context);
            if (reason != null && !reason.isEmpty()) {
                reasonContainer.setVisibility(View.VISIBLE);
                reasonBody.setText(reason);
            }

            tipView.setText("💡 Tip: Tap 'Inspect Retries' or tap the connection card anytime to inspect individual blocked attempts.");
            inspectBtnText = "Inspect Retries";

        } else if (isDns) {
            badgePreview.setText("🔁 " + totalCount + " queries");
            badgePreview.setTextColor(Color.parseColor("#38BDF8"));
            badgePreview.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor("#1E293B")));

            titleView.setText("Deduplicated DNS Requests (" + totalCount + ")");
            whatTitleView.setText("What does this tag mean?");
            whatTitleView.setTextColor(Color.parseColor("#38BDF8"));

            bodyView.setText("This app issued " + totalCount + " DNS domain lookup queries for '" + targetStr + "' within a short time window.");

            whyTitleView.setText("Why are they merged together?");
            whyBodyView.setText("Apps and Android OS components query DNS multiple times in rapid succession (e.g. separate IPv4 'A' and IPv6 'AAAA' queries, or cache refreshes). Deduplicating them keeps your list clean while highlighting the total query frequency.");

            tipView.setText("💡 Tip: Tap 'View DNS Details' or tap the card to see the latest IP resolution, latency, and upstream DNS server.");
            inspectBtnText = "View DNS Details";

        } else {
            badgePreview.setText("🔁 " + totalCount + " flows");
            badgePreview.setTextColor(Color.parseColor("#38BDF8"));
            badgePreview.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor("#1E293B")));

            titleView.setText("Aggregated Network Sockets (" + totalCount + ")");
            whatTitleView.setText("What does this tag mean?");
            whatTitleView.setTextColor(Color.parseColor("#38BDF8"));

            bodyView.setText("This application opened " + totalCount + " parallel network connections (TCP/UDP sockets) to this remote destination.");

            whyTitleView.setText("Why are they merged together?");
            whyBodyView.setText("Modern apps routinely open 5 to 15 simultaneous sockets for faster parallel loading (such as video streaming chunks, cloud file uploads, or concurrent API requests). KotSafe aggregates them into a single card with combined byte metrics so you aren't overwhelmed by duplicate rows.");

            tipView.setText("💡 Tip: Tap 'Inspect Sockets' or tap the card anytime to see the full breakdown of every individual socket, including source ports, data transfer, and active duration.");
            inspectBtnText = "Inspect Sockets";
        }

        MaterialAlertDialogBuilder builder = new MaterialAlertDialogBuilder(context)
                .setView(view)
                .setPositiveButton("Got It", null);

        if (onInspectAction != null) {
            builder.setNegativeButton(inspectBtnText, (dialog, which) -> onInspectAction.run());
        }

        builder.show();
    }

    public static void showForBlockedReason(
            Context context,
            String category,
            ConnectionDescriptor conn,
            @Nullable Runnable onInspectAction
    ) {
        if (context == null || conn == null) return;

        LayoutInflater inflater = LayoutInflater.from(context);
        View view = inflater.inflate(R.layout.dialog_tag_info, null);

        TextView badgePreview = view.findViewById(R.id.tag_badge_preview);
        TextView targetSubtitle = view.findViewById(R.id.tag_target_subtitle);
        TextView titleView = view.findViewById(R.id.tv_tag_title);
        TextView whatTitleView = view.findViewById(R.id.tv_tag_what_title);
        TextView bodyView = view.findViewById(R.id.tv_tag_body);
        TextView whyTitleView = view.findViewById(R.id.tv_tag_why_title);
        TextView whyBodyView = view.findViewById(R.id.tv_tag_why_body);
        LinearLayout reasonContainer = view.findViewById(R.id.container_reason);
        TextView reasonBody = view.findViewById(R.id.tv_tag_reason_body);
        TextView tipView = view.findViewById(R.id.tv_tag_tip);

        String targetStr = (conn.info != null && !conn.info.isEmpty()) ? conn.info : (conn.dst_ip + ":" + conn.dst_port);
        targetSubtitle.setText(targetStr);

        String cat = (category != null) ? category.toUpperCase() : "BLOCKED";
        badgePreview.setText(cat);

        switch (cat) {
            case "MALWARE":
            case "MALICIOUS":
                badgePreview.setTextColor(Color.parseColor("#FFFFFF"));
                badgePreview.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor("#EF4444")));

                titleView.setText("Threat Shield: Malware / Botnet");
                whatTitleView.setText("Security Classification");
                whatTitleView.setTextColor(Color.parseColor("#EF4444"));

                bodyView.setText("This remote destination matches known Command & Control (C2) servers, malware distributors, or high-risk threat intelligence feeds.");

                whyTitleView.setText("Action Taken by KotSafe");
                whyBodyView.setText("All network packets to and from this host were intercepted and dropped immediately to protect your device from infection, ransomware, or unauthorized remote control.");

                tipView.setText("🛡️ Threat Defense: KotSafe's Threat Intelligence engine blocks malicious traffic before it can leave your device.");
                break;

            case "ADS":
            case "ADS_TRACKER":
                badgePreview.setTextColor(Color.parseColor("#FFFFFF"));
                badgePreview.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor("#EC4899")));

                titleView.setText("Privacy Shield: Ad & Tracker Block");
                whatTitleView.setText("Privacy Classification");
                whatTitleView.setTextColor(Color.parseColor("#EC4899"));

                bodyView.setText("This address belongs to an advertising network, user tracking script, or behavioral telemetry provider.");

                whyTitleView.setText("Action Taken by KotSafe");
                whyBodyView.setText("Requests were dropped by KotSafe's Privacy & Tracker Shield to prevent third parties from collecting telemetry across apps and save background battery and data.");

                tipView.setText("🔒 Privacy Protected: You can customize tracker & host protection lists in Settings -> Privacy & Tracker Shield.");
                break;

            case "PHISH":
            case "PHISHING":
                badgePreview.setTextColor(Color.parseColor("#FFFFFF"));
                badgePreview.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor("#A855F7")));

                titleView.setText("Phishing Protection");
                whatTitleView.setText("Security Classification");
                whatTitleView.setTextColor(Color.parseColor("#A855F7"));

                bodyView.setText("This address is identified as a fraudulent phishing domain designed to mimic legitimate services and steal credentials or passwords.");

                whyTitleView.setText("Action Taken by KotSafe");
                whyBodyView.setText("Connection refused to prevent deceptive credential harvesting and account compromise.");

                tipView.setText("🛡️ Phishing Defense: Never enter passwords or personal details if an app is redirected to unknown domains.");
                break;

            case "FIREWALL":
            case "FIREWALL_RULE":
                badgePreview.setTextColor(Color.parseColor("#FFFFFF"));
                badgePreview.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor("#F59E0B")));

                titleView.setText("Firewall Policy Restriction");
                whatTitleView.setText("Firewall Rule Triggered");
                whatTitleView.setTextColor(Color.parseColor("#F59E0B"));

                bodyView.setText("This connection was blocked in accordance with your configured firewall policies for this application.");

                whyTitleView.setText("Why was it blocked?");
                whyBodyView.setText("Common reasons include: restricting this app to Wi-Fi only, blocking mobile data, disabling background network access, or locking down the app's network permissions.");

                tipView.setText("⚙️ Firewall Rules: Tap this card and use the quick action toggles to manage firewall rules for this app.");
                break;

            case "LAN":
            case "LAN_RULE":
                badgePreview.setTextColor(Color.parseColor("#FFFFFF"));
                badgePreview.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor("#6366F1")));

                titleView.setText("Local Network (LAN) Policy");
                whatTitleView.setText("LAN Isolation Rule");
                whatTitleView.setTextColor(Color.parseColor("#6366F1"));

                bodyView.setText("This connection attempted to access a private local area network address (e.g. 192.168.x.x, 10.x.x.x) or subnet.");

                whyTitleView.setText("Why was it blocked?");
                whyBodyView.setText("Blocked by LAN isolation policies to prevent untrusted apps from scanning or communicating with other devices on your home or office Wi-Fi.");

                tipView.setText("🏠 LAN Security: Protects your smart TVs, routers, and local NAS devices from unauthorized app access.");
                break;

            case "LIMIT":
            case "RATE_LIMIT":
                badgePreview.setTextColor(Color.parseColor("#FFFFFF"));
                badgePreview.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor("#F97316")));

                titleView.setText("Flood Guard / Rate Limiting");
                whatTitleView.setText("Rate Limit Triggered");
                whatTitleView.setTextColor(Color.parseColor("#F97316"));

                bodyView.setText("This application attempted to open network sockets at an unusually high rate exceeding safety thresholds.");

                whyTitleView.setText("Action Taken by KotSafe");
                whyBodyView.setText("Throttled and dropped to mitigate potential connection floods, denial-of-service loops, or runaway background processes.");

                tipView.setText("⚡ Flood Guard: Protects your phone from battery drain and connection exhaustion.");
                break;

            default:
                badgePreview.setTextColor(Color.parseColor("#FFFFFF"));
                badgePreview.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor("#EF4444")));

                titleView.setText("Blocked Connection");
                whatTitleView.setText("Firewall Status");
                whatTitleView.setTextColor(Color.parseColor("#EF4444"));

                bodyView.setText("This network request was blocked by KotSafe's network filtering engine.");

                whyTitleView.setText("Reason");
                whyBodyView.setText("Connection dropped per active security or firewall policy.");

                tipView.setText("🛡️ KotSafe Firewall: Inspect connection details to learn more about the block trigger.");
                break;
        }

        String reason = (conn.block_reason != null && !conn.block_reason.isEmpty()) ? conn.block_reason : conn.getBlockReasonLabel(context);
        if (reason != null && !reason.isEmpty()) {
            reasonContainer.setVisibility(View.VISIBLE);
            reasonBody.setText(reason);
        }

        MaterialAlertDialogBuilder builder = new MaterialAlertDialogBuilder(context)
                .setView(view)
                .setPositiveButton("Got It", null);

        if (onInspectAction != null) {
            builder.setNegativeButton("View Details", (dialog, which) -> onInspectAction.run());
        }

        builder.show();
    }

    public static void showForRiskBadge(
            Context context,
            String riskLabel,
            ConnectionDescriptor conn,
            @Nullable Runnable onInspectAction
    ) {
        if (context == null || conn == null) return;

        LayoutInflater inflater = LayoutInflater.from(context);
        View view = inflater.inflate(R.layout.dialog_tag_info, null);

        TextView badgePreview = view.findViewById(R.id.tag_badge_preview);
        TextView targetSubtitle = view.findViewById(R.id.tag_target_subtitle);
        TextView titleView = view.findViewById(R.id.tv_tag_title);
        TextView whatTitleView = view.findViewById(R.id.tv_tag_what_title);
        TextView bodyView = view.findViewById(R.id.tv_tag_body);
        TextView whyTitleView = view.findViewById(R.id.tv_tag_why_title);
        TextView whyBodyView = view.findViewById(R.id.tv_tag_why_body);
        TextView tipView = view.findViewById(R.id.tv_tag_tip);

        String targetStr = (conn.info != null && !conn.info.isEmpty()) ? conn.info : (conn.dst_ip + ":" + conn.dst_port);
        targetSubtitle.setText(targetStr);

        badgePreview.setText(riskLabel != null ? riskLabel : "RISK");
        badgePreview.setTextColor(Color.parseColor("#FFFFFF"));

        if ("MALICIOUS".equalsIgnoreCase(riskLabel)) {
            badgePreview.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor("#EF4444")));
            titleView.setText("Risk Evaluation: Malicious");
            whatTitleView.setText("Risk Analysis");
            whatTitleView.setTextColor(Color.parseColor("#EF4444"));
            bodyView.setText("This connection communicates with a verified malicious endpoint or known threat infrastructure.");
            whyTitleView.setText("Why is this high risk?");
            whyBodyView.setText("Threat intelligence databases classify this IP/domain as harmful. Communicating with it can lead to credential theft or device control.");
        } else if ("HIGH_RISK".equalsIgnoreCase(riskLabel) || "HIGH RISK".equalsIgnoreCase(riskLabel)) {
            badgePreview.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor("#D97706")));
            titleView.setText("Risk Evaluation: High Risk");
            whatTitleView.setText("Risk Analysis");
            whatTitleView.setTextColor(Color.parseColor("#D97706"));
            bodyView.setText("This connection exhibits multiple risk factors (e.g. unencrypted protocol over sensitive ports, unknown offshore hosting, or suspicious behavior).");
            whyTitleView.setText("Recommendation");
            whyBodyView.setText("Inspect the data sent and verify if this app should be making connections to this destination.");
        } else {
            badgePreview.setBackgroundTintList(ColorStateList.valueOf(Color.parseColor("#7C3AED")));
            titleView.setText("Risk Evaluation: Suspicious");
            whatTitleView.setText("Risk Analysis");
            whatTitleView.setTextColor(Color.parseColor("#7C3AED"));
            bodyView.setText("This connection triggered an anomaly in KotSafe's heuristic trust evaluator.");
            whyTitleView.setText("Recommendation");
            whyBodyView.setText("Check the connection overview to see the app's destination country and TLS encryption status.");
        }

        tipView.setText("🔍 Risk Engine: KotSafe evaluates trust scores in real time based on certificates, ports, and threat intel.");

        MaterialAlertDialogBuilder builder = new MaterialAlertDialogBuilder(context)
                .setView(view)
                .setPositiveButton("Got It", null);

        if (onInspectAction != null) {
            builder.setNegativeButton("View Details", (dialog, which) -> onInspectAction.run());
        }

        builder.show();
    }
}
