/*
 * This file is part of KotSafe / KotSafe Cyber Security Project.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.views;

import android.content.res.ColorStateList;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;

import com.kotsafe.security.AppsResolver;
import com.kotsafe.security.CaptureService;
import com.kotsafe.security.ConnectionsRegister;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.ai.AiClientEngine;
import com.kotsafe.security.ai.AiConfig;
import com.kotsafe.security.model.AppDescriptor;
import com.kotsafe.security.model.AppIntelligenceEngine;
import com.kotsafe.security.model.ConnectionDescriptor;
import com.kotsafe.security.model.SecurityRulesDb;
import com.kotsafe.security.model.TiCacheDb;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * AI Socket Flow & Exfiltration Risk Assessment Dialog.
 * Advanced audit engine inspecting:
 * - App Intelligence, install provenance & sensitive permissions
 * - Asymmetric data transfer (exfiltration indicator)
 * - Non-standard ports, cleartext traffic & anomalous protocols
 * - Multi-source Threat Intelligence feeds (OTX, ThreatFox, URLhaus)
 * - MITRE ATT&CK technique mapping
 * - Active firewall rules and 1-tap remediation
 */
public class ConnectionAiFlowDialog extends BottomSheetDialogFragment {

    private static final String ARG_CONN_ID = "conn_id";

    private int mConnId = -1;
    private ConnectionDescriptor mConn;

    private TextView mTvTarget;
    private TextView mTvModeBadge;
    private TextView mTvThreatProb;
    private TextView mTvVerdict;
    private TextView mTvClassification;
    private TextView mTvSignalRatio;
    private TextView mTvSignalPort;
    private TextView mTvSignalAsn;
    private TextView mTvSignalMitre;
    private TextView mTvReasoning;

    // App Intelligence views
    private ImageView mIvAuditAppIcon;
    private TextView mTvAuditAppName;
    private TextView mTvAuditAppPkg;
    private TextView mTvAuditAppProvenance;
    private TextView mTvAuditAppDetails;

    // 3-bullet structured verdict views
    private TextView mTvEndpointIdentity;
    private TextView mTvConnectionIntent;
    private TextView mTvActionRecommendation;
    private android.widget.Button mBtnRuleAction;

    public static ConnectionAiFlowDialog newInstance(int connId) {
        ConnectionAiFlowDialog dialog = new ConnectionAiFlowDialog();
        Bundle args = new Bundle();
        args.putInt(ARG_CONN_ID, connId);
        dialog.setArguments(args);
        return dialog;
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.dialog_connection_ai_flow, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        if (getArguments() != null) {
            mConnId = getArguments().getInt(ARG_CONN_ID, -1);
        }

        ConnectionsRegister reg = CaptureService.getConnsRegister();
        if (reg != null && mConnId >= 0) {
            mConn = reg.getConnById(mConnId);
        }

        initViews(view);
        evaluateFlow();
    }

    private void initViews(View v) {
        mTvTarget = v.findViewById(R.id.tv_flow_target);
        mTvModeBadge = v.findViewById(R.id.tv_flow_mode_badge);
        mTvThreatProb = v.findViewById(R.id.tv_threat_prob);
        mTvVerdict = v.findViewById(R.id.tv_flow_verdict);
        mTvClassification = v.findViewById(R.id.tv_flow_classification);
        mTvSignalRatio = v.findViewById(R.id.tv_signal_ratio);
        mTvSignalPort = v.findViewById(R.id.tv_signal_port);
        mTvSignalAsn = v.findViewById(R.id.tv_signal_asn);
        mTvSignalMitre = v.findViewById(R.id.tv_signal_mitre);
        mTvReasoning = v.findViewById(R.id.tv_flow_reasoning);

        // App Intelligence
        mIvAuditAppIcon = v.findViewById(R.id.iv_audit_app_icon);
        mTvAuditAppName = v.findViewById(R.id.tv_audit_app_name);
        mTvAuditAppPkg = v.findViewById(R.id.tv_audit_app_pkg);
        mTvAuditAppProvenance = v.findViewById(R.id.tv_audit_app_provenance);
        mTvAuditAppDetails = v.findViewById(R.id.tv_audit_app_details);

        // 3-bullet structured verdict
        mTvEndpointIdentity = v.findViewById(R.id.tv_endpoint_identity);
        mTvConnectionIntent = v.findViewById(R.id.tv_connection_intent);
        mTvActionRecommendation = v.findViewById(R.id.tv_action_recommendation);
        mBtnRuleAction = v.findViewById(R.id.btn_rule_action);

        v.findViewById(R.id.btn_close_flow).setOnClickListener(view -> dismiss());

        View btnInvestigate = v.findViewById(R.id.btn_investigate_flow);
        if (btnInvestigate != null) {
            btnInvestigate.setOnClickListener(view -> {
                if (mConn != null && getParentFragmentManager() != null && getContext() != null) {
                    String target = (mConn.info != null && !mConn.info.isEmpty()) ? mConn.info : mConn.dst_ip;
                    String type = (mConn.info != null && !mConn.info.isEmpty()) ? "DOMAIN" : "IP";
                    String pkg = "";
                    try {
                        AppsResolver resolver = new AppsResolver(requireContext());
                        AppDescriptor app = resolver.getAppByUid(mConn.uid, 0);
                        if (app != null) pkg = app.getPackageName();
                    } catch (Exception ignored) {}
                    ThreatInvestigationDialog.show(getParentFragmentManager(), target, type, pkg, "Live Connection Socket: Port " + mConn.dst_port);
                }
            });
        }

        v.findViewById(R.id.btn_block_firewall).setOnClickListener(view -> {
            if (mConn != null && getContext() != null) {
                SecurityRulesDb db = SecurityRulesDb.getInstance(requireContext());
                if (mConn.dst_ip != null && !mConn.dst_ip.isEmpty()) {
                    db.blockIp(mConn.dst_ip, "Blocked via AI Flow Assessment", SecurityRulesDb.SOURCE_USER);
                }
                if (mConn.info != null && !mConn.info.isEmpty()) {
                    db.blockDomain(mConn.info, "Blocked via AI Flow Assessment", SecurityRulesDb.SOURCE_USER);
                }
                Toast.makeText(requireContext(), "Destination blocked in Firewall!", Toast.LENGTH_SHORT).show();
                dismiss();
            }
        });
    }

    private void evaluateFlow() {
        if (mConn == null) {
            mTvVerdict.setText("Connection Inactive");
            mTvClassification.setText("Selected socket is no longer active in memory.");
            return;
        }

        String host = (mConn.info != null && !mConn.info.isEmpty()) ? mConn.info : mConn.dst_ip;
        mTvTarget.setText(host + ":" + mConn.dst_port + " (" + (mConn.l7proto != null ? mConn.l7proto : "TCP") + ")");

        // App Intelligence Population
        try {
            AppsResolver resolver = new AppsResolver(requireContext());
            AppDescriptor appDesc = resolver.getAppByUid(mConn.uid, 0);
            if (appDesc != null) {
                Drawable icon = appDesc.getIcon();
                if (mIvAuditAppIcon != null && icon != null) {
                    mIvAuditAppIcon.setImageDrawable(icon);
                }
                if (mTvAuditAppName != null) {
                    mTvAuditAppName.setText(appDesc.getName());
                }
                if (mTvAuditAppPkg != null) {
                    mTvAuditAppPkg.setText(appDesc.getPackageName());
                }
                AppIntelligenceEngine.AppSecurityProfile profile =
                        AppIntelligenceEngine.getInstance(requireContext()).getProfile(appDesc.getPackageName());
                if (profile != null) {
                    if (mTvAuditAppProvenance != null) {
                        if (profile.isSideloaded) {
                            mTvAuditAppProvenance.setText("⚠️ Sideloaded App");
                            mTvAuditAppProvenance.setTextColor(ContextCompat.getColor(requireContext(), R.color.warning));
                            mTvAuditAppProvenance.setBackgroundTintList(ColorStateList.valueOf(0x22F59E0B));
                        } else if (profile.isVettedStoreInstall) {
                            mTvAuditAppProvenance.setText("Verified Store");
                            mTvAuditAppProvenance.setTextColor(ContextCompat.getColor(requireContext(), R.color.ok));
                            mTvAuditAppProvenance.setBackgroundTintList(ColorStateList.valueOf(0x2222C55E));
                        } else if (profile.isSystemApp) {
                            mTvAuditAppProvenance.setText("System App");
                            mTvAuditAppProvenance.setTextColor(ContextCompat.getColor(requireContext(), R.color.colorSecondary));
                            mTvAuditAppProvenance.setBackgroundTintList(ColorStateList.valueOf(0x2200D4FF));
                        } else {
                            mTvAuditAppProvenance.setText("Installed App");
                            mTvAuditAppProvenance.setTextColor(ContextCompat.getColor(requireContext(), R.color.metricTextSecondary));
                        }
                    }
                    if (mTvAuditAppDetails != null) {
                        int sensitiveCount = (profile.permissionAnalysis != null && profile.permissionAnalysis.criticalCapabilities != null)
                                ? profile.permissionAnalysis.criticalCapabilities.size() : 0;
                        mTvAuditAppDetails.setText(String.format(Locale.getDefault(),
                                "Risk Score: %d/100 • Critical Perms: %d • Installer: %s",
                                profile.overallRiskScore, sensitiveCount,
                                (profile.installerPackage != null && !profile.installerPackage.isEmpty()) ? profile.installerPackage : "Direct APK"));
                    }
                }
            }
        } catch (Exception e) {
            // Ignore error loading app intelligence
        }

        AiConfig config = new AiConfig(requireContext());
        boolean canInspect = config.canAccessConnections();

        if (!canInspect) {
            mTvModeBadge.setText("PRIVACY RESTRICTED");
            mTvThreatProb.setText("N/A");
            mTvVerdict.setText("Connections Access Disabled");
            mTvClassification.setText("To evaluate socket flows, enable 'Connection Flows' in Settings -> AI Protection.");
            mTvReasoning.setText("🔒 Privacy Enforcement: KotSafe has restricted AI from inspecting live socket destinations because your granular privacy setting is currently disabled.");
            return;
        }

        FlowAssessment res = performLocalFlowAssessment(mConn);
        renderAssessment(res);

        boolean isAiActive = config.isAiEnabled() &&
                (config.getProvider().isOnDevice() || config.getProvider() == AiConfig.Provider.LOCAL_CUSTOM || !config.getApiKey().isEmpty());

        if (isAiActive) {
            if (config.getProvider() == AiConfig.Provider.LOCAL_QWEN_0_5B) {
                mTvModeBadge.setText("QWEN 2.5 REASONING...");
            } else if (config.getProvider() == AiConfig.Provider.LOCAL_SMOLLM_135M) {
                mTvModeBadge.setText("SMOLLM REASONING...");
            } else if (config.getProvider().isOnDevice()) {
                mTvModeBadge.setText("ON-DEVICE AI REASONING...");
            } else {
                mTvModeBadge.setText("CLOUD AI REASONING...");
            }
            queryAiFlowEnrichment(mConn, res, config);
        } else {
            mTvModeBadge.setText("OFFLINE EXPERT AUDIT");
        }
    }

    private void renderAssessment(FlowAssessment res) {
        if (getContext() == null) return;

        mTvThreatProb.setText(res.threatProb + "%");
        if (res.threatProb >= 70) {
            mTvThreatProb.setTextColor(0xFFEF4444);
            mTvVerdict.setText("MALICIOUS / HIGH RISK");
            mTvVerdict.setTextColor(0xFFEF4444);
        } else if (res.threatProb >= 40) {
            mTvThreatProb.setTextColor(ContextCompat.getColor(requireContext(), R.color.warning));
            mTvVerdict.setText("SUSPICIOUS FLOW");
            mTvVerdict.setTextColor(ContextCompat.getColor(requireContext(), R.color.warning));
        } else {
            mTvThreatProb.setTextColor(ContextCompat.getColor(requireContext(), R.color.ok));
            mTvVerdict.setText("BENIGN FLOW");
            mTvVerdict.setTextColor(ContextCompat.getColor(requireContext(), R.color.ok));
        }

        mTvClassification.setText(res.classification);

        // Signals
        mTvSignalRatio.setText(res.signalRatio);
        mTvSignalRatio.setTextColor(res.isRatioSuspicious ? 0xFFEF4444 : ContextCompat.getColor(requireContext(), R.color.ok));

        mTvSignalPort.setText(res.signalPort);
        mTvSignalPort.setTextColor(res.isPortSuspicious ? ContextCompat.getColor(requireContext(), R.color.warning) : ContextCompat.getColor(requireContext(), R.color.ok));

        mTvSignalAsn.setText(res.signalAsn);
        mTvSignalAsn.setTextColor(ContextCompat.getColor(requireContext(), R.color.metricTextPrimary));

        if (mTvSignalMitre != null && !res.mitreTechniques.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < res.mitreTechniques.size(); i++) {
                if (i > 0) sb.append(" • ");
                sb.append(res.mitreTechniques.get(i));
            }
            mTvSignalMitre.setText(sb.toString());
        }

        mTvReasoning.setText(res.reasoning);

        // Structured 3-Bullet Verdict populated immediately offline
        if (mTvEndpointIdentity != null)
            mTvEndpointIdentity.setText("🌐 Endpoint: " + res.endpointIdentity);
        if (mTvConnectionIntent != null)
            mTvConnectionIntent.setText("📊 Intent: " + res.connectionIntent);
        if (mTvActionRecommendation != null)
            mTvActionRecommendation.setText("⚠️ Recommendation: " + res.actionRecommendation);

        // If threat probability is high and destination is not already blocked, show recommendation action button
        if (res.threatProb >= 70 && !res.isBlockedByFirewall && mBtnRuleAction != null) {
            String targetToBlock = (mConn.info != null && !mConn.info.isEmpty()) ? mConn.info : mConn.dst_ip;
            mBtnRuleAction.setText("🚫 Block " + targetToBlock + " in Firewall");
            mBtnRuleAction.setVisibility(View.VISIBLE);
            mBtnRuleAction.setOnClickListener(v -> {
                SecurityRulesDb db = SecurityRulesDb.getInstance(requireContext());
                if (mConn.info != null && !mConn.info.isEmpty()) {
                    db.blockDomain(mConn.info, "Blocked via AI Flow Assessment", SecurityRulesDb.SOURCE_USER);
                } else if (mConn.dst_ip != null) {
                    db.blockIp(mConn.dst_ip, "Blocked via AI Flow Assessment", SecurityRulesDb.SOURCE_USER);
                }
                Toast.makeText(requireContext(), "Destination blocked in Firewall!", Toast.LENGTH_SHORT).show();
                mBtnRuleAction.setEnabled(false);
                mBtnRuleAction.setText("✅ Destination Blocked");
            });
        }
    }

    private static class FlowAssessment {
        int threatProb = 10;
        String classification = "";
        String signalRatio = "";
        boolean isRatioSuspicious = false;
        String signalPort = "";
        boolean isPortSuspicious = false;
        String signalAsn = "";
        String reasoning = "";
        boolean isBlockedByFirewall = false;
        List<String> mitreTechniques = new ArrayList<>();
        String endpointIdentity = "";
        String connectionIntent = "";
        String actionRecommendation = "";
    }

    private FlowAssessment performLocalFlowAssessment(ConnectionDescriptor c) {
        FlowAssessment f = new FlowAssessment();
        StringBuilder reasons = new StringBuilder();

        long sent = c.sent_bytes;
        long rcvd = c.rcvd_bytes;
        int port = c.dst_port;
        String host = c.info != null ? c.info.toLowerCase(Locale.ROOT) : "";
        String targetIoc = (c.info != null && !c.info.isEmpty()) ? c.info : c.dst_ip;

        // 1. App Intelligence Context
        AppsResolver resolver = new AppsResolver(requireContext());
        AppDescriptor appDesc = resolver.getAppByUid(c.uid, 0);
        AppIntelligenceEngine.AppSecurityProfile appProfile = null;
        if (appDesc != null) {
            appProfile = AppIntelligenceEngine.getInstance(requireContext()).getProfile(appDesc.getPackageName());
        }

        // 2. Active Firewall Rule Check
        SecurityRulesDb rulesDb = SecurityRulesDb.getInstance(requireContext());
        SecurityRulesDb.SecurityRule activeRule = rulesDb.findBlockRule(targetIoc);
        if (activeRule == null && c.dst_ip != null) {
            activeRule = rulesDb.findBlockRule(c.dst_ip);
        }
        if (activeRule != null) {
            f.isBlockedByFirewall = true;
            reasons.append("• Active Firewall Protection: Destination actively blocked by policy (" + activeRule.source + ": " + activeRule.reason + ").\n");
        }

        // 3. Threat Intelligence Database & Feeds Check
        TiCacheDb tiDb = TiCacheDb.getInstance(requireContext());
        TiCacheDb.CacheEntry tiEntry = tiDb.lookup(targetIoc);
        if (tiEntry == null && c.dst_ip != null) {
            tiEntry = tiDb.lookup(c.dst_ip);
        }
        if (c.isBlacklisted() || (tiEntry != null && tiEntry.isMalicious)) {
            f.threatProb = 95;
            f.classification = "Confirmed Blacklisted Threat Destination";
            String family = (tiEntry != null && tiEntry.malwareFamily != null && !tiEntry.malwareFamily.isEmpty())
                    ? " (" + tiEntry.malwareFamily + ")" : "";
            reasons.append("• Critical Threat Intel Hit: Endpoint matched threat feed" + family + ".\n");
        } else if (tiEntry != null && tiEntry.isSuspicious) {
            f.threatProb = Math.max(f.threatProb, 65);
            f.classification = "Suspicious Threat Intelligence Match";
            reasons.append("• Threat Intel Warning: Matched reputation feed with suspicious indicators (" + tiEntry.verdict + ").\n");
        }

        // 4. Transfer Asymmetry (Exfiltration Check) & Native Shannon Entropy
        try {
            com.kotsafe.security.engine.KotEngineBridge bridge = com.kotsafe.security.engine.KotEngineBridge.getInstance();
            byte[] payload = bridge.getPayload(c.ipproto, c.src_ip, c.src_port, c.dst_ip, c.dst_port, 0);
            if (payload != null && payload.length > 32) {
                float entropy = bridge.calculateEntropy(payload);
                boolean isStandardTls = (c.dst_port == 443 || c.dst_port == 8443) && (c.info != null && !c.info.isEmpty());
                if (entropy >= 7.85f && !isStandardTls) {
                    f.threatProb = Math.max(f.threatProb, 80);
                    f.mitreTechniques.add("T1027 (Obfuscated/Encrypted Payloads)");
                    f.mitreTechniques.add("T1041 (Exfiltration Over Non-Standard Port)");
                    reasons.append(String.format(Locale.ROOT, "• Shannon Entropy Anomaly: Native C engine measured %.2f / 8.00 bits/byte on non-standard port %d. High-entropy binary payload indicative of encrypted C2 or raw exfiltration.\n", entropy, c.dst_port));
                } else if (entropy >= 7.92f && isStandardTls && (sent > 200_000 && rcvd < 2_000)) {
                    f.threatProb = Math.max(f.threatProb, 65);
                    reasons.append(String.format(Locale.ROOT, "• Shannon Entropy Exfiltration Asymmetry: High entropy (%.2f / 8.00 bits/byte) with heavy outbound transmission.\n", entropy));
                }
            }
        } catch (Throwable ignored) {}

        if (sent > 50000 && rcvd < 2000) {
            f.threatProb = Math.max(f.threatProb, 68);
            f.signalRatio = "Heavy TX Exfiltration (" + Utils.formatBytes(sent) + " sent / " + Utils.formatBytes(rcvd) + " rcvd)";
            f.isRatioSuspicious = true;
            f.mitreTechniques.add("T1041 (Exfiltration Over C2)");
            reasons.append("• High Upload Ratio: App transmitted substantial payload with negligible inbound response. Potential background exfiltration.\n");
        } else if (sent > 0 && rcvd > 0) {
            f.signalRatio = "Balanced (" + Utils.formatBytes(sent) + " TX / " + Utils.formatBytes(rcvd) + " RX)";
            f.isRatioSuspicious = false;
        } else {
            f.signalRatio = "Low Volume (" + Utils.formatBytes(sent) + " TX / " + Utils.formatBytes(rcvd) + " RX)";
        }


        // 5. Port & Protocol Standard
        if (port == 443 || port == 8443) {
            f.signalPort = "Standard HTTPS (" + port + ")";
            f.mitreTechniques.add("T1071.001 (Web Protocols)");
            f.mitreTechniques.add("T1573.001 (Encrypted Channel)");
        } else if (port == 80 || port == 8080) {
            f.signalPort = "Unencrypted HTTP (" + port + ")";
            f.threatProb = Math.max(f.threatProb, 35);
            f.mitreTechniques.add("T1071.001 (Cleartext HTTP)");
            reasons.append("• Cleartext Channel: Traffic traverses unencrypted port " + port + ". Sensitive data exposed to eavesdropping.\n");
        } else if (port == 53 || port == 853) {
            f.signalPort = "DNS Resolver (" + port + ")";
            f.mitreTechniques.add("T1568 (Dynamic Resolution)");
        } else {
            f.signalPort = "Non-Standard Port (" + port + ")";
            f.isPortSuspicious = true;
            f.threatProb = Math.max(f.threatProb, 55);
            f.mitreTechniques.add("T1571 (Non-Standard Port)");
            reasons.append("• Anomalous Port: Connection directed to non-standard port " + port + ", commonly leveraged by evasion agents.\n");
        }

        // 6. Host & ASN Classification
        String asnOrg = (c.asn != null && c.asn.asname != null && !c.asn.asname.isEmpty()) ? c.asn.asname : "";
        long asnNum = c.asn != null ? c.asn.number : 0;
        String country = (c.country != null && !c.country.isEmpty()) ? c.country : "";
        String asnText = asnOrg;
        if (asnNum > 0) asnText += " (AS" + asnNum + ")";
        if (!country.isEmpty()) asnText += " [" + country + "]";

        boolean isMajorCloud = host.contains("google") || host.contains("gstatic") || host.contains("apple")
                || host.contains("microsoft") || host.contains("cloudflare") || host.contains("amazon")
                || asnOrg.toLowerCase(Locale.ROOT).contains("google") || asnOrg.toLowerCase(Locale.ROOT).contains("cloudflare")
                || asnOrg.toLowerCase(Locale.ROOT).contains("amazon");

        if (isMajorCloud) {
            f.signalAsn = !asnOrg.isEmpty() ? asnOrg : "Trusted Cloud CDN";
            f.threatProb = Math.min(f.threatProb, 20);
            if (f.classification.isEmpty()) f.classification = "Legitimate Cloud / Service Provider";
            reasons.append("• Verified Infrastructure: Endpoint verified as high-reputation CDN/Cloud host.\n");
        } else if (host.contains("fbcdn") || host.contains("facebook") || host.contains("tiktok") || host.contains("telemetry") || host.contains("analytics") || host.contains("adjust") || host.contains("appsflyer")) {
            f.signalAsn = !asnOrg.isEmpty() ? asnOrg : "Ad / Telemetry Network";
            f.threatProb = Math.max(f.threatProb, 35);
            if (f.classification.isEmpty()) f.classification = "Third-Party Analytics Telemetry";
            reasons.append("• Telemetry Profile: Destination matched commercial analytics or ad delivery network.\n");
        } else {
            f.signalAsn = !asnText.isEmpty() ? asnText : "Internet Host / VPS";
            if (f.classification.isEmpty()) f.classification = "Standard Application Socket";
        }

        // 7. App Provenance Weighting
        if (appProfile != null) {
            if (appProfile.isSideloaded) {
                f.threatProb = Math.min(100, f.threatProb + 15);
                reasons.append("• Sideloaded Provenance: Calling package was installed outside official vetted stores, increasing risk tier.\n");
            }
            if (appProfile.permissionAnalysis != null && appProfile.permissionAnalysis.criticalCapabilities != null && appProfile.permissionAnalysis.criticalCapabilities.size() >= 2) {
                f.threatProb = Math.min(100, f.threatProb + 10);
                reasons.append("• Sensitive Capabilities: Originating app possesses " + appProfile.permissionAnalysis.criticalCapabilities.size() + " critical capabilities (" + appProfile.permissionAnalysis.capabilityVerdict + ").\n");
            }
        }

        if (f.mitreTechniques.isEmpty()) {
            f.mitreTechniques.add("T1071 (Application Layer Protocol)");
        }

        if (reasons.length() == 0) {
            reasons.append("• Socket telemetry matches typical mobile API patterns.\n• Transfer metrics and protocols are within benign operating thresholds.");
        }
        f.reasoning = reasons.toString();

        // 8. Generate 3-Bullet Structured Verdict Immediately Offline
        f.endpointIdentity = (host.isEmpty() ? c.dst_ip : host) + " (" + c.dst_ip + ":" + c.dst_port + ") — "
                + (asnOrg.isEmpty() ? "Autonomous Infrastructure" : asnOrg)
                + (country.isEmpty() ? "" : ", " + country);

        String appLabel = appDesc != null ? appDesc.getName() : "Process (UID " + c.uid + ")";
        if (f.isRatioSuspicious) {
            f.connectionIntent = "Heavy outbound exfiltration stream initiated by " + appLabel + " (" + Utils.formatBytes(sent) + " uploaded).";
        } else if (f.threatProb >= 70) {
            f.connectionIntent = "Malicious or blacklisted socket communication initiated by " + appLabel + ".";
        } else if (isMajorCloud) {
            f.connectionIntent = "Routine API / CDN content retrieval and push sync for " + appLabel + ".";
        } else {
            f.connectionIntent = "Outbound " + (c.l7proto != null ? c.l7proto : "TCP") + " application communication by " + appLabel + ".";
        }

        if (f.isBlockedByFirewall) {
            f.actionRecommendation = "Destination is already blocked by active firewall rule. Outbound packets are quarantined.";
        } else if (f.threatProb >= 70) {
            f.actionRecommendation = "High risk detected. Recommend immediate Firewall Block to prevent further telemetry or data transfer.";
        } else if (f.threatProb >= 40) {
            f.actionRecommendation = "Suspicious indicators found. Monitor flow frequency and review application permissions.";
        } else {
            f.actionRecommendation = "Communication profile matches expected benign traffic. Safe to allow.";
        }

        return f;
    }

    private void queryAiFlowEnrichment(ConnectionDescriptor c, FlowAssessment local, AiConfig config) {
        String sys = "You are a Network Intrusion & Threat Forensic Analyst. Analyze this socket telemetry and output a 3-bullet security verdict:\n"
                + "1. **Endpoint Identity**: Organization, hosting datacenter, ASN, and country of origin.\n"
                + "2. **Connection Intent**: Traffic profile (Telemetry, Ad Tracker, Push Notification, API Payload, or Suspicious C2).\n"
                + "3. **Action Recommendation**: Clear verdict with optional tag [RULE_ACTION:BLOCK_DOMAIN:<domain>] or [RULE_ACTION:BLOCK_IP:<ip>] if blocking is warranted.";
        String user = "Destination: " + c.dst_ip + ":" + c.dst_port + "\n"
                + "Host: " + (c.info != null ? c.info : "N/A") + "\n"
                + "Proto: " + (c.l7proto != null ? c.l7proto : "TCP") + "\n"
                + "Sent: " + c.sent_bytes + " bytes | Received: " + c.rcvd_bytes + " bytes\n"
                + "Blacklisted: " + c.isBlacklisted();

        AiClientEngine.getInstance(requireContext()).askAssistant(user, sys, new AiClientEngine.Callback() {
            @Override
            public void onSuccess(String responseText) {
                if (isAdded() && getActivity() != null) {
                    if (config.getProvider() == AiConfig.Provider.LOCAL_QWEN_0_5B) {
                        mTvModeBadge.setText("QWEN 2.5 AUDITED");
                    } else if (config.getProvider() == AiConfig.Provider.LOCAL_SMOLLM_135M) {
                        mTvModeBadge.setText("SMOLLM AUDITED");
                    } else if (config.getProvider().isOnDevice()) {
                        mTvModeBadge.setText("ON-DEVICE AUDITED");
                    } else {
                        mTvModeBadge.setText("AI AUDITED");
                    }
                    mTvReasoning.setText(local.reasoning + "\n\n🤖 AI Security Insight (" + config.getProvider().displayName + "):\n" + responseText);

                    // Parse 3-bullet structured verdict into individual views
                    parseAndDisplayStructuredVerdict(responseText, c);

                    // Parse RULE_ACTION interactive button
                    parseRuleAction(responseText, c);
                }
            }

            @Override
            public void onError(String errorMessage) {
                if (isAdded() && getActivity() != null) {
                    mTvModeBadge.setText("OFFLINE EXPERT AUDIT");
                }
            }
        });
    }

    /**
     * Parse the 3-bullet structured verdict from the AI response and populate
     * the endpoint identity, connection intent, and action recommendation views.
     */
    private void parseAndDisplayStructuredVerdict(String response, ConnectionDescriptor c) {
        if (response == null || response.isEmpty()) return;
        String[] lines = response.split("\n");
        StringBuilder ep = new StringBuilder();
        StringBuilder intent = new StringBuilder();
        StringBuilder action = new StringBuilder();
        int section = 0;
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) continue;
            String lower = trimmed.toLowerCase(Locale.ROOT);
            if (lower.contains("endpoint identity") || lower.startsWith("1.")) {
                section = 1;
            } else if (lower.contains("connection intent") || lower.startsWith("2.")) {
                section = 2;
            } else if (lower.contains("action recommendation") || lower.startsWith("3.")) {
                section = 3;
            }
            String content = trimmed.replaceAll("^[\\d]+\\.\\s*\\*{0,2}[^:]+:\\*{0,2}\\s*", "").trim();
            if (content.isEmpty()) content = trimmed;
            switch (section) {
                case 1: if (ep.length() > 0) ep.append(" "); ep.append(content); break;
                case 2: if (intent.length() > 0) intent.append(" "); intent.append(content); break;
                case 3: if (action.length() > 0) action.append(" "); action.append(content.replaceAll("\\[RULE_ACTION:[^\\]]+\\]", "").trim()); break;
            }
        }
        if (mTvEndpointIdentity != null && ep.length() > 0)
            mTvEndpointIdentity.setText("🌐 Endpoint: " + ep.toString().trim());
        if (mTvConnectionIntent != null && intent.length() > 0)
            mTvConnectionIntent.setText("📊 Intent: " + intent.toString().trim());
        if (mTvActionRecommendation != null && action.length() > 0)
            mTvActionRecommendation.setText("⚠️ Recommendation: " + action.toString().trim());
    }

    /**
     * Scan the AI verdict for [RULE_ACTION:BLOCK_DOMAIN:domain] or
     * [RULE_ACTION:BLOCK_IP:ip] tags and configure an interactive button that
     * executes the action when tapped.
     */
    private void parseRuleAction(String response, ConnectionDescriptor c) {
        if (mBtnRuleAction == null || response == null) return;
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("\\[RULE_ACTION:(BLOCK_DOMAIN|BLOCK_IP):([^\\]]+)\\]")
                .matcher(response);
        if (m.find()) {
            String action = m.group(1); // BLOCK_DOMAIN or BLOCK_IP
            String target = m.group(2);
            String label = "BLOCK_DOMAIN".equals(action)
                    ? "🚫 Block Domain: " + target
                    : "🚫 Block IP: " + target;
            mBtnRuleAction.setText(label);
            mBtnRuleAction.setVisibility(View.VISIBLE);
            mBtnRuleAction.setOnClickListener(v -> {
                if (getContext() == null) return;
                SecurityRulesDb db = SecurityRulesDb.getInstance(requireContext());
                if ("BLOCK_DOMAIN".equals(action)) {
                    db.blockDomain(target, "Blocked via AI Verdict", SecurityRulesDb.SOURCE_USER);
                } else {
                    db.blockIp(target, "Blocked via AI Verdict", SecurityRulesDb.SOURCE_USER);
                }
                Toast.makeText(requireContext(), label + " applied!", Toast.LENGTH_SHORT).show();
                mBtnRuleAction.setEnabled(false);
                mBtnRuleAction.setText("✅ Rule Applied");
            });
        } else {
            mBtnRuleAction.setVisibility(View.GONE);
        }
    }
}
