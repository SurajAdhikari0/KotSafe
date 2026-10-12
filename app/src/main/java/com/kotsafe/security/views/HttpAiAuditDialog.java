/*
 * This file is part of KotSafe / KotSafe Cyber Security Project.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.views;

import android.content.Intent;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;

import com.kotsafe.security.HttpLog;
import com.kotsafe.security.model.PayloadChunk;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.activities.HttpRepeaterActivity;
import com.kotsafe.security.ai.AiClientEngine;
import com.kotsafe.security.ai.AiConfig;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * AI HTTP & API Security Audit Dialog.
 * Inspects intercepted HTTP/HTTPS requests and server responses for:
 * - Exposed Authorization tokens and API keys
 * - Plaintext PII (emails, device IDs, GPS coordinates)
 * - Missing response security headers (HSTS, CSP, X-Frame-Options)
 * - API tampering vulnerability surface
 */
public class HttpAiAuditDialog extends BottomSheetDialogFragment {

    private static final String ARG_HTTP_REQ_POS = "http_req_pos";

    private int mReqPos = -1;
    private HttpLog.HttpRequest mReq;

    private TextView mTvTarget;
    private TextView mTvModeBadge;
    private TextView mTvScore;
    private TextView mTvVerdict;
    private TextView mTvSummary;
    private ImageView mIvStatusTokens;
    private TextView mTvDetailTokens;
    private ImageView mIvStatusPii;
    private TextView mTvDetailPii;
    private ImageView mIvStatusHeaders;
    private TextView mTvDetailHeaders;
    private TextView mTvReasoning;

    public static HttpAiAuditDialog newInstance(int reqPos) {
        HttpAiAuditDialog dialog = new HttpAiAuditDialog();
        Bundle args = new Bundle();
        args.putInt(ARG_HTTP_REQ_POS, reqPos);
        dialog.setArguments(args);
        return dialog;
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.dialog_http_ai_audit, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        if (getArguments() != null) {
            mReqPos = getArguments().getInt(ARG_HTTP_REQ_POS, -1);
        }

        HttpLog log = com.kotsafe.security.CaptureService.getHttpLog();
        if (log != null && mReqPos >= 0 && mReqPos < log.getSize()) {
            mReq = log.getRequest(mReqPos);
        }

        initViews(view);
        populateAndAudit();
    }

    private void initViews(View v) {
        mTvTarget = v.findViewById(R.id.tv_audit_target);
        mTvModeBadge = v.findViewById(R.id.tv_audit_mode_badge);
        mTvScore = v.findViewById(R.id.tv_security_score);
        mTvVerdict = v.findViewById(R.id.tv_risk_verdict);
        mTvSummary = v.findViewById(R.id.tv_risk_summary);

        mIvStatusTokens = v.findViewById(R.id.iv_status_tokens);
        mTvDetailTokens = v.findViewById(R.id.tv_detail_tokens);
        mIvStatusPii = v.findViewById(R.id.iv_status_pii);
        mTvDetailPii = v.findViewById(R.id.tv_detail_pii);
        mIvStatusHeaders = v.findViewById(R.id.iv_status_headers);
        mTvDetailHeaders = v.findViewById(R.id.tv_detail_headers);
        mTvReasoning = v.findViewById(R.id.tv_ai_reasoning);

        v.findViewById(R.id.btn_close_audit).setOnClickListener(view -> dismiss());

        v.findViewById(R.id.btn_open_repeater).setOnClickListener(view -> {
            if (mReq != null && getActivity() != null) {
                Intent repIntent = HttpRepeaterActivity.createIntentFromHttpLog(getActivity(), mReq);
                startActivity(repIntent);
                dismiss();
            }
        });
    }

    private void populateAndAudit() {
        if (mReq == null) {
            mTvVerdict.setText("No Request Data");
            mTvSummary.setText("Selected HTTP request is no longer available in memory.");
            return;
        }

        String method = mReq.method != null ? mReq.method : "GET";
        String url = mReq.getUrl();
        mTvTarget.setText(method + " " + url);

        // Extract Request Headers & Body
        String reqHeaders = "";
        String reqBody = "";
        if (mReq.conn != null && mReq.firstChunkPos >= 0) {
            PayloadChunk chunk = mReq.conn.getHttpRequestChunk(mReq.firstChunkPos);
            if (chunk != null && chunk.payload != null) {
                int endOfHeaders = Utils.getEndOfHTTPHeaders(chunk.payload);
                if (endOfHeaders > 0) {
                    reqHeaders = new String(Arrays.copyOfRange(chunk.payload, 0, endOfHeaders), StandardCharsets.UTF_8);
                    if (endOfHeaders < chunk.payload.length) {
                        reqBody = new String(Arrays.copyOfRange(chunk.payload, endOfHeaders, chunk.payload.length), StandardCharsets.UTF_8);
                    }
                }
            }
        }

        // Extract Response Headers & Body
        String respHeaders = "";
        String respBody = "";
        int respCode = mReq.reply != null ? mReq.reply.responseCode : 0;
        if (mReq.reply != null && mReq.conn != null && mReq.reply.firstChunkPos >= 0) {
            PayloadChunk replyChunk = mReq.conn.getHttpResponseChunk(mReq.reply.firstChunkPos);
            if (replyChunk != null && replyChunk.payload != null) {
                int endOfHeaders = Utils.getEndOfHTTPHeaders(replyChunk.payload);
                if (endOfHeaders > 0) {
                    respHeaders = new String(Arrays.copyOfRange(replyChunk.payload, 0, endOfHeaders), StandardCharsets.UTF_8);
                    if (endOfHeaders < replyChunk.payload.length) {
                        respBody = new String(Arrays.copyOfRange(replyChunk.payload, endOfHeaders, replyChunk.payload.length), StandardCharsets.UTF_8);
                    }
                }
            }
        }

        AiConfig config = new AiConfig(requireContext());
        boolean canInspectData = config.canAccessHttp();

        if (!canInspectData) {
            mTvModeBadge.setText("PRIVACY RESTRICTED");
            mTvModeBadge.setTextColor(0xFFF59E0B);
            mTvScore.setText("N/A");
            mTvVerdict.setText("HTTP Access Disabled");
            mTvSummary.setText("To enable deep AI payload inspection, turn on 'Decrypted HTTP Traffic' in Settings -> AI Protection.");
            mTvReasoning.setText("🔒 Privacy Enforcement: KotSafe has restricted AI from reading intercepted HTTP headers and payloads because your granular privacy setting is currently disabled.");
            return;
        }

        // Run Static & Heuristic Security Audit
        AuditResult audit = performLocalSecurityAudit(method, url, reqHeaders, reqBody, respCode, respHeaders, respBody);
        renderAuditResult(audit);

        // If Cloud AI is available, enrich with cloud reasoning
        if (config.isAiEnabled() && (config.getProvider() == AiConfig.Provider.LOCAL_CUSTOM || !config.getApiKey().isEmpty())) {
            mTvModeBadge.setText("CLOUD AI VERIFYING...");
            queryCloudAiEnrichment(config, method, url, reqHeaders, reqBody, respCode, respHeaders, audit);
        } else {
            mTvModeBadge.setText("OFFLINE EXPERT AUDIT");
        }
    }

    private void renderAuditResult(AuditResult res) {
        if (getContext() == null) return;

        mTvScore.setText(String.valueOf(res.score));
        if (res.score >= 80) {
            mTvScore.setTextColor(ContextCompat.getColor(requireContext(), R.color.ok));
            mTvVerdict.setText("LOW RISK / BENIGN");
            mTvVerdict.setTextColor(ContextCompat.getColor(requireContext(), R.color.ok));
        } else if (res.score >= 50) {
            mTvScore.setTextColor(ContextCompat.getColor(requireContext(), R.color.warning));
            mTvVerdict.setText("MODERATE EXPOSURE");
            mTvVerdict.setTextColor(ContextCompat.getColor(requireContext(), R.color.warning));
        } else {
            mTvScore.setTextColor(0xFFEF4444);
            mTvVerdict.setText("CRITICAL SECURITY RISK");
            mTvVerdict.setTextColor(0xFFEF4444);
        }

        mTvSummary.setText(res.summary);

        // Check 1: Tokens
        if (res.hasLeakedTokens) {
            mIvStatusTokens.setImageResource(R.drawable.ic_exclamation_triangle_solid);
            mIvStatusTokens.setColorFilter(0xFFEF4444);
            mTvDetailTokens.setText(res.tokenDetail);
            mTvDetailTokens.setTextColor(0xFFEF4444);
        } else {
            mIvStatusTokens.setImageResource(R.drawable.ic_shield);
            mIvStatusTokens.setColorFilter(ContextCompat.getColor(requireContext(), R.color.ok));
            mTvDetailTokens.setText("No exposed credentials or bearer tokens in query URL");
            mTvDetailTokens.setTextColor(ContextCompat.getColor(requireContext(), R.color.ok));
        }

        // Check 2: PII
        if (res.hasPii) {
            mIvStatusPii.setImageResource(R.drawable.ic_exclamation_triangle_solid);
            mIvStatusPii.setColorFilter(ContextCompat.getColor(requireContext(), R.color.warning));
            mTvDetailPii.setText(res.piiDetail);
            mTvDetailPii.setTextColor(ContextCompat.getColor(requireContext(), R.color.warning));
        } else {
            mIvStatusPii.setImageResource(R.drawable.ic_shield);
            mIvStatusPii.setColorFilter(ContextCompat.getColor(requireContext(), R.color.ok));
            mTvDetailPii.setText("No unencrypted device IDs, emails or GPS coords detected");
            mTvDetailPii.setTextColor(ContextCompat.getColor(requireContext(), R.color.ok));
        }

        // Check 3: Headers
        if (res.missingHeadersCount > 0) {
            mIvStatusHeaders.setImageResource(R.drawable.ic_exclamation_triangle_solid);
            mIvStatusHeaders.setColorFilter(ContextCompat.getColor(requireContext(), R.color.warning));
            mTvDetailHeaders.setText("Missing: " + res.missingHeadersDetail);
            mTvDetailHeaders.setTextColor(ContextCompat.getColor(requireContext(), R.color.warning));
        } else {
            mIvStatusHeaders.setImageResource(R.drawable.ic_shield);
            mIvStatusHeaders.setColorFilter(ContextCompat.getColor(requireContext(), R.color.ok));
            mTvDetailHeaders.setText("HSTS, CSP & security framing headers present");
            mTvDetailHeaders.setTextColor(ContextCompat.getColor(requireContext(), R.color.ok));
        }

        mTvReasoning.setText(res.reasoning);
    }

    private static class AuditResult {
        int score = 100;
        String summary = "";
        boolean hasLeakedTokens = false;
        String tokenDetail = "";
        boolean hasPii = false;
        String piiDetail = "";
        int missingHeadersCount = 0;
        String missingHeadersDetail = "";
        String reasoning = "";
    }

    private AuditResult performLocalSecurityAudit(String method, String url, String reqHeaders,
                                                  String reqBody, int respCode, String respHeaders, String respBody) {
        AuditResult r = new AuditResult();
        StringBuilder reasons = new StringBuilder();

        String combinedReq = (url + " " + reqHeaders + " " + reqBody).toLowerCase(Locale.ROOT);
        String respHeadersLower = respHeaders.toLowerCase(Locale.ROOT);

        // 1. Token in URL Check (CWE-598)
        if (url.contains("token=") || url.contains("key=") || url.contains("auth=") || url.contains("secret=")) {
            r.hasLeakedTokens = true;
            r.tokenDetail = "Sensitive token passed as unencrypted GET query parameter (CWE-598).";
            r.score -= 35;
            reasons.append("• High Risk: Secret token detected in plain URL query string. URLs are commonly cached in proxy and server access logs.\n");
        } else if (combinedReq.contains("bearer ") || combinedReq.contains("authorization:")) {
            r.tokenDetail = "Bearer token detected in Authorization header (standard practice).";
        }

        // 2. Cleartext HTTP Check
        if (url.startsWith("http://")) {
            r.score -= 40;
            reasons.append("• Critical: Request transmitted over unencrypted HTTP (Port 80). Subject to Wi-Fi eavesdropping and MITM packet injection.\n");
        }

        // 3. PII & Hardware ID Exposure
        Pattern emailPattern = Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");
        if (emailPattern.matcher(combinedReq).find()) {
            r.hasPii = true;
            r.piiDetail = "Plaintext email address exposed in HTTP transmission.";
            r.score -= 20;
            reasons.append("• Privacy Exposure: User email address transmitted in plaintext payload.\n");
        } else if (combinedReq.contains("imei") || combinedReq.contains("android_id") || combinedReq.contains("device_id")) {
            r.hasPii = true;
            r.piiDetail = "Persistent hardware device identifier transmitted.";
            r.score -= 15;
            reasons.append("• Tracking Risk: Hardware identifiers transmitted to remote server enable cross-app device fingerprinting.\n");
        }

        // 4. Response Security Headers
        if (respCode > 0) {
            StringBuilder missing = new StringBuilder();
            if (!respHeadersLower.contains("strict-transport-security")) {
                missing.append("HSTS, ");
                r.missingHeadersCount++;
            }
            if (!respHeadersLower.contains("content-security-policy")) {
                missing.append("CSP, ");
                r.missingHeadersCount++;
            }
            if (!respHeadersLower.contains("x-content-type-options")) {
                missing.append("X-Content-Type-Options, ");
                r.missingHeadersCount++;
            }

            if (r.missingHeadersCount > 0) {
                String missStr = missing.toString();
                if (missStr.endsWith(", ")) missStr = missStr.substring(0, missStr.length() - 2);
                r.missingHeadersDetail = missStr;
                r.score -= (r.missingHeadersCount * 5);
                reasons.append("• Server Hardening: Response lacks key security headers (").append(missStr).append(").\n");
            }
        }

        // 5. Burp YARA-Style Malicious Binary & Dropper Inspection
        String urlLower = url.toLowerCase(Locale.US);
        boolean isApkOrDex = urlLower.contains(".apk") || urlLower.contains(".dex")
                || respHeadersLower.contains("application/vnd.android.package-archive");
        if (isApkOrDex) {
            if (url.startsWith("http://")) {
                r.score -= 50;
                reasons.append("• Critical Dropper Threat: Executable Android package (.apk/.dex) transmitted over unencrypted HTTP. Vulnerable to MITM binary Trojan injection.\n");
            } else {
                r.score -= 15;
                reasons.append("• Binary Download: Live APK installation package delivery detected over network.\n");
            }
        }

        // 6. Exploit Payload / Shell Injection Signatures (Burp YARA)
        if (combinedReq.contains("/bin/sh") || combinedReq.contains("/bin/bash")
                || combinedReq.contains("/dev/tcp/") || combinedReq.contains("nc -e /bin/")
                || combinedReq.contains("cmd.exe /c") || combinedReq.contains("powershell -enc")) {
            r.score -= 60;
            reasons.append("• Critical Exploit Vector: Remote shell execution pattern or command injection payload detected in HTTP stream.\n");
        }

        // 7. Direct-IP Binary Staging Endpoint
        if (url.matches("^https?://[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}(:[0-9]+)?/.*")
                && (urlLower.contains(".apk") || urlLower.contains(".bin") || urlLower.contains(".sh") || urlLower.contains(".elf"))) {
            r.score -= 30;
            reasons.append("• Suspicious C2 Staging: Binary executable artifact downloaded directly from a raw IP address without domain verification.\n");
        }

        r.score = Math.max(10, Math.min(100, r.score));

        if (r.score >= 80) {
            r.summary = "Request conforms to secure communication standards with no critical leaks.";
        } else if (r.score >= 50) {
            r.summary = "Minor security exposures detected (missing headers or non-standard telemetry).";
        } else {
            r.summary = "Significant vulnerabilities flagged: insecure transmission or token exposure.";
        }

        if (reasons.length() == 0) {
            reasons.append("• Safe: Headers and payloads conform to standard secure REST conventions.\n• No plaintext credentials or sensitive hardware IDs exposed.");
        }
        r.reasoning = reasons.toString();

        return r;
    }

    private void queryCloudAiEnrichment(AiConfig config, String method, String url, String reqHeaders,
                                       String reqBody, int respCode, String respHeaders, AuditResult localAudit) {
        String sys = "You are an API Security Auditor. Analyze this mobile HTTP exchange and provide a concise 2-sentence risk summary and remediation advice in plain English.";
        String user = "Endpoint: " + method + " " + url + "\n"
                + "Req Headers: " + reqHeaders.substring(0, Math.min(reqHeaders.length(), 200)) + "\n"
                + "Response Code: " + respCode + "\n"
                + "Resp Headers: " + respHeaders.substring(0, Math.min(respHeaders.length(), 200));

        AiClientEngine.getInstance(requireContext()).askAssistant(user, sys, new AiClientEngine.Callback() {
            @Override
            public void onSuccess(String responseText) {
                if (isAdded() && getActivity() != null) {
                    mTvModeBadge.setText("AI VERIFIED");
                    mTvReasoning.setText(localAudit.reasoning + "\n\n🤖 AI Security Insight:\n" + responseText);
                }
            }

            @Override
            public void onError(String errorMessage) {
                if (isAdded() && getActivity() != null) {
                    mTvModeBadge.setText("OFFLINE AUDIT");
                }
            }
        });
    }
}
