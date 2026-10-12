/*
 * This file is part of KotSafe / KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.fragments;

import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.HttpLog;
import com.kotsafe.security.Log;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.PayloadChunk;
import com.google.android.material.button.MaterialButton;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class HttpRepeaterFragment extends Fragment {
    private static final String TAG = "HttpRepeaterFragment";

    public static final String ARG_METHOD = "arg_method";
    public static final String ARG_URL = "arg_url";
    public static final String ARG_HEADERS = "arg_headers";
    public static final String ARG_BODY = "arg_body";

    private static final String[] HTTP_METHODS = {
            "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"
    };

    private Spinner mSpinnerMethod;
    private EditText mEditUrl;
    private MaterialButton mBtnSend;
    private ProgressBar mProgressLoading;

    private MaterialButton mTabHeaders;
    private MaterialButton mTabBody;
    private MaterialButton mBtnActionHelper;
    private View mLayoutHeaders;
    private View mLayoutBody;
    private EditText mEditHeaders;
    private EditText mEditBody;

    // Response Views
    private View mLayoutResponseStats;
    private TextView mTvResponseStatus;
    private TextView mTvResponseLatency;
    private TextView mTvResponseSize;
    private MaterialButton mBtnCopyResponse;
    private View mLayoutResponseTabs;
    private MaterialButton mTabRespBody;
    private MaterialButton mTabRespHeaders;
    private MaterialButton mTabRespRaw;
    private View mLayoutRespEmpty;
    private View mScrollResponseContent;
    private TextView mTvResponseContent;

    // State
    private boolean mIsRequestTabHeaders = true;
    private int mResponseTab = 0; // 0 = Body, 1 = Headers, 2 = Raw
    private String mRespBodyStr = "";
    private String mRespHeadersStr = "";
    private String mRespRawStr = "";

    private final ExecutorService mExecutor = Executors.newSingleThreadExecutor();
    private final Handler mMainHandler = new Handler(Looper.getMainLooper());
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    public static HttpRepeaterFragment newInstance(@Nullable String method, @Nullable String url,
                                                  @Nullable String headers, @Nullable String body) {
        HttpRepeaterFragment fragment = new HttpRepeaterFragment();
        Bundle args = new Bundle();
        if (method != null) args.putString(ARG_METHOD, method);
        if (url != null) args.putString(ARG_URL, url);
        if (headers != null) args.putString(ARG_HEADERS, headers);
        if (body != null) args.putString(ARG_BODY, body);
        fragment.setArguments(args);
        return fragment;
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_http_repeater, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        initViews(view);
        setupMethodSpinner();
        setupRequestTabs();
        setupResponseTabs();
        loadInitialDataFromArgs();
    }

    private void initViews(View view) {
        mSpinnerMethod = view.findViewById(R.id.spinner_method);
        mEditUrl = view.findViewById(R.id.edit_url);
        mBtnSend = view.findViewById(R.id.btn_send);
        mProgressLoading = view.findViewById(R.id.progress_loading);

        mTabHeaders = view.findViewById(R.id.tab_headers);
        mTabBody = view.findViewById(R.id.tab_body);
        mBtnActionHelper = view.findViewById(R.id.btn_action_helper);
        mLayoutHeaders = view.findViewById(R.id.layout_headers);
        mLayoutBody = view.findViewById(R.id.layout_body);
        mEditHeaders = view.findViewById(R.id.edit_headers);
        mEditBody = view.findViewById(R.id.edit_body);

        mLayoutResponseStats = view.findViewById(R.id.layout_response_stats);
        mTvResponseStatus = view.findViewById(R.id.tv_response_status);
        mTvResponseLatency = view.findViewById(R.id.tv_response_latency);
        mTvResponseSize = view.findViewById(R.id.tv_response_size);
        mBtnCopyResponse = view.findViewById(R.id.btn_copy_response);
        mLayoutResponseTabs = view.findViewById(R.id.layout_response_tabs);
        mTabRespBody = view.findViewById(R.id.tab_resp_body);
        mTabRespHeaders = view.findViewById(R.id.tab_resp_headers);
        mTabRespRaw = view.findViewById(R.id.tab_resp_raw);
        mLayoutRespEmpty = view.findViewById(R.id.layout_resp_empty);
        mScrollResponseContent = view.findViewById(R.id.scroll_response_content);
        mTvResponseContent = view.findViewById(R.id.tv_response_content);

        mBtnSend.setOnClickListener(v -> executeRequest());

        View returnBtn = view.findViewById(R.id.btn_return_to_connections);
        if (returnBtn != null) {
            returnBtn.setOnClickListener(v -> {
                Fragment parent = getParentFragment();
                if (parent instanceof DataViewContainerFragment) {
                    ((DataViewContainerFragment) parent).resetToConnectionsView();
                }
            });
        }

        mBtnCopyResponse.setOnClickListener(v -> {
            String textToCopy = getActiveResponseText();
            if (!textToCopy.isEmpty() && getContext() != null) {
                Utils.copyToClipboard(requireContext(), textToCopy);
                Utils.showToast(requireContext(), R.string.copied);
            }
        });

        mBtnActionHelper.setOnClickListener(v -> {
            if (mIsRequestTabHeaders) {
                // Add header template
                String current = mEditHeaders.getText().toString();
                if (!current.isEmpty() && !current.endsWith("\n")) {
                    current += "\n";
                }
                current += "Custom-Header: value\n";
                mEditHeaders.setText(current);
                mEditHeaders.setSelection(mEditHeaders.getText().length());
            } else {
                // Prettify JSON
                prettifyRequestBody();
            }
        });

        MaterialButton btnAiFuzz = view.findViewById(R.id.btn_ai_fuzz);
        if (btnAiFuzz != null) {
            btnAiFuzz.setOnClickListener(v -> showAiFuzzDialog());
        }

        MaterialButton btnAiExplainResp = view.findViewById(R.id.btn_ai_explain_resp);
        if (btnAiExplainResp != null) {
            btnAiExplainResp.setOnClickListener(v -> showAiExplainResponseDialog());
        }
    }

    private void setupMethodSpinner() {
        if (getContext() == null) return;
        ArrayAdapter<String> adapter = new ArrayAdapter<>(requireContext(),
                R.layout.item_repeater_spinner, HTTP_METHODS);
        adapter.setDropDownViewResource(R.layout.item_repeater_spinner_dropdown);
        mSpinnerMethod.setAdapter(adapter);
    }

    private void setupRequestTabs() {
        mTabHeaders.setOnClickListener(v -> setRequestTab(true));
        mTabBody.setOnClickListener(v -> setRequestTab(false));
        setRequestTab(true);
    }

    private void setRequestTab(boolean isHeaders) {
        if (getContext() == null) return;
        mIsRequestTabHeaders = isHeaders;
        int primaryColor = ContextCompat.getColor(requireContext(), R.color.colorPrimary);
        int secondaryColor = ContextCompat.getColor(requireContext(), R.color.metricTextSecondary);

        if (isHeaders) {
            mTabHeaders.setTextColor(primaryColor);
            mTabBody.setTextColor(secondaryColor);
            mLayoutHeaders.setVisibility(View.VISIBLE);
            mLayoutBody.setVisibility(View.GONE);
            mBtnActionHelper.setText("+ Header");
        } else {
            mTabHeaders.setTextColor(secondaryColor);
            mTabBody.setTextColor(primaryColor);
            mLayoutHeaders.setVisibility(View.GONE);
            mLayoutBody.setVisibility(View.VISIBLE);
            mBtnActionHelper.setText("Prettify JSON");
        }
    }

    private void setupResponseTabs() {
        mTabRespBody.setOnClickListener(v -> setResponseTab(0));
        mTabRespHeaders.setOnClickListener(v -> setResponseTab(1));
        mTabRespRaw.setOnClickListener(v -> setResponseTab(2));
    }

    private void setResponseTab(int tabIndex) {
        if (getContext() == null) return;
        mResponseTab = tabIndex;
        int primaryColor = ContextCompat.getColor(requireContext(), R.color.colorPrimary);
        int secondaryColor = ContextCompat.getColor(requireContext(), R.color.metricTextSecondary);

        mTabRespBody.setTextColor(tabIndex == 0 ? primaryColor : secondaryColor);
        mTabRespHeaders.setTextColor(tabIndex == 1 ? primaryColor : secondaryColor);
        mTabRespRaw.setTextColor(tabIndex == 2 ? primaryColor : secondaryColor);

        mTvResponseContent.setText(getActiveResponseText());
    }

    private String getActiveResponseText() {
        switch (mResponseTab) {
            case 1:
                return mRespHeadersStr;
            case 2:
                return mRespRawStr;
            case 0:
            default:
                return mRespBodyStr;
        }
    }

    public void setRequestData(@Nullable String method, @Nullable String url,
                               @Nullable String headers, @Nullable String body) {
        if (mSpinnerMethod != null && method != null) {
            for (int i = 0; i < HTTP_METHODS.length; i++) {
                if (HTTP_METHODS[i].equalsIgnoreCase(method)) {
                    mSpinnerMethod.setSelection(i);
                    break;
                }
            }
        }
        if (mEditUrl != null && url != null) {
            mEditUrl.setText(url);
        }
        if (mEditHeaders != null && headers != null) {
            mEditHeaders.setText(headers);
        }
        if (mEditBody != null && body != null) {
            mEditBody.setText(body);
            if (!body.isEmpty()) setRequestTab(false);
        }
    }

    private void loadInitialDataFromArgs() {
        Bundle args = getArguments();
        if (args != null) {
            String method = args.getString(ARG_METHOD);
            if (method != null) {
                for (int i = 0; i < HTTP_METHODS.length; i++) {
                    if (HTTP_METHODS[i].equalsIgnoreCase(method)) {
                        mSpinnerMethod.setSelection(i);
                        break;
                    }
                }
            }

            String url = args.getString(ARG_URL);
            if (url != null) {
                mEditUrl.setText(url);
            }

            String headers = args.getString(ARG_HEADERS);
            if (headers != null && !headers.isEmpty()) {
                mEditHeaders.setText(headers);
            }

            String body = args.getString(ARG_BODY);
            if (body != null && !body.isEmpty()) {
                mEditBody.setText(body);
                setRequestTab(false);
            }
        }
    }

    private void prettifyRequestBody() {
        String body = mEditBody.getText().toString().trim();
        if (body.isEmpty()) return;
        try {
            JsonElement el = JsonParser.parseString(body);
            String pretty = GSON.toJson(el);
            mEditBody.setText(pretty);
            if (getContext() != null) {
                Toast.makeText(requireContext(), "JSON formatted", Toast.LENGTH_SHORT).show();
            }
        } catch (Exception e) {
            if (getContext() != null) {
                Toast.makeText(requireContext(), "Not valid JSON: " + e.getMessage(), Toast.LENGTH_SHORT).show();
            }
        }
    }

    @android.annotation.SuppressLint({"TrustAllX509TrustManager", "BadHostnameVerifier", "CustomX509TrustManager"})
    private void executeRequest() {
        String urlStr = mEditUrl.getText().toString().trim();
        if (TextUtils.isEmpty(urlStr)) {
            mEditUrl.setError("URL cannot be empty");
            return;
        }
        if (!urlStr.startsWith("http://") && !urlStr.startsWith("https://")) {
            urlStr = "https://" + urlStr;
            mEditUrl.setText(urlStr);
        }

        final String finalUrl = urlStr;
        final String method = (String) mSpinnerMethod.getSelectedItem();
        final String headersStr = mEditHeaders.getText().toString();
        final String bodyStr = mEditBody.getText().toString();

        mBtnSend.setEnabled(false);
        mProgressLoading.setVisibility(View.VISIBLE);

        mExecutor.execute(() -> {
            long startTime = System.currentTimeMillis();
            HttpURLConnection conn = null;
            int responseCode = 0;
            String responseMessage = "";
            StringBuilder headersOut = new StringBuilder();
            StringBuilder rawOut = new StringBuilder();
            String responseBody = "";
            long elapsedMs = 0;
            long payloadSize = 0;

            try {
                URL url = new URL(finalUrl);
                conn = (HttpURLConnection) url.openConnection();

                // Secure SSL by default; lenient mode only if explicitly enabled in preferences
                if (conn instanceof HttpsURLConnection) {
                    HttpsURLConnection httpsConn = (HttpsURLConnection) conn;
                    boolean allowUntrusted = PreferenceManager.getDefaultSharedPreferences(requireContext())
                            .getBoolean("repeater_allow_untrusted_ssl", false);
                    if (allowUntrusted) {
                        TrustManager[] trustAll = new TrustManager[]{
                                new X509TrustManager() {
                                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                                }
                        };
                        SSLContext sc = SSLContext.getInstance("TLS");
                        sc.init(null, trustAll, new SecureRandom());
                        httpsConn.setSSLSocketFactory(sc.getSocketFactory());
                        httpsConn.setHostnameVerifier((hostname, session) -> true);
                    }
                }

                conn.setRequestMethod(method);
                conn.setConnectTimeout(15000);
                conn.setReadTimeout(20000);
                conn.setInstanceFollowRedirects(false);
                conn.setUseCaches(false);

                // Set headers
                if (!headersStr.isEmpty()) {
                    String[] lines = headersStr.split("\r?\n");
                    for (String line : lines) {
                        line = line.trim();
                        if (line.isEmpty() || line.startsWith("#")) continue;
                        int colon = line.indexOf(':');
                        if (colon > 0) {
                            String k = line.substring(0, colon).trim();
                            String v = line.substring(colon + 1).trim();
                            if (!k.equalsIgnoreCase("Host") && !k.equalsIgnoreCase("Content-Length")) {
                                conn.setRequestProperty(k, v);
                            }
                        }
                    }
                }

                // Write request body if present
                boolean hasBody = !bodyStr.isEmpty() && !"GET".equals(method) && !"HEAD".equals(method);
                if (hasBody) {
                    conn.setDoOutput(true);
                    byte[] bodyBytes = bodyStr.getBytes(StandardCharsets.UTF_8);
                    try (OutputStream os = conn.getOutputStream()) {
                        os.write(bodyBytes);
                        os.flush();
                    }
                }

                responseCode = conn.getResponseCode();
                responseMessage = conn.getResponseMessage();
                if (responseMessage == null) responseMessage = "";

                // Headers
                rawOut.append("HTTP/1.1 ").append(responseCode).append(" ").append(responseMessage).append("\r\n");
                for (Map.Entry<String, List<String>> entry : conn.getHeaderFields().entrySet()) {
                    if (entry.getKey() != null) {
                        for (String val : entry.getValue()) {
                            headersOut.append(entry.getKey()).append(": ").append(val).append("\n");
                            rawOut.append(entry.getKey()).append(": ").append(val).append("\r\n");
                        }
                    }
                }
                rawOut.append("\r\n");

                // Read Body
                InputStream is = (responseCode >= 400) ? conn.getErrorStream() : conn.getInputStream();
                if (is != null) {
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    byte[] buffer = new byte[4096];
                    int len;
                    while ((len = is.read(buffer)) != -1) {
                        bos.write(buffer, 0, len);
                    }
                    byte[] respBytes = bos.toByteArray();
                    payloadSize = respBytes.length;
                    responseBody = new String(respBytes, StandardCharsets.UTF_8);
                    rawOut.append(responseBody);
                }

                elapsedMs = System.currentTimeMillis() - startTime;
            } catch (Exception e) {
                Log.e(TAG, "Request execution error: " + e.getMessage());
                elapsedMs = System.currentTimeMillis() - startTime;
                responseCode = 0;
                responseMessage = "Connection Error";
                responseBody = "Error executing request:\n" + e.getClass().getSimpleName() + ": " + e.getMessage();
                rawOut.append(responseBody);
            } finally {
                if (conn != null) {
                    conn.disconnect();
                }
            }

            final int finalCode = responseCode;
            final String finalMsg = responseMessage;
            final String finalHeaders = headersOut.toString().trim();
            final String finalBody = responseBody;
            final String finalRaw = rawOut.toString();
            final long finalLatency = elapsedMs;
            final long finalSize = payloadSize;

            mMainHandler.post(() -> {
                if (isAdded() && getContext() != null) {
                    updateUiWithResponse(finalCode, finalMsg, finalHeaders, finalBody, finalRaw, finalLatency, finalSize);
                }
            });
        });
    }

    private void updateUiWithResponse(int code, String message, String headers, String body, String raw,
                                      long latencyMs, long payloadSize) {
        if (!isAdded() || getContext() == null) return;

        mBtnSend.setEnabled(true);
        mProgressLoading.setVisibility(View.GONE);

        String displayBody = body;
        if (!body.isEmpty() && (body.startsWith("{") || body.startsWith("["))) {
            try {
                JsonElement el = JsonParser.parseString(body);
                displayBody = GSON.toJson(el);
            } catch (Exception ignored) {}
        }

        mRespBodyStr = displayBody;
        mRespHeadersStr = headers;
        mRespRawStr = raw;

        mLayoutRespEmpty.setVisibility(View.GONE);
        mLayoutResponseStats.setVisibility(View.VISIBLE);
        mLayoutResponseTabs.setVisibility(View.VISIBLE);
        mScrollResponseContent.setVisibility(View.VISIBLE);
        mBtnCopyResponse.setVisibility(View.VISIBLE);

        if (code >= 200 && code < 300) {
            mTvResponseStatus.setText(code + " " + message);
            mTvResponseStatus.setTextColor(ContextCompat.getColor(requireContext(), R.color.badgeActiveFg));
            mTvResponseStatus.setBackgroundResource(R.drawable.badge_pill_active);
        } else if (code >= 300 && code < 400) {
            mTvResponseStatus.setText(code + " " + message);
            mTvResponseStatus.setTextColor(ContextCompat.getColor(requireContext(), R.color.badgeProtoFg));
            mTvResponseStatus.setBackgroundResource(R.drawable.badge_pill_proto);
        } else if (code > 0) {
            mTvResponseStatus.setText(code + " " + message);
            mTvResponseStatus.setTextColor(ContextCompat.getColor(requireContext(), R.color.badgeBlockedFg));
            mTvResponseStatus.setBackgroundResource(R.drawable.badge_pill_blocked);
        } else {
            mTvResponseStatus.setText(message);
            mTvResponseStatus.setTextColor(ContextCompat.getColor(requireContext(), R.color.badgeBlockedFg));
            mTvResponseStatus.setBackgroundResource(R.drawable.badge_pill_blocked);
        }

        mTvResponseLatency.setText(latencyMs + " ms");
        mTvResponseSize.setText(Utils.formatBytes(payloadSize));

        setResponseTab(mResponseTab);
    }

    private void showAiFuzzDialog() {
        if (getContext() == null) return;
        final String[] payloads = new String[]{
                "Auth Bypass: Authorization: Bearer admin_test_token",
                "Auth Bypass: X-Forwarded-For: 127.0.0.1",
                "IDOR Parameter: {\"id\": 1, \"admin\": true, \"role\": \"admin\"}",
                "SQLi Canary Probe: ' OR '1'='1' --",
                "Path Traversal: ../../../../etc/passwd",
                "XSS Canary Probe: <script>alert(1)</script>",
                "NoSQL Injection Probe: {\"$gt\": \"\"}",
                "JSON Array Wrap: [{\"id\": 0}]",
                "Debug Header: X-Debug-Mode: 1"
        };

        new AlertDialog.Builder(requireContext())
                .setTitle("🤖 AI & Security Fuzz Payloads")
                .setItems(payloads, (dialog, which) -> {
                    String selected = payloads[which];
                    if (selected.startsWith("Auth Bypass:") || selected.startsWith("Debug Header:")) {
                        String headerValue = selected.substring(selected.indexOf(":") + 1).trim();
                        String current = mEditHeaders.getText().toString();
                        if (!current.isEmpty() && !current.endsWith("\n")) current += "\n";
                        current += headerValue + "\n";
                        mEditHeaders.setText(current);
                        setRequestTab(true);
                        Toast.makeText(requireContext(), "Injected into Headers", Toast.LENGTH_SHORT).show();
                    } else {
                        String bodyValue = selected.substring(selected.indexOf(":") + 1).trim();
                        mEditBody.setText(bodyValue);
                        setRequestTab(false);
                        Toast.makeText(requireContext(), "Injected into Body", Toast.LENGTH_SHORT).show();
                    }
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void showAiExplainResponseDialog() {
        if (getContext() == null) return;
        String status = mTvResponseStatus.getText().toString();
        String latency = mTvResponseLatency.getText().toString();
        String size = mTvResponseSize.getText().toString();

        StringBuilder sb = new StringBuilder();
        sb.append("HTTP Status: ").append(status).append("\n");
        sb.append("Timing: ").append(latency).append(" | Payload: ").append(size).append("\n\n");

        if (status.startsWith("2")) {
            sb.append("🟢 Success (2xx):\nThe endpoint accepted the request. Check the response body for reflected data or sensitive database objects.");
        } else if (status.startsWith("401")) {
            sb.append("🔴 401 Unauthorized:\nThe endpoint requires authentication. Ensure a valid 'Authorization: Bearer <token>' or Cookie header is provided.");
        } else if (status.startsWith("403")) {
            sb.append("⚠️ 403 Forbidden:\nThe server recognized your identity but denied permission. Possible causes:\n• Missing RBAC/admin privileges\n• WAF / IP block rule triggered\n• Missing or invalid CSRF / Anti-tamper token.");
        } else if (status.startsWith("404")) {
            sb.append("⚪ 404 Not Found:\nThe requested resource or API path does not exist on this host.");
        } else if (status.startsWith("429")) {
            sb.append("⏳ 429 Too Many Requests:\nRate limit exceeded. The server or reverse proxy is throttling repeated requests.");
        } else if (status.startsWith("5")) {
            sb.append("🔥 5xx Server Error:\nThe server encountered an unhandled exception or crash while processing your payload. This is an indicator of potential injection, format mismatch, or backend denial-of-service.");
        } else {
            sb.append("Response received: ").append(status);
        }

        new AlertDialog.Builder(requireContext())
                .setTitle("🤖 AI Response Diagnosis")
                .setMessage(sb.toString())
                .setPositiveButton("Close", null)
                .show();
    }
}
