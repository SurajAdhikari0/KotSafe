/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.activities;

import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.core.content.ContextCompat;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.Log;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.HttpLog;
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

public class HttpRepeaterActivity extends AppCompatActivity {
    private static final String TAG = "HttpRepeaterActivity";

    public static final String EXTRA_METHOD = "extra_method";
    public static final String EXTRA_URL = "extra_url";
    public static final String EXTRA_HEADERS = "extra_headers";
    public static final String EXTRA_BODY = "extra_body";

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

    public static Intent createIntent(Context context, @Nullable String method, @Nullable String url,
                                      @Nullable String headers, @Nullable String body) {
        Intent intent = new Intent(context, HttpRepeaterActivity.class);
        if (method != null) intent.putExtra(EXTRA_METHOD, method);
        if (url != null) intent.putExtra(EXTRA_URL, url);
        if (headers != null) intent.putExtra(EXTRA_HEADERS, headers);
        if (body != null) intent.putExtra(EXTRA_BODY, body);
        return intent;
    }

    public static Intent createIntentFromHttpLog(Context context, HttpLog.HttpRequest req) {
        String method = (req.method != null && !req.method.isEmpty()) ? req.method : "GET";
        String url = req.getUrl();
        String headers = "";
        String body = "";

        if (req.conn != null && req.firstChunkPos >= 0) {
            PayloadChunk chunk = req.conn.getHttpRequestChunk(req.firstChunkPos);
            if (chunk != null && chunk.payload != null) {
                int endOfHeaders = Utils.getEndOfHTTPHeaders(chunk.payload);
                if (endOfHeaders > 0) {
                    byte[] headerBytes = Arrays.copyOfRange(chunk.payload, 0, endOfHeaders);
                    String rawHeaders = new String(headerBytes, StandardCharsets.UTF_8);
                    // Drop first line (e.g. "GET /path HTTP/1.1")
                    int firstLineBreak = rawHeaders.indexOf("\r\n");
                    if (firstLineBreak > 0 && firstLineBreak + 2 < rawHeaders.length()) {
                        headers = rawHeaders.substring(firstLineBreak + 2).trim();
                    } else {
                        headers = rawHeaders.trim();
                    }

                    if (endOfHeaders < chunk.payload.length) {
                        byte[] bodyBytes = Arrays.copyOfRange(chunk.payload, endOfHeaders, chunk.payload.length);
                        body = new String(bodyBytes, StandardCharsets.UTF_8);
                    }
                } else {
                    headers = new String(chunk.payload, StandardCharsets.UTF_8);
                }
            }
        }

        return createIntent(context, method, url, headers, body);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_http_repeater);

        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        }

        initViews();
        setupMethodSpinner();
        setupRequestTabs();
        setupResponseTabs();
        loadInitialDataFromIntent();
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        loadInitialDataFromIntent();
    }

    private void initViews() {
        mSpinnerMethod = findViewById(R.id.spinner_method);
        mEditUrl = findViewById(R.id.edit_url);
        mBtnSend = findViewById(R.id.btn_send);
        mProgressLoading = findViewById(R.id.progress_loading);

        mTabHeaders = findViewById(R.id.tab_headers);
        mTabBody = findViewById(R.id.tab_body);
        mBtnActionHelper = findViewById(R.id.btn_action_helper);
        mLayoutHeaders = findViewById(R.id.layout_headers);
        mLayoutBody = findViewById(R.id.layout_body);
        mEditHeaders = findViewById(R.id.edit_headers);
        mEditBody = findViewById(R.id.edit_body);

        mLayoutResponseStats = findViewById(R.id.layout_response_stats);
        mTvResponseStatus = findViewById(R.id.tv_response_status);
        mTvResponseLatency = findViewById(R.id.tv_response_latency);
        mTvResponseSize = findViewById(R.id.tv_response_size);
        mBtnCopyResponse = findViewById(R.id.btn_copy_response);
        mLayoutResponseTabs = findViewById(R.id.layout_response_tabs);
        mTabRespBody = findViewById(R.id.tab_resp_body);
        mTabRespHeaders = findViewById(R.id.tab_resp_headers);
        mTabRespRaw = findViewById(R.id.tab_resp_raw);
        mLayoutRespEmpty = findViewById(R.id.layout_resp_empty);
        mScrollResponseContent = findViewById(R.id.scroll_response_content);
        mTvResponseContent = findViewById(R.id.tv_response_content);

        mBtnSend.setOnClickListener(v -> executeRequest());

        mBtnCopyResponse.setOnClickListener(v -> {
            String textToCopy = getActiveResponseText();
            if (!textToCopy.isEmpty()) {
                Utils.copyToClipboard(this, textToCopy);
                Utils.showToast(this, R.string.copied);
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
    }

    private void setupMethodSpinner() {
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this,
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
        mIsRequestTabHeaders = isHeaders;
        int primaryColor = ContextCompat.getColor(this, R.color.colorPrimary);
        int secondaryColor = ContextCompat.getColor(this, R.color.metricTextSecondary);

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
        mResponseTab = tabIndex;
        int primaryColor = ContextCompat.getColor(this, R.color.colorPrimary);
        int secondaryColor = ContextCompat.getColor(this, R.color.metricTextSecondary);

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

    private void loadInitialDataFromIntent() {
        Intent intent = getIntent();
        if (intent != null) {
            String method = intent.getStringExtra(EXTRA_METHOD);
            if (method != null) {
                for (int i = 0; i < HTTP_METHODS.length; i++) {
                    if (HTTP_METHODS[i].equalsIgnoreCase(method)) {
                        mSpinnerMethod.setSelection(i);
                        break;
                    }
                }
            }

            String url = intent.getStringExtra(EXTRA_URL);
            if (url != null) {
                mEditUrl.setText(url);
            }

            String headers = intent.getStringExtra(EXTRA_HEADERS);
            if (headers != null && !headers.isEmpty()) {
                mEditHeaders.setText(headers);
            }

            String body = intent.getStringExtra(EXTRA_BODY);
            if (body != null && !body.isEmpty()) {
                mEditBody.setText(body);
                // If body exists, open Body tab initially
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
            Toast.makeText(this, "JSON formatted", Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            Toast.makeText(this, "Not valid JSON: " + e.getMessage(), Toast.LENGTH_SHORT).show();
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
                    boolean allowUntrusted = PreferenceManager.getDefaultSharedPreferences(HttpRepeaterActivity.this)
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
                            // Skip setting Host header directly on standard connection to avoid RestrictedHeader exception
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

                // Connect and get status
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

            mMainHandler.post(() -> updateUiWithResponse(finalCode, finalMsg, finalHeaders, finalBody, finalRaw, finalLatency, finalSize));
        });
    }

    private void updateUiWithResponse(int code, String message, String headers, String body, String raw,
                                      long latencyMs, long payloadSize) {
        mBtnSend.setEnabled(true);
        mProgressLoading.setVisibility(View.GONE);

        // Try prettifying JSON body for convenience
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

        // Visibility
        mLayoutRespEmpty.setVisibility(View.GONE);
        mLayoutResponseStats.setVisibility(View.VISIBLE);
        mLayoutResponseTabs.setVisibility(View.VISIBLE);
        mScrollResponseContent.setVisibility(View.VISIBLE);
        mBtnCopyResponse.setVisibility(View.VISIBLE);

        // Status badge
        if (code >= 200 && code < 300) {
            mTvResponseStatus.setText(code + " " + message);
            mTvResponseStatus.setTextColor(ContextCompat.getColor(this, R.color.badgeActiveFg));
            mTvResponseStatus.setBackgroundResource(R.drawable.badge_pill_active);
        } else if (code >= 300 && code < 400) {
            mTvResponseStatus.setText(code + " " + message);
            mTvResponseStatus.setTextColor(ContextCompat.getColor(this, R.color.badgeProtoFg));
            mTvResponseStatus.setBackgroundResource(R.drawable.badge_pill_proto);
        } else if (code > 0) {
            mTvResponseStatus.setText(code + " " + message);
            mTvResponseStatus.setTextColor(ContextCompat.getColor(this, R.color.badgeBlockedFg));
            mTvResponseStatus.setBackgroundResource(R.drawable.badge_pill_blocked);
        } else {
            mTvResponseStatus.setText("ERROR");
            mTvResponseStatus.setTextColor(ContextCompat.getColor(this, R.color.badgeBlockedFg));
            mTvResponseStatus.setBackgroundResource(R.drawable.badge_pill_blocked);
        }

        mTvResponseLatency.setText(latencyMs + " ms");
        mTvResponseLatency.setBackgroundResource(R.drawable.badge_pill_proto);
        mTvResponseLatency.setTextColor(ContextCompat.getColor(this, R.color.badgeProtoFg));
        mTvResponseSize.setText(Utils.formatBytes(payloadSize));

        setResponseTab(0); // Show body
    }

    private void copyAsCurl() {
        String method = (String) mSpinnerMethod.getSelectedItem();
        String url = mEditUrl.getText().toString().trim();
        String headers = mEditHeaders.getText().toString();
        String body = mEditBody.getText().toString();

        if (url.isEmpty()) {
            Toast.makeText(this, "Enter a URL first", Toast.LENGTH_SHORT).show();
            return;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("curl -X ").append(method).append(" '").append(url).append("'");

        if (!headers.isEmpty()) {
            String[] lines = headers.split("\r?\n");
            for (String line : lines) {
                line = line.trim();
                if (!line.isEmpty() && line.contains(":")) {
                    sb.append(" -H '").append(line.replace("'", "\\'")).append("'");
                }
            }
        }

        if (!body.isEmpty() && !"GET".equals(method) && !"HEAD".equals(method)) {
            sb.append(" --data '").append(body.replace("'", "\\'")).append("'");
        }

        Utils.copyToClipboard(this, sb.toString());
        Utils.showToast(this, R.string.copied);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        menu.add(Menu.NONE, 101, Menu.NONE, "Copy as cURL")
                .setShowAsAction(MenuItem.SHOW_AS_ACTION_NEVER);
        menu.add(Menu.NONE, 102, Menu.NONE, "Clear All")
                .setShowAsAction(MenuItem.SHOW_AS_ACTION_NEVER);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
            return true;
        } else if (item.getItemId() == 101) {
            copyAsCurl();
            return true;
        } else if (item.getItemId() == 102) {
            mEditUrl.setText("");
            mEditHeaders.setText("");
            mEditBody.setText("");
            mLayoutResponseStats.setVisibility(View.GONE);
            mLayoutResponseTabs.setVisibility(View.GONE);
            mScrollResponseContent.setVisibility(View.GONE);
            mBtnCopyResponse.setVisibility(View.GONE);
            mLayoutRespEmpty.setVisibility(View.VISIBLE);
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        mExecutor.shutdown();
    }
}
