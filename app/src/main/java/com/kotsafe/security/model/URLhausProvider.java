/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import android.content.Context;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * URLhaus provider — abuse.ch active malware URL and payload intelligence.
 *
 * Supports querying:
 *  - URLs (checks active malware distribution sites)
 *  - Domains / Hosts (checks if host is serving malware)
 *  - Hashes (checks if SHA-256 payload was distributed by known malicious URLs)
 *
 * API: https://urlhaus-api.abuse.ch/v1/
 */
public class URLhausProvider implements ThreatIntelProvider {
    private static final String TAG = "URLhausProvider";
    private static final String API_BASE = "https://urlhaus-api.abuse.ch/v1/";
    public static final String PREF_URLHAUS_KEY = "urlhaus_api_key";
    public static final String PREF_URLHAUS_ENABLED = "urlhaus_enabled";

    private static volatile long sCircuitBreakerUntil = 0;
    private final Context mContext;

    public URLhausProvider(Context context) {
        mContext = context.getApplicationContext();
    }

    @Override
    public String getProviderName() {
        return "URLhaus (Abuse.ch)";
    }

    @Override
    public String getProviderCode() {
        return "URLHAUS";
    }

    @Override
    public boolean isAvailable() {
        boolean enabled = PreferenceManager.getDefaultSharedPreferences(mContext)
                .getBoolean(PREF_URLHAUS_ENABLED, true);
        return enabled && System.currentTimeMillis() > sCircuitBreakerUntil;
    }

    // ─── Query URL ────────────────────────────────────────────────────────────

    @Override
    public ThreatReport queryUrl(String url) {
        if (url == null || url.isEmpty() || !isAvailable()) {
            return null;
        }

        try {
            String formBody = "url=" + URLEncoder.encode(url, "UTF-8");
            JSONObject root = postRequest(API_BASE + "url/", formBody);
            if (root == null) return ThreatReport.error(getProviderName(), url);

            String status = root.optString("query_status", "");
            ThreatReport report = new ThreatReport();
            report.provider = getProviderName();
            report.iocValue = url;
            report.iocType = "URL";

            if ("ok".equalsIgnoreCase(status)) {
                String urlStatus = root.optString("url_status", "");
                String threat = root.optString("threat", "Malware Distribution");
                JSONArray tagsArr = root.optJSONArray("tags");

                report.isMalicious = true;
                report.riskScore = "online".equalsIgnoreCase(urlStatus) ? 95 : 85;
                report.verdict = "MALICIOUS";
                report.malwareFamily = threat;
                report.details = "URLhaus Status: " + urlStatus.toUpperCase() + " | Threat: " + threat;

                if (tagsArr != null && tagsArr.length() > 0) {
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < tagsArr.length(); i++) {
                        if (i > 0) sb.append(", ");
                        sb.append(tagsArr.getString(i));
                    }
                    report.details += " | Tags: " + sb;
                }

                report.confidence = 0.95f;
                return report;
            } else if ("no_results".equalsIgnoreCase(status)) {
                return ThreatReport.clean(getProviderName(), url, "URL");
            } else {
                return ThreatReport.error(getProviderName(), url);
            }
        } catch (Exception e) {
            Log.w(TAG, "URLhaus queryUrl error: " + e.getMessage());
            return ThreatReport.error(getProviderName(), url);
        }
    }

    // ─── Query Domain / Host ──────────────────────────────────────────────────

    @Override
    public ThreatReport queryDomain(String domain) {
        return queryHost(domain, "DOMAIN");
    }

    @Override
    public ThreatReport queryIp(String ip) {
        return queryHost(ip, "IP");
    }

    private ThreatReport queryHost(String host, String iocType) {
        if (host == null || host.isEmpty() || !isAvailable()) {
            return null;
        }

        try {
            String formBody = "host=" + URLEncoder.encode(host, "UTF-8");
            JSONObject root = postRequest(API_BASE + "host/", formBody);
            if (root == null) return ThreatReport.error(getProviderName(), host);

            String status = root.optString("query_status", "");
            ThreatReport report = new ThreatReport();
            report.provider = getProviderName();
            report.iocValue = host;
            report.iocType = iocType;

            if ("ok".equalsIgnoreCase(status)) {
                int urlCount = root.optInt("url_count", 0);
                JSONArray urlsArr = root.optJSONArray("urls");

                report.isMalicious = urlCount > 0;
                report.isSuspicious = urlCount == 0;
                report.riskScore = urlCount > 0 ? Math.min(100, 75 + (urlCount * 5)) : 50;
                report.verdict = urlCount > 0 ? "MALICIOUS" : "SUSPICIOUS";
                report.details = "URLhaus Host associated with " + urlCount + " malware URL(s)";

                if (urlsArr != null && urlsArr.length() > 0) {
                    JSONObject firstUrl = urlsArr.getJSONObject(0);
                    String threat = firstUrl.optString("threat", "");
                    if (!threat.isEmpty()) {
                        report.malwareFamily = threat;
                        report.details += " | Recent Threat: " + threat;
                    }
                }

                report.confidence = 0.90f;
                return report;
            } else if ("no_results".equalsIgnoreCase(status)) {
                return ThreatReport.clean(getProviderName(), host, iocType);
            } else {
                return ThreatReport.error(getProviderName(), host);
            }
        } catch (Exception e) {
            Log.w(TAG, "URLhaus queryHost error: " + e.getMessage());
            return ThreatReport.error(getProviderName(), host);
        }
    }

    // ─── Query Payload Hash ───────────────────────────────────────────────────

    @Override
    public ThreatReport queryHash(String sha256) {
        if (sha256 == null || sha256.isEmpty() || !isAvailable()) {
            return null;
        }

        try {
            String formBody = "sha256_hash=" + URLEncoder.encode(sha256, "UTF-8");
            JSONObject root = postRequest(API_BASE + "payload/", formBody);
            if (root == null) return ThreatReport.error(getProviderName(), sha256);

            String status = root.optString("query_status", "");
            ThreatReport report = new ThreatReport();
            report.provider = getProviderName();
            report.iocValue = sha256;
            report.iocType = "HASH";

            if ("ok".equalsIgnoreCase(status)) {
                String signature = root.optString("signature", "");
                String fileType = root.optString("file_type", "");
                int urlCount = root.optInt("url_count", 0);

                report.isMalicious = true;
                report.riskScore = 95;
                report.verdict = "MALICIOUS";
                report.signature = signature;
                report.malwareFamily = signature.isEmpty() ? fileType : signature;
                report.details = "Known Malware Payload (" + fileType + ") | Distributed by " + urlCount + " URLs";
                report.confidence = 0.98f;
                return report;
            } else if ("no_results".equalsIgnoreCase(status)) {
                return ThreatReport.clean(getProviderName(), sha256, "HASH");
            } else {
                return ThreatReport.error(getProviderName(), sha256);
            }
        } catch (Exception e) {
            Log.w(TAG, "URLhaus queryHash error: " + e.getMessage());
            return ThreatReport.error(getProviderName(), sha256);
        }
    }

    // ─── HTTP Helper ─────────────────────────────────────────────────────────

    private JSONObject postRequest(String endpoint, String formBody) {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(endpoint);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

            String key = PreferenceManager.getDefaultSharedPreferences(mContext)
                    .getString(PREF_URLHAUS_KEY, "").trim();
            if (!key.isEmpty()) {
                conn.setRequestProperty("Auth-Key", key);
            }

            conn.setDoOutput(true);
            conn.setConnectTimeout(4000);
            conn.setReadTimeout(4000);

            byte[] bodyBytes = formBody.getBytes(StandardCharsets.UTF_8);
            conn.setFixedLengthStreamingMode(bodyBytes.length);
            try (DataOutputStream dos = new DataOutputStream(conn.getOutputStream())) {
                dos.write(bodyBytes);
                dos.flush();
            }

            int code = conn.getResponseCode();
            if (code == 401 || code == 403) {
                Log.w(TAG, "URLhaus authentication required (" + code + ")");
                sCircuitBreakerUntil = System.currentTimeMillis() + 300_000;
                return null;
            }
            if (code == 429) {
                Log.w(TAG, "URLhaus rate limit reached (429)");
                sCircuitBreakerUntil = System.currentTimeMillis() + 60_000;
                return null;
            }
            if (code != 200) {
                Log.w(TAG, "URLhaus HTTP " + code);
                return null;
            }

            StringBuilder sb = new StringBuilder();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line);
                }
            }

            return new JSONObject(sb.toString());
        } catch (Exception e) {
            Log.w(TAG, "URLhaus POST failed: " + e.getMessage());
            return null;
        } finally {
            if (conn != null) {
                try { conn.disconnect(); } catch (Exception ignored) {}
            }
        }
    }
}
