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
import java.nio.charset.StandardCharsets;

/**
 * ThreatFox provider — abuse.ch IOC sharing platform for malware and botnets.
 *
 * Supports querying:
 *  - IP addresses (Botnet C2, payload delivery)
 *  - Domains & Hostnames (Malware infrastructure)
 *  - URLs (C2 endpoints, phishing, drops)
 *  - Hashes (SHA-256 malware payloads)
 *
 * API: https://threatfox-api.abuse.ch/api/v1/
 */
public class ThreatFoxProvider implements ThreatIntelProvider {
    private static final String TAG = "ThreatFoxProvider";
    private static final String API_URL = "https://threatfox-api.abuse.ch/api/v1/";
    public static final String PREF_THREATFOX_KEY = "threatfox_api_key";
    public static final String PREF_THREATFOX_ENABLED = "threatfox_enabled";

    private static volatile long sCircuitBreakerUntil = 0;
    private final Context mContext;

    public ThreatFoxProvider(Context context) {
        mContext = context.getApplicationContext();
    }

    @Override
    public String getProviderName() {
        return "ThreatFox (Abuse.ch)";
    }

    @Override
    public String getProviderCode() {
        return "THREATFOX";
    }

    @Override
    public boolean isAvailable() {
        boolean enabled = PreferenceManager.getDefaultSharedPreferences(mContext)
                .getBoolean(PREF_THREATFOX_ENABLED, true);
        return enabled && System.currentTimeMillis() > sCircuitBreakerUntil;
    }

    // ─── Query IOC (IP / Domain / URL) ────────────────────────────────────────

    @Override
    public ThreatReport queryIp(String ip) {
        return searchIoc(ip, "IP");
    }

    @Override
    public ThreatReport queryDomain(String domain) {
        return searchIoc(domain, "DOMAIN");
    }

    @Override
    public ThreatReport queryUrl(String url) {
        return searchIoc(url, "URL");
    }

    private ThreatReport searchIoc(String ioc, String iocType) {
        if (ioc == null || ioc.isEmpty() || !isAvailable()) {
            return null;
        }

        try {
            JSONObject body = new JSONObject();
            body.put("query", "search_ioc");
            body.put("search_term", ioc);

            JSONObject root = postJson(body);
            if (root == null) return ThreatReport.error(getProviderName(), ioc);

            return parseThreatFoxResponse(root, ioc, iocType);
        } catch (Exception e) {
            Log.w(TAG, "ThreatFox searchIoc error for " + ioc + ": " + e.getMessage());
            return ThreatReport.error(getProviderName(), ioc);
        }
    }

    // ─── Query Hash ───────────────────────────────────────────────────────────

    @Override
    public ThreatReport queryHash(String sha256) {
        if (sha256 == null || sha256.isEmpty() || !isAvailable()) {
            return null;
        }

        try {
            JSONObject body = new JSONObject();
            body.put("query", "search_hash");
            body.put("hash", sha256);

            JSONObject root = postJson(body);
            if (root == null) return ThreatReport.error(getProviderName(), sha256);

            return parseThreatFoxResponse(root, sha256, "HASH");
        } catch (Exception e) {
            Log.w(TAG, "ThreatFox queryHash error for " + sha256 + ": " + e.getMessage());
            return ThreatReport.error(getProviderName(), sha256);
        }
    }

    // ─── Response Parser ──────────────────────────────────────────────────────

    private ThreatReport parseThreatFoxResponse(JSONObject root, String ioc, String iocType) {
        String status = root.optString("query_status", "");
        ThreatReport report = new ThreatReport();
        report.provider = getProviderName();
        report.iocValue = ioc;
        report.iocType = iocType;

        if ("ok".equalsIgnoreCase(status)) {
            JSONArray data = root.optJSONArray("data");
            if (data != null && data.length() > 0) {
                JSONObject first = data.optJSONObject(0);
                String malware = first.optString("malware_printable", "Unknown Malware");
                String threatType = first.optString("threat_type_desc", first.optString("threat_type", "Malware IOC"));
                int confidence = first.optInt("confidence_level", 80);
                JSONArray tagsArr = first.optJSONArray("tags");

                report.isMalicious = confidence >= 50;
                report.isSuspicious = confidence < 50;
                report.riskScore = Math.max(confidence, 75);
                report.verdict = report.isMalicious ? "MALICIOUS" : "SUSPICIOUS";
                report.malwareFamily = malware;
                report.details = "Threat: " + threatType + " (" + malware + ") | Confidence: " + confidence + "%";

                if (tagsArr != null && tagsArr.length() > 0) {
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < tagsArr.length(); i++) {
                        if (i > 0) sb.append(", ");
                        sb.append(tagsArr.optString(i));
                    }
                    report.details += " | Tags: " + sb;
                }

                report.confidence = Math.min(1.0f, (float) confidence / 100.0f);
                return report;
            }
        } else if ("no_result".equalsIgnoreCase(status) || "no_results".equalsIgnoreCase(status)) {
            return ThreatReport.clean(getProviderName(), ioc, iocType);
        }

        return ThreatReport.error(getProviderName(), ioc);
    }

    // ─── HTTP Helper ─────────────────────────────────────────────────────────

    private JSONObject postJson(JSONObject jsonBody) {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(API_URL);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");

            String key = PreferenceManager.getDefaultSharedPreferences(mContext)
                    .getString(PREF_THREATFOX_KEY, "").trim();
            if (!key.isEmpty()) {
                conn.setRequestProperty("Auth-Key", key);
                conn.setRequestProperty("API-KEY", key);
            }

            conn.setDoOutput(true);
            conn.setConnectTimeout(4000);
            conn.setReadTimeout(4000);

            byte[] bodyBytes = jsonBody.toString().getBytes(StandardCharsets.UTF_8);
            conn.setFixedLengthStreamingMode(bodyBytes.length);
            try (DataOutputStream dos = new DataOutputStream(conn.getOutputStream())) {
                dos.write(bodyBytes);
                dos.flush();
            }

            int code = conn.getResponseCode();
            if (code == 401 || code == 403) {
                Log.w(TAG, "ThreatFox auth error (HTTP " + code + ")");
                sCircuitBreakerUntil = System.currentTimeMillis() + 300_000;
                return null;
            }
            if (code == 429) {
                Log.w(TAG, "ThreatFox rate limited (HTTP 429)");
                sCircuitBreakerUntil = System.currentTimeMillis() + 60_000;
                return null;
            }
            if (code != 200) {
                Log.w(TAG, "ThreatFox HTTP " + code);
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
            Log.w(TAG, "ThreatFox POST error: " + e.getMessage());
            return null;
        } finally {
            if (conn != null) {
                try { conn.disconnect(); } catch (Exception ignored) {}
            }
        }
    }
}
