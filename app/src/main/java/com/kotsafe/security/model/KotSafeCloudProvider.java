/*
 * This file is part of KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import android.content.Context;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.Log;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * KotSafe Cloud Threat Intelligence Provider.
 *
 * Connects directly to the KotSafe Threat Intelligence engine on the KotSafe Admin/Backend.
 * Centralizes AlienVault OTX, URLhaus, MalwareBazaar, Feodo Tracker, and VirusTotal lookups
 * through server-side connectors and Neon Serverless PostgreSQL without requiring personal
 * API keys on client Android devices.
 *
 * Endpoint: POST https://kotsafe.com/api/v1/threat-intel/lookup
 */
public class KotSafeCloudProvider implements ThreatIntelProvider {
    private static final String TAG = "KotSafeCloudProvider";
    public static final String DEFAULT_ENDPOINT = "https://kotsafe.com/api/v1/threat-intel/lookup";
    public static final String PREF_CLOUD_INTEL_ENABLED = "kotsafe_cloud_intel_enabled";
    public static final String PREF_CUSTOM_ENDPOINT = "kotsafe_threat_intel_url";

    private final Context mContext;

    public KotSafeCloudProvider(Context context) {
        mContext = context.getApplicationContext();
    }

    @Override
    public String getProviderName() {
        return "KotSafe Cloud Intelligence";
    }

    @Override
    public String getProviderCode() {
        return "KOTSAFE";
    }

    @Override
    public boolean isAvailable() {
        return PreferenceManager.getDefaultSharedPreferences(mContext)
                .getBoolean(PREF_CLOUD_INTEL_ENABLED, true);
    }

    public String getEndpointUrl() {
        String custom = PreferenceManager.getDefaultSharedPreferences(mContext)
                .getString(PREF_CUSTOM_ENDPOINT, "").trim();
        return custom.isEmpty() ? DEFAULT_ENDPOINT : custom;
    }

    @Override
    public ThreatReport queryHash(String sha256) {
        return lookup(sha256, "HASH");
    }

    @Override
    public ThreatReport queryIp(String ip) {
        return lookup(ip, "IP");
    }

    @Override
    public ThreatReport queryDomain(String domain) {
        return lookup(domain, "DOMAIN");
    }

    @Override
    public ThreatReport queryUrl(String url) {
        return lookup(url, "URL");
    }

    /**
     * Executes synchronous threat intelligence query against KotSafe Cloud API.
     */
    public ThreatReport lookup(String ioc, String type) {
        if (ioc == null || ioc.trim().isEmpty()) {
            return null;
        }

        String cleanIoc = ioc.trim();
        if ("IP".equalsIgnoreCase(type)) {
            cleanIoc = ThreatIntelManager.cleanIp(cleanIoc);
            if (ThreatIntelManager.isPrivateOrLocalIp(cleanIoc)) {
                return ThreatReport.clean(getProviderName(), cleanIoc, "IP");
            }
        } else if ("DOMAIN".equalsIgnoreCase(type)) {
            cleanIoc = ThreatIntelManager.cleanDomain(cleanIoc);
        } else if ("HASH".equalsIgnoreCase(type)) {
            cleanIoc = cleanIoc.toLowerCase(Locale.ROOT).replace("sha256:", "").replace("md5:", "").trim();
        }

        if (cleanIoc.isEmpty()) {
            return null;
        }

        HttpURLConnection conn = null;
        try {
            URL url = new URL(getEndpointUrl());
            if (!"https".equalsIgnoreCase(url.getProtocol())) return null;
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(4000);
            conn.setReadTimeout(20000);
            conn.setInstanceFollowRedirects(false);
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("User-Agent", "KotSafe-Android/2.0");

            JSONObject payload = new JSONObject();
            payload.put("query", cleanIoc);
            payload.put("type", type != null ? type.toLowerCase(Locale.ROOT) : "auto");

            byte[] postData = payload.toString().getBytes(StandardCharsets.UTF_8);
            conn.setFixedLengthStreamingMode(postData.length);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(postData);
                os.flush();
            }

            int responseCode = conn.getResponseCode();
            if (responseCode >= 200 && responseCode < 300) {
                String resp = readStream(conn.getInputStream());
                JSONObject json = new JSONObject(resp);
                if (json.optBoolean("success", false) && json.has("data")) {
                    JSONObject data = json.getJSONObject("data");
                    ThreatReport r = new ThreatReport();
                    r.iocValue = cleanIoc;
                    r.iocType = type != null ? type.toUpperCase(Locale.ROOT) : "UNKNOWN";
                    r.isMalicious = data.optBoolean("isMalicious", false);
                    r.isSuspicious = !r.isMalicious && data.optBoolean("isSuspicious", false);
                    r.riskScore = data.optInt("maliciousScore", 0);

                    String verdict = data.optString("verdict", "unknown");
                    r.verdict = r.isMalicious ? "MALICIOUS" : (r.isSuspicious ? "SUSPICIOUS" : verdict.toUpperCase(Locale.ROOT));

                    String family = data.optString("family", null);
                    if (family == null || family.isEmpty() || "null".equalsIgnoreCase(family)) {
                        family = data.optString("malware_family", null);
                    }
                    r.malwareFamily = family;
                    r.details = data.optString("details", "");
                    r.confidence = Math.max(0, Math.min(100, data.optInt("confidence", 0))) / 100f;
                    r.provider = family != null && !family.isEmpty()
                            ? "KotSafe Cloud (" + family + ")"
                            : "KotSafe Cloud Intelligence";
                    r.resultJson = resp;
                    return r;
                }
            } else {
                Log.w(TAG, "KotSafe Cloud returned HTTP " + responseCode);
            }
        } catch (Exception e) {
            Log.w(TAG, "KotSafe Cloud lookup failed: " + e.getMessage());
        } finally {
            if (conn != null) conn.disconnect();
        }

        return null;
    }

    public interface CloudCallback {
        void onSuccess(String message);
        void onError(String error);
    }

    /**
     * Diagnostic test connection probe for Settings screen.
     */
    public void testConnection(CloudCallback callback) {
        new Thread(() -> {
            try {
                URL url = new URL(getEndpointUrl());
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setConnectTimeout(6000);
                conn.setReadTimeout(6000);
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
                conn.setRequestProperty("Accept", "application/json");
                conn.setRequestProperty("User-Agent", "KotSafe-Android/2.0");

                JSONObject testPayload = new JSONObject();
                testPayload.put("query", "8.8.8.8");
                testPayload.put("type", "ip");

                byte[] b = testPayload.toString().getBytes(StandardCharsets.UTF_8);
                conn.setFixedLengthStreamingMode(b.length);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(b);
                    os.flush();
                }

                int code = conn.getResponseCode();
                if (code == 200) {
                    String resp = readStream(conn.getInputStream());
                    JSONObject json = new JSONObject(resp);
                    if (json.optBoolean("success", false) && json.optJSONObject("data") != null) {
                        callback.onSuccess("KotSafe Cloud API responded. This confirms connectivity, not detection accuracy.");
                        return;
                    }
                }
                callback.onError("Server returned status HTTP " + code);
            } catch (Exception e) {
                callback.onError("Connection failed: " + e.getMessage());
            }
        }).start();
    }

    private static String readStream(InputStream is) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            if (sb.length() + line.length() > 262144) throw new java.io.IOException("Cloud response exceeds limit");
            sb.append(line);
        }
        reader.close();
        return sb.toString();
    }
}
