/*
 * This file is part of KotSafe.
 *
 * KotSafe is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * KotSafe is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with KotSafe.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.kotsafe.security;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.model.ThreatIntelManager;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public class ThreatIntelApiClient {
    private static final String TAG = "ThreatIntelApiClient";

    public static final String PREF_OTX_KEY = "otx_api_key";
    public static final String PREF_VT_KEY = "virustotal_api_key";
    public static final String PREF_AUTO_SCAN = "auto_threat_query_during_scan";

    private final Context mContext;
    private final SharedPreferences mPrefs;
    private final Map<String, ThreatReport> mCache;

    private static ThreatIntelApiClient sInstance;

    public static synchronized ThreatIntelApiClient getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new ThreatIntelApiClient(context.getApplicationContext());
        }
        return sInstance;
    }

    private ThreatIntelApiClient(Context context) {
        mContext = context;
        mPrefs = PreferenceManager.getDefaultSharedPreferences(context);
        // Simple bounded LRU cache for 500 lookups
        mCache = Collections.synchronizedMap(new LinkedHashMap<String, ThreatReport>(100, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, ThreatReport> eldest) {
                return size() > 500;
            }
        });
    }

    public static class ThreatReport {
        public String iocValue = "";
        public String iocType = ""; // IP, DOMAIN, HASH, URL
        public boolean isMalicious;
        public boolean isSuspicious;
        public int maliciousScore; // Count of detections
        public int totalScans;
        public String provider = "";
        public String details = "";
    }

    public interface ApiCallback<T> {
        void onSuccess(T result);
        void onError(String message);
    }

    public String getOtxKey() {
        return mPrefs.getString(PREF_OTX_KEY, "").trim();
    }

    public String getVtKey() {
        return mPrefs.getString(PREF_VT_KEY, "").trim();
    }

    public boolean isAutoThreatQueryEnabled() {
        return mPrefs.getBoolean(PREF_AUTO_SCAN, true);
    }

    public boolean hasAnyApiKey() {
        return !getOtxKey().isEmpty() || !getVtKey().isEmpty();
    }

    public void testOtxConnection(String key, ApiCallback<String> callback) {
        new Thread(() -> {
            try {
                if (key == null || key.trim().isEmpty()) {
                    callback.onError("OTX API Key is empty");
                    return;
                }
                URL url = new URL("https://otx.alienvault.com/api/v1/user/me");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setRequestProperty("X-OTX-API-KEY", key.trim());
                conn.setConnectTimeout(8000);
                conn.setReadTimeout(8000);

                int code = conn.getResponseCode();
                if (code == 200) {
                    String resp = readStream(conn.getInputStream());
                    JsonObject json = JsonParser.parseString(resp).getAsJsonObject();
                    String username = json.has("username") ? json.get("username").getAsString() : "User";
                    callback.onSuccess("Connected: Logged in as " + username);
                } else if (code == 403 || code == 401) {
                    callback.onError("Authentication Failed: Invalid API Key (HTTP " + code + ")");
                } else {
                    callback.onError("Server Error: HTTP " + code);
                }
            } catch (Exception e) {
                callback.onError("Connection Failed: " + e.getMessage());
            }
        }).start();
    }

    public void testVirusTotalConnection(String key, ApiCallback<String> callback) {
        new Thread(() -> {
            try {
                if (key == null || key.trim().isEmpty()) {
                    callback.onError("VirusTotal API Key is empty");
                    return;
                }
                URL url = new URL("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setRequestProperty("x-apikey", key.trim());
                conn.setConnectTimeout(8000);
                conn.setReadTimeout(8000);

                int code = conn.getResponseCode();
                if (code == 200) {
                    callback.onSuccess("Connected: VirusTotal API Key Valid (Quota Active)");
                } else if (code == 401 || code == 403) {
                    callback.onError("Authentication Failed: Invalid API Key (HTTP " + code + ")");
                } else {
                    callback.onError("Server Error: HTTP " + code);
                }
            } catch (Exception e) {
                callback.onError("Connection Failed: " + e.getMessage());
            }
        }).start();
    }

    public void testUrlhausConnection(String key, ApiCallback<String> callback) {
        new Thread(() -> {
            try {
                URL url = new URL("https://urlhaus-api.abuse.ch/v1/urls/recent/");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                if (key != null && !key.trim().isEmpty()) {
                    conn.setRequestProperty("Auth-Key", key.trim());
                }
                conn.setConnectTimeout(8000);
                conn.setReadTimeout(8000);

                int code = conn.getResponseCode();
                if (code == 200) {
                    callback.onSuccess("Connected: URLhaus (Abuse.ch) API is Reachable & Operational");
                } else {
                    callback.onError("URLhaus Status Error: HTTP " + code);
                }
            } catch (Exception e) {
                callback.onError("URLhaus Connection Failed: " + e.getMessage());
            }
        }).start();
    }

    public void testThreatFoxConnection(String key, ApiCallback<String> callback) {
        new Thread(() -> {
            try {
                URL url = new URL("https://threatfox-api.abuse.ch/api/v1/");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
                if (key != null && !key.trim().isEmpty()) {
                    conn.setRequestProperty("Auth-Key", key.trim());
                }
                conn.setDoOutput(true);
                conn.setConnectTimeout(8000);
                conn.setReadTimeout(8000);

                String payload = "{\"query\":\"get_iocs\",\"days\":1}";
                byte[] bytes = payload.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                conn.setFixedLengthStreamingMode(bytes.length);
                try (java.io.DataOutputStream dos = new java.io.DataOutputStream(conn.getOutputStream())) {
                    dos.write(bytes);
                    dos.flush();
                }

                int code = conn.getResponseCode();
                if (code == 200) {
                    callback.onSuccess("Connected: ThreatFox (Abuse.ch) IOC Feed is Reachable & Operational");
                } else {
                    callback.onError("ThreatFox Status Error: HTTP " + code);
                }
            } catch (Exception e) {
                callback.onError("ThreatFox Connection Failed: " + e.getMessage());
            }
        }).start();
    }

    public void testMalwareBazaarConnection(String key, ApiCallback<String> callback) {
        new Thread(() -> {
            try {
                URL url = new URL("https://mb-api.abuse.ch/api/v1/");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                if (key != null && !key.trim().isEmpty()) {
                    conn.setRequestProperty("Auth-Key", key.trim());
                }
                conn.setDoOutput(true);
                conn.setConnectTimeout(8000);
                conn.setReadTimeout(8000);

                String payload = "query=get_recent&selector=time";
                byte[] bytes = payload.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                conn.setFixedLengthStreamingMode(bytes.length);
                try (java.io.DataOutputStream dos = new java.io.DataOutputStream(conn.getOutputStream())) {
                    dos.write(bytes);
                    dos.flush();
                }

                int code = conn.getResponseCode();
                if (code == 200) {
                    callback.onSuccess("Connected: MalwareBazaar (Abuse.ch) Hash Feed is Reachable & Operational");
                } else {
                    callback.onError("MalwareBazaar Status Error: HTTP " + code);
                }
            } catch (Exception e) {
                callback.onError("MalwareBazaar Connection Failed: " + e.getMessage());
            }
        }).start();
    }

    public void testSiemConnection(String endpoint, String token, ApiCallback<String> callback) {
        new Thread(() -> {
            try {
                if (endpoint == null || endpoint.trim().isEmpty()) {
                    callback.onError("SIEM Endpoint URL is empty");
                    return;
                }
                URL url = new URL(endpoint.trim());
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setConnectTimeout(8000);
                conn.setReadTimeout(8000);
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
                if (token != null && !token.trim().isEmpty()) {
                    if (token.startsWith("Splunk ") || token.startsWith("Bearer ")) {
                        conn.setRequestProperty("Authorization", token.trim());
                    } else {
                        conn.setRequestProperty("Authorization", "Bearer " + token.trim());
                    }
                }
                String ping = "{\"event\":{\"category\":\"test\",\"action\":\"ping\"},\"message\":\"KotSafe SIEM connection test\"}";
                byte[] b = ping.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                conn.setFixedLengthStreamingMode(b.length);
                try (java.io.OutputStream os = conn.getOutputStream()) {
                    os.write(b);
                    os.flush();
                }
                int code = conn.getResponseCode();
                if (code >= 200 && code < 300) {
                    callback.onSuccess("Connected: SIEM Ingest Endpoint responded HTTP " + code);
                } else {
                    callback.onError("SIEM Server returned HTTP " + code);
                }
            } catch (Exception e) {
                callback.onError("SIEM Connection failed: " + e.getMessage());
            }
        }).start();
    }

    public ThreatReport queryIoc(String ioc, String type) {
        if (ioc == null || ioc.trim().isEmpty()) return null;
        String cacheKey = type + ":" + ioc;
        ThreatReport cached = mCache.get(cacheKey);
        if (cached != null) return cached;

        String otxKey = getOtxKey();
        String vtKey = getVtKey();

        ThreatReport report = new ThreatReport();
        report.iocValue = ioc;
        report.iocType = type;

        String cleanIoc = ioc;
        if ("IP".equalsIgnoreCase(type)) {
            cleanIoc = ThreatIntelManager.cleanIp(ioc);
        } else if ("DOMAIN".equalsIgnoreCase(type) || "URL".equalsIgnoreCase(type)) {
            cleanIoc = ThreatIntelManager.cleanDomain(ioc);
        } else if ("HASH".equalsIgnoreCase(type)) {
            cleanIoc = ThreatIntelManager.cleanHash(ioc);
        }

        // Try VirusTotal first if key available
        if (!vtKey.isEmpty() && !cleanIoc.isEmpty()) {
            try {
                String endpoint = "";
                if ("IP".equalsIgnoreCase(type)) {
                    endpoint = "https://www.virustotal.com/api/v3/ip_addresses/" + cleanIoc;
                } else if ("DOMAIN".equalsIgnoreCase(type) || "URL".equalsIgnoreCase(type)) {
                    endpoint = "https://www.virustotal.com/api/v3/domains/" + cleanIoc;
                } else if ("HASH".equalsIgnoreCase(type)) {
                    endpoint = "https://www.virustotal.com/api/v3/files/" + cleanIoc;
                }

                if (!endpoint.isEmpty()) {
                    URL url = new URL(endpoint);
                    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                    conn.setRequestMethod("GET");
                    conn.setRequestProperty("x-apikey", vtKey);
                    conn.setConnectTimeout(5000);
                    conn.setReadTimeout(5000);

                    if (conn.getResponseCode() == 200) {
                        String resp = readStream(conn.getInputStream());
                        JsonObject root = JsonParser.parseString(resp).getAsJsonObject();
                        if (root.has("data")) {
                            JsonObject data = root.getAsJsonObject("data");
                            if (data.has("attributes")) {
                                JsonObject attrs = data.getAsJsonObject("attributes");
                                if (attrs.has("last_analysis_stats")) {
                                    JsonObject stats = attrs.getAsJsonObject("last_analysis_stats");
                                    int malicious = stats.has("malicious") ? stats.get("malicious").getAsInt() : 0;
                                    int suspicious = stats.has("suspicious") ? stats.get("suspicious").getAsInt() : 0;
                                    int harmless = stats.has("harmless") ? stats.get("harmless").getAsInt() : 0;
                                    int undetected = stats.has("undetected") ? stats.get("undetected").getAsInt() : 0;

                                    report.maliciousScore = malicious;
                                    report.totalScans = malicious + suspicious + harmless + undetected;
                                    report.isMalicious = malicious >= 2;
                                    report.isSuspicious = suspicious > 0 || malicious == 1;
                                    report.provider = "VirusTotal";
                                    report.details = malicious + " / " + report.totalScans + " engines detected this indicator";
                                    mCache.put(cacheKey, report);
                                    return report;
                                }
                            }
                        }
                    }
                }
            } catch (Exception e) {
                Log.w(TAG, "VT query failed: " + e.getMessage());
            }
        }

        // Try AlienVault OTX if key available
        if (!otxKey.isEmpty() && !cleanIoc.isEmpty()) {
            try {
                String endpoint = "";
                if ("IP".equalsIgnoreCase(type)) {
                    endpoint = "https://otx.alienvault.com/api/v1/indicators/IPv4/" + cleanIoc + "/general";
                } else if ("DOMAIN".equalsIgnoreCase(type) || "URL".equalsIgnoreCase(type)) {
                    endpoint = "https://otx.alienvault.com/api/v1/indicators/domain/" + cleanIoc + "/general";
                } else if ("HASH".equalsIgnoreCase(type)) {
                    endpoint = "https://otx.alienvault.com/api/v1/indicators/file/" + cleanIoc + "/general";
                }

                if (!endpoint.isEmpty()) {
                    URL url = new URL(endpoint);
                    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                    conn.setRequestMethod("GET");
                    conn.setRequestProperty("X-OTX-API-KEY", otxKey);
                    conn.setConnectTimeout(5000);
                    conn.setReadTimeout(5000);

                    if (conn.getResponseCode() == 200) {
                        String resp = readStream(conn.getInputStream());
                        JsonObject root = JsonParser.parseString(resp).getAsJsonObject();
                        int pulseCount = 0;
                        if (root.has("pulse_info")) {
                            JsonObject pulseInfo = root.getAsJsonObject("pulse_info");
                            if (pulseInfo.has("count")) {
                                pulseCount = pulseInfo.get("count").getAsInt();
                            }
                        }
                        report.maliciousScore = pulseCount;
                        report.isMalicious = pulseCount >= 2;
                        report.isSuspicious = pulseCount == 1;
                        report.provider = "AlienVault OTX";
                        report.details = pulseCount > 0 ? "Reported in " + pulseCount + " OTX threat pulses" : "Clean in AlienVault OTX";
                        mCache.put(cacheKey, report);
                        return report;
                    }
                }
            } catch (Exception e) {
                Log.w(TAG, "OTX query failed: " + e.getMessage());
            }
        }

        return report;
    }

    private static String readStream(InputStream is) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(is));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line);
        }
        reader.close();
        return sb.toString();
    }
}
