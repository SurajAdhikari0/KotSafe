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
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * OTX (AlienVault Open Threat Exchange) provider implementation.
 * Supports hash, IP, and domain lookups.
 */
public class OTXProvider implements ThreatIntelProvider {
    private static final String TAG = "OTXProvider";
    private static final String BASE_URL = "https://otx.alienvault.com/api/v1/indicators/";
    private static final String PREF_OTX_KEY = "otx_api_key";

    private final Context mContext;

    public OTXProvider(Context context) {
        mContext = context.getApplicationContext();
    }

    @Override
    public String getProviderName() { return "AlienVault OTX"; }

    @Override
    public String getProviderCode() { return "OTX"; }

    @Override
    public boolean isAvailable() {
        String key = PreferenceManager.getDefaultSharedPreferences(mContext)
                .getString(PREF_OTX_KEY, "");
        return key != null && !key.trim().isEmpty();
    }

    @Override
    public ThreatReport queryHash(String sha256) {
        return query("file/" + sha256 + "/general", sha256, "HASH");
    }

    @Override
    public ThreatReport queryIp(String ip) {
        return query("IPv4/" + ip + "/general", ip, "IP");
    }

    @Override
    public ThreatReport queryDomain(String domain) {
        return query("domain/" + domain + "/general", domain, "DOMAIN");
    }

    @Override
    public ThreatReport queryUrl(String url) {
        // OTX URL indicator uses url-encoded endpoint
        try {
            String encoded = java.net.URLEncoder.encode(url, "UTF-8");
            return query("url/" + encoded + "/general", url, "URL");
        } catch (Exception e) {
            return ThreatReport.error(getProviderName(), url);
        }
    }

    private ThreatReport query(String endpoint, String iocValue, String iocType) {
        ThreatReport report = new ThreatReport();
        report.provider = getProviderName();
        report.iocValue = iocValue;
        report.iocType = iocType;
        report.verdict = "SAFE";

        String apiKey = PreferenceManager.getDefaultSharedPreferences(mContext)
                .getString(PREF_OTX_KEY, "");
        if (apiKey == null || apiKey.trim().isEmpty()) {
            return ThreatReport.error(getProviderName(), iocValue);
        }

        HttpURLConnection conn = null;
        try {
            URL url = new URL(BASE_URL + endpoint);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("X-OTX-API-KEY", apiKey.trim());
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(8000);

            int code = conn.getResponseCode();
            if (code == 429) {
                Log.w(TAG, "OTX rate limit reached (429) for " + iocValue);
                ThreatReport err = ThreatReport.error(getProviderName(), iocValue);
                err.details = "OTX rate limit exceeded (429)";
                return err;
            }
            if (code != 200) {
                Log.w(TAG, "OTX HTTP " + code + " for " + iocValue);
                return ThreatReport.error(getProviderName(), iocValue);
            }

            StringBuilder sb = new StringBuilder();
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(conn.getInputStream()))) {
                String line;
                while ((line = br.readLine()) != null) sb.append(line);
            }

            String json = sb.toString();
            report.resultJson = json;
            JSONObject root = new JSONObject(json);

            // Parse pulse count (main malicious indicator in OTX)
            int pulseCount = 0;
            if (root.has("pulse_info")) {
                JSONObject pulseInfo = root.getJSONObject("pulse_info");
                pulseCount = pulseInfo.optInt("count", 0);
            }
            // For file hashes, check "malware_families"
            if ("HASH".equals(iocType) && root.has("malware_families")) {
                JSONArray families = root.getJSONArray("malware_families");
                if (families.length() > 0) {
                    report.malwareFamily = families.getJSONObject(0).optString("family", "");
                    report.isMalicious = true;
                    report.riskScore = Math.min(100, 60 + families.length() * 5);
                }
            }

            if (pulseCount > 0 && !report.isMalicious) {
                if (pulseCount >= 3) {
                    report.isMalicious = true;
                    report.riskScore = Math.min(100, 55 + pulseCount * 3);
                } else {
                    report.isSuspicious = true;
                    report.riskScore = 25 + pulseCount * 10;
                }
            }

            report.details = pulseCount + " OTX pulse(s)";
            report.verdict = report.isMalicious ? "MALICIOUS"
                    : report.isSuspicious ? "SUSPICIOUS" : "SAFE";
            report.confidence = 0.85f;

        } catch (java.net.SocketTimeoutException e) {
            Log.w(TAG, "OTX query timeout for " + iocValue);
            ThreatReport err = ThreatReport.error(getProviderName(), iocValue);
            err.details = "Connection timeout";
            return err;
        } catch (java.net.UnknownHostException e) {
            Log.w(TAG, "OTX DNS resolution failed (offline?): " + e.getMessage());
            ThreatReport err = ThreatReport.error(getProviderName(), iocValue);
            err.details = "No internet connection";
            return err;
        } catch (Exception e) {
            Log.e(TAG, "OTX query error for " + iocValue + ": " + e.getMessage());
            return ThreatReport.error(getProviderName(), iocValue);
        } finally {
            if (conn != null) {
                try {
                    conn.disconnect();
                } catch (Exception ignored) {}
            }
        }
        return report;
    }
}
