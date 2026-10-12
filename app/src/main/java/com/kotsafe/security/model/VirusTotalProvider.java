/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import android.content.Context;

import androidx.preference.PreferenceManager;

import com.kotsafe.security.Log;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * VirusTotal v3 provider — optional, requires user-supplied API key.
 *
 * Supports: hash, IP, domain, URL lookups.
 * Free tier: 4 requests/minute, 500/day.
 * The router respects rate limits via the TI cache — identical IOCs
 * are served from cache and never re-queried within the TTL window.
 */
public class VirusTotalProvider implements ThreatIntelProvider {
    private static final String TAG = "VirusTotalProvider";
    private static final String BASE_URL = "https://www.virustotal.com/api/v3/";
    public static final String PREF_VT_KEY = "virustotal_api_key";

    private final Context mContext;

    public VirusTotalProvider(Context context) {
        mContext = context.getApplicationContext();
    }

    @Override public String getProviderName() { return "VirusTotal"; }
    @Override public String getProviderCode() { return "VT"; }

    @Override
    public boolean isAvailable() {
        String key = PreferenceManager.getDefaultSharedPreferences(mContext)
                .getString(PREF_VT_KEY, "");
        return key != null && !key.trim().isEmpty();
    }

    @Override
    public ThreatReport queryHash(String sha256) {
        return get("files/" + sha256, sha256, "HASH");
    }

    @Override
    public ThreatReport queryIp(String ip) {
        return get("ip_addresses/" + ip, ip, "IP");
    }

    @Override
    public ThreatReport queryDomain(String domain) {
        return get("domains/" + domain, domain, "DOMAIN");
    }

    @Override
    public ThreatReport queryUrl(String url) {
        // VT URL lookup requires base64url-encoded URL
        try {
            String encoded = android.util.Base64.encodeToString(
                    url.getBytes("UTF-8"),
                    android.util.Base64.URL_SAFE | android.util.Base64.NO_PADDING | android.util.Base64.NO_WRAP);
            return get("urls/" + encoded, url, "URL");
        } catch (Exception e) {
            return ThreatReport.error(getProviderName(), url);
        }
    }

    private ThreatReport get(String endpoint, String iocValue, String iocType) {
        ThreatReport report = new ThreatReport();
        report.provider = getProviderName();
        report.iocValue = iocValue;
        report.iocType = iocType;
        report.verdict = "SAFE";

        String apiKey = PreferenceManager.getDefaultSharedPreferences(mContext)
                .getString(PREF_VT_KEY, "");
        if (apiKey == null || apiKey.trim().isEmpty()) {
            return ThreatReport.error(getProviderName(), iocValue);
        }

        HttpURLConnection conn = null;
        try {
            URL url = new URL(BASE_URL + endpoint);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("x-apikey", apiKey.trim());
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);

            int code = conn.getResponseCode();
            if (code == 404) {
                // Not found = not in VT DB
                report.verdict = "SAFE";
                report.details = "Not found in VirusTotal";
                return report;
            }
            if (code == 429) {
                Log.w(TAG, "VT rate limit reached (429) for " + iocValue);
                ThreatReport err = ThreatReport.error(getProviderName(), iocValue);
                err.details = "VirusTotal rate limit / quota exceeded (429)";
                return err;
            }
            if (code != 200) {
                Log.w(TAG, "VT HTTP " + code + " for " + iocValue);
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
            JSONObject data = root.optJSONObject("data");
            if (data == null) return ThreatReport.error(getProviderName(), iocValue);

            JSONObject attributes = data.optJSONObject("attributes");
            if (attributes == null) return ThreatReport.error(getProviderName(), iocValue);

            // last_analysis_stats is present for files, IPs, domains, URLs
            JSONObject stats = attributes.optJSONObject("last_analysis_stats");
            if (stats != null) {
                int malicious = stats.optInt("malicious", 0);
                int suspicious = stats.optInt("suspicious", 0);
                int harmless = stats.optInt("harmless", 0);
                int undetected = stats.optInt("undetected", 0);
                int total = malicious + suspicious + harmless + undetected;

                report.details = malicious + "/" + total + " engines detected";

                if (malicious >= 3) {
                    report.isMalicious = true;
                    report.riskScore = Math.min(100, 50 + malicious * 3);
                    report.verdict = "MALICIOUS";
                } else if (malicious >= 1 || suspicious >= 3) {
                    report.isSuspicious = true;
                    report.riskScore = 25 + malicious * 10 + suspicious * 5;
                    report.verdict = "SUSPICIOUS";
                }

                report.confidence = total > 0 ? (float) (malicious + suspicious) / total : 0f;
            }

            // Malware family names
            if ("HASH".equals(iocType)) {
                JSONObject names = attributes.optJSONObject("popular_threat_classification");
                if (names != null) {
                    JSONObject family = names.optJSONObject("suggested_threat_label");
                    if (family != null) {
                        report.malwareFamily = family.optString("value", "");
                    }
                }
            }

        } catch (java.net.SocketTimeoutException e) {
            Log.w(TAG, "VT query timeout for " + iocValue);
            ThreatReport err = ThreatReport.error(getProviderName(), iocValue);
            err.details = "Connection timeout";
            return err;
        } catch (java.net.UnknownHostException e) {
            Log.w(TAG, "VT DNS resolution failed (offline?): " + e.getMessage());
            ThreatReport err = ThreatReport.error(getProviderName(), iocValue);
            err.details = "No internet connection";
            return err;
        } catch (Exception e) {
            Log.e(TAG, "VT query error for " + iocValue + ": " + e.getMessage());
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
