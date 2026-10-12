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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * ThreatFeedSyncManager — synchronizes live cyber threat feeds (URLhaus & ThreatFox)
 * directly into the local SecurityRulesDb and TiCacheDb for zero-latency, offline firewall blocking.
 */
public class ThreatFeedSyncManager {
    private static final String TAG = "ThreatFeedSyncManager";

    public static final String PREF_AUTO_FEED_SYNC = "auto_threat_feed_sync";
    public static final String PREF_LAST_SYNC_TIME = "threat_feed_last_sync_time";
    public static final String PREF_LAST_SYNC_COUNT = "threat_feed_last_sync_count";

    private static ThreatFeedSyncManager sInstance;
    private final Context mContext;
    private final ExecutorService mExecutor = Executors.newSingleThreadExecutor();
    private boolean mIsSyncing = false;

    public interface SyncCallback {
        void onProgress(String status);
        void onSuccess(int totalRulesAdded);
        void onError(String errorMessage);
    }

    public static synchronized ThreatFeedSyncManager getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new ThreatFeedSyncManager(context.getApplicationContext());
        }
        return sInstance;
    }

    private ThreatFeedSyncManager(Context context) {
        mContext = context;
    }

    public boolean isSyncing() {
        return mIsSyncing;
    }

    public void syncNow(SyncCallback callback) {
        if (mIsSyncing) {
            if (callback != null) callback.onError("Threat feed sync is already in progress");
            return;
        }

        mIsSyncing = true;
        mExecutor.execute(() -> {
            int addedCount = 0;
            try {
                if (callback != null) callback.onProgress("Fetching URLhaus active malware feed…");
                int urlhausCount = syncUrlhausFeed();
                addedCount += urlhausCount;
                Log.i(TAG, "URLhaus sync added " + urlhausCount + " rules");

                if (callback != null) callback.onProgress("Fetching ThreatFox C2 & botnet feed…");
                int threatFoxCount = syncThreatFoxFeed();
                addedCount += threatFoxCount;
                Log.i(TAG, "ThreatFox sync added " + threatFoxCount + " rules");

                if (callback != null) callback.onProgress("Fetching MalwareBazaar recent malware hashes…");
                int mbCount = syncMalwareBazaarFeed();
                addedCount += mbCount;
                Log.i(TAG, "MalwareBazaar sync added " + mbCount + " malware hashes");

                // Reload local fast blocklist in memory
                SecurityBlocklistManager.getInstance(mContext).reloadCache();

                // Save metadata
                long now = System.currentTimeMillis();
                PreferenceManager.getDefaultSharedPreferences(mContext).edit()
                        .putLong(PREF_LAST_SYNC_TIME, now)
                        .putInt(PREF_LAST_SYNC_COUNT, addedCount)
                        .apply();

                if (callback != null) {
                    callback.onSuccess(addedCount);
                }
            } catch (Exception e) {
                Log.e(TAG, "Threat feed sync failed: " + e.getMessage());
                if (callback != null) {
                    callback.onError(e.getMessage() != null ? e.getMessage() : "Unknown sync error");
                }
            } finally {
                mIsSyncing = false;
            }
        });
    }

    // ─── URLhaus Feed Sync ───────────────────────────────────────────────────

    private int syncUrlhausFeed() {
        int added = 0;
        HttpURLConnection conn = null;
        try {
            URL url = new URL("https://urlhaus-api.abuse.ch/v1/urls/recent/");
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(10000);

            String key = PreferenceManager.getDefaultSharedPreferences(mContext)
                    .getString(URLhausProvider.PREF_URLHAUS_KEY, "").trim();
            if (!key.isEmpty()) {
                conn.setRequestProperty("Auth-Key", key);
            }

            if (conn.getResponseCode() != 200) {
                Log.w(TAG, "URLhaus recent feed HTTP " + conn.getResponseCode());
                return 0;
            }

            StringBuilder sb = new StringBuilder();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line);
                }
            }

            JSONObject root = new JSONObject(sb.toString());
            if (!"ok".equalsIgnoreCase(root.optString("query_status", ""))) {
                return 0;
            }

            JSONArray urls = root.optJSONArray("urls");
            if (urls == null) return 0;

            SecurityRulesDb rulesDb = SecurityRulesDb.getInstance(mContext);
            TiCacheDb cacheDb = TiCacheDb.getInstance(mContext);

            int limit = Math.min(urls.length(), 200); // Cap per sync to keep fast
            for (int i = 0; i < limit; i++) {
                JSONObject item = urls.getJSONObject(i);
                String itemUrl = item.optString("url", "");
                String urlStatus = item.optString("url_status", "");
                String threat = item.optString("threat", "Malware URL");
                String host = extractHost(itemUrl);

                if ("online".equalsIgnoreCase(urlStatus) && host != null && !host.isEmpty()) {
                    // Cache in TiCacheDb
                    cacheDb.store(host, "DOMAIN", "URLhaus Feed", true, false, 95, "MALICIOUS", threat, "Active URLhaus malware host", TiCacheDb.DEFAULT_TTL_MS);

                    // Add to SecurityRulesDb
                    if (rulesDb.findBlockRule(host) == null) {
                        rulesDb.blockDomain(host, "URLhaus Feed: " + threat, "URLhaus Feed");
                        added++;
                    }
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "URLhaus feed sync error: " + e.getMessage());
        } finally {
            if (conn != null) {
                try { conn.disconnect(); } catch (Exception ignored) {}
            }
        }
        return added;
    }

    // ─── ThreatFox Feed Sync ──────────────────────────────────────────────────

    private int syncThreatFoxFeed() {
        int added = 0;
        HttpURLConnection conn = null;
        try {
            URL url = new URL("https://threatfox-api.abuse.ch/api/v1/");
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");

            String key = PreferenceManager.getDefaultSharedPreferences(mContext)
                    .getString(ThreatFoxProvider.PREF_THREATFOX_KEY, "").trim();
            if (!key.isEmpty()) {
                conn.setRequestProperty("Auth-Key", key);
            }

            conn.setDoOutput(true);
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(10000);

            JSONObject req = new JSONObject();
            req.put("query", "get_iocs");
            req.put("days", 1);

            byte[] bytes = req.toString().getBytes(StandardCharsets.UTF_8);
            conn.setFixedLengthStreamingMode(bytes.length);
            try (DataOutputStream dos = new DataOutputStream(conn.getOutputStream())) {
                dos.write(bytes);
                dos.flush();
            }

            if (conn.getResponseCode() != 200) {
                Log.w(TAG, "ThreatFox get_iocs HTTP " + conn.getResponseCode());
                return 0;
            }

            StringBuilder sb = new StringBuilder();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line);
                }
            }

            JSONObject root = new JSONObject(sb.toString());
            if (!"ok".equalsIgnoreCase(root.optString("query_status", ""))) {
                return 0;
            }

            JSONArray data = root.optJSONArray("data");
            if (data == null) return 0;

            SecurityRulesDb rulesDb = SecurityRulesDb.getInstance(mContext);
            TiCacheDb cacheDb = TiCacheDb.getInstance(mContext);

            int limit = Math.min(data.length(), 200); // Cap per sync
            for (int i = 0; i < limit; i++) {
                JSONObject ioc = data.getJSONObject(i);
                String iocValue = ioc.optString("ioc_value", "");
                String iocType = ioc.optString("ioc_type", "");
                String malware = ioc.optString("malware_printable", "Botnet / C2");
                int confidence = ioc.optInt("confidence_level", 80);

                if (confidence >= 70 && !iocValue.isEmpty()) {
                    if ("ip:port".equalsIgnoreCase(iocType) || "ip".equalsIgnoreCase(iocType)) {
                        String ip = iocValue.contains(":") ? iocValue.split(":")[0] : iocValue;
                        cacheDb.store(ip, "IP", "ThreatFox Feed", true, false, confidence, "MALICIOUS", malware, "Active ThreatFox C2 server", TiCacheDb.DEFAULT_TTL_MS);
                        if (rulesDb.findBlockRule(ip) == null) {
                            rulesDb.blockIp(ip, "ThreatFox C2: " + malware, "ThreatFox Feed");
                            added++;
                        }
                    } else if ("domain".equalsIgnoreCase(iocType) || "url".equalsIgnoreCase(iocType)) {
                        String host = extractHost(iocValue);
                        if (host != null && !host.isEmpty()) {
                            cacheDb.store(host, "DOMAIN", "ThreatFox Feed", true, false, confidence, "MALICIOUS", malware, "ThreatFox Malicious Domain", TiCacheDb.DEFAULT_TTL_MS);
                            if (rulesDb.findBlockRule(host) == null) {
                                rulesDb.blockDomain(host, "ThreatFox: " + malware, "ThreatFox Feed");
                                added++;
                            }
                            String lowerMalware = malware.toLowerCase();
                            if (lowerMalware.contains("pegasus") || lowerMalware.contains("predator")
                                    || lowerMalware.contains("hermit") || lowerMalware.contains("spyware")
                                    || lowerMalware.contains("c2") || lowerMalware.contains("rat")) {
                                MercenarySpywareDetector.addDynamicMercenaryDomain(host);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "ThreatFox feed sync error: " + e.getMessage());
        } finally {
            if (conn != null) {
                try { conn.disconnect(); } catch (Exception ignored) {}
            }
        }
        return added;
    }

    // ─── MalwareBazaar Feed Sync ─────────────────────────────────────────────

    private int syncMalwareBazaarFeed() {
        int added = 0;
        HttpURLConnection conn = null;
        try {
            URL url = new URL("https://mb-api.abuse.ch/api/v1/");
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");
            conn.setDoOutput(true);
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(10000);

            String postBody = "query=get_recent&selector=time";
            byte[] bytes = postBody.getBytes(StandardCharsets.UTF_8);
            conn.setFixedLengthStreamingMode(bytes.length);
            try (DataOutputStream dos = new DataOutputStream(conn.getOutputStream())) {
                dos.write(bytes);
                dos.flush();
            }

            if (conn.getResponseCode() != 200) {
                Log.w(TAG, "MalwareBazaar get_recent HTTP " + conn.getResponseCode());
                return 0;
            }

            StringBuilder sb = new StringBuilder();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line);
                }
            }

            JSONObject root = new JSONObject(sb.toString());
            if (!"ok".equalsIgnoreCase(root.optString("query_status", ""))) {
                return 0;
            }

            JSONArray data = root.optJSONArray("data");
            if (data == null) return 0;

            TiCacheDb cacheDb = TiCacheDb.getInstance(mContext);
            FileHashDbHelper hashDb = FileHashDbHelper.getInstance(mContext);

            int limit = Math.min(data.length(), 200);
            for (int i = 0; i < limit; i++) {
                JSONObject item = data.getJSONObject(i);
                String sha256 = item.optString("sha256_hash", "").trim().toLowerCase();
                String signature = item.optString("signature", "");
                if (signature.isEmpty() || "null".equalsIgnoreCase(signature)) {
                    signature = "Generic Malware";
                }
                String fileType = item.optString("file_type", "");
                String fileName = item.optString("file_name", "malware_sample");

                if (!sha256.isEmpty()) {
                    cacheDb.store(sha256, "HASH", "MalwareBazaar Feed", true, false, 95, "MALICIOUS", signature, "Active MalwareBazaar: " + fileType + " (" + fileName + ")", TiCacheDb.DEFAULT_TTL_MS);

                    FileHashEntry entry = new FileHashEntry();
                    entry.fileName = fileName;
                    entry.filePath = "";
                    entry.sha256 = sha256;
                    entry.fileSize = item.optLong("file_size", 0);
                    entry.fileClass = fileType.equalsIgnoreCase("apk") ? FileHashEntry.FILE_CLASS_APK : FileHashEntry.FILE_CLASS_SO;
                    entry.scanType = FileHashEntry.SCAN_TYPE_STORAGE;
                    entry.scanPriority = FileHashEntry.PRIORITY_HIGH;
                    entry.scanStatus = FileHashEntry.SCAN_STATUS_DONE;
                    entry.threatStatus = FileHashEntry.THREAT_MALICIOUS;
                    entry.threatDetails = "MalwareBazaar Feed: " + signature + " [" + fileType + "]";
                    entry.fileLastModified = System.currentTimeMillis();
                    hashDb.upsertFileHash(entry);

                    added++;
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "MalwareBazaar feed sync error: " + e.getMessage());
        } finally {
            if (conn != null) {
                try { conn.disconnect(); } catch (Exception ignored) {}
            }
        }
        return added;
    }

    private String extractHost(String raw) {
        if (raw == null) return null;
        String clean = raw.trim();
        if (clean.startsWith("http://") || clean.startsWith("https://")) {
            clean = clean.replaceFirst("^https?://", "");
        }
        int slash = clean.indexOf('/');
        if (slash > 0) {
            clean = clean.substring(0, slash);
        }
        int colon = clean.indexOf(':');
        if (colon > 0) {
            clean = clean.substring(0, colon);
        }
        return clean.trim().toLowerCase();
    }
}
