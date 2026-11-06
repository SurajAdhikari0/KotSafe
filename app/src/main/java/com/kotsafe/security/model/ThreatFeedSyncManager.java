/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.util.Base64;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.BuildConfig;
import com.kotsafe.security.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
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
    public static final String PREF_CLOUD_THREAT_LAST_SYNC_TS = "kotsafe_cloud_threat_last_sync_ts";
    public static final String DEFAULT_CLOUD_DELTA_URL = "https://kotsafe.com/api/v1/threat-intel/delta";

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
                if (callback != null) callback.onProgress("Syncing KotSafe Cloud threat intelligence delta…");
                int cloudDeltaCount = syncKotSafeCloudDelta();
                addedCount += cloudDeltaCount;
                Log.i(TAG, "KotSafe Cloud delta sync added " + cloudDeltaCount + " indicators");

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

    // ─── KotSafe Cloud Threat Delta Sync ────────────────────────────────────

    private int syncKotSafeCloudDelta() throws Exception {
        int added = 0;
        HttpURLConnection conn = null;
        try {
            long lastSyncTs = PreferenceManager.getDefaultSharedPreferences(mContext)
                    .getLong(PREF_CLOUD_THREAT_LAST_SYNC_TS, 0L);

            String cursor = null;
            long serverWatermark = 0L;
            int pages = 0;
            do {
            if (++pages > 10000) throw new java.io.IOException("Threat-feed page limit exceeded; watermark retained.");
            String requestUrl = DEFAULT_CLOUD_DELTA_URL;
            if (cursor != null) requestUrl += "?cursor=" + java.net.URLEncoder.encode(cursor, "UTF-8");
            else if (lastSyncTs > 0) requestUrl += "?since=" + (lastSyncTs / 1000L);

            URL url = new URL(requestUrl);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(10000);
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("User-Agent", "KotSafe-Android/" + BuildConfig.VERSION_NAME);

            int responseCode = conn.getResponseCode();
            if (responseCode == 304) {
                Log.i(TAG, "KotSafe Cloud threat delta: 304 Not Modified (up to date)");
                return 0;
            }
            if (responseCode != 200) {
                throw new java.io.IOException("KotSafe Cloud threat delta HTTP " + responseCode);
            }

            StringBuilder sb = new StringBuilder();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line);
                }
            }

            JSONObject root = new JSONObject(sb.toString());
            if (!"success".equalsIgnoreCase(root.optString("status", ""))) throw new java.io.IOException("Invalid threat-feed response.");
            root = verifiedCloudPage(root);
            JSONObject delta = root.optJSONObject("delta");
            if (delta == null) throw new java.io.IOException("Missing threat delta.");
            serverWatermark = Long.parseLong(root.getString("version")) * 1000L;

            SecurityBlocklistManager blm = SecurityBlocklistManager.getInstance(mContext);
            TiCacheDb cacheDb = TiCacheDb.getInstance(mContext);
            FileHashDbHelper hashDb = FileHashDbHelper.getInstance(mContext);

            // 1. Process Added Domains
            JSONArray domainsAdded = delta.optJSONArray("domains_added");
            if (domainsAdded != null) {
                for (int i = 0; i < domainsAdded.length(); i++) {
                    JSONObject item = domainsAdded.getJSONObject(i);
                    String domain = item.optString("domain", "").trim().toLowerCase();
                    String threatType = item.optString("threat_type", "malware");
                    String family = item.optString("family", "");
                    int confidence = item.optInt("confidence", 90);

                    if (!domain.isEmpty() && confidence >= 70) {
                        cacheDb.store(domain, "DOMAIN", "KotSafe Cloud", true, false, confidence, "MALICIOUS", threatType, family, TiCacheDb.DEFAULT_TTL_MS);
                        if (!blm.isDomainBlocked(domain)) {
                            blm.blockDomain(domain, "Cloud Sentinel: " + threatType + (family.isEmpty() ? "" : " (" + family + ")"), "KotSafe Cloud");
                            added++;
                        }
                    }
                }
            }

            // 2. Process Removed Domains (False-Positive Unblocking)
            JSONArray domainsRemoved = delta.optJSONArray("domains_removed");
            if (domainsRemoved != null) {
                for (int i = 0; i < domainsRemoved.length(); i++) {
                    String domain = domainsRemoved.getString(i).trim().toLowerCase();
                    if (!domain.isEmpty()) {
                        blm.removeCloudIndicator(domain);
                        cacheDb.removeProviderValue(domain, "KotSafe Cloud");
                    }
                }
            }

            // 3. Process Added IPs
            JSONArray ipsAdded = delta.optJSONArray("ips_added");
            if (ipsAdded != null) {
                for (int i = 0; i < ipsAdded.length(); i++) {
                    JSONObject item = ipsAdded.getJSONObject(i);
                    String ip = item.optString("ip", "").trim();
                    String threatType = item.optString("threat_type", "c2_botnet");
                    int confidence = item.optInt("confidence", 90);

                    if (!ip.isEmpty() && confidence >= 70) {
                        cacheDb.store(ip, "IP", "KotSafe Cloud", true, false, confidence, "MALICIOUS", threatType, "Active C2 Node", TiCacheDb.DEFAULT_TTL_MS);
                        if (!blm.isBlocked(ip)) blm.blockIp(ip, "Cloud Sentinel C2: " + threatType, "KotSafe Cloud");
                        added++;
                    }
                }
            }

            // 4. Process Added Hashes (SHA-256)
            JSONArray hashesAdded = delta.optJSONArray("hashes_added");
            if (hashesAdded != null) {
                for (int i = 0; i < hashesAdded.length(); i++) {
                    JSONObject item = hashesAdded.getJSONObject(i);
                    String sha256 = item.optString("sha256", "").trim().toLowerCase();
                    String threatType = item.optString("threat_type", "banking_trojan");
                    String family = item.optString("family", "Malware Signature");
                    int confidence = item.optInt("confidence", 99);

                    if (sha256.matches("[a-f0-9]{64}") && confidence >= 70) {
                        cacheDb.store(sha256, "HASH", "KotSafe Cloud", true, false, confidence, "MALICIOUS", threatType, family, TiCacheDb.DEFAULT_TTL_MS);

                        FileHashEntry entry = new FileHashEntry();
                        entry.fileName = family + ".apk";
                        entry.filePath = "";
                        entry.sha256 = sha256;
                        entry.fileClass = FileHashEntry.FILE_CLASS_APK;
                        entry.scanType = FileHashEntry.SCAN_TYPE_DOWNLOAD;
                        entry.scanPriority = FileHashEntry.PRIORITY_HIGH;
                        entry.scanStatus = FileHashEntry.SCAN_STATUS_DONE;
                        entry.threatStatus = FileHashEntry.THREAT_MALICIOUS;
                        entry.threatDetails = "KotSafe Cloud: " + threatType + " (" + family + ")";
                        entry.fileLastModified = System.currentTimeMillis();
                        hashDb.upsertFileHash(entry);
                        added++;
                    }
                }
            }

            for (String key : new String[]{"ips_removed", "hashes_removed"}) {
                JSONArray removed = delta.optJSONArray(key);
                if (removed == null) continue;
                for (int i=0; i<removed.length(); i++) {
                    String value=removed.getString(i).trim().toLowerCase();
                    cacheDb.removeProviderValue(value, "KotSafe Cloud");
                    if ("ips_removed".equals(key)) blm.removeCloudIndicator(value);
                    else hashDb.removeCloudHash(value);
                }
            }
            cursor = root.isNull("next_cursor") ? null : root.optString("next_cursor", null);
            if (root.optBoolean("has_more", false) && (cursor == null || cursor.isEmpty())) throw new java.io.IOException("Threat-feed continuation is missing.");
            if (conn != null) { conn.disconnect(); conn = null; }
            } while (cursor != null && !cursor.isEmpty());
            // Only a fully applied server snapshot advances the watermark.
            SecurityBlocklistManager.getInstance(mContext).syncWithCaptureService();

            // Update last sync timestamp
            PreferenceManager.getDefaultSharedPreferences(mContext).edit()
                    .putLong(PREF_CLOUD_THREAT_LAST_SYNC_TS, serverWatermark)
                    .apply();

        } catch (Exception e) {
            Log.w(TAG, "KotSafe Cloud delta sync error: " + e.getMessage());
            throw e;
        } finally {
            if (conn != null) {
                try { conn.disconnect(); } catch (Exception ignored) {}
            }
        }
        return added;
    }

    /**
     * The transport is HTTPS, but the feed is also signed so a compromised relay or
     * TLS endpoint cannot silently insert block rules. The public key is pinned in
     * the release build; never accept a public key supplied by the response itself.
     */
    private static JSONObject verifiedCloudPage(JSONObject response) throws Exception {
        String pinned = BuildConfig.THREAT_FEED_PUBLIC_KEY == null ? "" : BuildConfig.THREAT_FEED_PUBLIC_KEY.trim();
        String payload = response.optString("signed_payload", "");
        String signature = response.optString("signature", "");
        if (pinned.isEmpty() || payload.isEmpty() || signature.isEmpty()) {
            throw new java.io.IOException("Signed cloud threat feed is not configured.");
        }
        byte[] key = Base64.decode(pinned, Base64.DEFAULT);
        if (key.length == 32) {
            byte[] wrapped = new byte[44];
            byte[] prefix = new byte[]{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};
            System.arraycopy(prefix, 0, wrapped, 0, prefix.length);
            System.arraycopy(key, 0, wrapped, prefix.length, key.length);
            key = wrapped;
        }
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(key)));
        verifier.update(("kotsafe-threat-delta-v1:" + payload).getBytes(StandardCharsets.UTF_8));
        if (!verifier.verify(Base64.decode(signature, Base64.DEFAULT))) {
            throw new java.io.IOException("Cloud threat-feed signature verification failed.");
        }
        JSONObject verified = new JSONObject(payload);
        if (!"success".equalsIgnoreCase(verified.optString("status", "")) || verified.optJSONObject("delta") == null) {
            throw new java.io.IOException("Signed cloud threat-feed payload is invalid.");
        }
        return verified;
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
