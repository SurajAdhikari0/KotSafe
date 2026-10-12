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
 *
 * Copyright 2026 KotSafe Cyber Security Project
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.os.Handler;
import android.os.Looper;

import com.kotsafe.security.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Manages Cloud Detection Rules:
 *  - Loads offline bundled rules from assets
 *  - Caches persistent rules in internal storage
 *  - Synchronizes dynamic rule updates from GitHub repository
 *  - Evaluates rules across Apps, Network, and Files
 */
public class DetectionRulesManager {
    private static final String TAG = "DetectionRulesManager";
    public static final String DEFAULT_GITHUB_RULES_URL =
            "https://raw.githubusercontent.com/CyberResercher/android_detection_rules/main/rules/index.json";
    private static final String CACHE_FILE_NAME = "detection_rules_cache.json";

    private static volatile DetectionRulesManager sInstance;
    private final Context mContext;
    private final ExecutorService mExecutor = Executors.newSingleThreadExecutor();
    private final Handler mMainHandler = new Handler(Looper.getMainLooper());
    private final List<DetectionRule> mRules = new ArrayList<>();
    private long mRulesVersion = 1;
    private boolean mLoaded = false;

    public interface SyncCallback {
        void onSuccess(int rulesCount);
        void onError(String errorMessage);
    }

    private DetectionRulesManager(Context context) {
        mContext = context.getApplicationContext();
        loadRules();
    }

    public static synchronized DetectionRulesManager getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new DetectionRulesManager(context);
        }
        return sInstance;
    }

    /**
     * Loads rules from disk cache if present, otherwise from individual rule files in assets/rules/.
     */
    public synchronized void loadRules() {
        mRules.clear();
        String jsonContent = null;

        // 1. Try reading from cache file first
        File cacheFile = new File(mContext.getFilesDir(), CACHE_FILE_NAME);
        if (cacheFile.exists()) {
            try (FileInputStream fis = new FileInputStream(cacheFile);
                 BufferedReader reader = new BufferedReader(new InputStreamReader(fis, StandardCharsets.UTF_8))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append('\n');
                }
                jsonContent = sb.toString();
                Log.i(TAG, "Loaded detection rules from disk cache: " + cacheFile.getAbsolutePath());
            } catch (Exception e) {
                Log.w(TAG, "Failed to read cache file, falling back to bundled assets: " + e.getMessage());
            }
        }

        if (jsonContent != null && !jsonContent.trim().isEmpty()) {
            parseRulesJson(jsonContent);
        }

        // 2. If no cache or empty, load individual rule files from bundled assets/rules/
        if (mRules.isEmpty()) {
            try {
                String[] ruleFiles = mContext.getAssets().list("rules");
                if (ruleFiles != null && ruleFiles.length > 0) {
                    for (String fname : ruleFiles) {
                        if (fname != null && fname.endsWith(".json") && !fname.equalsIgnoreCase("index.json")) {
                            try (InputStream is = mContext.getAssets().open("rules/" + fname);
                                 BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                                StringBuilder sb = new StringBuilder();
                                String line;
                                while ((line = reader.readLine()) != null) {
                                    sb.append(line).append('\n');
                                }
                                JSONObject ruleObj = new JSONObject(sb.toString());
                                DetectionRule rule = DetectionRule.fromJson(ruleObj);
                                if (rule != null && rule.id != null) {
                                    mRules.add(rule);
                                }
                            } catch (Exception re) {
                                Log.w(TAG, "Error parsing rule file rules/" + fname + ": " + re.getMessage());
                            }
                        }
                    }
                    if (!mRules.isEmpty()) {
                        mRulesVersion = 2;
                        Log.i(TAG, "Loaded " + mRules.size() + " individual detection rules from assets/rules/");
                    }
                }
            } catch (Exception e) {
                Log.w(TAG, "Failed to list individual rules from assets/rules/: " + e.getMessage());
            }
        }

        // 3. Fall back to bundled monolithic detection_rules.json if still empty
        if (mRules.isEmpty()) {
            try (InputStream is = mContext.getAssets().open("detection_rules.json");
                 BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append('\n');
                }
                jsonContent = sb.toString();
                parseRulesJson(jsonContent);
            } catch (Exception ignored) {}
        }
        mLoaded = true;
    }

    private synchronized void parseRulesJson(String jsonStr) {
        try {
            JSONObject root = new JSONObject(jsonStr);
            mRulesVersion = root.optLong("version", 1);
            JSONArray rulesArr = root.optJSONArray("rules");
            if (rulesArr != null) {
                for (int i = 0; i < rulesArr.length(); i++) {
                    JSONObject ruleObj = rulesArr.getJSONObject(i);
                    DetectionRule rule = DetectionRule.fromJson(ruleObj);
                    mRules.add(rule);
                }
            }
            Log.i(TAG, "Successfully parsed " + mRules.size() + " detection rules (Version: " + mRulesVersion + ")");
        } catch (Exception e) {
            Log.e(TAG, "Error parsing rules JSON: " + e.getMessage());
        }
    }

    public synchronized List<DetectionRule> getRules() {
        if (!mLoaded) {
            loadRules();
        }
        return Collections.unmodifiableList(new ArrayList<>(mRules));
    }

    public synchronized int getActiveRulesCount() {
        if (!mLoaded) {
            loadRules();
        }
        int count = 0;
        for (DetectionRule r : mRules) {
            if (r.enabled) count++;
        }
        return count;
    }

    public long getRulesVersion() {
        return mRulesVersion;
    }

    /**
     * Checks if automatic synchronization is needed (e.g. on app launch or scan start)
     * and triggers a background sync if detection rules are enabled and older than 6 hours.
     */
    public void checkAndAutoSync() {
        if (!Prefs.isDetectionRulesEnabled(mContext)) {
            return;
        }
        long lastSync = Prefs.getDetectionRulesLastSyncTime(mContext);
        long now = System.currentTimeMillis();
        if (lastSync == 0 || (now - lastSync) > java.util.concurrent.TimeUnit.HOURS.toMillis(6)) {
            Log.i(TAG, "Triggering automatic background detection rules sync...");
            syncRulesFromGitHub(new SyncCallback() {
                @Override
                public void onSuccess(int rulesCount) {
                    Log.i(TAG, "Automatic rules sync complete: " + rulesCount + " active rules");
                }

                @Override
                public void onError(String errorMessage) {
                    Log.w(TAG, "Automatic rules sync deferred: " + errorMessage);
                }
            });
        }
    }

    /**
     * Synchronizes dynamic rules from GitHub repository in the background.
     * Supports both individual rule files listed in index.json and full rule arrays.
     */
    public void syncRulesFromGitHub(SyncCallback callback) {
        mExecutor.execute(() -> {
            String repoUrl = Prefs.getDetectionRulesGithubUrl(mContext);
            if (repoUrl == null || repoUrl.trim().isEmpty()) {
                repoUrl = DEFAULT_GITHUB_RULES_URL;
            }

            try {
                String responseData = downloadHttpString(repoUrl);
                JSONObject rootObj = new JSONObject(responseData);
                long remoteVersion = rootObj.optLong("version", 1);
                JSONArray testRules = rootObj.optJSONArray("rules");
                List<DetectionRule> fetchedRules = new ArrayList<>();
                JSONArray cachedRulesArray = new JSONArray();

                if (testRules != null && testRules.length() > 0) {
                    String baseUrl = repoUrl.contains("/") ? repoUrl.substring(0, repoUrl.lastIndexOf('/') + 1) : "";
                    for (int i = 0; i < testRules.length(); i++) {
                        JSONObject ruleEntry = testRules.getJSONObject(i);
                        // If entry references an individual file and doesn't already contain full detection logic, fetch it
                        if (ruleEntry.has("file") && !ruleEntry.has("logic")) {
                            String filename = ruleEntry.getString("file");
                            String fileUrl = baseUrl + filename;
                            try {
                                String fileContent = downloadHttpString(fileUrl);
                                JSONObject indivRuleObj = new JSONObject(fileContent);
                                DetectionRule dr = DetectionRule.fromJson(indivRuleObj);
                                if (dr != null && dr.id != null) {
                                    fetchedRules.add(dr);
                                    cachedRulesArray.put(indivRuleObj);
                                }
                            } catch (Exception fe) {
                                Log.w(TAG, "Failed to fetch individual rule file " + filename + ": " + fe.getMessage());
                            }
                        } else {
                            // Already complete rule object
                            DetectionRule dr = DetectionRule.fromJson(ruleEntry);
                            if (dr != null && dr.id != null) {
                                fetchedRules.add(dr);
                                cachedRulesArray.put(ruleEntry);
                            }
                        }
                    }
                }

                if (!fetchedRules.isEmpty()) {
                    // Persist to local cache so offline restarts immediately have all rules
                    JSONObject combinedCache = new JSONObject();
                    combinedCache.put("version", remoteVersion);
                    combinedCache.put("rules", cachedRulesArray);
                    File cacheFile = new File(mContext.getFilesDir(), CACHE_FILE_NAME);
                    try (FileOutputStream fos = new FileOutputStream(cacheFile)) {
                        fos.write(combinedCache.toString(2).getBytes(StandardCharsets.UTF_8));
                    }

                    synchronized (this) {
                        mRules.clear();
                        mRules.addAll(fetchedRules);
                        mRulesVersion = remoteVersion;
                    }

                    long now = System.currentTimeMillis();
                    Prefs.setDetectionRulesLastSyncTime(mContext, now);

                    final int finalCount = mRules.size();
                    mMainHandler.post(() -> {
                        if (callback != null) callback.onSuccess(finalCount);
                    });
                    return;
                }

                final String err = "No valid detection rules found in repository response";
                mMainHandler.post(() -> {
                    if (callback != null) callback.onError(err);
                });
            } catch (Exception e) {
                final String err = e.getMessage() != null ? e.getMessage() : "Network error";
                mMainHandler.post(() -> {
                    if (callback != null) callback.onError(err);
                });
            }
        });
    }

    private String downloadHttpString(String urlStr) throws Exception {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        try {
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(15000);
            conn.setRequestProperty("User-Agent", "KotSafe-Antivirus/1.0");
            conn.setRequestProperty("Accept", "application/json");

            int code = conn.getResponseCode();
            if (code == 404) {
                throw new IOException("GitHub 404: Repository is hidden/flagged on GitHub.");
            } else if (code < 200 || code >= 300) {
                throw new IOException("HTTP " + code + " from " + urlStr);
            }

            try (InputStream is = conn.getInputStream();
                 BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append('\n');
                }
                return sb.toString();
            }
        } finally {
            conn.disconnect();
        }
    }

    /**
     * Evaluates active rules against an application.
     */
    public synchronized List<DetectionRule> evaluateApp(PackageInfo pkgInfo, boolean isSideloaded, List<String> permissions) {
        return evaluateApp(pkgInfo, isSideloaded, permissions, null);
    }

    public synchronized List<DetectionRule> evaluateApp(PackageInfo pkgInfo, boolean isSideloaded, List<String> permissions, String sha256) {
        List<DetectionRule> hits = new ArrayList<>();
        if (!Prefs.isDetectionRulesEnabled(mContext)) return hits;

        for (DetectionRule rule : mRules) {
            if (rule.evaluateApp(pkgInfo, isSideloaded, permissions, sha256)) {
                hits.add(rule);
            }
        }
        return hits;
    }

    /**
     * Evaluates active rules against network activity.
     */
    public synchronized List<DetectionRule> evaluateNetwork(String domain, String ip, int port, double dgaEntropy) {
        List<DetectionRule> hits = new ArrayList<>();
        if (!Prefs.isDetectionRulesEnabled(mContext)) return hits;

        for (DetectionRule rule : mRules) {
            if (rule.evaluateNetwork(domain, ip, port, dgaEntropy)) {
                hits.add(rule);
            }
        }
        return hits;
    }

    /**
     * Evaluates active rules against a file.
     */
    public synchronized List<DetectionRule> evaluateFile(String filePath, String fileName, List<String> contentStrings) {
        return evaluateFile(filePath, fileName, contentStrings, null);
    }

    public synchronized List<DetectionRule> evaluateFile(String filePath, String fileName, List<String> contentStrings, String sha256) {
        List<DetectionRule> hits = new ArrayList<>();
        if (!Prefs.isDetectionRulesEnabled(mContext)) return hits;

        for (DetectionRule rule : mRules) {
            if (rule.evaluateFile(filePath, fileName, contentStrings, sha256)) {
                hits.add(rule);
            }
        }
        return hits;
    }
}
