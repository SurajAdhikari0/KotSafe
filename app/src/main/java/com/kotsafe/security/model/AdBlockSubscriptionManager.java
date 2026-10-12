/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.Log;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Clean-Room Ad & Tracker Subscription Blocklist Manager.
 *
 * Manages remote hosts subscriptions (StevenBlack, OISD, AdAway, Peter Lowe),
 * user custom whitelists/blacklists, and builds an in-memory DomainSuffixTree
 * for sub-millisecond wildcard blocking.
 */
public class AdBlockSubscriptionManager {
    private static final String TAG = "AdBlockSubscription";

    public static final String PREF_ADBLOCK_ENABLED = "pref_adblock_enabled";
    private static final String PREF_SUBSCRIPTION_LISTS = "pref_adblock_subscriptions_json";
    private static final String PREF_USER_WHITELIST = "pref_adblock_user_whitelist";
    private static final String PREF_USER_BLACKLIST = "pref_adblock_user_blacklist";
    private static final String PREF_UPSTREAM_DOH_PROVIDER = "pref_upstream_doh_provider";

    public static class SubscriptionFeed {
        public String id;
        public String name;
        public String url;
        public boolean isEnabled;
        public String etag;
        public String lastModified;
        public int ruleCount;
        public long lastUpdatedMs;

        public SubscriptionFeed() {}

        public SubscriptionFeed(String id, String name, String url, boolean isEnabled) {
            this.id = id;
            this.name = name;
            this.url = url;
            this.isEnabled = isEnabled;
        }
    }

    public interface SyncListener {
        void onSyncProgress(String feedName, int current, int total);
        void onSyncComplete(int totalRulesLoaded);
    }

    private static AdBlockSubscriptionManager sInstance;
    private final Context mContext;
    private final SharedPreferences mPrefs;
    private final ExecutorService mExecutor = Executors.newSingleThreadExecutor();
    private final DomainSuffixTree mCompiledTree = new DomainSuffixTree();
    private final Set<String> mUserWhitelist = new HashSet<>();
    private final Set<String> mUserBlacklist = new HashSet<>();
    private final Set<String> mSeedDomains = new HashSet<>();
    private List<SubscriptionFeed> mFeeds = new ArrayList<>();
    private boolean mIsInitialized = false;

    public static synchronized AdBlockSubscriptionManager getInstance(@NonNull Context context) {
        if (sInstance == null) {
            sInstance = new AdBlockSubscriptionManager(context.getApplicationContext());
        }
        return sInstance;
    }

    private AdBlockSubscriptionManager(Context context) {
        mContext = context;
        mPrefs = PreferenceManager.getDefaultSharedPreferences(context);
        loadFeeds();
        loadUserLists();
        mExecutor.execute(() -> {
            rebuildTreeFromDisk();
            // Automatically trigger background feed sync if no feeds exist on disk yet
            boolean hasDownloadedFeeds = false;
            for (SubscriptionFeed feed : mFeeds) {
                File f = new File(getFeedFilePath(feed.id));
                if (f.exists() && f.length() > 0) {
                    hasDownloadedFeeds = true;
                    break;
                }
            }
            if (!hasDownloadedFeeds) {
                Log.i(TAG, "AdBlock feeds missing on disk. Starting automatic background initial sync.");
                syncAllFeeds(null);
            }
        });
    }

    public boolean isAdBlockEnabled() {
        return mPrefs.getBoolean(PREF_ADBLOCK_ENABLED, true);
    }

    public void setAdBlockEnabled(boolean enabled) {
        mPrefs.edit().putBoolean(PREF_ADBLOCK_ENABLED, enabled).apply();
    }

    public synchronized List<SubscriptionFeed> getFeeds() {
        return new ArrayList<>(mFeeds);
    }

    private void loadFeeds() {
        String json = mPrefs.getString(PREF_SUBSCRIPTION_LISTS, null);
        if (json != null && !json.isEmpty()) {
            try {
                mFeeds = new Gson().fromJson(json, new TypeToken<List<SubscriptionFeed>>(){}.getType());
            } catch (Exception e) {
                Log.w(TAG, "Error parsing feeds JSON: " + e.getMessage());
            }
        }

        if (mFeeds == null || mFeeds.isEmpty()) {
            mFeeds = buildDefaultFeeds();
            saveFeeds();
        }
    }

    private List<SubscriptionFeed> buildDefaultFeeds() {
        List<SubscriptionFeed> defaults = new ArrayList<>();
        defaults.add(new SubscriptionFeed(
                "stevenblack_unified",
                "StevenBlack Unified (Ads + Malware)",
                "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
                true
        ));
        defaults.add(new SubscriptionFeed(
                "oisd_basic",
                "OISD Basic / Light (Fast Privacy)",
                "https://small.oisd.nl",
                true
        ));
        defaults.add(new SubscriptionFeed(
                "adaway_community",
                "AdAway Community Default Hosts",
                "https://adaway.org/hosts.txt",
                true
        ));
        defaults.add(new SubscriptionFeed(
                "peter_lowe",
                "Peter Lowe's Ad Server List",
                "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
                false
        ));
        return defaults;
    }

    public synchronized void saveFeeds() {
        mPrefs.edit().putString(PREF_SUBSCRIPTION_LISTS, new Gson().toJson(mFeeds)).apply();
    }

    public synchronized void addCustomFeed(String name, String url) {
        String id = "custom_" + System.currentTimeMillis();
        SubscriptionFeed feed = new SubscriptionFeed(id, name, url, true);
        mFeeds.add(feed);
        saveFeeds();
    }

    public synchronized void toggleFeed(String feedId, boolean enabled) {
        for (SubscriptionFeed f : mFeeds) {
            if (f.id.equals(feedId)) {
                f.isEnabled = enabled;
                break;
            }
        }
        saveFeeds();
        mExecutor.execute(this::rebuildTreeFromDisk);
    }

    public synchronized void removeFeed(String feedId) {
        mFeeds.removeIf(f -> f.id.equals(feedId));
        saveFeeds();
        File f = new File(getFeedFilePath(feedId));
        if (f.exists()) f.delete();
        mExecutor.execute(this::rebuildTreeFromDisk);
    }

    // ── User Whitelist & Blacklist ───────────────────────────────────────────

    private void loadUserLists() {
        Set<String> wl = mPrefs.getStringSet(PREF_USER_WHITELIST, null);
        if (wl != null) mUserWhitelist.addAll(wl);

        Set<String> bl = mPrefs.getStringSet(PREF_USER_BLACKLIST, null);
        if (bl != null) mUserBlacklist.addAll(bl);
    }

    public synchronized Set<String> getUserWhitelist() {
        return new HashSet<>(mUserWhitelist);
    }

    public synchronized Set<String> getUserBlacklist() {
        return new HashSet<>(mUserBlacklist);
    }

    public synchronized void addToWhitelist(String domain) {
        String clean = DomainSuffixTree.cleanDomain(domain);
        if (clean.isEmpty()) return;
        mUserWhitelist.add(clean);
        mUserBlacklist.remove(clean);
        mPrefs.edit().putStringSet(PREF_USER_WHITELIST, mUserWhitelist)
                     .putStringSet(PREF_USER_BLACKLIST, mUserBlacklist).apply();
    }

    public synchronized void removeFromWhitelist(String domain) {
        String clean = DomainSuffixTree.cleanDomain(domain);
        mUserWhitelist.remove(clean);
        mPrefs.edit().putStringSet(PREF_USER_WHITELIST, mUserWhitelist).apply();
    }

    public synchronized void addToBlacklist(String domain) {
        String clean = DomainSuffixTree.cleanDomain(domain);
        if (clean.isEmpty()) return;
        mUserBlacklist.add(clean);
        mUserWhitelist.remove(clean);
        mCompiledTree.addDomain(clean, "User Blacklist");
        mPrefs.edit().putStringSet(PREF_USER_BLACKLIST, mUserBlacklist)
                     .putStringSet(PREF_USER_WHITELIST, mUserWhitelist).apply();
    }

    public synchronized void removeFromBlacklist(String domain) {
        String clean = DomainSuffixTree.cleanDomain(domain);
        mUserBlacklist.remove(clean);
        mPrefs.edit().putStringSet(PREF_USER_BLACKLIST, mUserBlacklist).apply();
        mExecutor.execute(this::rebuildTreeFromDisk);
    }

    public Set<String> getCustomWhitelist() {
        return getUserWhitelist();
    }

    public Set<String> getCustomBlacklist() {
        return getUserBlacklist();
    }

    public synchronized Set<String> getSeedAndCustomHostnames() {
        // Return only explicit user-configured blacklist rules.
        // Never inject bulk subscription feeds directly into the native VPN packet drop list
        // to avoid false-positive blocking of non-malicious websites.
        return new HashSet<>(mUserBlacklist);
    }

    public void addCustomWhitelist(String domain) {
        addToWhitelist(domain);
    }

    public void removeCustomWhitelist(String domain) {
        removeFromWhitelist(domain);
    }

    public void addCustomBlacklist(String domain) {
        addToBlacklist(domain);
    }

    public void removeCustomBlacklist(String domain) {
        removeFromBlacklist(domain);
    }

    public int getTotalRulesCount() {
        return getTotalRulesLoaded();
    }

    public synchronized void setActiveFeedIds(Set<String> activeIds) {
        if (activeIds == null) return;
        for (SubscriptionFeed f : mFeeds) {
            f.isEnabled = activeIds.contains(f.id);
        }
        saveFeeds();
        mExecutor.execute(this::rebuildTreeFromDisk);
    }

    public interface UpdateCallback {
        void onSuccess(int totalRules, int updatedCount);
        void onError(String message);
    }

    public void updateSubscriptions(UpdateCallback callback) {
        syncAllFeeds(new SyncListener() {
            @Override
            public void onSyncProgress(String feedName, int current, int total) {}

            @Override
            public void onSyncComplete(int totalRulesLoaded) {
                if (callback != null) {
                    callback.onSuccess(totalRulesLoaded, totalRulesLoaded);
                }
            }
        });
    }

    public static class CheckResult {
        public final boolean isBlocked;
        public final String ruleOrFeed;

        public CheckResult(boolean isBlocked, String ruleOrFeed) {
            this.isBlocked = isBlocked;
            this.ruleOrFeed = ruleOrFeed;
        }
    }

    public synchronized CheckResult evaluateDomain(@Nullable String domain) {
        String reason = checkDomain(domain);
        return new CheckResult(reason != null, reason);
    }

    // ── Matching / Query Evaluation ──────────────────────────────────────────

    /**
     * Checks if a domain is blocked by user blacklist or any enabled subscription feed,
     * unless explicitly exempted by user whitelist.
     *
     * @param domain Domain to evaluate
     * @return Block reason/source name, or null if allowed.
     */
    @Nullable
    public synchronized String checkDomain(@Nullable String domain) {
        if (!isAdBlockEnabled() || domain == null) return null;
        String clean = DomainSuffixTree.cleanDomain(domain);
        if (clean.isEmpty()) return null;

        // Official system infrastructure (OS, OEM, banking, time) is never blocked
        if (SecurityBlocklistManager.isOfficialDomain(clean)) {
            return null;
        }

        // 1. User Whitelist has absolute priority
        if (isUserWhitelisted(clean)) {
            return null;
        }

        // 2. User Blacklist
        if (isUserBlacklisted(clean)) {
            return "User Custom Blacklist";
        }

        // 3. Subscription Radix Tree
        return mCompiledTree.matches(clean);
    }

    public synchronized boolean isBlocked(@Nullable String domain) {
        return checkDomain(domain) != null;
    }

    private boolean isUserWhitelisted(String cleanDomain) {
        if (mUserWhitelist.contains(cleanDomain)) return true;
        String[] parts = cleanDomain.split("\\.");
        StringBuilder sb = new StringBuilder();
        for (int i = parts.length - 1; i >= 0; i--) {
            if (sb.length() > 0) sb.insert(0, ".");
            sb.insert(0, parts[i]);
            if (mUserWhitelist.contains(sb.toString())) return true;
        }
        return false;
    }

    private boolean isUserBlacklisted(String cleanDomain) {
        if (mUserBlacklist.contains(cleanDomain)) return true;
        String[] parts = cleanDomain.split("\\.");
        StringBuilder sb = new StringBuilder();
        for (int i = parts.length - 1; i >= 0; i--) {
            if (sb.length() > 0) sb.insert(0, ".");
            sb.insert(0, parts[i]);
            if (mUserBlacklist.contains(sb.toString())) return true;
        }
        return false;
    }

    public synchronized int getTotalRulesLoaded() {
        return mCompiledTree.size();
    }

    // ── Sync & Parsing ───────────────────────────────────────────────────────

    private String getFeedFilePath(String feedId) {
        File dir = new File(mContext.getFilesDir(), "adblock_feeds");
        if (!dir.exists()) dir.mkdirs();
        return new File(dir, feedId + ".txt").getAbsolutePath();
    }

    public void syncAllFeeds(@Nullable SyncListener listener) {
        mExecutor.execute(() -> {
            List<SubscriptionFeed> current = getFeeds();
            for (int i = 0; i < current.size(); i++) {
                SubscriptionFeed feed = current.get(i);
                if (!feed.isEnabled) continue;
                if (listener != null) listener.onSyncProgress(feed.name, i + 1, current.size());
                downloadFeed(feed);
            }
            saveFeeds();
            rebuildTreeFromDisk();
            if (listener != null) listener.onSyncComplete(mCompiledTree.size());
        });
    }

    private void downloadFeed(SubscriptionFeed feed) {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(feed.url);
            conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(30000);
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Android; Mobile) KotSafe-DNS-Shield/2.0");

            // Bandwidth saving: ETag & Last-Modified checks
            if (feed.etag != null && !feed.etag.isEmpty()) {
                conn.setRequestProperty("If-None-Match", feed.etag);
            }
            if (feed.lastModified != null && !feed.lastModified.isEmpty()) {
                conn.setRequestProperty("If-Modified-Since", feed.lastModified);
            }

            conn.connect();
            int respCode = conn.getResponseCode();
            if (respCode == HttpURLConnection.HTTP_NOT_MODIFIED) {
                Log.d(TAG, "Feed " + feed.name + " not modified (HTTP 304). Skipping download.");
                feed.lastUpdatedMs = System.currentTimeMillis();
                return;
            }

            if (respCode == HttpURLConnection.HTTP_OK) {
                String newEtag = conn.getHeaderField("ETag");
                String newLastMod = conn.getHeaderField("Last-Modified");

                File target = new File(getFeedFilePath(feed.id));
                try (InputStream in = conn.getInputStream();
                     FileOutputStream out = new FileOutputStream(target)) {
                    byte[] buf = new byte[8192];
                    int len;
                    while ((len = in.read(buf)) != -1) {
                        out.write(buf, 0, len);
                    }
                }

                feed.etag = newEtag != null ? newEtag : "";
                feed.lastModified = newLastMod != null ? newLastMod : "";
                feed.lastUpdatedMs = System.currentTimeMillis();
                Log.i(TAG, "Downloaded fresh blocklist: " + feed.name);
            }
        } catch (Exception e) {
            Log.w(TAG, "Error syncing feed " + feed.name + ": " + e.getMessage());
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    public synchronized void rebuildTreeFromDisk() {
        mCompiledTree.clear();
        mSeedDomains.clear();

        // 1. Load User Blacklist
        for (String bl : mUserBlacklist) {
            mCompiledTree.addDomain(bl, "User Blacklist");
        }

        // 1. Always load bundled high-impact mobile seed rules first
        loadBundledSeedRules();

        // 2. Load Enabled Subscription Feeds from disk
        int feedsLoaded = 0;
        for (SubscriptionFeed feed : mFeeds) {
            if (!feed.isEnabled) continue;
            File f = new File(getFeedFilePath(feed.id));
            if (!f.exists() || f.length() == 0) continue;

            int count = parseHostsFile(f, feed.name);
            feed.ruleCount = count;
            if (count > 0) feedsLoaded++;
        }

        mIsInitialized = true;
        Log.i(TAG, "Compiled DomainSuffixTree with " + mCompiledTree.size() + " domain rules.");
    }

    private void loadBundledSeedRules() {
        try (InputStream in = mContext.getAssets().open("default_adblock_hosts.txt")) {
            int count = parseHostsStream(in, "KotSafe Default Seed Rules");
            Log.i(TAG, "Loaded " + count + " bundled offline seed adblock rules.");
        } catch (Exception e) {
            Log.w(TAG, "No bundled adblock rules found or failed to load: " + e.getMessage());
        }
    }

    private int parseHostsFile(File file, String sourceName) {
        try (InputStream in = new FileInputStream(file)) {
            return parseHostsStream(in, sourceName);
        } catch (Exception e) {
            Log.w(TAG, "Error opening hosts file " + file.getName() + ": " + e.getMessage());
            return 0;
        }
    }

    private int parseHostsStream(InputStream in, String sourceName) {
        int added = 0;
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#") || line.startsWith("!")) continue;

                // Strip inline comments
                int hashIdx = line.indexOf('#');
                if (hashIdx >= 0) line = line.substring(0, hashIdx).trim();
                if (line.isEmpty()) continue;

                // Handle standard hosts format: 0.0.0.0 domain.com OR 127.0.0.1 domain.com
                String[] tokens = line.split("\\s+");
                String domainCandidate = null;

                if (tokens.length >= 2) {
                    String ipPrefix = tokens[0];
                    if (ipPrefix.equals("0.0.0.0") || ipPrefix.equals("127.0.0.1") || ipPrefix.equals("::1")) {
                        domainCandidate = tokens[1];
                    }
                } else if (tokens.length == 1 && !tokens[0].contains("/")) {
                    // Plain domain list line
                    domainCandidate = tokens[0];
                }

                if (domainCandidate != null) {
                    String clean = DomainSuffixTree.cleanDomain(domainCandidate);
                    if (!clean.isEmpty() && !isLocalhostOrSystem(clean)) {
                        mCompiledTree.addDomain(clean, sourceName);
                        if (sourceName.contains("Seed") || mSeedDomains.size() < 500) {
                            mSeedDomains.add(clean);
                        }
                        added++;
                    }
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "Error parsing stream for " + sourceName + ": " + e.getMessage());
        }
        return added;
    }

    private static boolean isLocalhostOrSystem(String domain) {
        return domain.equals("localhost")
                || domain.equals("local")
                || domain.equals("localhost.localdomain")
                || domain.equals("broadcasthost")
                || domain.equals("ip6-localhost")
                || domain.equals("ip6-loopback")
                || domain.equals("0.0.0.0");
    }
}
