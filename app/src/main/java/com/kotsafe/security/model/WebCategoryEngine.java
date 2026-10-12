/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 *
 * WebCategoryEngine — Phase 4 Web Category Policy Engine
 *
 * Classifies traffic into policy categories modelled after Sophos Web Intelligence:
 *   ADULT, GAMBLING, SOCIAL, ADS_TRACKERS, MALWARE_C2, PHISHING, CRYPTO, GAMING,
 *   NEWS, SHOPPING, PRODUCTIVITY, STREAMING, CLOUD_STORAGE, VPN_PROXY, UNKNOWN
 *
 * Per-category ALLOW / WARN / BLOCK policy is persisted in SharedPreferences.
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.preference.PreferenceManager;

import com.kotsafe.security.Log;

import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

public class WebCategoryEngine {

    private static final String TAG = "WebCategoryEngine";

    // ── Category Enum ─────────────────────────────────────────────────────────

    public enum Category {
        ADULT("Adult Content",       80),
        GAMBLING("Gambling",         70),
        SOCIAL("Social Media",       20),
        ADS_TRACKERS("Ads & Trackers", 15),
        MALWARE_C2("Malware / C2",  100),
        PHISHING("Phishing",         95),
        CRYPTO("Crypto / Mining",    60),
        GAMING("Gaming",             10),
        NEWS("News & Media",          0),
        SHOPPING("Shopping",          0),
        PRODUCTIVITY("Productivity", 0),
        STREAMING("Streaming",       10),
        CLOUD_STORAGE("Cloud",        5),
        VPN_PROXY("VPN / Proxy",     50),
        UNKNOWN("Uncategorized",      0);

        public final String label;
        /** Default risk contribution (0-100) when traffic from this category is seen. */
        public final int defaultRisk;
        Category(String label, int defaultRisk) {
            this.label = label;
            this.defaultRisk = defaultRisk;
        }
    }

    // ── Policy Actions ────────────────────────────────────────────────────────

    public enum PolicyAction { ALLOW, WARN, BLOCK }

    // ── Classification Result ─────────────────────────────────────────────────

    public static class ClassificationResult {
        public final Category     category;
        public final PolicyAction action;
        public final int          riskBoost;
        public final String       reason;

        public ClassificationResult(Category category, PolicyAction action, int riskBoost, String reason) {
            this.category  = category;
            this.action    = action;
            this.riskBoost = riskBoost;
            this.reason    = reason;
        }

        public boolean isBlocked() { return action == PolicyAction.BLOCK; }
        public boolean isWarned()  { return action == PolicyAction.WARN;  }
    }

    // ── Singleton ─────────────────────────────────────────────────────────────

    private static volatile WebCategoryEngine sInstance;

    public static WebCategoryEngine getInstance(Context context) {
        if (sInstance == null) {
            synchronized (WebCategoryEngine.class) {
                if (sInstance == null) {
                    sInstance = new WebCategoryEngine(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    private final Context mContext;
    private final EnumMap<Category, PolicyAction> mPolicyOverrides = new EnumMap<>(Category.class);

    private WebCategoryEngine(Context ctx) {
        mContext = ctx;
        loadPolicies();
    }

    // ── Domain / URL classifier keyword sets ─────────────────────────────────

    private static final Set<String> ADULT_KEYWORDS = new HashSet<>(Arrays.asList(
            "porn","xxx","sex","adult","nude","nsfw","erotic","hentai",
            "onlyfans","webcam","camgirl","xvideo","xhamster","xnxx",
            "redtube","youporn","pornhub","chaturbate","livejasmin"
    ));

    private static final Set<String> GAMBLING_KEYWORDS = new HashSet<>(Arrays.asList(
            "casino","poker","bet365","betway","1xbet","ladbrokes",
            "bovada","draftkings","fanduel","mgmbet","unibet","sportingbet",
            "jackpot","slots","blackjack","roulette","bingo","lottery"
    ));

    private static final Set<String> SOCIAL_KEYWORDS = new HashSet<>(Arrays.asList(
            "facebook","instagram","twitter","tiktok","snapchat","linkedin",
            "pinterest","reddit","tumblr","discord","telegram","whatsapp",
            "wechat","line.me","vk.com","ok.ru","kik","mewe","mastodon"
    ));

    private static final Set<String> ADS_TRACKER_KEYWORDS = new HashSet<>(Arrays.asList(
            "doubleclick","googlesyndication","googleadservices","adsystem",
            "adserver","adtech","adnxs","criteo","taboola","outbrain",
            "moatads","scorecardresearch","quantserve","bidswitch",
            "openx","rubiconproject","pubmatic","appnexus","tradedesk",
            "amazon-adsystem","adsafeprotected","adskeeper","adform",
            "tracker","analytics","tracking","telemetry","pixel",
            "mixpanel","amplitude","segment.io","adjust.com","appsflyer",
            "branch.io","flurry"
    ));

    private static final Set<String> MALWARE_C2_KEYWORDS = new HashSet<>(Arrays.asList(
            "cobaltrike","cobaltstrike","metasploit-framework","meterpreter","mimikatz"
    ));

    private static final Set<String> PHISHING_KEYWORDS = new HashSet<>(Arrays.asList(
            "paypal-security-update","credential-harvest","account-steal","login-credential-phish"
    ));

    private static final Set<String> CRYPTO_KEYWORDS = new HashSet<>(Arrays.asList(
            "cryptomining","minerpool","nanopool","ethermine","f2pool",
            "2miners","poolin","antpool","nicehash","miningrigrentals",
            "stratum","monero","bitcoin","ethereum","dogecoin","coinhive",
            "jsecoin","cryptoloot","authedmine","minergate"
    ));

    private static final Set<String> GAMING_KEYWORDS = new HashSet<>(Arrays.asList(
            "steam","epicgames","roblox","minecraft","battlenet","ea.com",
            "ubisoft","origin","gog.com","twitch","xbox","playstation",
            "nintendo","itch.io","kongregate","pogo.com","addictinggames"
    ));

    private static final Set<String> STREAMING_KEYWORDS = new HashSet<>(Arrays.asList(
            "netflix","youtube","spotify","hulu","disneyplus","primevideo",
            "hbomax","peacocktv","paramountplus","appletv","vimeo",
            "dailymotion","crunchyroll","funimation","sling","fubo",
            "deezer","tidal","soundcloud","pandora","iheartradio"
    ));

    private static final Set<String> VPN_PROXY_KEYWORDS = new HashSet<>(Arrays.asList(
            "nordvpn","expressvpn","surfshark","protonvpn","mullvad",
            "cyberghost","hidemyass","hide.me","torguard","ipvanish",
            "windscribe","tunnelbear","hotspotshield","zenmate",
            "proxy","socks5","tor2web","i2p","anonymizer","hidemy",
            "proxybay","unblocker","bypass","circumvent"
    ));

    private static final Set<String> PRODUCTIVITY_KEYWORDS = new HashSet<>(Arrays.asList(
            "office","gsuite","google.com","microsoft.com","slack",
            "notion","trello","jira","confluence","asana","dropbox",
            "box.com","zoom","webex","teams.microsoft","meet.google",
            "github","gitlab","bitbucket","stackoverflow"
    ));

    private static final Set<String> CLOUD_STORAGE_KEYWORDS = new HashSet<>(Arrays.asList(
            "drive.google","onedrive","icloud","dropbox","mega.nz",
            "mediafire","wetransfer","filestack","cloudinary","backblaze",
            "wasabi","storj","gdrive","box.net"
    ));

    // ── Core Classification ───────────────────────────────────────────────────

    /**
     * Classify a domain (and optional URL path) into a {@link Category} and apply the current policy.
     *
     * @param domain lower-cased hostname
     * @param url    optional full URL for path-level pattern matching
     * @return ClassificationResult, never null
     */
    public ClassificationResult classify(String domain, String url) {
        if (domain == null || domain.isEmpty()) return result(Category.UNKNOWN);

        final String d = domain.toLowerCase().trim();
        final String u = url != null ? url.toLowerCase() : "";

        // Known official or trusted infrastructure is never malicious
        if (SecurityBlocklistManager.isOfficialDomain(d) || SecurityBlocklistManager.isTrustedAdOrAnalyticsDomain(d)) {
            return result(Category.PRODUCTIVITY);
        }

        // Priority 1: Explicit C2 keywords
        if (containsAny(d, MALWARE_C2_KEYWORDS)) {
            return result(Category.MALWARE_C2);
        }

        // Priority 2: Phishing
        if (containsAny(d, PHISHING_KEYWORDS)) {
            return result(Category.PHISHING);
        }

        // Priority 3: VPN / Proxy
        if (containsAny(d, VPN_PROXY_KEYWORDS)) {
            return result(Category.VPN_PROXY);
        }

        // Priority 4: Adult
        if (containsAny(d, ADULT_KEYWORDS)) {
            return result(Category.ADULT);
        }

        // Priority 5: Gambling
        if (containsAny(d, GAMBLING_KEYWORDS)) {
            return result(Category.GAMBLING);
        }

        // Priority 6: Crypto mining
        if (containsAny(d, CRYPTO_KEYWORDS) || containsAny(u, CRYPTO_KEYWORDS)) {
            return result(Category.CRYPTO);
        }

        // Priority 7: Ads & Trackers
        if (containsAny(d, ADS_TRACKER_KEYWORDS)) {
            return result(Category.ADS_TRACKERS);
        }

        // Priority 8: Social
        if (containsAny(d, SOCIAL_KEYWORDS)) {
            return result(Category.SOCIAL);
        }

        // Priority 9: Streaming
        if (containsAny(d, STREAMING_KEYWORDS)) {
            return result(Category.STREAMING);
        }

        // Priority 10: Gaming
        if (containsAny(d, GAMING_KEYWORDS)) {
            return result(Category.GAMING);
        }

        // Priority 11: Cloud Storage
        if (containsAny(d, CLOUD_STORAGE_KEYWORDS)) {
            return result(Category.CLOUD_STORAGE);
        }

        // Priority 12: Productivity
        if (containsAny(d, PRODUCTIVITY_KEYWORDS)) {
            return result(Category.PRODUCTIVITY);
        }

        return result(Category.UNKNOWN);
    }

    // ── Policy Management ─────────────────────────────────────────────────────

    public void setPolicy(Category category, PolicyAction action) {
        mPolicyOverrides.put(category, action);
        savePolicies();
        Log.i(TAG, "Web policy set: " + category.name() + " => " + action.name());
    }

    public PolicyAction getPolicy(Category category) {
        PolicyAction override = mPolicyOverrides.get(category);
        return override != null ? override : defaultPolicy(category);
    }

    private static PolicyAction defaultPolicy(Category c) {
        // Do not block any site if they are not confirmed malicious.
        // Default policy is WARN for sensitive categories and ALLOW for standard categories.
        switch (c) {
            case MALWARE_C2:
            case PHISHING:
            case ADULT:
            case GAMBLING:
            case CRYPTO:
            case VPN_PROXY:
                return PolicyAction.WARN;
            default:
                return PolicyAction.ALLOW;
        }
    }

    /** Return an unmodifiable snapshot of all effective policies (for UI). */
    public Map<Category, PolicyAction> getAllPolicies() {
        EnumMap<Category, PolicyAction> result = new EnumMap<>(Category.class);
        for (Category c : Category.values()) result.put(c, getPolicy(c));
        return Collections.unmodifiableMap(result);
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    private static final String PREF_PREFIX = "web_cat_policy_";

    private void savePolicies() {
        SharedPreferences.Editor ed = PreferenceManager.getDefaultSharedPreferences(mContext).edit();
        for (Map.Entry<Category, PolicyAction> e : mPolicyOverrides.entrySet()) {
            ed.putString(PREF_PREFIX + e.getKey().name(), e.getValue().name());
        }
        ed.apply();
    }

    private void loadPolicies() {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(mContext);
        for (Category c : Category.values()) {
            String val = prefs.getString(PREF_PREFIX + c.name(), null);
            if (val != null) {
                try { mPolicyOverrides.put(c, PolicyAction.valueOf(val)); }
                catch (IllegalArgumentException ignored) {}
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private ClassificationResult result(Category c) {
        PolicyAction action = getPolicy(c);
        return new ClassificationResult(c, action, c.defaultRisk,
                c.label + " — policy: " + action.name());
    }

    private static boolean containsAny(String haystack, Set<String> needles) {
        if (haystack == null || haystack.isEmpty()) return false;
        for (String needle : needles) {
            if (haystack.contains(needle)) return true;
        }
        return false;
    }
}
