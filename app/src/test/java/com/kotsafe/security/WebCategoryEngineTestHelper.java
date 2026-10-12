/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 *
 * Test helper: context-free wrapper around WebCategoryEngine's classification
 * that uses default policies (no SharedPreferences / Android APIs needed).
 */

package com.kotsafe.security;

import com.kotsafe.security.model.WebCategoryEngine;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Mirror of {@link WebCategoryEngine}'s pure classification logic, extracted
 * for JVM-only unit testing (no Android context required).
 */
public class WebCategoryEngineTestHelper {

    // ── Keyword sets mirrored from WebCategoryEngine ─────────────────────────

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
            "cobaltrike","cobaltstrike","metasploit","empire","sliver",
            "havoc","meterpreter","beacon","backdoor","botnet","zombie",
            "dropper","keylog","exfil","rootkit","cryptominer","xmrig"
    ));
    private static final Set<String> PHISHING_KEYWORDS = new HashSet<>(Arrays.asList(
            "login-verify","account-verify","secure-login","signin-verify",
            "update-account","confirm-email","bank-verify","paypal-secure",
            "appleid-verify","microsoft-login","google-signin","facebook-login",
            "amazon-verify","netflix-confirm","phish","credential-harvest"
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

    private static final Pattern SUSPICIOUS_TLD_PATTERN =
            Pattern.compile("\\.(tk|ml|ga|cf|gq)$");

    // DGA-like: random-looking long label with no vowel sequences typical of English words.
    // Only the most egregious patterns — 16+ char random-looking single-label .com/.net/.org
    // are excluded since they are legitimate.
    private static final Pattern DGA_PATTERN =
            Pattern.compile("^[a-z0-9]{18,}\\.[a-z]{2,4}$");

    // ── Classification ────────────────────────────────────────────────────────

    public static WebCategoryEngine.ClassificationResult classify(String domain, String url) {
        if (domain == null || domain.isEmpty())
            return result(WebCategoryEngine.Category.UNKNOWN);

        final String d = domain.toLowerCase().trim();
        final String u = url != null ? url.toLowerCase() : "";

        // Priority 1: Explicit C2 keyword match
        if (containsAny(d, MALWARE_C2_KEYWORDS) || containsAny(u, MALWARE_C2_KEYWORDS))
            return result(WebCategoryEngine.Category.MALWARE_C2);

        // Priority 2: Phishing
        if (containsAny(d, PHISHING_KEYWORDS) || containsAny(u, PHISHING_KEYWORDS))
            return result(WebCategoryEngine.Category.PHISHING);

        // Priority 3: VPN / Proxy
        if (containsAny(d, VPN_PROXY_KEYWORDS))
            return result(WebCategoryEngine.Category.VPN_PROXY);

        // Priority 4: Adult
        if (containsAny(d, ADULT_KEYWORDS) || containsAny(u, ADULT_KEYWORDS))
            return result(WebCategoryEngine.Category.ADULT);

        // Priority 5: Gambling
        if (containsAny(d, GAMBLING_KEYWORDS))
            return result(WebCategoryEngine.Category.GAMBLING);

        // Priority 6: Crypto
        if (containsAny(d, CRYPTO_KEYWORDS) || containsAny(u, CRYPTO_KEYWORDS))
            return result(WebCategoryEngine.Category.CRYPTO);

        // Priority 7: Ads & Trackers
        if (containsAny(d, ADS_TRACKER_KEYWORDS))
            return result(WebCategoryEngine.Category.ADS_TRACKERS);

        // Priority 8: Social
        if (containsAny(d, SOCIAL_KEYWORDS))
            return result(WebCategoryEngine.Category.SOCIAL);

        // Priority 9: Streaming
        if (containsAny(d, STREAMING_KEYWORDS))
            return result(WebCategoryEngine.Category.STREAMING);

        // Priority 10: Gaming
        if (containsAny(d, GAMING_KEYWORDS))
            return result(WebCategoryEngine.Category.GAMING);

        // Priority 11: Cloud Storage
        if (containsAny(d, CLOUD_STORAGE_KEYWORDS))
            return result(WebCategoryEngine.Category.CLOUD_STORAGE);

        // Priority 12: Productivity
        if (containsAny(d, PRODUCTIVITY_KEYWORDS))
            return result(WebCategoryEngine.Category.PRODUCTIVITY);

        // Priority 13 (last): Suspicious TLD and DGA-like patterns
        // Checked LAST so keyword whitelists always win.
        if (SUSPICIOUS_TLD_PATTERN.matcher(d).find() || DGA_PATTERN.matcher(d).find())
            return result(WebCategoryEngine.Category.MALWARE_C2);

        return result(WebCategoryEngine.Category.UNKNOWN);
    }

    private static WebCategoryEngine.ClassificationResult result(WebCategoryEngine.Category c) {
        WebCategoryEngine.PolicyAction action = defaultPolicy(c);
        return new WebCategoryEngine.ClassificationResult(c, action, c.defaultRisk,
                c.label + " — policy: " + action.name());
    }

    private static WebCategoryEngine.PolicyAction defaultPolicy(WebCategoryEngine.Category c) {
        switch (c) {
            case MALWARE_C2:
            case PHISHING:  return WebCategoryEngine.PolicyAction.BLOCK;
            case ADULT:
            case GAMBLING:
            case CRYPTO:
            case VPN_PROXY: return WebCategoryEngine.PolicyAction.WARN;
            default:        return WebCategoryEngine.PolicyAction.ALLOW;
        }
    }

    private static boolean containsAny(String haystack, Set<String> needles) {
        if (haystack == null || haystack.isEmpty()) return false;
        for (String n : needles) if (haystack.contains(n)) return true;
        return false;
    }
}
