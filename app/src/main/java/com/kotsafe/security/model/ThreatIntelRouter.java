/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import android.content.Context;

import com.kotsafe.security.Log;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * ThreatIntelRouter — central dispatcher for all threat intelligence queries.
 *
 * Architecture:
 *   1. Check TiCacheDb first (no network call if cached and not expired).
 *   2. Route to all enabled providers in order.
 *   3. Merge results — take the highest risk score across providers.
 *   4. Store merged result in TiCacheDb for future lookups.
 *
 * Adding a new provider: implement ThreatIntelProvider, add to buildProviders().
 * No other code changes needed.
 *
 * Query methods:
 *   ThreatIntelRouter.queryHash(sha256)
 *   ThreatIntelRouter.queryIp(ip)
 *   ThreatIntelRouter.queryDomain(domain)
 *   ThreatIntelRouter.queryUrl(url)
 */
public class ThreatIntelRouter {
    private static final String TAG = "ThreatIntelRouter";

    private static ThreatIntelRouter sInstance;

    private final Context mContext;
    private final TiCacheDb mCache;
    private final List<ThreatIntelProvider> mProviders;

    public static synchronized ThreatIntelRouter getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new ThreatIntelRouter(context.getApplicationContext());
        }
        return sInstance;
    }

    private ThreatIntelRouter(Context context) {
        mContext = context;
        mCache = TiCacheDb.getInstance(context);
        mProviders = new CopyOnWriteArrayList<>(buildProviders());
    }

    /** Builds the ordered list of providers. Edit here to add future providers. */
    private List<ThreatIntelProvider> buildProviders() {
        List<ThreatIntelProvider> list = new ArrayList<>();
        list.add(new ThreatFoxProvider(mContext));
        list.add(new URLhausProvider(mContext));
        list.add(new MalwareBazaarProvider(mContext));
        list.add(new OTXProvider(mContext));
        list.add(new VirusTotalProvider(mContext));
        return list;
    }

    /** Force re-evaluation of which providers are available (e.g. after API key change). */
    public void refresh() {
        mProviders.clear();
        mProviders.addAll(buildProviders());
    }

    public boolean hasAnyProvider() {
        for (ThreatIntelProvider p : mProviders) {
            if (p.isAvailable()) return true;
        }
        return false;
    }

    // ─── Public query API ─────────────────────────────────────────────────────

    public ThreatIntelProvider.ThreatReport queryHash(String sha256) {
        if (sha256 == null || sha256.isEmpty()) return null;
        return route(sha256, "HASH", p -> p.queryHash(sha256));
    }

    public ThreatIntelProvider.ThreatReport queryIp(String ip) {
        if (ip == null || ip.isEmpty()) return null;
        return route(ip, "IP", p -> p.queryIp(ip));
    }

    public ThreatIntelProvider.ThreatReport queryDomain(String domain) {
        if (domain == null || domain.isEmpty()) return null;
        // Normalize: strip scheme if accidentally included
        domain = domain.replaceFirst("^https?://", "").split("/")[0].trim().toLowerCase();
        String normalizedDomain = domain;
        return route(normalizedDomain, "DOMAIN", p -> p.queryDomain(normalizedDomain));
    }

    public ThreatIntelProvider.ThreatReport queryUrl(String url) {
        if (url == null || url.isEmpty()) return null;
        return route(url, "URL", p -> p.queryUrl(url));
    }

    // ─── Internal routing ─────────────────────────────────────────────────────

    private interface ProviderQuery {
        ThreatIntelProvider.ThreatReport query(ThreatIntelProvider provider);
    }

    private ThreatIntelProvider.ThreatReport route(String iocValue, String iocType,
                                                    ProviderQuery queryFn) {
        // Step 1: Cache hit?
        TiCacheDb.CacheEntry cached = mCache.lookup(iocValue);
        if (cached != null) {
            Log.d(TAG, "Cache hit for " + iocValue + " [" + cached.provider + "]");
            return cacheEntryToReport(cached);
        }

        // Step 2: Query all enabled providers
        ThreatIntelProvider.ThreatReport merged = null;
        int queriedCount = 0;

        for (ThreatIntelProvider provider : mProviders) {
            if (!provider.isAvailable()) continue;
            try {
                ThreatIntelProvider.ThreatReport result = queryFn.query(provider);
                if (result == null) continue;

                queriedCount++;
                Log.d(TAG, provider.getProviderCode() + " → " + iocValue +
                        " riskScore=" + result.riskScore + " verdict=" + result.verdict);

                merged = merge(merged, result);

                // Short-circuit: if already confirmed malicious by one provider, stop querying
                if (merged.isMalicious && merged.riskScore >= 90) {
                    Log.d(TAG, "High-confidence malicious, stopping provider chain");
                    break;
                }
            } catch (Exception e) {
                Log.e(TAG, "Provider " + provider.getProviderCode() + " error: " + e.getMessage());
            }
        }

        if (merged == null) {
            // No providers available or all failed
            ThreatIntelProvider.ThreatReport unknown = new ThreatIntelProvider.ThreatReport();
            unknown.iocValue = iocValue;
            unknown.iocType = iocType;
            unknown.verdict = "UNKNOWN";
            unknown.provider = "NONE";
            return unknown;
        }

        // Step 3: Cache merged result
        mCache.store(
                iocValue, iocType,
                merged.provider,
                merged.isMalicious, merged.isSuspicious,
                merged.riskScore, merged.verdict,
                merged.malwareFamily, merged.details,
                TiCacheDb.DEFAULT_TTL_MS
        );

        return merged;
    }

    /**
     * Merge two ThreatReports — keep the highest risk score and most severe verdict.
     * Provider name becomes a comma-separated list of contributors.
     */
    private ThreatIntelProvider.ThreatReport merge(ThreatIntelProvider.ThreatReport existing,
                                                    ThreatIntelProvider.ThreatReport incoming) {
        if (existing == null) return incoming;
        if (incoming == null) return existing;

        ThreatIntelProvider.ThreatReport merged = new ThreatIntelProvider.ThreatReport();
        merged.iocValue = existing.iocValue;
        merged.iocType = existing.iocType;

        // Take highest risk score
        if (incoming.riskScore > existing.riskScore) {
            merged.riskScore = incoming.riskScore;
            merged.malwareFamily = incoming.malwareFamily != null ? incoming.malwareFamily : existing.malwareFamily;
            merged.details = incoming.details;
        } else {
            merged.riskScore = existing.riskScore;
            merged.malwareFamily = existing.malwareFamily != null ? existing.malwareFamily : incoming.malwareFamily;
            merged.details = existing.details;
        }

        merged.isMalicious = existing.isMalicious || incoming.isMalicious;
        merged.isSuspicious = existing.isSuspicious || incoming.isSuspicious;
        merged.confidence = Math.max(existing.confidence, incoming.confidence);

        // Combined provider string e.g. "OTX, MalwareBazaar"
        merged.provider = combineProviders(existing.provider, incoming.provider);

        // Final verdict based on merged state
        merged.verdict = merged.isMalicious ? "MALICIOUS"
                : merged.isSuspicious ? "SUSPICIOUS"
                : verdictFromScore(merged.riskScore);

        // Append additional details
        if (incoming.details != null && !incoming.details.equals(existing.details)) {
            if (merged.details != null && !merged.details.isEmpty()) {
                merged.details += " | " + incoming.details;
            } else {
                merged.details = incoming.details;
            }
        }

        return merged;
    }

    private String verdictFromScore(int score) {
        if (score >= 80) return "MALICIOUS";
        if (score >= 60) return "HIGH";
        if (score >= 30) return "SUSPICIOUS";
        return "SAFE";
    }

    private String combineProviders(String a, String b) {
        if (a == null || a.isEmpty()) return b;
        if (b == null || b.isEmpty()) return a;
        if (a.equals(b)) return a;
        return a + ", " + b;
    }

    private ThreatIntelProvider.ThreatReport cacheEntryToReport(TiCacheDb.CacheEntry e) {
        ThreatIntelProvider.ThreatReport r = new ThreatIntelProvider.ThreatReport();
        r.provider = e.provider + " (cached)";
        r.iocValue = e.iocValue;
        r.iocType = e.iocType;
        r.isMalicious = e.isMalicious;
        r.isSuspicious = e.isSuspicious;
        r.riskScore = e.riskScore;
        r.verdict = e.verdict;
        r.malwareFamily = e.malwareFamily;
        r.details = e.details;
        return r;
    }

    /** Returns list of provider names that are currently active. */
    public List<String> getActiveProviderNames() {
        List<String> names = new ArrayList<>();
        for (ThreatIntelProvider p : mProviders) {
            if (p.isAvailable()) names.add(p.getProviderName());
        }
        return names;
    }
}
