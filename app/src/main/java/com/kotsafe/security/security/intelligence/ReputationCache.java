/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * ReputationCache
 * ===============
 * In-memory, high-speed multi-indicator reputation cache:
 * SHA-256 -> Verdict
 * IP      -> Verdict
 * Domain  -> Verdict
 * URL     -> Verdict
 * Cert    -> Verdict
 * Eliminates repetitive external API calls and provides instant synchronous lookups.
 */

package com.kotsafe.security.security.intelligence;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class ReputationCache {
    private static volatile ReputationCache sInstance;

    public static class CachedReputation {
        public final String indicator;
        public final String indicatorType; // HASH, IP, DOMAIN, URL, CERT
        public final String verdict;        // SAFE, SUSPICIOUS, MALICIOUS
        public final int riskScore;         // 0-100
        public final float confidence;      // 0.0 - 1.0
        public final String provider;
        public final String details;
        public final long cachedAt;
        public final long expiresAt;

        public CachedReputation(String indicator, String indicatorType, String verdict, int riskScore,
                                float confidence, String provider, String details, long ttlMs) {
            this.indicator = indicator;
            this.indicatorType = indicatorType;
            this.verdict = verdict;
            this.riskScore = riskScore;
            this.confidence = confidence;
            this.provider = provider;
            this.details = details;
            this.cachedAt = System.currentTimeMillis();
            this.expiresAt = this.cachedAt + ttlMs;
        }

        public boolean isExpired() {
            return System.currentTimeMillis() > expiresAt;
        }
    }

    private final Map<String, CachedReputation> mCache = new ConcurrentHashMap<>();
    private static final long DEFAULT_TTL_MS = TimeUnit.HOURS.toMillis(24);

    public static ReputationCache getInstance() {
        if (sInstance == null) {
            synchronized (ReputationCache.class) {
                if (sInstance == null) {
                    sInstance = new ReputationCache();
                }
            }
        }
        return sInstance;
    }

    private ReputationCache() {}

    private String makeKey(String type, String indicator) {
        return (type != null ? type.toUpperCase() : "UNKNOWN") + ":" + (indicator != null ? indicator.toLowerCase().trim() : "");
    }

    public CachedReputation get(String type, String indicator) {
        if (indicator == null || indicator.isEmpty()) return null;
        String key = makeKey(type, indicator);
        CachedReputation entry = mCache.get(key);
        if (entry != null) {
            if (entry.isExpired()) {
                mCache.remove(key);
                return null;
            }
            return entry;
        }
        return null;
    }

    public void put(String type, String indicator, String verdict, int riskScore, float confidence, String provider, String details) {
        put(type, indicator, verdict, riskScore, confidence, provider, details, DEFAULT_TTL_MS);
    }

    public void put(String type, String indicator, String verdict, int riskScore, float confidence, String provider, String details, long ttlMs) {
        if (indicator == null || indicator.isEmpty()) return;
        String key = makeKey(type, indicator);
        mCache.put(key, new CachedReputation(indicator, type, verdict, riskScore, confidence, provider, details, ttlMs));
    }

    public void clear() {
        mCache.clear();
    }
}
