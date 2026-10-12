/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * High-performance, thread-safe Token Bucket Rate Limiter and Flood Guard.
 *
 * Provides granular rate-limiting (per-app, per-IP, or composite keys) inspired by
 * web application firewalls (SafeLine). Throttles request bursts, mitigates mobile DoS,
 * and temporarily auto-quarantines persistent flooders to protect battery and network resources.
 */
public class TokenBucketRateLimiter {

    public static class RateLimitConfig {
        public final double capacity;          // Max burst capacity (tokens)
        public final double refillRatePerSec;  // Tokens replenished per second
        public final int maxViolationsBeforeCooldown; // Violations until auto-quarantine
        public final long cooldownDurationMs;  // Quarantine duration in milliseconds

        public RateLimitConfig(double capacity, double refillRatePerSec) {
            this(capacity, refillRatePerSec, 5, 30_000L);
        }

        public RateLimitConfig(double capacity, double refillRatePerSec,
                               int maxViolationsBeforeCooldown, long cooldownDurationMs) {
            this.capacity = capacity;
            this.refillRatePerSec = refillRatePerSec;
            this.maxViolationsBeforeCooldown = maxViolationsBeforeCooldown;
            this.cooldownDurationMs = cooldownDurationMs;
        }

        /** Standard default: burst of 200, sustains 30.0 req/sec (1800 req/min) for normal apps */
        public static RateLimitConfig defaultConfig() {
            return new RateLimitConfig(200.0, 30.0, 20, 15_000L);
        }

        /** Aggressive flood guard: burst of 50, sustains 5.0 req/sec */
        public static RateLimitConfig strictConfig() {
            return new RateLimitConfig(50.0, 5.0, 10, 30_000L);
        }
    }

    public static class LimitStatus {
        public final boolean allowed;
        public final double remainingTokens;
        public final boolean isQuarantined;
        public final long cooldownRemainingMs;
        public final int violationCount;

        public LimitStatus(boolean allowed, double remainingTokens,
                           boolean isQuarantined, long cooldownRemainingMs, int violationCount) {
            this.allowed = allowed;
            this.remainingTokens = remainingTokens;
            this.isQuarantined = isQuarantined;
            this.cooldownRemainingMs = cooldownRemainingMs;
            this.violationCount = violationCount;
        }
    }

    private static class Bucket {
        private double tokens;
        private long lastRefillMs;
        private int violationCount;
        private long quarantinedUntilMs;
        private final RateLimitConfig config;

        Bucket(RateLimitConfig config, long nowMs) {
            this.config = config;
            this.tokens = config.capacity;
            this.lastRefillMs = nowMs;
            this.violationCount = 0;
            this.quarantinedUntilMs = 0L;
        }

        synchronized LimitStatus tryConsume(double cost, long nowMs) {
            // 1. Check if under quarantine/cooldown
            if (quarantinedUntilMs > nowMs) {
                violationCount++;
                return new LimitStatus(false, 0.0, true, quarantinedUntilMs - nowMs, violationCount);
            }

            // 2. Refill tokens based on elapsed time
            long elapsedMs = Math.max(0, nowMs - lastRefillMs);
            lastRefillMs = nowMs;
            double tokensToAdd = (elapsedMs / 1000.0) * config.refillRatePerSec;
            tokens = Math.min(config.capacity, tokens + tokensToAdd);

            // 3. Evaluate consumption
            if (tokens >= cost) {
                tokens -= cost;
                // Decay violation count over clean transactions
                if (violationCount > 0 && Math.random() < 0.2) {
                    violationCount--;
                }
                return new LimitStatus(true, tokens, false, 0L, violationCount);
            }

            // 4. Rate limit exceeded
            violationCount++;
            if (violationCount >= config.maxViolationsBeforeCooldown) {
                quarantinedUntilMs = nowMs + config.cooldownDurationMs;
                return new LimitStatus(false, tokens, true, config.cooldownDurationMs, violationCount);
            }

            return new LimitStatus(false, tokens, false, 0L, violationCount);
        }

        synchronized LimitStatus inspect(long nowMs) {
            long elapsedMs = Math.max(0, nowMs - lastRefillMs);
            double simulatedTokens = Math.min(config.capacity, tokens + (elapsedMs / 1000.0) * config.refillRatePerSec);
            boolean quarantined = quarantinedUntilMs > nowMs;
            long cdRemaining = quarantined ? (quarantinedUntilMs - nowMs) : 0L;
            return new LimitStatus(!quarantined && simulatedTokens >= 1.0, simulatedTokens, quarantined, cdRemaining, violationCount);
        }

        synchronized boolean isIdle(long nowMs, long maxIdleMs) {
            return (nowMs - lastRefillMs) > maxIdleMs && quarantinedUntilMs <= nowMs;
        }
    }

    private final RateLimitConfig mDefaultConfig;
    private final ConcurrentHashMap<String, RateLimitConfig> mConfigOverrides = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Bucket> mBuckets = new ConcurrentHashMap<>();
    private long mLastPruneMs = System.currentTimeMillis();

    public TokenBucketRateLimiter() {
        this(RateLimitConfig.defaultConfig());
    }

    public TokenBucketRateLimiter(RateLimitConfig defaultConfig) {
        this.mDefaultConfig = defaultConfig != null ? defaultConfig : RateLimitConfig.defaultConfig();
    }

    /**
     * Sets a custom rate configuration for a specific key (e.g. high-volume browser package).
     */
    public void setConfigOverride(String key, RateLimitConfig config) {
        if (key != null && config != null) {
            mConfigOverrides.put(key, config);
        }
    }

    /**
     * Removes an override for a key.
     */
    public void removeConfigOverride(String key) {
        if (key != null) {
            mConfigOverrides.remove(key);
        }
    }

    /**
     * Tries to consume 1.0 token for the specified key using the current system time.
     */
    public LimitStatus tryConsume(String key) {
        return tryConsume(key, 1.0, System.currentTimeMillis());
    }

    /**
     * Tries to consume `cost` tokens for the specified key at `nowMs`.
     */
    public LimitStatus tryConsume(String key, double cost, long nowMs) {
        if (key == null || key.isEmpty()) {
            return new LimitStatus(true, Double.MAX_VALUE, false, 0L, 0);
        }

        Bucket bucket = mBuckets.computeIfAbsent(key, k -> {
            RateLimitConfig cfg = mConfigOverrides.getOrDefault(k, mDefaultConfig);
            return new Bucket(cfg, nowMs);
        });

        LimitStatus status = bucket.tryConsume(cost, nowMs);

        // Periodically prune idle buckets (every 5 minutes)
        if (nowMs - mLastPruneMs > 300_000L) {
            pruneIdleBuckets(nowMs);
        }

        return status;
    }

    /**
     * Inspects current status without consuming tokens.
     */
    public LimitStatus checkLimit(String key) {
        return checkLimit(key, System.currentTimeMillis());
    }

    public LimitStatus checkLimit(String key, long nowMs) {
        if (key == null || key.isEmpty()) {
            return new LimitStatus(true, Double.MAX_VALUE, false, 0L, 0);
        }
        Bucket b = mBuckets.get(key);
        if (b == null) {
            RateLimitConfig cfg = mConfigOverrides.getOrDefault(key, mDefaultConfig);
            return new LimitStatus(true, cfg.capacity, false, 0L, 0);
        }
        return b.inspect(nowMs);
    }

    /**
     * Resets rate tracking for a specific key.
     */
    public void reset(String key) {
        if (key != null) {
            mBuckets.remove(key);
        }
    }

    /**
     * Clears all tracking buckets.
     */
    public void clear() {
        mBuckets.clear();
    }

    /**
     * Returns the number of currently tracked buckets.
     */
    public int getTrackedCount() {
        return mBuckets.size();
    }

    /**
     * Prunes buckets that have been inactive for more than 10 minutes.
     */
    public synchronized void pruneIdleBuckets(long nowMs) {
        mLastPruneMs = nowMs;
        long maxIdleMs = 600_000L; // 10 minutes
        Iterator<Map.Entry<String, Bucket>> it = mBuckets.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, Bucket> entry = it.next();
            if (entry.getValue().isIdle(nowMs, maxIdleMs)) {
                it.remove();
            }
        }
    }
}
