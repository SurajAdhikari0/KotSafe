/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.kotsafe.security.model.TokenBucketRateLimiter;

import org.junit.Test;

public class TokenBucketRateLimiterTest {

    @Test
    public void testBurstAndRefill() {
        // Capacity: 5 tokens, Refill: 2 tokens/sec
        TokenBucketRateLimiter.RateLimitConfig config = new TokenBucketRateLimiter.RateLimitConfig(5.0, 2.0, 3, 5000L);
        TokenBucketRateLimiter limiter = new TokenBucketRateLimiter(config);

        long now = 1000000L;
        String appKey = "com.test.app";

        // Consume all 5 tokens
        for (int i = 0; i < 5; i++) {
            TokenBucketRateLimiter.LimitStatus status = limiter.tryConsume(appKey, 1.0, now);
            assertTrue("Token " + i + " should be allowed", status.allowed);
        }

        // 6th token should fail
        TokenBucketRateLimiter.LimitStatus failStatus = limiter.tryConsume(appKey, 1.0, now);
        assertFalse("6th token should be throttled", failStatus.allowed);

        // Advance 1 second -> should refill 2 tokens
        now += 1000L;
        TokenBucketRateLimiter.LimitStatus refill1 = limiter.tryConsume(appKey, 1.0, now);
        assertTrue("Refilled token 1 should be allowed", refill1.allowed);

        TokenBucketRateLimiter.LimitStatus refill2 = limiter.tryConsume(appKey, 1.0, now);
        assertTrue("Refilled token 2 should be allowed", refill2.allowed);

        TokenBucketRateLimiter.LimitStatus refill3 = limiter.tryConsume(appKey, 1.0, now);
        assertFalse("Exceeded refilled capacity", refill3.allowed);
    }

    @Test
    public void testAutoQuarantineOnRepeatedViolations() {
        // Capacity: 2 tokens, max violations before cooldown: 2, cooldown: 10_000ms
        TokenBucketRateLimiter.RateLimitConfig config = new TokenBucketRateLimiter.RateLimitConfig(2.0, 1.0, 2, 10_000L);
        TokenBucketRateLimiter limiter = new TokenBucketRateLimiter(config);

        long now = 2000000L;
        String spamApp = "com.spam.bot";

        // Consume 2 tokens
        assertTrue(limiter.tryConsume(spamApp, 1.0, now).allowed);
        assertTrue(limiter.tryConsume(spamApp, 1.0, now).allowed);

        // Violation 1
        TokenBucketRateLimiter.LimitStatus v1 = limiter.tryConsume(spamApp, 1.0, now);
        assertFalse(v1.allowed);
        assertFalse(v1.isQuarantined);

        // Violation 2 -> Triggers Quarantine
        TokenBucketRateLimiter.LimitStatus v2 = limiter.tryConsume(spamApp, 1.0, now);
        assertFalse(v2.allowed);
        assertTrue("Should enter quarantine", v2.isQuarantined);
        assertEquals(10_000L, v2.cooldownRemainingMs);

        // Advance 5 seconds (still inside cooldown)
        now += 5000L;
        TokenBucketRateLimiter.LimitStatus duringCd = limiter.tryConsume(spamApp, 1.0, now);
        assertFalse(duringCd.allowed);
        assertTrue(duringCd.isQuarantined);

        // Advance past cooldown (11 seconds total)
        now += 6000L;
        TokenBucketRateLimiter.LimitStatus afterCd = limiter.tryConsume(spamApp, 1.0, now);
        assertTrue("Should be allowed after cooldown expiration", afterCd.allowed);
        assertFalse(afterCd.isQuarantined);
    }

    @Test
    public void testPerKeyOverride() {
        TokenBucketRateLimiter limiter = new TokenBucketRateLimiter(new TokenBucketRateLimiter.RateLimitConfig(2.0, 1.0));
        // Give browser app a huge burst capacity of 100
        limiter.setConfigOverride("com.android.chrome", new TokenBucketRateLimiter.RateLimitConfig(100.0, 10.0));

        long now = 3000000L;
        // Chrome can consume 20 tokens easily
        for (int i = 0; i < 20; i++) {
            assertTrue(limiter.tryConsume("com.android.chrome", 1.0, now).allowed);
        }

        // Standard app fails after 2
        assertTrue(limiter.tryConsume("com.other.app", 1.0, now).allowed);
        assertTrue(limiter.tryConsume("com.other.app", 1.0, now).allowed);
        assertFalse(limiter.tryConsume("com.other.app", 1.0, now).allowed);
    }
}
