/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * ThreatIntelOrchestrator
 * =======================
 * Orchestrates multi-indicator threat intelligence lookups across:
 * - Local Security Blocklist (SecurityBlocklistManager)
 * - In-memory High-speed ReputationCache
 * - Persistent TiCacheDb
 * - External Intelligence Providers (ThreatFox, URLhaus, MalwareBazaar, VirusTotal, OTX)
 * Fully asynchronous to ensure zero latency on the packet capture path.
 */

package com.kotsafe.security.security.intelligence;

import android.content.Context;

import com.kotsafe.security.Log;
import com.kotsafe.security.model.SecurityBlocklistManager;
import com.kotsafe.security.model.ThreatIntelProvider;
import com.kotsafe.security.model.ThreatIntelRouter;
import com.kotsafe.security.security.event.EventTypes;
import com.kotsafe.security.security.event.SecurityEvent;
import com.kotsafe.security.security.event.SecurityEventBus;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ThreatIntelOrchestrator {
    private static final String TAG = "ThreatIntelOrchestrator";

    public interface ThreatLookupCallback {
        void onResult(String indicator, String type, boolean isMalicious, int riskScore, String details);
    }

    private static volatile ThreatIntelOrchestrator sInstance;
    private final Context mContext;
    private final ReputationCache mReputationCache;
    private final ThreatIntelRouter mRouter;
    private final ExecutorService mThreadPool = Executors.newFixedThreadPool(3);

    public static ThreatIntelOrchestrator getInstance(Context context) {
        if (sInstance == null) {
            synchronized (ThreatIntelOrchestrator.class) {
                if (sInstance == null) {
                    sInstance = new ThreatIntelOrchestrator(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    private ThreatIntelOrchestrator(Context context) {
        mContext = context;
        mReputationCache = ReputationCache.getInstance();
        mRouter = ThreatIntelRouter.getInstance(context);
    }

    public void queryAsync(String type, String indicator, ThreatLookupCallback callback) {
        if (indicator == null || indicator.isEmpty()) {
            if (callback != null) callback.onResult("", type, false, 0, "Empty indicator");
            return;
        }

        // 1. Check in-memory fast cache first
        ReputationCache.CachedReputation cached = mReputationCache.get(type, indicator);
        if (cached != null) {
            if (callback != null) {
                callback.onResult(indicator, type, "MALICIOUS".equals(cached.verdict), cached.riskScore, cached.details);
            }
            return;
        }

        // 2. Check local blocklist manager
        SecurityBlocklistManager secMgr = SecurityBlocklistManager.getInstance(mContext);
        if ("IP".equalsIgnoreCase(type) && secMgr.isBlocked(indicator)) {
            mReputationCache.put(type, indicator, "MALICIOUS", 95, 1.0f, "LocalFirewallPolicy", "Blocked by firewall rules");
            if (callback != null) callback.onResult(indicator, type, true, 95, "Blocked by firewall policy");
            return;
        }
        if ("DOMAIN".equalsIgnoreCase(type) && secMgr.isDomainBlocked(indicator)) {
            mReputationCache.put(type, indicator, "MALICIOUS", 95, 1.0f, "LocalFirewallPolicy", "Blocked by firewall rules");
            if (callback != null) callback.onResult(indicator, type, true, 95, "Blocked by firewall policy");
            return;
        }
        if ("HASH".equalsIgnoreCase(type) && secMgr.isHashBlocked(indicator)) {
            mReputationCache.put(type, indicator, "MALICIOUS", 100, 1.0f, "LocalFirewallPolicy", "Blocked by firewall rules");
            if (callback != null) callback.onResult(indicator, type, true, 100, "Blocked by firewall policy");
            return;
        }

        // 3. Dispatch to background thread for network intelligence lookup
        mThreadPool.submit(() -> {
            try {
                ThreatIntelProvider.ThreatReport report = null;
                if ("HASH".equalsIgnoreCase(type)) {
                    report = mRouter.queryHash(indicator);
                } else if ("IP".equalsIgnoreCase(type)) {
                    report = mRouter.queryIp(indicator);
                } else if ("DOMAIN".equalsIgnoreCase(type)) {
                    report = mRouter.queryDomain(indicator);
                } else if ("URL".equalsIgnoreCase(type)) {
                    report = mRouter.queryUrl(indicator);
                }

                boolean isMal = report != null && report.isMalicious;
                int score = report != null ? report.riskScore : 0;
                String details = report != null && report.details != null ? report.details : "Clean";
                String verdict = isMal ? "MALICIOUS" : (report != null && report.isSuspicious ? "SUSPICIOUS" : "SAFE");
                float conf = report != null ? report.confidence : 1.0f;
                String prov = report != null && report.provider != null ? report.provider : "ThreatIntelRouter";

                // Save to cache
                mReputationCache.put(type, indicator, verdict, score, conf, prov, details);

                // Publish threat event if malicious
                if (isMal) {
                    SecurityEvent.Builder eventBuilder = new SecurityEvent.Builder(SecurityEvent.Domain.INTELLIGENCE, EventTypes.MALICIOUS_IP)
                            .severity(SecurityEvent.Severity.HIGH)
                            .title("Threat Intelligence Hit: " + indicator)
                            .description(details)
                            .attribute("indicator", indicator)
                            .attribute("type", type)
                            .attribute("risk_score", score)
                            .attribute("provider", prov);
                    SecurityEventBus.getInstance().publish(eventBuilder.build());
                }

                if (callback != null) {
                    callback.onResult(indicator, type, isMal, score, details);
                }
            } catch (Exception e) {
                Log.w(TAG, "Async TI lookup error for " + indicator + ": " + e.getMessage());
                if (callback != null) {
                    callback.onResult(indicator, type, false, 0, e.getMessage());
                }
            }
        });
    }
}
