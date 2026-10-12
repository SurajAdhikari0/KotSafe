/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.Log;
import com.kotsafe.security.Utils;
import com.kotsafe.security.decoders.Ja3Fingerprinter;
import com.kotsafe.security.model.WebCategoryEngine;
import com.kotsafe.security.model.UnifiedIncidentTimeline;
import com.kotsafe.security.model.backend.BackendProviderFactory;

/**
 * Always-on network security monitor.
 *
 * Called from CaptureService/FirewallLogManager on every new connection event.
 * NEVER blocks the packet path — all TI queries are async via SecurityTaskScheduler.
 *
 * Flow:
 *   1. Log the URL visit to UrlVisitDbHelper (logs domain)
 *   2. Check SecurityRulesDb for known blocks — instant verdict
 *   3. If not blocked, queue async TI enrichment (P1/P2 priority)
 *   4. On TI result: update log record verdict, store evidence, fire SmartScreen if needed
 */
public class NetworkSecurityMonitor {
    private static final String TAG = "NetworkSecurityMonitor";

    private static NetworkSecurityMonitor sInstance;

    private final Context mContext;
    private final SecurityDatabase mSecDb;
    private final SecurityTaskScheduler mScheduler;
    private final TokenBucketRateLimiter mRateLimiter = new TokenBucketRateLimiter();
    private final ReconnaissanceDetector mReconDetector = new ReconnaissanceDetector();

    public static synchronized NetworkSecurityMonitor getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new NetworkSecurityMonitor(context.getApplicationContext());
        }
        return sInstance;
    }

    private NetworkSecurityMonitor(Context context) {
        mContext = context;
        mSecDb = SecurityDatabase.getInstance(context);
        mScheduler = SecurityTaskScheduler.getInstance(context);
    }

    public TokenBucketRateLimiter getRateLimiter() {
        return mRateLimiter;
    }

    public ReconnaissanceDetector getReconDetector() {
        return mReconDetector;
    }

    /**
     * Called for every new connection observed by the VPN tunnel.
     * Guaranteed non-blocking — returns immediately.
     *
     * @param appName     human-readable app name
     * @param packageName package of originating app
     * @param ip          destination IP
     * @param domain      destination domain/SNI (may be null for raw IP connections)
     * @param url         full URL if available from MITM (may be null)
     * @param method      HTTP method or "CONNECT"
     */
    public void onConnection(String appName, String packageName,
                              String ip, String domain, String url, String method) {
        onConnection(appName, packageName, ip, 0, domain, url, method);
    }

    public void onConnection(String appName, String packageName,
                              String ip, int port, String domain, String url, String method) {
        onConnection(appName, packageName, ip, port, domain, url, method, null);
    }

    public void onConnection(String appName, String packageName,
                              String ip, int port, String domain, String url, String method, String ja3) {
        if (port <= 0 && url != null && url.contains(":")) {
            try {
                int colon = url.lastIndexOf(':');
                int slash = url.indexOf('/', colon);
                String pStr = (slash != -1) ? url.substring(colon + 1, slash) : url.substring(colon + 1);
                port = Integer.parseInt(pStr);
            } catch (Exception ignored) {}
        }

        // Automatic Whitelisting: exempt authorized P2P Tunnel, KotSafe self, and Gateway routing
        boolean isP2pTunnel = "com.kotsafe.security.p2p".equals(packageName)
                || "com.kotsafe.security".equals(packageName)
                || (packageName != null && (packageName.startsWith("com.kotsafe.security") || packageName.startsWith("com.kotsafe.security")))
                || "com.kotsafe.security.p2p".equals(packageName)
                || "com.kotsafe.security".equals(packageName)
                || (appName != null && (appName.startsWith("[P2P Remote:") || appName.startsWith("[P2P Decrypted:")))
                || (domain != null && domain.contains("trycloudflare.com"))
                || BackendProviderFactory.isRelayEndpoint(ip);

        try {
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(mContext);
            String customRelay = prefs.getString("personal_gateway_custom_relay_url", "");
            if (!customRelay.isEmpty() && ((ip != null && customRelay.contains(ip)) || (domain != null && customRelay.contains(domain)))) {
                isP2pTunnel = true;
            }
        } catch (Exception ignored) {}

        // Step 1: build visit record
        UrlVisitLog visit = new UrlVisitLog();
        visit.timestamp = System.currentTimeMillis();
        visit.appName = appName;
        visit.packageName = packageName;
        visit.ip = ip;
        visit.domain = domain != null ? domain : ip;
        visit.url = url != null ? url : (domain != null ? domain : ip);
        visit.method = method;
        visit.riskScore = 0;
        visit.verdict = "SAFE";
        visit.wasBlocked = false;

        // Feed live network flow to CorrelationEngine for Antivirus EDR correlation
        try {
            CorrelationEngine.getInstance(mContext).onNetworkFlowObserved(appName, packageName, ip, port, domain, url);
        } catch (Exception ignored) {}

        // Feed live network flow to Pillar 1: AppBehaviorProfileManager (Zero-Trust Anomaly Engine)
        try {
            AppBehaviorProfileManager.getInstance(mContext).processFlow(appName, packageName, ip, port, domain, url);
        } catch (Exception ignored) {}

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(mContext);
        boolean isFirewallEnabled = Prefs.isFirewallEnabled(mContext, prefs);

        boolean isExempt = "android".equals(packageName)
                || "com.android.systemui".equals(packageName)
                || "com.google.android.gms".equals(packageName)
                || Utils.isVerifiedGoogleTrustedService(mContext, packageName)
                || Utils.isEssentialOrBrowserApp(mContext, packageName);

        // Step 2: instant block check (DB lookup — synchronous, fast)
        String checkValue = domain != null ? domain.toLowerCase() : ip;
        SecurityBlocklistManager blMgr = SecurityBlocklistManager.getInstance(mContext);

        SecurityRulesDb.SecurityRule blockRule = null;

        // Only enforce firewall blocks, rate limiting, and category rules if Firewall is active
        if (isFirewallEnabled && !isP2pTunnel) {
            // Check domain, URL, and IP blocks
            if (domain != null) {
                blockRule = blMgr.findBlockRule(domain);
            }
            if (blockRule == null && url != null) {
                blockRule = blMgr.findUrlBlockRule(url);
            }
            if (blockRule == null && ip != null) {
                blockRule = blMgr.findBlockRule(ip);
            }

            // Check package block rule (exempting core OS services, Google trusted services, and essential/browser apps)
            if (blockRule == null && packageName != null && !isExempt) {
                blockRule = blMgr.findBlockRule(packageName);
                if (blockRule == null) {
                    try {
                        int uid = Utils.getPackageUid(mContext.getPackageManager(), packageName, 0);
                        if (com.kotsafe.security.KotSafe.getInstance().getBlocklist().matchesApp(uid)) {
                            blockRule = new SecurityRulesDb.SecurityRule();
                            blockRule.type = SecurityRulesDb.TYPE_APP;
                            blockRule.value = packageName;
                            blockRule.reason = "Firewall App Rule";
                            blockRule.enabled = true;
                        }
                    } catch (Exception ignored) {}
                }
            }

            // SafeLine Token-Bucket Rate Limiter & Flood Guard: throttle spamming apps/IPs
            // Never rate limit or auto-quarantine exempted apps (browsers, media streaming like Netflix, OS services)
            String rateKey = packageName != null ? "app:" + packageName : (ip != null ? "ip:" + ip : null);
            if (blockRule == null && rateKey != null && !isExempt) {
                TokenBucketRateLimiter.LimitStatus rateStatus = mRateLimiter.tryConsume(rateKey);
                if (!rateStatus.allowed) {
                    blockRule = new SecurityRulesDb.SecurityRule();
                    blockRule.type = SecurityRulesDb.TYPE_APP;
                    blockRule.value = rateKey;
                    blockRule.action = SecurityRulesDb.ACTION_RATE_LIMIT;
                    blockRule.reason = rateStatus.isQuarantined
                            ? "Flood Guard Auto-Quarantine (" + (rateStatus.cooldownRemainingMs / 1000) + "s remaining)"
                            : "Token Bucket Rate Limit Exceeded";
                    blockRule.enabled = true;
                }
            }

            // SafeLine-style Compound Rule Engine check
            if (blockRule == null) {
                CompoundRule matchedCompound = mSecDb.rules().matchCompoundRule(
                        packageName, ip, port, domain, method, ja3);
                if (matchedCompound != null) {
                    if (SecurityRulesDb.ACTION_BLOCK.equalsIgnoreCase(matchedCompound.action)
                            || SecurityRulesDb.ACTION_QUARANTINE.equalsIgnoreCase(matchedCompound.action)) {
                        blockRule = new SecurityRulesDb.SecurityRule();
                        blockRule.id = matchedCompound.id;
                        blockRule.type = SecurityRulesDb.TYPE_COMPOUND;
                        blockRule.value = matchedCompound.name != null ? matchedCompound.name : "Compound Rule";
                        blockRule.action = matchedCompound.action;
                        blockRule.source = matchedCompound.source;
                        blockRule.reason = matchedCompound.reason != null ? matchedCompound.reason : "Compound Rule Match";
                        blockRule.enabled = true;
                    } else if (matchedCompound.rateLimitPerMin > 0 && !isExempt) {
                        String crKey = "compound:" + matchedCompound.id;
                        mRateLimiter.setConfigOverride(crKey, new TokenBucketRateLimiter.RateLimitConfig(
                                Math.max(10.0, matchedCompound.rateLimitPerMin / 2.0),
                                matchedCompound.rateLimitPerMin / 60.0
                        ));
                        TokenBucketRateLimiter.LimitStatus crStatus = mRateLimiter.tryConsume(crKey);
                        if (!crStatus.allowed) {
                            blockRule = new SecurityRulesDb.SecurityRule();
                            blockRule.id = matchedCompound.id;
                            blockRule.type = SecurityRulesDb.TYPE_COMPOUND;
                            blockRule.value = matchedCompound.name != null ? matchedCompound.name : "Compound Rule Rate Limit";
                            blockRule.action = SecurityRulesDb.ACTION_RATE_LIMIT;
                            blockRule.reason = "Compound Rule Rate Limit Exceeded (" + matchedCompound.rateLimitPerMin + "/min)";
                            blockRule.enabled = true;
                        }
                    }
                }
            }
        }

        // TLS JA3 Fingerprint detection (User rules + known C2 signatures)
        if (!isP2pTunnel && blockRule == null && ja3 != null && !ja3.isEmpty()) {
            if (isFirewallEnabled) {
                blockRule = mSecDb.rules().findJa3BlockRule(ja3);
            }
            if (blockRule == null) {
                Ja3Fingerprinter.MaliciousJa3Info mInfo = Ja3Fingerprinter.detectMalicious(ja3);
                if (mInfo != null) {
                    // Record JA3 hit to forensic timeline
                    UnifiedIncidentTimeline.getInstance(mContext).recordJa3Match(
                            ja3, mInfo.name, mInfo.category, packageName);
                    if (isFirewallEnabled) {
                        blockRule = new SecurityRulesDb.SecurityRule();
                        blockRule.type = SecurityRulesDb.TYPE_JA3;
                        blockRule.value = ja3;
                        blockRule.action = SecurityRulesDb.ACTION_BLOCK;
                        blockRule.source = SecurityRulesDb.SOURCE_TI;
                        blockRule.reason = "Malicious TLS JA3 Fingerprint: " + mInfo.name + " (" + mInfo.category + ")";
                        blockRule.enabled = true;
                    }
                }
            }
        }

        // Web Category Policy Engine — classify domain/URL into policy bucket
        WebCategoryEngine.ClassificationResult catResult = null;
        if (isFirewallEnabled && !isP2pTunnel && blockRule == null && (domain != null || url != null)) {
            catResult = WebCategoryEngine.getInstance(mContext).classify(
                    domain != null ? domain : "", url);
            // CRITICAL: Do NOT block any site if it is not confirmed malicious!
            if (catResult.isBlocked()) {
                boolean isConfirmedMalicious = (catResult.category == WebCategoryEngine.Category.MALWARE_C2
                        || catResult.category == WebCategoryEngine.Category.PHISHING)
                        && (blMgr.isFastBlocked(domain != null ? domain : url)
                            || (domain != null && !SecurityBlocklistManager.isOfficialDomain(domain)
                                && !SecurityBlocklistManager.isTrustedAdOrAnalyticsDomain(domain)
                                && catResult.riskBoost >= 95));
                if (isConfirmedMalicious) {
                    blockRule = new SecurityRulesDb.SecurityRule();
                    blockRule.type   = SecurityRulesDb.TYPE_DOMAIN;
                    blockRule.value  = domain != null ? domain : (url != null ? url : "");
                    blockRule.action = SecurityRulesDb.ACTION_BLOCK;
                    blockRule.source = SecurityRulesDb.SOURCE_TI;
                    blockRule.reason = "Confirmed Malicious: " + catResult.category.label;
                    blockRule.enabled = true;
                    UnifiedIncidentTimeline.getInstance(mContext).recordWebCategoryBlock(
                            domain != null ? domain : url, catResult.category, packageName);
                } else {
                    // Not confirmed malicious -> warn only, DO NOT block
                    visit.riskScore = Math.max(visit.riskScore, catResult.riskBoost);
                    UnifiedIncidentTimeline.getInstance(mContext).recordWebCategoryWarn(
                            domain != null ? domain : url, catResult.category, packageName);
                }
            } else if (catResult.isWarned()) {
                // Warn: boost risk score but don't block
                visit.riskScore = Math.max(visit.riskScore, catResult.riskBoost);
                UnifiedIncidentTimeline.getInstance(mContext).recordWebCategoryWarn(
                        domain != null ? domain : url, catResult.category, packageName);
            }
        }

        if (blockRule != null) {
            visit.wasBlocked = true;
            boolean isHostileThreat = SecurityRulesDb.SOURCE_TI.equalsIgnoreCase(blockRule.source)
                    || SecurityRulesDb.SOURCE_YARA.equalsIgnoreCase(blockRule.source)
                    || SecurityRulesDb.TYPE_JA3.equalsIgnoreCase(blockRule.type);
            visit.verdict = isHostileThreat ? "MALICIOUS" : (blockRule.isRateLimit() ? "THROTTLED" : "BLOCKED");
            visit.riskScore = isHostileThreat ? 100 : (blockRule.isRateLimit() ? 40 : 0);
            if (blockRule.id > 0) {
                blockRule.hitCount++;
                mSecDb.rules().incrementHitCount(blockRule.id);
            }
            Log.d(TAG, "BLOCKED: " + checkValue + " rule=" + blockRule.reason);

            // Record to Unified Incident Timeline (skip JA3/WebCat — already recorded above)
            if (!SecurityRulesDb.TYPE_JA3.equalsIgnoreCase(blockRule.type)
                    && (catResult == null || !catResult.isBlocked())) {
                if (blockRule.isRateLimit()) {
                    boolean quarantined = blockRule.reason != null
                            && blockRule.reason.contains("Quarantine");
                    UnifiedIncidentTimeline.getInstance(mContext).recordRateLimit(
                            blockRule.value != null ? blockRule.value : checkValue,
                            quarantined, packageName);
                } else {
                    UnifiedIncidentTimeline.getInstance(mContext).recordFirewallBlock(
                            checkValue,
                            blockRule.reason,
                            packageName,
                            visit.riskScore);
                }
            }

            try {
                AlertStore.getInstance(mContext).add(
                        AlertRecord.Severity.MEDIUM,
                        AlertRecord.AlertType.FIREWALL_BLOCK,
                        "Firewall Block: " + checkValue,
                        "Blocked connection to " + checkValue + " (" + (blockRule.reason != null ? blockRule.reason : "Security Rule") + ")",
                        packageName != null ? packageName : (appName != null ? appName : "Network")
                );
            } catch (Exception ignored) {}

            // Trigger official Defender-style Firewall Block Page notification ONLY for confirmed hostile/malicious threats or explicit user block rules
            boolean isUserExplicitBlock = blockRule != null && SecurityRulesDb.SOURCE_USER.equalsIgnoreCase(blockRule.source);
            boolean isEssentialApp = packageName != null && (Utils.isEssentialOrBrowserApp(mContext, packageName) || Utils.isVerifiedGoogleTrustedService(mContext, packageName));
            boolean shouldShowBlockPage = !isEssentialApp && (isHostileThreat
                    || (blockRule != null && SecurityRulesDb.SOURCE_TI.equalsIgnoreCase(blockRule.source))
                    || "MALICIOUS".equalsIgnoreCase(visit.verdict)
                    || isUserExplicitBlock);
            if (blockRule != null && SecurityRulesDb.SOURCE_HEURISTIC.equalsIgnoreCase(blockRule.source)) {
                shouldShowBlockPage = false;
            }

            if (shouldShowBlockPage) {
                try {
                    String targetType = blockRule.type != null ? blockRule.type : "SITE";
                    String targetDisplay = checkValue;

                    if (blockRule.value != null && !blockRule.value.isEmpty()) {
                        targetDisplay = blockRule.value;
                    } else if ("IP".equalsIgnoreCase(targetType) && ip != null && !ip.isEmpty()) {
                        targetDisplay = ip;
                    } else if ("URL".equalsIgnoreCase(targetType) && url != null && !url.isEmpty()) {
                        targetDisplay = url;
                    } else if ("APP".equalsIgnoreCase(targetType) && packageName != null && !packageName.isEmpty()) {
                        targetDisplay = packageName;
                    } else if (domain != null && !domain.isEmpty()) {
                        targetDisplay = domain;
                    } else if (url != null && !url.isEmpty()) {
                        targetDisplay = url;
                    } else if (ip != null && !ip.isEmpty()) {
                        targetDisplay = ip;
                    }

                    // Strip DNS port artifacts if present
                    if (targetDisplay != null) {
                        if (targetDisplay.endsWith(":53")) {
                            targetDisplay = targetDisplay.substring(0, targetDisplay.length() - 3);
                        }
                        if (targetDisplay.startsWith("http://") && targetDisplay.indexOf('/', 7) == -1 && !targetDisplay.contains(":")) {
                            targetDisplay = targetDisplay.substring(7);
                        }
                    }

                    String reason = blockRule.reason != null ? blockRule.reason : "Blocked by Administrator";
                    SmartScreenManager.getInstance(mContext).showFirewallBlockPage(
                            targetDisplay,
                            targetType,
                            reason,
                            appName != null ? appName : "Network App",
                            packageName != null ? packageName : ""
                    );
                } catch (Exception e) {
                    Log.w(TAG, "showFirewallBlockPage error: " + e.getMessage());
                }
            }
        }

        // Log immediately regardless of block status
        final long visitId = mSecDb.logs().logUrlVisit(visit);

        // Feed to high-volume TelemetryDataParser & AI activity bridge
        try {
            TelemetryDataParser.TelemetryRecord rec = new TelemetryDataParser.TelemetryRecord();
            rec.timestamp = visit.timestamp;
            rec.source = "NETWORK";
            rec.packageName = packageName;
            rec.appName = appName;
            rec.ip = ip;
            rec.domain = domain;
            rec.url = url;
            rec.method = method;
            rec.isSystemApp = (packageName != null && Utils.isSystemApp(mContext, packageName));
            rec.wasBlocked = visit.wasBlocked;
            rec.verdict = visit.verdict;
            rec.riskScore = visit.riskScore;
            TelemetryDataParser.getInstance(mContext).enqueue(rec);
        } catch (Exception ignored) {}

        // Publish to central SecurityEventBus for CrossDomainCorrelationEngine
        try {
            boolean isBlocked = visit.wasBlocked;
            boolean isMalicious = "MALICIOUS".equalsIgnoreCase(visit.verdict);
            com.kotsafe.security.security.event.SecurityEvent.Severity severity = isBlocked
                    ? (isMalicious ? com.kotsafe.security.security.event.SecurityEvent.Severity.CRITICAL : com.kotsafe.security.security.event.SecurityEvent.Severity.HIGH)
                    : com.kotsafe.security.security.event.SecurityEvent.Severity.INFO;
            String eventType = isBlocked
                    ? com.kotsafe.security.security.event.EventTypes.FIREWALL_BLOCK
                    : com.kotsafe.security.security.event.EventTypes.NETWORK_CONNECTION;

            com.kotsafe.security.security.event.SecurityEvent.Builder eventBuilder =
                    new com.kotsafe.security.security.event.SecurityEvent.Builder(
                            com.kotsafe.security.security.event.SecurityEvent.Domain.NETWORK, eventType)
                            .severity(severity)
                            .title((isBlocked ? "Firewall Blocked: " : "Outbound Socket: ") + (domain != null ? domain : ip))
                            .description("Destination: " + ip + ":" + port + (domain != null ? " (" + domain + ")" : ""))
                            .subject(packageName, -1)
                            .attribute("dst_ip", ip)
                            .attribute("dst_port", port)
                            .attribute("domain", domain)
                            .attribute("url", url)
                            .attribute("is_blocked", isBlocked);

            if (blockRule != null && blockRule.reason != null) {
                eventBuilder.attribute("block_reason", blockRule.reason);
            }
            com.kotsafe.security.security.event.SecurityEventBus.getInstance().publish(eventBuilder.build());
        } catch (Exception ignored) {}

        // Step 3: Real-time heuristic anomaly detection (DGA entropy, hostile ports, Dynamic DNS)
        if (!visit.wasBlocked && !isP2pTunnel) {
            HeuristicAnalyzer.HeuristicResult hr = HeuristicAnalyzer.analyzeConnection(domain, ip, port, packageName);
            if (hr.isMalicious || hr.isSuspicious) {
                visit.riskScore = hr.riskScore;
                visit.verdict = hr.isMalicious ? "MALICIOUS" : "SUSPICIOUS";
                mSecDb.logs().updateUrlVerdict(visitId, hr.riskScore, visit.verdict);

                String ioc = domain != null ? domain : ip;
                String iocType = domain != null ? "DOMAIN" : "IP";
                String details = String.join(" | ", hr.findings);

                mSecDb.evidence().insertEvidence(
                        "NETWORK",
                        (hr.isMalicious ? "Hostile Traffic Detected: " : "Suspicious Traffic: ") + ioc,
                        details,
                        hr.riskScore,
                        hr.isMalicious ? EvidenceDbHelper.VERDICT_MALICIOUS : EvidenceDbHelper.VERDICT_SUSPICIOUS,
                        packageName != null ? packageName : "",
                        ioc,
                        iocType,
                        "HEURISTIC"
                );

                try {
                    AlertStore.getInstance(mContext).add(
                            hr.isMalicious ? AlertRecord.Severity.HIGH : AlertRecord.Severity.MEDIUM,
                            AlertRecord.AlertType.MALWARE,
                            (hr.isMalicious ? "Network Anomaly Alert: " : "Suspicious Connection: ") + ioc,
                            details + " (Risk score: " + hr.riskScore + "/100)",
                            packageName != null ? packageName : (appName != null ? appName : "Network")
                    );
                } catch (Exception ignored) {}
            }

            final String enrichDomain = domain;
            final String enrichIp = ip;
            final String finalAppName = appName;

            // Use P2 for normal connections, P1 if from a suspicious app
            int priority = SecurityTaskScheduler.P2_NORMAL;
            mScheduler.submitNormal("TiEnrich:" + checkValue, () ->
                    enrichAsync(visitId, finalAppName, packageName,
                            enrichIp, enrichDomain, url));
        }
    }

    /**
     * Async TI enrichment — runs on background worker, never on packet path.
     */
    private void enrichAsync(long visitId, String appName, String packageName,
                              String ip, String domain, String url) {
        try {
            ThreatIntelRouter router = ThreatIntelRouter.getInstance(mContext);
            if (!router.hasAnyProvider()) return;

            ThreatIntelProvider.ThreatReport report = null;

            // Prefer domain query; fall back to IP
            if (domain != null && !domain.isEmpty()) {
                report = router.queryDomain(domain);
            } else if (ip != null && !ip.isEmpty()) {
                report = router.queryIp(ip);
            }

            if (report == null) return;

            // Update log record with enriched verdict
            mSecDb.logs().updateUrlVerdict(visitId, report.riskScore, report.verdict);

            if (report.isMalicious || report.isSuspicious) {
                Log.i(TAG, "TI enrichment: " + (domain != null ? domain : ip)
                        + " verdict=" + report.verdict + " score=" + report.riskScore
                        + " provider=" + report.provider);

                // Store evidence
                String ioc = domain != null ? domain : ip;
                String iocType = domain != null ? "DOMAIN" : "IP";

                boolean isSystem = (packageName != null && (Utils.isSystemApp(mContext, packageName)
                    || Utils.isVerifiedGoogleTrustedService(mContext, packageName)))
                        || SecurityBlocklistManager.getInstance(mContext).isSystemWhitelisted(ioc)
                        || (ip != null && SecurityBlocklistManager.getInstance(mContext).isSystemWhitelisted(ip));

                // Official Android, Google, Samsung, and OEM apps are whitelisted and must NEVER show in suspicious activity
                if (isSystem) {
                    mSecDb.logs().updateUrlVerdict(visitId, 0, EvidenceDbHelper.VERDICT_SAFE);
                    return;
                }

                int risk = Math.max(report.riskScore, report.isMalicious ? 75 : 35);
                String verdict = report.isMalicious
                        ? EvidenceDbHelper.VERDICT_MALICIOUS
                        : EvidenceDbHelper.VERDICT_SUSPICIOUS;

                String details = report.details != null ? report.details : "Flagged by " + report.provider;

                mSecDb.evidence().insertEvidence(
                        "NETWORK",
                        "Suspicious connection from " + appName,
                        details,
                        risk, verdict, packageName, ioc, iocType, "TI"
                );

                try {
                    AlertRecord.Severity sev = report.isMalicious ? AlertRecord.Severity.HIGH : AlertRecord.Severity.MEDIUM;
                    AlertRecord.AlertType aType = report.isMalicious ? AlertRecord.AlertType.MALWARE : AlertRecord.AlertType.SMARTSCREEN;
                    AlertStore.getInstance(mContext).add(
                            sev,
                            aType,
                            (report.isMalicious ? "Threat Intelligence Alert: " : "Suspicious Host: ") + ioc,
                            details + " (Risk score: " + risk + "/100)",
                            packageName != null ? packageName : (appName != null ? appName : "Network")
                    );
                } catch (Exception ignored) {}

                // Record TI hit to forensic timeline
                try {
                    UnifiedIncidentTimeline.getInstance(mContext).record(
                        new UnifiedIncidentTimeline.IncidentEvent.Builder()
                            .type(UnifiedIncidentTimeline.EventType.THREAT_INTEL)
                            .severity(report.isMalicious
                                ? UnifiedIncidentTimeline.Severity.HIGH
                                : UnifiedIncidentTimeline.Severity.MEDIUM)
                            .title((report.isMalicious ? "TI Alert: " : "TI Suspicious: ") + ioc)
                            .detail(report.details != null ? report.details : "Flagged by " + report.provider)
                            .sourceApp(packageName)
                            .target(ioc)
                            .risk(risk)
                            .build());
                } catch (Exception ignored) {}

                // IMPORTANT: NEVER silently auto-block IPs or domains from TI in the background!
                // Automatic blocking without user consent breaks normal apps and shared CDN IPs.
                // If threat is found, notify SmartScreen so the user can review and decide whether to block manually.
                if (report.isMalicious && report.confidence >= 0.8f) {
                    SmartScreenManager.getInstance(mContext).showNetworkThreat(
                            appName, ioc, iocType, verdict, report.provider);
                } else if (report.isSuspicious) {
                    SmartScreenManager.getInstance(mContext).showSuspiciousWarning(
                            appName, ioc, iocType, report.riskScore, report.provider);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "enrichAsync error: " + e.getMessage());
        }
    }

    /**
     * Called when a URL visit log entry already exists but needs a manual verdict update.
     * Used by the Actions Center when user manually blocks something.
     */
    public void forceBlockDomain(String domain, String reason) {
        mSecDb.rules().blockDomain(domain, reason, SecurityRulesDb.SOURCE_USER);
        Log.i(TAG, "User force-blocked domain: " + domain);
    }

    public void forceBlockIp(String ip, String reason) {
        mSecDb.rules().blockIp(ip, reason, SecurityRulesDb.SOURCE_USER);
        Log.i(TAG, "User force-blocked IP: " + ip);
    }

    public void forceWhitelist(String value, String type, String reason) {
        mSecDb.rules().whitelist(type, value, SecurityRulesDb.SCOPE_EXACT, reason);
        Log.i(TAG, "User whitelisted: " + value);
    }
}
