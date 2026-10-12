/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

/**
 * Pluggable Threat Intelligence provider interface.
 *
 * Each provider (OTX, MalwareBazaar, VirusTotal, future) implements this interface.
 * The ThreatIntelRouter dispatches queries to all enabled providers and merges results.
 * Adding or removing a provider never requires changes to the detection engine.
 */
public interface ThreatIntelProvider {

    /** Human-readable provider name shown in UI and evidence records. */
    String getProviderName();

    /** Unique short code for cache keys. e.g. "OTX", "MB", "VT" */
    String getProviderCode();

    /** Returns true if this provider is configured and enabled. */
    boolean isAvailable();

    /**
     * Queries by SHA-256 file hash.
     * This is the most common query type for file scanning.
     */
    ThreatReport queryHash(String sha256);

    /** Queries by IP address. */
    ThreatReport queryIp(String ip);

    /** Queries by domain name (without scheme, e.g. "evil.example.com"). */
    ThreatReport queryDomain(String domain);

    /** Queries by full URL. Providers that don't support URL queries may return null. */
    ThreatReport queryUrl(String url);

    // ─── Unified result model ─────────────────────────────────────────────────

    class ThreatReport {
        public String provider;       // which provider produced this
        public String iocValue;       // the queried IOC
        public String iocType;        // HASH | IP | DOMAIN | URL

        public boolean isMalicious;
        public boolean isSuspicious;
        public int riskScore;         // 0–100
        public String verdict;        // SAFE | SUSPICIOUS | HIGH | MALICIOUS

        public String malwareFamily;
        public String details;
        public String resultJson;     // raw provider response (for evidence storage)
        public float confidence;      // 0.0–1.0

        // MalwareBazaar extras
        public String signature;
        public String[] tags;
        public long firstSeen;
        public long lastSeen;

        public static ThreatReport clean(String provider, String ioc, String iocType) {
            ThreatReport r = new ThreatReport();
            r.provider = provider;
            r.iocValue = ioc;
            r.iocType = iocType;
            r.isMalicious = false;
            r.isSuspicious = false;
            r.riskScore = 0;
            r.verdict = "SAFE";
            r.confidence = 1.0f;
            return r;
        }

        public static ThreatReport error(String provider, String ioc) {
            ThreatReport r = new ThreatReport();
            r.provider = provider;
            r.iocValue = ioc;
            r.verdict = "UNKNOWN";
            return r;
        }
    }
}
