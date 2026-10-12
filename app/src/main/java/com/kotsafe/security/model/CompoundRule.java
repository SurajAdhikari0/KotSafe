/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import com.kotsafe.security.Cidr;
import com.kotsafe.security.Log;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.util.regex.Pattern;

/**
 * Encapsulates a multi-condition compound firewall rule inspired by modern WAF engines (SafeLine).
 *
 * Supports boolean AND matching across:
 * - Application Package name (exact or wildcard, e.g. "com.evil.*")
 * - Destination IP / CIDR block (e.g. "192.168.1.0/24", "45.33.32.156")
 * - Destination Port / Port Range (e.g. "80", "8000-8080", "!443", "80,443,8443")
 * - Domain / Host Pattern (e.g. "evil.com", "*.evil.com", "regex:.*tracker.*")
 * - L4/L7 Protocol ("TCP", "UDP", "ICMP", "ANY")
 * - TLS Client JA3 Fingerprint (MD5 hash)
 * - Rate Limiting Threshold (requests per minute)
 */
public class CompoundRule {
    private static final String TAG = "CompoundRule";
    private static final Gson GSON = new GsonBuilder().create();

    public long id;
    public String name;
    public String packageName;      // e.g. "com.target.app" or "com.target.*"
    public String ipOrCidr;         // e.g. "192.168.1.0/24" or "1.2.3.4"
    public String portRange;        // e.g. "80", "8000-8080", "!443", "80,443"
    public String domainPattern;    // e.g. "*.domain.com", "domain.com", "regex:..."
    public String protocol;         // e.g. "TCP", "UDP", "ANY"
    public String ja3Hash;          // e.g. "a0e9f5d64349fb13191bc781f81f42e1"
    public double rateLimitPerMin;  // > 0 enforces token bucket threshold
    public String action;           // BLOCK, ALLOW, WARN, QUARANTINE, RATE_LIMIT
    public String source;           // USER, SYSTEM, TI, HEURISTIC
    public String reason;
    public int priority;
    public boolean enabled = true;
    public int hitCount;
    public long createdAt;

    // Transient cached matchers for performance
    private transient Cidr mCachedCidr;
    private transient Pattern mCachedRegex;
    private transient boolean mCidrParseAttempted;

    public CompoundRule() {
        this.action = SecurityRulesDb.ACTION_BLOCK;
        this.source = SecurityRulesDb.SOURCE_USER;
        this.priority = SecurityRulesDb.PRIORITY_EXPLICIT_BLOCK;
        this.createdAt = System.currentTimeMillis();
    }

    public static class Builder {
        private final CompoundRule rule = new CompoundRule();

        public Builder setName(String name) { rule.name = name; return this; }
        public Builder setPackageName(String pkg) { rule.packageName = pkg; return this; }
        public Builder setIpOrCidr(String ipOrCidr) { rule.ipOrCidr = ipOrCidr; return this; }
        public Builder setPortRange(String portRange) { rule.portRange = portRange; return this; }
        public Builder setDomainPattern(String pattern) { rule.domainPattern = pattern; return this; }
        public Builder setProtocol(String proto) { rule.protocol = proto; return this; }
        public Builder setJa3Hash(String ja3) { rule.ja3Hash = ja3; return this; }
        public Builder setRateLimitPerMin(double rate) { rule.rateLimitPerMin = rate; return this; }
        public Builder setAction(String action) { rule.action = action; return this; }
        public Builder setSource(String source) { rule.source = source; return this; }
        public Builder setReason(String reason) { rule.reason = reason; return this; }
        public Builder setPriority(int priority) { rule.priority = priority; return this; }
        public Builder setEnabled(boolean enabled) { rule.enabled = enabled; return this; }

        public CompoundRule build() {
            return rule;
        }
    }

    /**
     * Evaluates if this compound rule matches all specified network parameters.
     * Empty or null criteria in the rule are treated as wildcards (match anything).
     */
    public boolean matches(String app, String dstIp, int dstPort, String domain, String proto, String ja3) {
        if (!enabled) return false;

        // 1. Package Name
        if (packageName != null && !packageName.trim().isEmpty() && !packageName.equals("*")) {
            if (app == null || !matchesPackage(app, packageName.trim())) {
                return false;
            }
        }

        // 2. IP / CIDR
        if (ipOrCidr != null && !ipOrCidr.trim().isEmpty() && !ipOrCidr.equals("*")) {
            if (dstIp == null || !matchesIpOrCidr(dstIp, ipOrCidr.trim())) {
                return false;
            }
        }

        // 3. Port / Port Range
        if (portRange != null && !portRange.trim().isEmpty() && !portRange.equals("*")) {
            if (dstPort <= 0 || !matchesPort(dstPort, portRange.trim())) {
                return false;
            }
        }

        // 4. Domain Pattern
        if (domainPattern != null && !domainPattern.trim().isEmpty() && !domainPattern.equals("*")) {
            if (domain == null || !matchesDomain(domain, domainPattern.trim())) {
                return false;
            }
        }

        // 5. Protocol
        if (protocol != null && !protocol.trim().isEmpty() && !protocol.equalsIgnoreCase("ANY") && !protocol.equals("*")) {
            if (proto == null || !proto.equalsIgnoreCase(protocol.trim())) {
                return false;
            }
        }

        // 6. JA3 Hash
        if (ja3Hash != null && !ja3Hash.trim().isEmpty() && !ja3Hash.equals("*")) {
            if (ja3 == null || !ja3.trim().equalsIgnoreCase(ja3Hash.trim())) {
                return false;
            }
        }

        // All configured conditions matched!
        return true;
    }

    private boolean matchesPackage(String app, String pattern) {
        if (pattern.endsWith("*")) {
            String prefix = pattern.substring(0, pattern.length() - 1);
            return app.startsWith(prefix);
        }
        return app.equalsIgnoreCase(pattern);
    }

    private boolean matchesIpOrCidr(String actualIp, String ruleIpOrCidr) {
        if (actualIp.equalsIgnoreCase(ruleIpOrCidr)) {
            return true;
        }
        if (ruleIpOrCidr.contains("/")) {
            try {
                if (!mCidrParseAttempted && mCachedCidr == null) {
                    mCachedCidr = new Cidr(ruleIpOrCidr);
                    mCidrParseAttempted = true;
                }
                if (mCachedCidr != null) {
                    return mCachedCidr.isInRange(actualIp);
                }
            } catch (Exception e) {
                mCidrParseAttempted = true;
                Log.w(TAG, "Invalid CIDR in rule: " + ruleIpOrCidr);
            }
        }
        return false;
    }

    public static boolean matchesPort(int actualPort, String portExpr) {
        if (portExpr == null || portExpr.isEmpty()) return true;
        String[] tokens = portExpr.split(",");
        boolean hasPositiveToken = false;
        boolean matchedPositive = false;

        for (String rawToken : tokens) {
            String token = rawToken.trim();
            if (token.startsWith("!")) {
                try {
                    int excludedPort = Integer.parseInt(token.substring(1).trim());
                    if (actualPort == excludedPort) return false;
                } catch (NumberFormatException ignored) {}
            } else {
                hasPositiveToken = true;
                if (token.contains("-")) {
                    String[] range = token.split("-");
                    if (range.length == 2) {
                        try {
                            int min = Integer.parseInt(range[0].trim());
                            int max = Integer.parseInt(range[1].trim());
                            if (actualPort >= min && actualPort <= max) {
                                matchedPositive = true;
                            }
                        } catch (NumberFormatException ignored) {}
                    }
                } else {
                    try {
                        int p = Integer.parseInt(token);
                        if (actualPort == p) {
                            matchedPositive = true;
                        }
                    } catch (NumberFormatException ignored) {}
                }
            }
        }

        return hasPositiveToken ? matchedPositive : true;
    }

    private boolean matchesDomain(String actualDomain, String pattern) {
        String act = actualDomain.toLowerCase().trim();
        String pat = pattern.toLowerCase().trim();

        if (act.equals(pat)) return true;

        // Wildcard: *.evil.com
        if (pat.startsWith("*.")) {
            String suffix = pat.substring(2);
            return act.endsWith("." + suffix) || act.equals(suffix);
        }

        // Regex: regex:^.*evil.*$
        if (pat.startsWith("regex:")) {
            try {
                if (mCachedRegex == null) {
                    mCachedRegex = Pattern.compile(pattern.substring(6).trim(), Pattern.CASE_INSENSITIVE);
                }
                return mCachedRegex.matcher(actualDomain).matches();
            } catch (Exception e) {
                return false;
            }
        }

        // Suffix match if pattern starts with dot: .evil.com
        if (pat.startsWith(".")) {
            return act.endsWith(pat) || act.equals(pat.substring(1));
        }

        return false;
    }

    public String toJson() {
        return GSON.toJson(this);
    }

    public static CompoundRule fromJson(String json) {
        if (json == null || json.trim().isEmpty()) return null;
        try {
            return GSON.fromJson(json, CompoundRule.class);
        } catch (Exception e) {
            Log.e(TAG, "Failed to parse CompoundRule JSON: " + e.getMessage());
            return null;
        }
    }
}
