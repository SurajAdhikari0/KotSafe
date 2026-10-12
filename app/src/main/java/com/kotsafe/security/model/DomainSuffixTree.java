/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * High-performance, memory-compact reverse-domain suffix tree.
 *
 * Facilitates sub-millisecond wildcard and exact domain evaluations against 250k+ rules:
 * - Exact match: "ads.google.com" matches rule "ads.google.com"
 * - Subdomain match: "sub.ads.google.com" automatically matches rule "ads.google.com" or "*.google.com"
 * - Clean-room original data structure implementation.
 */
public class DomainSuffixTree {

    private static class Node {
        final Map<String, Node> children = new HashMap<>(2);
        boolean isTerminal = false;
        String ruleSource = null;
    }

    private final Node mRoot = new Node();
    private int mRuleCount = 0;

    public synchronized void addDomain(@Nullable String domain, @Nullable String ruleSource) {
        if (domain == null) return;
        String clean = cleanDomain(domain);
        if (clean.isEmpty()) return;

        // Strip wildcard prefix if user/list specified "*.domain.com"
        if (clean.startsWith("*.")) {
            clean = clean.substring(2);
        }
        if (clean.startsWith(".")) {
            clean = clean.substring(1);
        }
        if (clean.isEmpty()) return;

        String[] parts = clean.split("\\.");
        Node curr = mRoot;
        // Traverse from right to left (TLD -> SLD -> subdomains)
        for (int i = parts.length - 1; i >= 0; i--) {
            String part = parts[i];
            if (part.isEmpty()) continue;
            Node next = curr.children.get(part);
            if (next == null) {
                next = new Node();
                curr.children.put(part, next);
            }
            curr = next;
        }
        if (!curr.isTerminal) {
            curr.isTerminal = true;
            curr.ruleSource = ruleSource;
            mRuleCount++;
        }
    }

    public synchronized void addAll(@Nullable Set<String> domains, @Nullable String ruleSource) {
        if (domains == null) return;
        for (String d : domains) {
            addDomain(d, ruleSource);
        }
    }

    /**
     * Checks if the queried domain or any of its parent domains match a rule.
     * e.g. "tracker.adservice.google.com" checks:
     *      - com -> google -> adservice -> tracker
     *      - triggers if any ancestor is marked terminal (e.g. adservice.google.com).
     *
     * @param queryDomain Domain to check
     * @return Source name of matching rule, or null if allowed.
     */
    @Nullable
    public synchronized String matches(@Nullable String queryDomain) {
        if (queryDomain == null) return null;
        String clean = cleanDomain(queryDomain);
        if (clean.isEmpty()) return null;

        String[] parts = clean.split("\\.");
        Node curr = mRoot;
        for (int i = parts.length - 1; i >= 0; i--) {
            String part = parts[i];
            if (part.isEmpty()) continue;

            Node next = curr.children.get(part);
            if (next == null) {
                // Not matched further down this branch
                return null;
            }
            if (next.isTerminal) {
                // Suffix matched! (e.g. "doubleclick.net" matched, so "ad.sub.doubleclick.net" matches)
                return next.ruleSource != null ? next.ruleSource : "Blocked Domain";
            }
            curr = next;
        }

        return null;
    }

    public synchronized boolean isBlocked(@Nullable String queryDomain) {
        return matches(queryDomain) != null;
    }

    public synchronized int size() {
        return mRuleCount;
    }

    public synchronized void clear() {
        mRoot.children.clear();
        mRuleCount = 0;
    }

    @NonNull
    public static String cleanDomain(@NonNull String raw) {
        String s = raw.trim().toLowerCase();
        // Strip protocols if provided (e.g. http://, https://)
        if (s.startsWith("http://")) s = s.substring(7);
        else if (s.startsWith("https://")) s = s.substring(8);

        // Strip ABP filter prefix ||
        if (s.startsWith("||")) {
            s = s.substring(2);
        }

        // Strip ABP options / flags if present after $
        int dollar = s.indexOf('$');
        if (dollar >= 0) s = s.substring(0, dollar);

        // Strip path / query
        int slash = s.indexOf('/');
        if (slash >= 0) s = s.substring(0, slash);

        // Strip port
        int colon = s.indexOf(':');
        if (colon >= 0) s = s.substring(0, colon);

        // Strip ABP filter suffixes (^ or |)
        while (s.endsWith("^") || s.endsWith("|")) {
            s = s.substring(0, s.length() - 1);
        }

        // Strip wildcard prefixes
        if (s.startsWith("*.")) {
            s = s.substring(2);
        }
        if (s.startsWith(".")) {
            s = s.substring(1);
        }

        // Strip trailing dots
        while (s.endsWith(".")) {
            s = s.substring(0, s.length() - 1);
        }
        return s;
    }
}
