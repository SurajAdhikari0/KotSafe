/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import android.content.Context;

import com.kotsafe.security.Log;
import com.kotsafe.security.Utils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Risk Correlation Engine — combines signals from multiple sensors
 * to detect threats that no single sensor can identify alone.
 *
 * Correlation rules (examples):
 *   - App with hidden service + contacts suspicious C2 IP → HIGH risk
 *   - Side-loaded APK + accesses sensitive permissions + DGA domain → CRITICAL
 *   - App with 0 hits (new install) + communicates on port 4444 → HIGH
 *   - Same domain contacted by 3+ different apps → possible SDK C2
 *   - Hash flagged by 2+ TI providers → confirmed malware
 *
 * All results are stored in EvidenceDbHelper as correlated evidence items.
 */
public class RiskCorrelationEngine {
    private static final String TAG = "RiskCorrelationEngine";

    public static class CorrelationResult {
        public int finalRiskScore;
        public String verdict;
        public String packageName;
        public List<String> signals = new ArrayList<>();
        public String recommendation;

        public CorrelationResult(int score, String verdict) {
            this.finalRiskScore = score;
            this.verdict = verdict;
        }
    }

    private final Context mContext;
    private final SecurityDatabase mDb;

    public RiskCorrelationEngine(Context context) {
        mContext = context.getApplicationContext();
        mDb = SecurityDatabase.getInstance(context);
    }

    // ─── Correlate app behaviour ──────────────────────────────────────────────

    /**
     * Correlates all evidence for a given package name.
     * Returns a combined risk verdict.
     */
    public CorrelationResult correlateApp(String packageName) {
        boolean isSelf = packageName != null && packageName.equals(mContext.getPackageName());
        if (isSelf) {
            CorrelationResult res = new CorrelationResult(0, "CLEAN");
            res.packageName = packageName;
            res.signals = java.util.Collections.singletonList("KotSafe Security Sentinel (Self Host Application)");
            res.recommendation = "Self Core Protection Engine";
            return res;
        }

        boolean isSys = packageName != null && Utils.isSystemApp(mContext, packageName);

        int score = 0;
        List<String> signals = new ArrayList<>();
        boolean planeStatic = false;
        boolean planeNetwork = false;
        boolean planeBehavioral = false;

        // Signal 1: Hash flagged by TI or YARA
        List<FileHashEntry> hashes = FileHashDbHelper.getInstance(mContext)
                .queryHashesByPackage(packageName);
        int maliciousHashCount = 0;
        int suspiciousHashCount = 0;
        for (FileHashEntry h : hashes) {
            if (FileHashEntry.THREAT_MALICIOUS.equals(h.threatStatus)) maliciousHashCount++;
            else if (FileHashEntry.THREAT_SUSPICIOUS.equals(h.threatStatus)) suspiciousHashCount++;
        }
        if (maliciousHashCount > 0) {
            score += 50;
            planeStatic = true;
            signals.add("Hash confirmed malicious by Threat Intelligence (" + maliciousHashCount + " APK segments)");
        } else if (suspiciousHashCount > 0) {
            score += 20;
            signals.add("Hash flagged suspicious by Threat Intelligence");
        }

        // Signal 2: Hidden service (no launcher)?
        boolean isHiddenService = false;
        for (FileHashEntry h : hashes) {
            if (h.isServiceApp && !h.isSystemApp && h.threatStatus != null
                    && h.threatStatus.equals(FileHashEntry.THREAT_SUSPICIOUS)) {
                isHiddenService = true;
                break;
            }
        }
        if (isHiddenService) {
            score += 25;
            planeBehavioral = true;
            signals.add("Hidden background service (no launcher activity)");
        }

        // Signal 3: Network connections to suspicious endpoints?
        List<UrlVisitLog> visits = mDb.logs().getVisitsForPackage(packageName, 50);
        int suspiciousVisits = 0, maliciousVisits = 0;
        Map<String, Integer> domainCount = new HashMap<>();
        for (UrlVisitLog v : visits) {
            if ("MALICIOUS".equals(v.verdict)) maliciousVisits++;
            else if ("SUSPICIOUS".equals(v.verdict)) suspiciousVisits++;
            String dom = v.domain;
            if (dom != null && !SecurityBlocklistManager.isOfficialDomain(dom)) {
                domainCount.put(dom, domainCount.getOrDefault(dom, 0) + 1);
            }
        }
        if (maliciousVisits > 0) {
            score += 35;
            planeNetwork = true;
            signals.add("Connected to " + maliciousVisits + " confirmed malicious endpoints");
        }
        if (suspiciousVisits > 0) {
            score += 15;
            signals.add("Connected to " + suspiciousVisits + " suspicious endpoints");
        }

        // Signal 4: Beaconing pattern (same non-official domain hit many times)?
        for (Map.Entry<String, Integer> e : domainCount.entrySet()) {
            String domain = e.getKey();
            if (e.getValue() >= 10 && !SecurityBlocklistManager.isOfficialDomain(domain)) {
                boolean isSuspiciousHost = SecurityBlocklistManager.getInstance(mContext).isDomainBlocked(domain)
                        || domain.endsWith(".onion") || domain.endsWith(".xyz") || domain.endsWith(".top")
                        || suspiciousVisits > 0 || maliciousVisits > 0;
                if (isSuspiciousHost) {
                    score += 15;
                    planeNetwork = true;
                    signals.add("Possible C2 beaconing cadence to untrusted endpoint: " + domain + " (" + e.getValue() + " hits)");
                    break;
                }
            }
        }

        // Signal 5: Heuristic analysis of file
        Set<String> uniqueFindings = new HashSet<>();
        int heuristicScore = 0;
        for (FileHashEntry h : hashes) {
            HeuristicAnalyzer.HeuristicResult hr = HeuristicAnalyzer.analyzeFile(h);
            for (String f : hr.findings) {
                if (uniqueFindings.add(f)) {
                    heuristicScore += hr.riskScore / 4;
                    signals.add(f);
                }
            }
        }
        score += Math.min(30, heuristicScore);

        // Signal 6: Sideloaded installer check (Non-system only)
        if (!isSys && packageName != null) {
            try {
                android.content.pm.PackageManager pm = mContext.getPackageManager();
                String installer = pm.getInstallerPackageName(packageName);
                if (installer == null || (!installer.equals("com.android.vending") && !installer.contains("fdroid"))) {
                    score += 15;
                    planeBehavioral = true;
                    signals.add("Sideloaded / untrusted installation origin: " + (installer != null ? installer : "Unknown source"));
                }
            } catch (Exception ignored) {}
        }

        // Multi-Plane True Positive Correlation Rule:
        int correlatedPlanes = (planeStatic ? 1 : 0) + (planeNetwork ? 1 : 0) + (planeBehavioral ? 1 : 0);
        if (correlatedPlanes >= 2 && !isSys) {
            if (planeStatic) {
                score = Math.max(85, score);
                signals.add("HIGH-CONFIDENCE TRUE POSITIVE: Corroborated with verified static IOC across " + correlatedPlanes + " independent telemetry planes");
            } else {
                // Without static malware corroboration, behavioral + network anomalies are capped at SUSPICIOUS (Monitored)
                score = Math.max(50, Math.min(score, 65));
                signals.add("ELEVATED ANOMALY: Corroborated behavioral & network telemetry without confirmed static malware IOC (Monitored)");
            }
        }

        // System App & Service Safeguard:
        // System components are NEVER treated as malware; capped strictly at LOW
        String verdict;
        if (isSys) {
            score = (score > 0) ? Math.min(12, score) : 0;
            verdict = (score > 0) ? "LOW" : EvidenceDbHelper.VERDICT_SAFE;
            if (score > 0) {
                signals.add("System OS Service - Monitored for AI Log & Activity Baseline Analysis");
            }
        } else {
            score = Math.min(100, score);
            verdict = score >= 75 ? EvidenceDbHelper.VERDICT_MALICIOUS
                    : score >= 40 ? EvidenceDbHelper.VERDICT_SUSPICIOUS
                    : score >= 20 ? "LOW"
                    : EvidenceDbHelper.VERDICT_SAFE;
        }

        CorrelationResult result = new CorrelationResult(score, verdict);
        result.packageName = packageName;
        result.signals = signals;
        if (isSys) {
            result.recommendation = "System OS Service - Low Risk / Monitored (Future AI baseline telemetry).";
        } else {
            result.recommendation = buildRecommendation(score, signals);
        }

        // Store correlation result as evidence if suspicious/malicious or system low-risk
        if (score >= 40 && !isSys) {
            String detail = signals.isEmpty() ? "No additional details" : "• " + String.join("\n• ", signals);
            mDb.evidence().insertEvidence(
                    "CORRELATION",
                    "Correlated threat: " + packageName,
                    detail, score, verdict, packageName,
                    packageName, "APP", "CORRELATION"
            );
            Log.i(TAG, "Correlation result for " + packageName +
                    ": score=" + score + " verdict=" + verdict);
        }

        return result;
    }

    /**
     * Correlates all evidence from the last scan.
     * Looks for cross-app signals (shared C2, shared SDK, etc.)
     */
    public List<CorrelationResult> correlateScanResults() {
        List<CorrelationResult> results = new ArrayList<>();

        // Cross-app correlation: find domains contacted by 3+ distinct apps
        Map<String, Set<String>> domainToApps = new HashMap<>();
        List<UrlVisitLog> recentVisits = mDb.logs().getRecentVisits(500);
        for (UrlVisitLog v : recentVisits) {
            if (v.domain == null || v.packageName == null) continue;
            domainToApps.computeIfAbsent(v.domain, k -> new HashSet<>()).add(v.packageName);
        }

        for (Map.Entry<String, Set<String>> e : domainToApps.entrySet()) {
            Set<String> apps = e.getValue();
            if (apps.size() >= 3) {
                // Multiple distinct apps sharing same domain — possible SDK tracking or malware C2
                String domain = e.getKey();
                HeuristicAnalyzer.HeuristicResult hr = HeuristicAnalyzer.analyzeConnection(
                        domain, null, 443, null);

                if (hr.isSuspicious || hr.isMalicious) {
                    int score = Math.min(100, 30 + hr.riskScore);
                    CorrelationResult cr = new CorrelationResult(score,
                            hr.isMalicious ? EvidenceDbHelper.VERDICT_MALICIOUS
                                    : EvidenceDbHelper.VERDICT_SUSPICIOUS);
                    cr.signals.add("Domain " + domain + " contacted by " + apps.size() + " distinct apps");
                    cr.signals.addAll(hr.findings);
                    cr.recommendation = "Investigate shared domain: " + domain;
                    results.add(cr);

                    List<String> appList = new ArrayList<>(apps);
                    mDb.evidence().insertEvidence(
                            "CORRELATION",
                            "Shared suspicious domain: " + domain,
                            "Contacted by " + apps.size() + " distinct apps: " + appList.subList(0, Math.min(3, appList.size())),
                            score, cr.verdict, null, domain, "DOMAIN", "CORRELATION"
                    );
                }
            }
        }

        return results;
    }

    private String buildRecommendation(int score, List<String> signals) {
        if (score >= 75) return "⛔ High confidence threat. Block immediately and consider uninstall.";
        if (score >= 50) return "⚠️ Suspicious activity confirmed. Review permissions and network access.";
        if (score >= 30) return "ℹ️ Low-risk indicators found. Monitor for further activity.";
        return "✅ No significant threats detected.";
    }
}
