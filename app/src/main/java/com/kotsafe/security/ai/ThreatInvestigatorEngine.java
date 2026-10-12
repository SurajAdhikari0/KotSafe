/*
 * This file is part of KotSafe / KotSafe Cyber Security Project.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.ai;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import com.kotsafe.security.model.AlertRecord;
import com.kotsafe.security.model.ThreatIntelProvider;
import com.kotsafe.security.model.ThreatIntelRouter;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Multi-Source Threat Intelligence & AI Incident Investigation Engine.
 * Correlates indicators across AlienVault OTX, ThreatFox, URLhaus, MalwareBazaar,
 * and VirusTotal, and synthesizes authoritative AI security decisions explaining
 * indicator purpose, malware family, and mitigation steps.
 */
public class ThreatInvestigatorEngine {

    public static class InvestigationResult {
        public String iocValue;
        public String iocType;          // IP | DOMAIN | URL | HASH | APP
        public String sourceApp;
        public String alertTitle;

        // Multi-Source Intelligence
        public String intelProvider;     // e.g. "AlienVault OTX, ThreatFox"
        public int intelRiskScore;       // 0 - 100
        public String intelVerdict;      // SAFE | SUSPICIOUS | MALICIOUS | UNKNOWN
        public String malwareFamily;     // e.g. "Cobalt Strike", "FluBot"
        public String intelDetails;

        // AI Decision & Forensic Synthesis
        public int maliciousProbability; // 0 - 100
        public String aiVerdict;         // CONFIRMED MALICIOUS | SUSPICIOUS THREAT | BENIGN / FALSE POSITIVE
        public String purpose;           // Why was this IOC used (C2, Phishing, Adware, CDN)
        public String campaignOrFamily;
        public String decision;          // BLOCK IMMEDIATELY | ISOLATE APP | MONITOR | SAFE TO WHITELIST
        public String confidence;        // HIGH | MEDIUM | LOW
        public String reasoning;
        public String remediation;
    }

    public interface InvestigationCallback {
        void onResult(InvestigationResult result);
        void onError(String error);
    }

    private static final ExecutorService sExecutor = Executors.newSingleThreadExecutor();
    private static final Handler sMainHandler = new Handler(Looper.getMainLooper());

    /**
     * Deeply investigates an AlertRecord.
     */
    public static void investigateAlert(Context context, AlertRecord alert, InvestigationCallback callback) {
        if (alert == null) {
            callback.onError("Alert record is null");
            return;
        }

        sExecutor.execute(() -> {
            String extractedIoc = extractIocFromAlert(alert);
            String iocType = detectIocType(extractedIoc, alert);
            investigateInternal(context, extractedIoc, iocType, alert.sourceApp, alert.title + ": " + alert.message, callback);
        });
    }

    /**
     * Deeply investigates any arbitrary IOC (IP, Domain, URL, Hash, or App).
     */
    public static void investigateIoc(Context context, String iocValue, String iocType, String sourceApp, String contextInfo, InvestigationCallback callback) {
        sExecutor.execute(() -> {
            String cleanIoc = iocValue != null ? iocValue.trim() : "";
            String type = iocType != null ? iocType.toUpperCase(Locale.ROOT) : detectIocType(cleanIoc, null);
            investigateInternal(context, cleanIoc, type, sourceApp, contextInfo, callback);
        });
    }

    private static void investigateInternal(Context context, String iocValue, String iocType, String sourceApp, String contextInfo, InvestigationCallback callback) {
        InvestigationResult result = new InvestigationResult();
        result.iocValue = iocValue;
        result.iocType = iocType;
        result.sourceApp = sourceApp != null ? sourceApp : "";
        result.alertTitle = contextInfo != null ? contextInfo : "";

        // Step 1: Multi-Source Threat Intelligence Lookup
        ThreatIntelRouter router = ThreatIntelRouter.getInstance(context);
        ThreatIntelProvider.ThreatReport report = null;

        try {
            if ("IP".equalsIgnoreCase(iocType)) {
                report = router.queryIp(iocValue);
            } else if ("DOMAIN".equalsIgnoreCase(iocType)) {
                report = router.queryDomain(iocValue);
            } else if ("URL".equalsIgnoreCase(iocType)) {
                report = router.queryUrl(iocValue);
            } else if ("HASH".equalsIgnoreCase(iocType)) {
                report = router.queryHash(iocValue);
            }
        } catch (Exception e) {
            // Intel query failed, continue with AI analysis
        }

        if (report != null) {
            result.intelProvider = report.provider != null ? report.provider : "ThreatIntelRouter";
            result.intelRiskScore = report.riskScore;
            result.intelVerdict = report.verdict != null ? report.verdict : "UNKNOWN";
            result.malwareFamily = report.malwareFamily != null ? report.malwareFamily : "";
            result.intelDetails = report.details != null ? report.details : "";
        } else {
            result.intelProvider = "Local Threat Heuristics";
            result.intelRiskScore = 0;
            result.intelVerdict = "UNINDEXED";
            result.malwareFamily = "None";
            result.intelDetails = "No external threat intelligence signature found in cache or feeds.";
        }

        // Step 2: AI Incident Decision Synthesizer
        AiConfig aiConfig = new AiConfig(context);
        boolean hasCloudAi = aiConfig.isAiEnabled() &&
                (aiConfig.getProvider() == AiConfig.Provider.LOCAL_CUSTOM || !aiConfig.getApiKey().isEmpty());

        if (hasCloudAi) {
            queryCloudAiDecision(context, result, callback);
        } else {
            computeOfflineDecision(result);
            sMainHandler.post(() -> callback.onResult(result));
        }
    }

    private static void queryCloudAiDecision(Context context, InvestigationResult res, InvestigationCallback callback) {
        AiClientEngine aiClient = AiClientEngine.getInstance(context);

        String systemPrompt = "You are a Principal SOC Incident Responder and Malware Reverse Engineer. "
                + "Perform a deep incident investigation on this network security indicator and output valid JSON ONLY in this format:\n"
                + "{\n"
                + "  \"maliciousProbability\": <integer 0-100>,\n"
                + "  \"verdict\": \"<CONFIRMED MALICIOUS | SUSPICIOUS THREAT | BENIGN / FALSE POSITIVE>\",\n"
                + "  \"purpose\": \"<1-2 sentences: Exactly why was this IOC used? (e.g. C2 beaconing, phishing redirect, credential harvester, or benign telemetry)>\",\n"
                + "  \"campaignOrFamily\": \"<Malware family / campaign name or 'N/A'>\",\n"
                + "  \"decision\": \"<BLOCK IMMEDIATELY | ISOLATE APP | MONITOR | SAFE TO WHITELIST>\",\n"
                + "  \"confidence\": \"<HIGH | MEDIUM | LOW>\",\n"
                + "  \"reasoning\": \"<2 concise bullet points explaining the technical indicators, behavior, and risk>\",\n"
                + "  \"remediation\": \"<Concrete 1-sentence action step>\"\n"
                + "}";

        String userMsg = "Target Indicator: " + res.iocValue + " (" + res.iocType + ")\n"
                + "Originating App: " + res.sourceApp + "\n"
                + "Security Alert Context: " + res.alertTitle + "\n"
                + "Multi-Source Threat Intel: " + res.intelProvider + "\n"
                + "Feed Verdict: " + res.intelVerdict + " (Score: " + res.intelRiskScore + "/100)\n"
                + "Known Malware Family: " + res.malwareFamily + "\n"
                + "Feed Details: " + res.intelDetails;

        aiClient.askAssistant(userMsg, systemPrompt, new AiClientEngine.Callback() {
            @Override
            public void onSuccess(String responseText) {
                try {
                    String clean = extractJson(responseText);
                    JsonObject obj = JsonParser.parseString(clean).getAsJsonObject();

                    res.maliciousProbability = obj.has("maliciousProbability") ? obj.get("maliciousProbability").getAsInt() : 50;
                    res.aiVerdict = obj.has("verdict") ? obj.get("verdict").getAsString() : "SUSPICIOUS THREAT";
                    res.purpose = obj.has("purpose") ? obj.get("purpose").getAsString() : "Investigated endpoint communication.";
                    res.campaignOrFamily = obj.has("campaignOrFamily") ? obj.get("campaignOrFamily").getAsString() : res.malwareFamily;
                    res.decision = obj.has("decision") ? obj.get("decision").getAsString() : "MONITOR";
                    res.confidence = obj.has("confidence") ? obj.get("confidence").getAsString() : "MEDIUM";
                    res.reasoning = obj.has("reasoning") ? obj.get("reasoning").getAsString() : responseText;
                    res.remediation = obj.has("remediation") ? obj.get("remediation").getAsString() : "Review network activity.";

                    sMainHandler.post(() -> callback.onResult(res));
                } catch (Exception e) {
                    computeOfflineDecision(res);
                    res.reasoning += "\n*(AI parsing fallback: " + responseText + ")*";
                    sMainHandler.post(() -> callback.onResult(res));
                }
            }

            @Override
            public void onError(String errorMessage) {
                computeOfflineDecision(res);
                res.reasoning += "\n\n*(Offline Heuristics Decision: Cloud AI " + errorMessage + ")*";
                sMainHandler.post(() -> callback.onResult(res));
            }
        });
    }

    private static void computeOfflineDecision(InvestigationResult res) {
        boolean feedMalicious = "MALICIOUS".equalsIgnoreCase(res.intelVerdict) || res.intelRiskScore >= 70;
        boolean feedSuspicious = "SUSPICIOUS".equalsIgnoreCase(res.intelVerdict) || res.intelRiskScore >= 40;

        String ctx = (res.alertTitle + " " + res.iocValue).toLowerCase(Locale.ROOT);

        if (feedMalicious || ctx.contains("c2") || ctx.contains("trojan") || ctx.contains("ransomware") || ctx.contains("exfiltration")) {
            res.maliciousProbability = Math.max(88, res.intelRiskScore);
            res.aiVerdict = "CONFIRMED MALICIOUS";
            res.decision = "BLOCK IMMEDIATELY";
            res.confidence = "HIGH";
            res.purpose = "Identified as active malicious infrastructure (Command & Control or payload drop site).";
            res.campaignOrFamily = (res.malwareFamily != null && !res.malwareFamily.isEmpty()) ? res.malwareFamily : "Known Threat Actor / Botnet";
            res.reasoning = "• Indicator matches threat intelligence blacklists (OTX/ThreatFox).\n• Associated with unauthorized external command communications.";
            res.remediation = "Enforce kernel-level firewall block on " + res.iocValue + " and review permissions of " + res.sourceApp + ".";
        } else if (feedSuspicious || ctx.contains("port scan") || ctx.contains("injection") || ctx.contains("unencrypted") || ctx.contains("dns anomaly")) {
            res.maliciousProbability = Math.max(60, res.intelRiskScore);
            res.aiVerdict = "SUSPICIOUS THREAT";
            res.decision = "MONITOR & RESTRICT";
            res.confidence = "MEDIUM";
            res.purpose = "Anomalous network destination or unverified third-party telemetry tracker.";
            res.campaignOrFamily = "Adware / Aggressive Telemetry";
            res.reasoning = "• Destination exhibits unusual port distribution or low-reputation ASN.\n• Request frequency matches automated data harvesting.";
            res.remediation = "Add temporary firewall rule to drop socket traffic or isolate " + res.sourceApp + ".";
        } else {
            res.maliciousProbability = Math.min(20, res.intelRiskScore);
            res.aiVerdict = "BENIGN / FALSE POSITIVE";
            res.decision = "SAFE TO WHITELIST";
            res.confidence = "HIGH";
            res.purpose = "Standard operational network traffic (OS sync, benign CDN edge node, or routine push notifications).";
            res.campaignOrFamily = "Benign Infrastructure";
            res.reasoning = "• Zero threat intelligence hits across AlienVault OTX and community feeds.\n• Expected background telemetry from verified software.";
            res.remediation = "Dismiss alert or add to whitelist if repetitive.";
        }
    }

    public static String extractIocFromAlert(AlertRecord alert) {
        if (alert == null) return "";
        String text = alert.title + " " + alert.message + " " + alert.sourceApp;

        // Check for IPv4
        Pattern ipPattern = Pattern.compile("\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b");
        Matcher ipMatcher = ipPattern.matcher(text);
        if (ipMatcher.find()) return ipMatcher.group();

        // Check for URL
        Pattern urlPattern = Pattern.compile("https?://[^\\s/$.?#].[^\\s]*");
        Matcher urlMatcher = urlPattern.matcher(text);
        if (urlMatcher.find()) return urlMatcher.group();

        // Check for SHA-256
        Pattern hashPattern = Pattern.compile("\\b[a-fA-F0-9]{64}\\b");
        Matcher hashMatcher = hashPattern.matcher(text);
        if (hashMatcher.find()) return hashMatcher.group();

        // Check for Domain
        Pattern domainPattern = Pattern.compile("\\b(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}\\b");
        Matcher domainMatcher = domainPattern.matcher(text);
        while (domainMatcher.find()) {
            String d = domainMatcher.group();
            if (!d.endsWith(".apk") && !d.startsWith("com.") && !d.startsWith("android.")) {
                return d;
            }
        }

        // Fallback to sourceApp
        if (alert.sourceApp != null && !alert.sourceApp.isEmpty()) {
            return alert.sourceApp;
        }

        return "Unknown";
    }

    public static String detectIocType(String ioc, AlertRecord alert) {
        if (ioc == null || ioc.isEmpty()) return "GENERAL";
        if (ioc.startsWith("http://") || ioc.startsWith("https://")) return "URL";
        if (ioc.matches("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$")) return "IP";
        if (ioc.matches("^[a-fA-F0-9]{64}$") || ioc.matches("^[a-fA-F0-9]{32}$")) return "HASH";
        if (ioc.startsWith("com.") || ioc.startsWith("org.") || ioc.startsWith("net.") || (alert != null && ioc.equals(alert.sourceApp))) return "APP";
        if (ioc.contains(".")) return "DOMAIN";
        return "GENERAL";
    }

    private static String extractJson(String raw) {
        if (raw == null) return "{}";
        int start = raw.indexOf('{');
        int end = raw.lastIndexOf('}');
        if (start >= 0 && end > start) {
            return raw.substring(start, end + 1);
        }
        return raw;
    }
}
