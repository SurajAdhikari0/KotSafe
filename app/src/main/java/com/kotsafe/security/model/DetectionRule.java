/*
 * This file is part of KotSafe.
 *
 * KotSafe is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * KotSafe is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with KotSafe.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2026 KotSafe Cyber Security Project
 */

package com.kotsafe.security.model;

import android.content.pm.PackageInfo;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Represents an advanced SIEM / Microsoft Sentinel / Sigma-style detection rule.
 * Can be fetched dynamically from a GitHub repository or loaded from bundled assets.
 */
public class DetectionRule implements Serializable {
    public static final String TARGET_APP = "app";
    public static final String TARGET_NETWORK = "network";
    public static final String TARGET_FILE = "file";

    public static final String SEVERITY_CRITICAL = "CRITICAL";
    public static final String SEVERITY_HIGH = "HIGH";
    public static final String SEVERITY_MEDIUM = "MEDIUM";
    public static final String SEVERITY_LOW = "LOW";
    public static final String SEVERITY_INFO = "INFORMATIONAL";

    public static final String TRIGGER_ON_SCAN = "ON_SCAN";
    public static final String TRIGGER_REALTIME_NET = "REALTIME_NET";
    public static final String TRIGGER_PERIODIC = "PERIODIC";

    public String id = "";
    public String name = "";
    public String severity = SEVERITY_MEDIUM;
    public String description = "";
    public String target = TARGET_APP;
    public String triggerSchedule = TRIGGER_ON_SCAN;
    public List<String> mitreTechniques = new ArrayList<>();
    public List<String> tactics = new ArrayList<>();
    public String matchType = "all"; // "all" or "any"
    public List<RuleCondition> conditions = new ArrayList<>();
    public String remediation = "";
    public boolean enabled = true;
    public long version = 1;

    // Direct Indicators of Compromise (IOCs)
    public List<String> iocDomains = new ArrayList<>();
    public List<String> iocIps = new ArrayList<>();
    public List<String> iocSha256 = new ArrayList<>();
    public List<String> iocUrls = new ArrayList<>();
    public String lastMatchedIoc = "";

    public static class RuleCondition implements Serializable {
        public String field = "";
        public String operator = "equals";
        public Object value;
        public List<String> valuesList = new ArrayList<>();

        public boolean evaluate(Object targetValue) {
            if (targetValue == null && !"is_null".equals(operator)) {
                return false;
            }

            switch (operator.toLowerCase(Locale.ROOT)) {
                case "equals":
                    return String.valueOf(targetValue).equalsIgnoreCase(String.valueOf(value));

                case "not_equals":
                    return !String.valueOf(targetValue).equalsIgnoreCase(String.valueOf(value));

                case "contains":
                    return String.valueOf(targetValue).toLowerCase(Locale.ROOT)
                            .contains(String.valueOf(value).toLowerCase(Locale.ROOT));

                case "contains_any":
                    if (targetValue instanceof List) {
                        List<?> list = (List<?>) targetValue;
                        for (String v : valuesList) {
                            for (Object item : list) {
                                if (String.valueOf(item).equalsIgnoreCase(v) ||
                                        String.valueOf(item).toLowerCase(Locale.ROOT).contains(v.toLowerCase(Locale.ROOT))) {
                                    return true;
                                }
                            }
                        }
                    } else {
                        String s = String.valueOf(targetValue).toLowerCase(Locale.ROOT);
                        for (String v : valuesList) {
                            if (s.contains(v.toLowerCase(Locale.ROOT))) {
                                return true;
                            }
                        }
                    }
                    return false;

                case "contains_all":
                    if (targetValue instanceof List) {
                        List<?> list = (List<?>) targetValue;
                        for (String v : valuesList) {
                            boolean found = false;
                            for (Object item : list) {
                                if (String.valueOf(item).equalsIgnoreCase(v) ||
                                        String.valueOf(item).toLowerCase(Locale.ROOT).contains(v.toLowerCase(Locale.ROOT))) {
                                    found = true;
                                    break;
                                }
                            }
                            if (!found) return false;
                        }
                        return true;
                    }
                    return false;

                case "in":
                    if (valuesList != null && !valuesList.isEmpty()) {
                        String s = String.valueOf(targetValue).trim();
                        for (String v : valuesList) {
                            if (s.equalsIgnoreCase(v.trim())) return true;
                        }
                    }
                    return false;

                case "regex":
                    try {
                        String patternStr = String.valueOf(value);
                        Pattern p = Pattern.compile(patternStr, Pattern.CASE_INSENSITIVE);
                        return p.matcher(String.valueOf(targetValue)).find();
                    } catch (Exception e) {
                        return false;
                    }

                case "greater_than":
                    try {
                        double v1 = Double.parseDouble(String.valueOf(targetValue));
                        double v2 = Double.parseDouble(String.valueOf(value));
                        return v1 > v2;
                    } catch (Exception e) {
                        return false;
                    }

                case "less_than":
                    try {
                        double v1 = Double.parseDouble(String.valueOf(targetValue));
                        double v2 = Double.parseDouble(String.valueOf(value));
                        return v1 < v2;
                    } catch (Exception e) {
                        return false;
                    }

                default:
                    return false;
            }
        }
    }

    public static DetectionRule fromJson(JSONObject json) {
        DetectionRule rule = new DetectionRule();
        try {
            rule.id = json.optString("id", "RULE-CUSTOM");
            rule.name = json.optString("name", "Untitled Rule");
            rule.severity = json.optString("severity", SEVERITY_MEDIUM).toUpperCase(Locale.ROOT);
            rule.description = json.optString("description", "");
            rule.target = json.optString("target", TARGET_APP).toLowerCase(Locale.ROOT);
            rule.triggerSchedule = json.optString("triggerSchedule", TRIGGER_ON_SCAN).toUpperCase(Locale.ROOT);
            rule.remediation = json.optString("remediation", "");
            rule.enabled = json.optBoolean("enabled", true);
            rule.version = json.optLong("version", 1);

            JSONArray mitreArr = json.optJSONArray("mitreTechniques");
            if (mitreArr != null) {
                for (int i = 0; i < mitreArr.length(); i++) {
                    rule.mitreTechniques.add(mitreArr.getString(i));
                }
            }

            JSONArray tacticsArr = json.optJSONArray("tactics");
            if (tacticsArr != null) {
                for (int i = 0; i < tacticsArr.length(); i++) {
                    rule.tactics.add(tacticsArr.getString(i));
                }
            }

            JSONObject logicObj = json.optJSONObject("logic");
            if (logicObj != null) {
                rule.matchType = logicObj.optString("match", "all").toLowerCase(Locale.ROOT);
                JSONArray condArr = logicObj.optJSONArray("conditions");
                if (condArr != null) {
                    for (int i = 0; i < condArr.length(); i++) {
                        JSONObject cJson = condArr.getJSONObject(i);
                        RuleCondition cond = new RuleCondition();
                        cond.field = cJson.optString("field", "");
                        cond.operator = cJson.optString("operator", "equals").toLowerCase(Locale.ROOT);
                        if (cJson.has("value")) {
                            cond.value = cJson.get("value");
                        }
                        JSONArray valsArr = cJson.optJSONArray("values");
                        if (valsArr != null) {
                            for (int v = 0; v < valsArr.length(); v++) {
                                cond.valuesList.add(valsArr.getString(v));
                            }
                        }
                        rule.conditions.add(cond);
                    }
                }
            }
            JSONObject iocsObj = json.optJSONObject("iocs");
            if (iocsObj != null) {
                JSONArray domArr = iocsObj.optJSONArray("domains");
                if (domArr != null) {
                    for (int i = 0; i < domArr.length(); i++) rule.iocDomains.add(domArr.getString(i));
                }
                JSONArray ipArr = iocsObj.optJSONArray("ips");
                if (ipArr != null) {
                    for (int i = 0; i < ipArr.length(); i++) rule.iocIps.add(ipArr.getString(i));
                }
                JSONArray shaArr = iocsObj.optJSONArray("sha256");
                if (shaArr != null) {
                    for (int i = 0; i < shaArr.length(); i++) rule.iocSha256.add(shaArr.getString(i));
                }
                JSONArray urlArr = iocsObj.optJSONArray("urls");
                if (urlArr != null) {
                    for (int i = 0; i < urlArr.length(); i++) rule.iocUrls.add(urlArr.getString(i));
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return rule;
    }

    public boolean hasIocs() {
        return !iocDomains.isEmpty() || !iocIps.isEmpty() || !iocSha256.isEmpty() || !iocUrls.isEmpty();
    }

    public String getIocsSummary() {
        List<String> parts = new ArrayList<>();
        if (!iocDomains.isEmpty()) parts.add(iocDomains.size() + " Domains");
        if (!iocIps.isEmpty()) parts.add(iocIps.size() + " IPs");
        if (!iocSha256.isEmpty()) parts.add(iocSha256.size() + " Hashes");
        if (!iocUrls.isEmpty()) parts.add(iocUrls.size() + " URLs");
        if (parts.isEmpty()) return "Behavioral Logic Only";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < parts.size(); i++) {
            if (i > 0) sb.append(" • ");
            sb.append(parts.get(i));
        }
        return sb.toString();
    }

    /**
     * Evaluates the rule against an installed application.
     */
    public boolean evaluateApp(PackageInfo pkgInfo, boolean isSideloaded, List<String> permissions) {
        return evaluateApp(pkgInfo, isSideloaded, permissions, null);
    }

    public boolean evaluateApp(PackageInfo pkgInfo, boolean isSideloaded, List<String> permissions, String sha256) {
        if (!enabled || !TARGET_APP.equalsIgnoreCase(target)) {
            return false;
        }

        // 1. Direct Hash IOC Match
        if (sha256 != null && !sha256.isEmpty() && !iocSha256.isEmpty()) {
            for (String h : iocSha256) {
                if (sha256.equalsIgnoreCase(h.trim())) {
                    lastMatchedIoc = "Known Threat Hash IOC: " + h;
                    return true;
                }
            }
        }

        if (conditions.isEmpty()) {
            return false;
        }

        // 2. Behavioral Condition Logic
        boolean isMatchAll = "all".equalsIgnoreCase(matchType);
        for (RuleCondition cond : conditions) {
            boolean condMatched = false;
            switch (cond.field.toLowerCase(Locale.ROOT)) {
                case "issideloaded":
                    condMatched = cond.evaluate(isSideloaded);
                    break;
                case "packagename":
                    condMatched = (pkgInfo != null) && cond.evaluate(pkgInfo.packageName);
                    break;
                case "permissions":
                    condMatched = (permissions != null) && cond.evaluate(permissions);
                    break;
                case "targetsdkversion":
                    if (pkgInfo != null && pkgInfo.applicationInfo != null) {
                        condMatched = cond.evaluate(pkgInfo.applicationInfo.targetSdkVersion);
                    }
                    break;
                default:
                    condMatched = false;
                    break;
            }

            if (isMatchAll && !condMatched) {
                return false;
            }
            if (!isMatchAll && condMatched) {
                lastMatchedIoc = "Behavioral: " + cond.field + " (" + cond.operator + ")";
                return true;
            }
        }

        if (isMatchAll) {
            lastMatchedIoc = "Multi-Factor Behavioral Heuristic";
        }
        return isMatchAll;
    }

    /**
     * Evaluates the rule against network flow indicators (domain, ip, port, entropy).
     */
    public boolean evaluateNetwork(String domain, String ip, int port, double dgaEntropy) {
        if (!enabled || !TARGET_NETWORK.equalsIgnoreCase(target)) {
            return false;
        }

        // 1. Direct Domain & IP IOC Matching
        if (domain != null && !domain.isEmpty() && !iocDomains.isEmpty()) {
            String lowerDomain = domain.toLowerCase(Locale.ROOT);
            for (String dIoc : iocDomains) {
                String cleanIoc = dIoc.toLowerCase(Locale.ROOT).trim();
                if (lowerDomain.equals(cleanIoc) || lowerDomain.endsWith("." + cleanIoc) || lowerDomain.contains(cleanIoc)) {
                    lastMatchedIoc = "Known C2 Domain IOC: " + dIoc;
                    return true;
                }
            }
        }

        if (ip != null && !ip.isEmpty() && !iocIps.isEmpty()) {
            for (String ipIoc : iocIps) {
                if (ip.trim().equalsIgnoreCase(ipIoc.trim())) {
                    lastMatchedIoc = "Known Malicious IP IOC: " + ipIoc;
                    return true;
                }
            }
        }

        if (conditions.isEmpty()) {
            return false;
        }

        // 2. Behavioral Condition Logic
        boolean isMatchAll = "all".equalsIgnoreCase(matchType);
        for (RuleCondition cond : conditions) {
            boolean condMatched = false;
            switch (cond.field.toLowerCase(Locale.ROOT)) {
                case "domain":
                    condMatched = (domain != null) && cond.evaluate(domain);
                    break;
                case "ip":
                    condMatched = (ip != null) && cond.evaluate(ip);
                    break;
                case "port":
                    condMatched = cond.evaluate(port);
                    break;
                case "dgaentropy":
                    condMatched = cond.evaluate(dgaEntropy);
                    break;
                default:
                    condMatched = false;
                    break;
            }

            if (isMatchAll && !condMatched) {
                return false;
            }
            if (!isMatchAll && condMatched) {
                lastMatchedIoc = "Behavioral: " + cond.field + " (" + cond.operator + ")";
                return true;
            }
        }

        if (isMatchAll) {
            lastMatchedIoc = "Network Behavioral Pattern";
        }
        return isMatchAll;
    }

    /**
     * Evaluates the rule against storage or APK file contents.
     */
    public boolean evaluateFile(String filePath, String fileName, List<String> contentStrings) {
        return evaluateFile(filePath, fileName, contentStrings, null);
    }

    public boolean evaluateFile(String filePath, String fileName, List<String> contentStrings, String sha256) {
        if (!enabled || !TARGET_FILE.equalsIgnoreCase(target)) {
            return false;
        }

        // 1. Direct File Hash IOC Matching
        if (sha256 != null && !sha256.isEmpty() && !iocSha256.isEmpty()) {
            for (String h : iocSha256) {
                if (sha256.equalsIgnoreCase(h.trim())) {
                    lastMatchedIoc = "Malicious File Hash IOC: " + h;
                    return true;
                }
            }
        }

        if (conditions.isEmpty()) {
            return false;
        }

        // 2. File Content & Name Matching
        boolean isMatchAll = "all".equalsIgnoreCase(matchType);
        for (RuleCondition cond : conditions) {
            boolean condMatched = false;
            switch (cond.field.toLowerCase(Locale.ROOT)) {
                case "filepath":
                    condMatched = (filePath != null) && cond.evaluate(filePath);
                    break;
                case "filename":
                    condMatched = (fileName != null) && cond.evaluate(fileName);
                    break;
                case "content_strings":
                case "contentstrings":
                    condMatched = (contentStrings != null) && cond.evaluate(contentStrings);
                    break;
                default:
                    condMatched = false;
                    break;
            }

            if (isMatchAll && !condMatched) {
                return false;
            }
            if (!isMatchAll && condMatched) {
                lastMatchedIoc = "Payload Signature in " + fileName;
                return true;
            }
        }

        if (isMatchAll) {
            lastMatchedIoc = "File Heuristic Pattern";
        }
        return isMatchAll;
    }
}

