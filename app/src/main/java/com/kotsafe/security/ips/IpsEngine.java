/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.ips;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * High-Performance Intrusion Prevention System (IPS) Exploit Signature Engine.
 *
 * Inspects outbound and inbound cleartext and decrypted TLS traffic for:
 * 1. SQL Injection (SQLi)
 * 2. Remote Code Execution & Reverse Shells (RCE)
 * 3. Path Traversal & Local File Inclusion (LFI)
 * 4. JNDI / Log4Shell / Spring4Shell injection
 * 5. Automated Scanners & Exploit Tool User-Agents
 * 6. Sensitive Data Leakage (Credit cards, Private keys, credentials in query strings)
 */
public class IpsEngine {

    public static class IpsMatch {
        public final boolean hasThreat;
        public final String ruleId;
        public final String ruleName;
        public final String category;   // SQLI, RCE, TRAVERSAL, JNDI, SCANNER, DATA_LEAK
        public final String severity;   // LOW, MEDIUM, HIGH, CRITICAL
        public final String matchedSnippet;
        public final String mitigation;

        public IpsMatch(boolean hasThreat, String ruleId, String ruleName, String category,
                        String severity, String matchedSnippet, String mitigation) {
            this.hasThreat = hasThreat;
            this.ruleId = ruleId != null ? ruleId : "";
            this.ruleName = ruleName != null ? ruleName : "";
            this.category = category != null ? category : "";
            this.severity = severity != null ? severity : "LOW";
            this.matchedSnippet = matchedSnippet != null ? matchedSnippet : "";
            this.mitigation = mitigation != null ? mitigation : "";
        }

        public static IpsMatch clean() {
            return new IpsMatch(false, "", "Clean Payload", "NONE", "INFO", "", "Allow traffic");
        }
    }

    private static class IpsRule {
        final String id;
        final String name;
        final String category;
        final String severity;
        final Pattern pattern;
        final String mitigation;
        final boolean inspectHeadersOnly;

        IpsRule(String id, String name, String category, String severity,
                String regex, String mitigation, boolean inspectHeadersOnly) {
            this.id = id;
            this.name = name;
            this.category = category;
            this.severity = severity;
            this.pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
            this.mitigation = mitigation;
            this.inspectHeadersOnly = inspectHeadersOnly;
        }
    }

    private static final List<IpsRule> RULES = new ArrayList<>();

    static {
        // --- 1. SQL Injection ---
        RULES.add(new IpsRule("IPS-SQLI-01", "SQLi: Boolean Authentication Bypass", "SQLI", "CRITICAL",
                "(?:'|%27)\\s*(?:or|and)\\s+[\\w\\d'\"]+\\s*=\\s*[\\w\\d'\"]+", "Block request and inspect application queries", false));
        RULES.add(new IpsRule("IPS-SQLI-02", "SQLi: UNION SELECT Exfiltration", "SQLI", "CRITICAL",
                "\\bunion\\s+(?:all\\s+)?select\\b", "Enforce prepared statements; block payload", false));
        RULES.add(new IpsRule("IPS-SQLI-03", "SQLi: Schema / System Table Enumeration", "SQLI", "HIGH",
                "\\bselect\\s+.*\\bfrom\\s+(?:information_schema|sysusers|syscat|sysobjects)\\b", "Block unauthorized DB schema inspection", false));
        RULES.add(new IpsRule("IPS-SQLI-04", "SQLi: Destructive DDL Statement", "SQLI", "CRITICAL",
                "\\b(?:drop|alter|truncate)\\s+table\\b", "Quarantine connection; drop DDL query", false));
        RULES.add(new IpsRule("IPS-SQLI-05", "SQLi: Extended Stored Procedure Execution", "SQLI", "CRITICAL",
                "\\bexec(?:\\s|\\+)+(?:xp_cmdshell|sp_executesql)", "Block xp_cmdshell execution", false));

        // --- 2. Remote Command Execution & Reverse Shells ---
        RULES.add(new IpsRule("IPS-RCE-01", "RCE: Interactive Reverse Shell Spawn", "RCE", "CRITICAL",
                ";\\s*(?:bash|sh|zsh|dash)\\s+-i", "Immediately terminate socket; isolate client process", false));
        RULES.add(new IpsRule("IPS-RCE-02", "RCE: Netcat Reverse Shell / Listener", "RCE", "CRITICAL",
                "\\b(?:nc|netcat|ncat)\\s+(?:-[elp]|\\d+)", "Kill reverse shell invocation", false));
        RULES.add(new IpsRule("IPS-RCE-03", "RCE: Pipe to Shell Download Stager", "RCE", "CRITICAL",
                "(?:\\||;|&&)?\\s*(?:curl|wget)\\s+[^|&;]+\\|\\s*(?:sh|bash)", "Prevent dynamic shell script piping", false));
        RULES.add(new IpsRule("IPS-RCE-04", "RCE: Encoded PowerShell Command Execution", "RCE", "CRITICAL",
                "\\bpowershell(?:\\.exe)?\\s+(?:-[eE](?:nc(?:odedcommand)?)?|\\s*-c(?:ommand)?)\\s+", "Block obfuscated PowerShell execution", false));
        RULES.add(new IpsRule("IPS-RCE-05", "RCE: Destructive File Deletion Command", "RCE", "HIGH",
                "\\b(?:rm\\s+-rf\\s+/|mkfifo\\s+/tmp/)", "Block root wipe or FIFO pipe creation", false));

        // --- 3. Path Traversal & LFI ---
        RULES.add(new IpsRule("IPS-LFI-01", "Path Traversal: Dot-Dot-Slash Sequence", "TRAVERSAL", "HIGH",
                "(?:\\.\\.[\\/\\\\]){2,}", "Sanitize file path inputs; reject traversal tokens", false));
        RULES.add(new IpsRule("IPS-LFI-02", "LFI: Sensitive System File Access", "TRAVERSAL", "CRITICAL",
                "(?:/etc/(?:passwd|shadow|hosts|group)|/proc/self/(?:environ|maps|cmdline)|win\\.ini|boot\\.ini)", "Block access to OS credential files", false));

        // --- 4. JNDI / Log4Shell / Spring4Shell ---
        RULES.add(new IpsRule("IPS-JNDI-01", "Log4Shell: JNDI Remote Class Lookup", "JNDI", "CRITICAL",
                "\\$\\{jndi:(?:ldap|rmi|dns|nis|iiop|corba|nds):", "Patch Log4j; block JNDI interpolation", false));
        RULES.add(new IpsRule("IPS-SPRING-01", "Spring4Shell: ClassLoader Manipulation", "JNDI", "CRITICAL",
                "class\\.module\\.classLoader", "Block Spring framework parameter binding exploit", false));

        // --- 5. Automated Scanners & Exploit Tool User-Agents ---
        RULES.add(new IpsRule("IPS-SCAN-01", "Scanner: Known Vulnerability Exploit Tool UA", "SCANNER", "HIGH",
                "\\b(?:sqlmap|nikto|masscan|dirbuster|gobuster|wpscan|acunetix|havij|nessus|openvas|zgrab)\\b",
                "Block automated scanner probe", true));

        // --- 6. Sensitive Data Leakage ---
        RULES.add(new IpsRule("IPS-LEAK-01", "Data Leak: Unencrypted Private Key", "DATA_LEAK", "CRITICAL",
                "-----BEGIN (?:RSA|EC|OPENSSH|DSA) PRIVATE KEY-----", "Halt outbound transmission of cryptographic keys", false));
        RULES.add(new IpsRule("IPS-LEAK-02", "Data Leak: Credentials in Query String", "DATA_LEAK", "MEDIUM",
                "[?&](?:password|passwd|pwd|access[_-]?token)=([^&\\s]{4,})", "Enforce POST body or Authorization header for secrets", false));
    }

    /**
     * Inspects cleartext or decrypted HTTP request data for exploits and threats.
     *
     * @param method HTTP method (GET, POST, etc.)
     * @param url Target URL or path
     * @param headers HTTP headers map
     * @param body Optional request body bytes
     * @return IpsMatch detailing any identified exploit or clean status
     */
    public static IpsMatch inspect(String method, String url, Map<String, String> headers, byte[] body) {
        StringBuilder inspectBuffer = new StringBuilder();

        // 1. URL and decoded URL
        if (url != null && !url.isEmpty()) {
            inspectBuffer.append(url).append("\n");
            try {
                String decoded = URLDecoder.decode(url, "UTF-8");
                if (!decoded.equals(url)) {
                    inspectBuffer.append(decoded).append("\n");
                }
            } catch (Exception ignored) {}
        }

        // 2. Headers inspection
        StringBuilder headersBuffer = new StringBuilder();
        if (headers != null) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                String hStr = entry.getKey() + ": " + entry.getValue() + "\n";
                headersBuffer.append(hStr);
                inspectBuffer.append(hStr);
            }
        }

        // 3. Body sample (capped at 32 KB to prevent ReDoS / memory spikes)
        if (body != null && body.length > 0) {
            int bodySampleLen = Math.min(body.length, 32768);
            String bodyStr = new String(body, 0, bodySampleLen, StandardCharsets.UTF_8);
            inspectBuffer.append(bodyStr);
        }

        String fullText = inspectBuffer.toString();
        String headerText = headersBuffer.toString();

        // 4. Evaluate IPS rules
        for (IpsRule rule : RULES) {
            String target = rule.inspectHeadersOnly ? headerText : fullText;
            if (target.isEmpty()) continue;

            Matcher matcher = rule.pattern.matcher(target);
            if (matcher.find()) {
                String matchSnippet = extractSnippet(target, matcher.start(), matcher.end());
                return new IpsMatch(true, rule.id, rule.name, rule.category, rule.severity,
                        matchSnippet, rule.mitigation);
            }
        }

        // 5. Card number leakage check
        if (fullText.length() > 16) {
            String cardLeak = detectCreditCardLeak(fullText);
            if (cardLeak != null) {
                return new IpsMatch(true, "IPS-LEAK-CC", "Data Leak: Unencrypted Payment Card Number",
                        "DATA_LEAK", "CRITICAL", cardLeak, "Mask payment card data before network transmission");
            }
        }

        return IpsMatch.clean();
    }

    private static String extractSnippet(String source, int start, int end) {
        int snipStart = Math.max(0, start - 20);
        int snipEnd = Math.min(source.length(), end + 20);
        String s = source.substring(snipStart, snipEnd).replace('\r', ' ').replace('\n', ' ');
        return s.length() > 80 ? s.substring(0, 80) + "…" : s;
    }

    /**
     * Scans for 13 to 16 digit numbers that pass the Luhn algorithm (Credit Cards).
     */
    public static String detectCreditCardLeak(String text) {
        Matcher m = Pattern.compile("\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\\b").matcher(text);
        while (m.find()) {
            String candidate = m.group();
            if (isLuhnValid(candidate)) {
                return "Card Number Ending with " + candidate.substring(candidate.length() - 4);
            }
        }
        return null;
    }

    private static boolean isLuhnValid(String number) {
        int sum = 0;
        boolean alternate = false;
        for (int i = number.length() - 1; i >= 0; i--) {
            int n = Integer.parseInt(number.substring(i, i + 1));
            if (alternate) {
                n *= 2;
                if (n > 9) n = (n % 10) + 1;
            }
            sum += n;
            alternate = !alternate;
        }
        return (sum % 10 == 0);
    }
}
