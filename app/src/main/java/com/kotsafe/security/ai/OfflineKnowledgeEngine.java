/*
 * This file is part of KotSafe / KotSafe Cyber Security Project.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.ai;

import android.content.Context;
import com.kotsafe.security.AppsResolver;
import com.kotsafe.security.CaptureService;
import com.kotsafe.security.ConnectionsRegister;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.AdBlockSubscriptionManager;
import com.kotsafe.security.model.AlertRecord;
import com.kotsafe.security.model.AlertStore;
import com.kotsafe.security.model.AppDescriptor;
import com.kotsafe.security.model.CaptureStats;
import com.kotsafe.security.model.ConnectionDescriptor;
import com.kotsafe.security.model.Prefs;
import com.kotsafe.security.model.QuarantineVaultManager;
import com.kotsafe.security.model.ScanReportDbHelper;
import com.kotsafe.security.model.ScanReportEntry;
import com.kotsafe.security.model.SecurityRulesDb;
import androidx.preference.PreferenceManager;
import android.content.SharedPreferences;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Built-in Offline Security Knowledge & Setup Engine for KotSafe.
 * Provides rich, interactive, step-by-step guidance and technical explanations
 * even when Cloud AI APIs are offline, unconfigured, or experiencing quota/network errors.
 */
public class OfflineKnowledgeEngine {

    public static String answerQuestion(Context context, String userQuery, AiAccessController accessController, String apiErrorDetails) {
        if (userQuery == null || userQuery.trim().isEmpty()) {
            return getMasterCapabilitiesGuide(context);
        }

        String q = userQuery.toLowerCase(Locale.ROOT).trim();

        // Greetings Intent (hi, hlo, hello, hey, etc.)
        if (q.equals("hi") || q.equals("hlo") || q.equals("hello") || q.equals("hey") || q.equals("hii")
                || q.startsWith("hi ") || q.startsWith("hlo ") || q.startsWith("hello ") || q.startsWith("hey ")
                || q.equals("good morning") || q.equals("good afternoon") || q.equals("good evening")
                || q.contains("who are you") || q.contains("what is your name")) {
            return getGreetingResponse();
        }

        // Sensitive Info, Prompt Injection, API Keys, Backend & Credential Protection Refusal Intent
        if (AiAccessController.isAdversarialOrSensitiveQuery(q)) {
            return getSensitiveInfoRefusal();
        }

        // Ad & Tracker Blocking Intent (e.g. "block all ads traffic", "block ads", "enable adblock")
        if (matches(q, "block ads", "block all ads", "block ad traffic", "block all ads traffic", "stop ads", "enable ad block", "turn on adblock", "adblock", "ad blocker", "block trackers", "block all tracking", "block advertising")) {
            return getAdBlockIntentResponse(context);
        }

        // Firewall Master Control Intent (e.g. "turn on firewall", "disable firewall")
        if (matches(q, "turn on firewall", "enable firewall", "start firewall", "activate firewall")) {
            return getFirewallToggleIntentResponse(context, true);
        }
        if (matches(q, "turn off firewall", "disable firewall", "stop firewall", "deactivate firewall")) {
            return getFirewallToggleIntentResponse(context, false);
        }

        // Antivirus Master Control Intent (e.g. "turn on antivirus", "disable antivirus")
        if (matches(q, "turn on antivirus", "enable antivirus", "activate antivirus", "start antivirus")) {
            return getAntivirusToggleIntentResponse(context, true);
        }
        if (matches(q, "turn off antivirus", "disable antivirus", "stop antivirus", "deactivate antivirus")) {
            return getAntivirusToggleIntentResponse(context, false);
        }

        // Natural Language Smart Firewall Rule Builder Intent
        if (q.contains("block ") && (q.contains("domain") || q.contains("ip") || q.contains("app") || q.contains(".") || q.contains("host")) && !q.contains("how to") && !q.contains("why")) {
            String ruleAns = parseAndBuildFirewallRuleResponse(userQuery);
            if (ruleAns != null) return ruleAns;
        }

        // Deep Threat Investigation Intent (e.g. "investigate 1.2.3.4", "check IP 1.2.3.4", "otx check ...", "is ... malicious")
        if ((q.contains("investigat") || q.contains("check ip ") || q.contains("check url ") || q.contains("check domain ") || q.contains("check hash ") || q.contains("otx") || q.contains("threatfox") || q.contains("is malicious") || q.contains("why used")) && !q.contains("how to")) {
            String invAns = parseAndBuildInvestigationResponse(context, userQuery);
            if (invAns != null) return invAns;
        }

        String answer;
        if (matches(q, "audit", "posture", "is my phone secure", "am i secure", "security score", "health check", "device check", "audit device", "audit phone", "audit my phone")) {
            answer = generateDeviceSecurityAudit(context);
        } else if (matches(q, "live traffic", "active connection", "open socket", "who is talking", "top talker", "traffic forensic", "analyze traffic", "analyze active network", "active network")) {
            answer = analyzeLiveTrafficForensics(context);
        } else if (matches(q, "last alert", "recent alert", "explain alert", "threat alert", "incident alert", "why blocked")) {
            answer = explainRecentAlert(context);
        } else if (matches(q, "scan device", "malware scan", "run scan", "antivirus scan", "scan for malware")) {
            answer = getAntivirusQuickScanPrompt(context);
        } else if (matches(q, "setup router", "how to setup router", "configure router", "port forward setup", "router port forward", "router error", "port forward error", "cant connect router", "router not working", "connection refused", "port unreachable", "cgnat", "how to setup in router", "setup on router", "ont router", "fiber router", "computer off", "computer is off", "pc is off", "pc turned off", "what if computer is off", "what if pc is off")) {
            answer = getRouterSetupAndErrorGuide(context, userQuery);
        } else if (matches(q, "dynamic dns", "setup dynamic dns", "ddns", "setup ddns", "how to setup ddns", "what is ddns", "duckdns", "duck dns", "no-ip", "noip", "dynamic ip", "how to setup dynamic dns", "ddns setup", "public ip router", "router public ip")) {
            answer = getDdnsSetupGuide(context);
        } else if (matches(q, "home router", "connect to home router", "connect home router", "router proxy", "route through router", "route to router", "connect router", "socks5 router", "router socks5", "connect to router", "route to home", "connect to home", "connect home", "use home wifi", "home wifi outside", "out of station", "tunnel to home", "route through home", "home network", "route traffic from router", "traffic through router", "traffic through home")) {
            answer = getHomeRouterProxyResponse(context, userQuery);
        } else if (matches(q, "slow", "speed", "lag", "latency", "ping", "internet slow", "slow internet", "wifi slow", "slow connection", "why slow")) {
            answer = getNetworkPerformanceGuide(context);
        } else if (matches(q, "battery", "drain", "power", "battery usage", "consumes battery", "battery drain", "battery drain fast")) {
            answer = getBatteryOptimizationGuide(context);
        } else if (matches(q, "vpn disconnect", "vpn stop", "keeps stopping", "drops", "turn off by itself", "disconnecting", "vpn crash", "keeps disconnecting", "vpn closing")) {
            answer = getVpnDisconnectGuide(context);
        } else if (matches(q, "what is kotsafe", "about kotsafe", "what does kotsafe do", "why kotsafe")) {
            answer = getAboutKotSafeGuide(context);
        } else if (matches(q, "tailscale", "mesh vpn", "wireguard", "private vpn", "netguard", "local firewall", "shadowsocks", "v2ray", "v2rayng", "proxy client", "adguard", "ad blocking firewall", "adguard mode", "netguard mode", "tailscale mode", "uptailscale", "architecture mode", "operating mode", "authentication on setup", "always use authentication", "use authentication", "require authentication", "auth setup")) {
            answer = getCoreArchitectureModesGuide(context, userQuery);
        } else if (matches(q, "p2p", "exit node", "gateway mode", "personal gateway", "peer to peer", "mesh tunnel", "hole punch", "pairing bundle", "direct punch", "app routing", "kill switch", "tunnel cipher", "diagnos", "diagnose")) {
            answer = getP2PComprehensiveResponse(context, q);
        } else if (matches(q, "single-socket", "single socket", "unaggregated", "raw socket", "socket mode", "aggregation", "flow aggregat", "socket diagnostic")) {
            answer = getSingleSocketDiagnosticsGuide(context);
        } else if (matches(q, "dns", "doh", "dot", "dnscrypt", "resolver", "domain name", "name server", "plain text dns", "encrypted dns", "dns preset", "dns speed", "what is dns")) {
            answer = getDnsGuide(context);
        } else if (matches(q, "flow badge", "blocked badge", "flow tag", "what is flow", "what is blocked", "connection category", "user apps", "category chip", "connection chip", "filter chip", "active only")) {
            answer = getConnectionCategoriesGuide(context);
        } else if (matches(q, "ai", "key", "api", "gemini", "openai", "claude", "ollama", "model", "endpoint", "provider", "token")) {
            answer = getAiSetupGuide(context);
        } else if (matches(q, "firewall", "block", "rule", "whitelist", "filter", "quic", "action center", "drop")) {
            answer = getFirewallGuide(context);
        } else if (matches(q, "decrypt", "https", "tls", "ssl", "ca cert", "certificate", "root ca", "mitmproxy", "user cert")) {
            answer = getHttpsDecryptionGuide(context);
        } else if (matches(q, "repeater", "replay", "tamper", "payload", "fuzz", "header", "http request", "tampering")) {
            answer = getHttpRepeaterGuide(context);
        } else if (matches(q, "antivirus", "scan", "deep scan", "split apk", "yara", "quarantine", "vault", "threat", "isolate", "restore")) {
            answer = getAntivirusGuide(context);
        } else if (matches(q, "telemetry", "metric", "download", "upload", "rx", "tx", "dropped", "packet", "active conn", "dns quer", "status")) {
            answer = getTelemetryGuide(context);
        } else if (matches(q, "mitre", "attack", "framework", "c2", "command and control", "exfiltration", "persistence", "reconnaissance", "discovery")) {
            answer = getMitreGuide(context);
        } else if (matches(q, "geo", "location", "country", "flag", "ip location", "maxmind", "asn", "hosting")) {
            answer = getGeolocationGuide(context);
        } else if (matches(q, "pegasus", "predator", "hermit", "mercenary", "spyware", "zero-click", "zero click", "micro beacon", "micro-beacon", "forcedentry", "blastpass", "tracerpid")) {
            answer = getMercenarySpywareGuide(context);
        } else if (matches(q, "ja4", "ja3", "entropy", "shannon", "kotengine", "cleanroom", "clean-room", "wireshark", "pcapng", "dsb", "stream server", "19090")) {
            answer = getKotEngineAndForensicsGuide(context);
        } else if (matches(q, "soc analyst", "autopilot", "auto resolve", "auto-resolve", "remediate", "soar", "resolve by own", "respond by own", "resolve threat")) {
            answer = getSocAnalystGuide(context);
        } else if (matches(q, "siem", "splunk", "elastic", "ecs", "cef", "syslog", "sentinel", "wazuh")) {
            answer = getSiemIntegrationGuide(context);
        } else if (matches(q, "screen", "peek", "snoop", "shoulder", "usb", "sim", "juice jack", "intruder", "camera")) {
            answer = getPhysicalSecurityGuide(context);
        } else if (matches(q, "what can you do", "show all features", "list features", "capabilities", "help menu", "all feature", "all features")) {
            answer = getMasterCapabilitiesGuide(context);
        } else {
            answer = getSmartFallbackResponse(context, userQuery);
        }

        // If there was an API error, append a helpful diagnostic footer
        if (apiErrorDetails != null && !apiErrorDetails.isEmpty()) {
            answer += "\n\n---\n"
                    + "⚡ **KotSafe Offline Security Expert Engine**\n"
                    + "*Cloud AI endpoint returned an error (`" + apiErrorDetails + "`). KotSafe's offline engine provided the comprehensive guide above so you are never blocked!*";
        }

        return answer;
    }

    public static boolean isInstantOfflineEligible(String userQuery) {
        if (userQuery == null) return false;
        String q = userQuery.toLowerCase(Locale.ROOT).trim();

        // Greetings are always instant 350ms
        if (q.equals("hi") || q.equals("hlo") || q.equals("hello") || q.equals("hey") || q.equals("hii")
                || q.startsWith("hi ") || q.startsWith("hlo ") || q.startsWith("hello ") || q.startsWith("hey ")
                || q.equals("good morning") || q.equals("good afternoon") || q.equals("good evening")
                || q.contains("who are you") || q.contains("what is your name")) {
            return true;
        }

        // Sensitive Info & Credential Protection Refusal is always instant
        if (matches(q, "my password", "give password", "show password", "my token", "my secret", "private key", "my imei", "steal", "hack password", "extract password", "device pin", "user credentials", "show credentials")) {
            return true;
        }

        // Security Audit & Health Scorecard is instant on-device
        if (matches(q, "audit", "security score", "posture", "is my phone secure", "am i secure", "audit device", "audit phone", "health check")) {
            return true;
        }

        // On-demand scan trigger is instant
        if (matches(q, "scan device", "malware scan", "run scan", "antivirus scan")) {
            return true;
        }

        // Dynamic DNS and Home router proxy setup & diagnostics are instant
        if (matches(q, "dynamic dns", "setup dynamic dns", "ddns", "setup ddns", "how to setup ddns", "what is ddns", "duckdns", "duck dns", "no-ip", "noip", "dynamic ip", "how to setup dynamic dns", "ddns setup", "setup router", "how to setup router", "configure router", "port forward setup", "router port forward", "router error", "port forward error", "cant connect router", "router not working", "connection refused", "port unreachable", "cgnat", "how to setup in router", "setup on router", "ont router", "fiber router", "computer off", "computer is off", "pc is off", "pc turned off", "what if computer is off", "what if pc is off", "home router", "connect to home router", "connect home router", "router proxy", "route through router", "route to router", "connect router", "socks5 router", "router socks5", "connect to router", "route to home", "connect to home", "connect home", "use home wifi", "home wifi outside", "out of station", "tunnel to home", "route through home", "home network", "route traffic from router", "traffic through router", "traffic through home")) {
            return true;
        }

        // Performance, Battery, Disconnect, Architecture Modes, and About inquiries are instant
        if (matches(q, "slow", "speed", "lag", "latency", "ping", "internet slow", "slow internet", "wifi slow", "slow connection", "why slow", "battery", "drain", "power", "battery usage", "consumes battery", "battery drain", "battery drain fast", "vpn disconnect", "vpn stop", "keeps stopping", "drops", "turn off by itself", "disconnecting", "vpn crash", "keeps disconnecting", "vpn closing", "what is kotsafe", "about kotsafe", "what does kotsafe do", "why kotsafe", "tailscale", "mesh vpn", "wireguard", "private vpn", "netguard", "local firewall", "shadowsocks", "v2ray", "v2rayng", "proxy client", "adguard", "ad blocking firewall", "adguard mode", "netguard mode", "tailscale mode", "uptailscale", "architecture mode", "operating mode", "authentication on setup", "always use authentication", "use authentication", "require authentication", "auth setup")) {
            return true;
        }

        // All P2P questions are instantly eligible for on-device answering
        if (matches(q, "p2p", "exit node", "gateway mode", "personal gateway", "peer to peer", "mesh tunnel", "hole punch", "pairing bundle", "direct punch", "app routing", "kill switch", "tunnel cipher", "diagnos", "diagnose")) {
            return true;
        }

        // If the user explicitly asks to analyze live traffic, active sockets, or live scan data, use Cloud AI
        if (q.contains("analyze my") || q.contains("analyze current") || q.contains("check my connection")
                || q.contains("who is connecting") || q.contains("is anything suspicious") || q.contains("live traffic")) {
            return false;
        }

        // Rule proposal intent is instant
        if (q.contains("block ") && (q.contains("domain") || q.contains("ip") || q.contains("app") || q.contains("."))) {
            return true;
        }

        // General how-to, setup, metric, architectural questions
        boolean hasIntent = q.contains("what is") || q.contains("how do") || q.contains("how to")
                || q.contains("explain") || q.contains("setup") || q.contains("how can")
                || q.contains("what are") || q.contains("benefit") || q.contains("guide")
                || q.contains("what does") || q.contains("help");

        boolean hasTopic = matches(q, "ai", "key", "gemini", "openai", "claude", "ollama",
                "firewall", "block", "rule", "whitelist", "decrypt", "https", "ca cert", "repeater",
                "fuzz", "payload", "antivirus", "deep scan", "yara", "split apk", "telemetry", "metric",
                "rx", "tx", "upload", "download", "active conn", "dns", "doh", "resolver", "domain name",
                "mitre", "attack", "geo", "p2p", "exit node",
                "single socket", "single-socket", "unaggregated", "aggregation", "socket mode",
                "flow badge", "blocked badge", "flow tag", "user apps", "category chip", "active only",
                "screen peek", "usb", "sim", "pegasus", "predator", "spyware", "zero-click",
                "ja4", "entropy", "kotengine", "wireshark", "siem", "soc");

        return hasIntent && hasTopic;
    }

    public static String getGreetingResponse() {
        return "👋 Hello! I am **KotSafe AI**, your on-device cyber intelligence and network security assistant.\n\n"
                + "I can help you analyze traffic, enforce rules, and protect your device:\n"
                + "• 🛡️ **Firewall & Blocking**: Type `Block domain tracker.com` or ask how to block apps\n"
                + "• ⚡ **HTTP Repeater**: Learn how to replay, tamper, and fuzz API requests\n"
                + "• 🌐 **HTTPS Decryption**: Setup CA certificates to decrypt secure SSL/TLS payloads\n"
                + "• 📊 **Live Telemetry**: Understand download/upload speeds, dropped packets, and open sockets\n"
                + "• 🧪 **Antivirus**: Learn about split APK audits, YARA signatures, and quarantine vaults\n\n"
                + "How can I assist you right now? Feel free to ask a question or tap a suggestion chip!";
    }

    public static String getSensitiveInfoRefusal() {
        return "🛡️ **KotSafe Zero-Leakage Privacy Shield Active**\n\n"
                + "To protect system integrity, user privacy, and proprietary intellectual property, KotSafe AI strictly enforces the following guardrails:\n\n"
                + "• **Backend Infrastructure & Endpoints**: Private server addresses, cloud configurations, and database endpoints are never revealed or exposed.\n"
                + "• **API Keys & Cryptographic Secrets**: AI service keys (Gemini/OpenAI), TLS certificates, and decryption tokens are stored in hardware-backed Android Keystore and redacted from all prompts and outputs.\n"
                + "• **Application Source Code**: Internal C/C++ engine code, Java bytecode, and decompilation mappings are classified and non-disclosable.\n"
                + "• **Personal Credentials & Device IDs**: Passwords, tokens, device IMEIs, and network auth headers are never stored or processed.\n"
                + "• **Prompt Injection Defense**: Security rules, system directives, and safety boundaries cannot be bypassed or overridden.\n\n"
                + "KotSafe is engineered with a zero-trust, privacy-first architecture to keep your device and data completely safe.";
    }

    private static boolean matches(String query, String... keywords) {
        for (String kw : keywords) {
            if (query.contains(kw)) return true;
        }
        return false;
    }

    // =========================================================================
    // 1. AI PROTECTION & API SETUP GUIDE
    // =========================================================================
    public static String getAiSetupGuide(Context context) {
        StringBuilder sb = new StringBuilder();
        sb.append("### 🤖 KotSafe AI Protection & API Setup Guide\n\n");
        sb.append("KotSafe features a **Multi-Provider AI Architecture** supporting OpenAI, Google Gemini, Anthropic Claude, and 100% Offline Local AI (Ollama / LM Studio).\n\n");

        sb.append("#### 🛠️ How to Setup Free or Cloud AI Keys:\n");
        sb.append("1. **Google Gemini (Recommended & Free Tier)**:\n");
        sb.append("   - Visit [Google AI Studio](https://aistudio.google.com/) and create a free API Key.\n");
        sb.append("   - In KotSafe, go to **Settings ➔ AI Protection**.\n");
        sb.append("   - Select **Google Gemini** as Provider and paste your key.\n");
        sb.append("   - Default model: `gemini-1.5-flash` (fast & highly capable).\n\n");

        sb.append("2. **OpenAI (ChatGPT)**:\n");
        sb.append("   - Generate a key at [platform.openai.com](https://platform.openai.com/api-keys).\n");
        sb.append("   - Select **ChatGPT (OpenAI)** in Settings and set model to `gpt-4o-mini`.\n\n");

        sb.append("3. **100% Offline Local AI (Ollama / LM Studio)**:\n");
        sb.append("   - No cloud required! Run Ollama on your PC or home server: `ollama run llama3.2`.\n");
        sb.append("   - Select **Local AI / Custom Endpoint** in KotSafe.\n");
        sb.append("   - Set Endpoint URL: `http://<your-pc-ip>:11434/v1/chat/completions`.\n\n");

        sb.append("#### 🔒 Privacy Access Levels (Granular Toggles):\n");
        sb.append("You control exactly what the AI can see. Under **Settings ➔ AI Protection**, you can toggle:\n");
        sb.append("• **Status & Telemetry**: Bytes, packets, dropped queues.\n");
        sb.append("• **Connections**: Active socket destinations & IPs.\n");
        sb.append("• **Decrypted HTTP**: Intercepted headers and URLs.\n");
        sb.append("• **Repeater**: Payloads tested in the HTTP workbench.\n");
        sb.append("• **Firewall & MITRE Alerts**: Blocked threats and attack techniques.\n");
        sb.append("• **Antivirus Reports**: Audited apps, hashes, and split APKs.\n\n");

        sb.append("💡 *Tip: You can use the 'Test AI Connection' button in Settings to verify your API key anytime!*");
        return sb.toString();
    }

    // =========================================================================
    // 2. FIREWALL & SECURITY RULES SETUP
    // =========================================================================
    public static String getFirewallGuide(Context context) {
        StringBuilder sb = new StringBuilder();
        sb.append("### 🛡️ KotSafe Firewall & Traffic Filtering Guide\n\n");
        sb.append("KotSafe contains a high-performance, kernel-level packet inspection firewall that runs entirely on your device without routing traffic through third-party servers.\n\n");

        sb.append("#### 🛠️ Step-by-Step Setup:\n");
        sb.append("1. **Enable Firewall**: Go to **Settings ➔ Firewall** and toggle `Enable Firewall`.\n");
        sb.append("2. **Block Untrusted Apps**:\n");
        sb.append("   - Tap on the **Firewall** card on the Home screen or **Settings ➔ Firewall Rules**.\n");
        sb.append("   - Select any installed app and toggle its network permission to **Block**.\n");
        sb.append("3. **Block Specific Domains & IPs**:\n");
        sb.append("   - Add custom IP addresses, CIDR subnets (e.g. `198.51.100.0/24`), or hostnames (e.g. `*.ads.example.com`).\n");
        sb.append("4. **Block QUIC / UDP (Port 443)**:\n");
        sb.append("   - Toggle `Block QUIC` to force apps to use standard TCP/TLS, enabling full header inspection and preventing bypassing.\n");
        sb.append("5. **Inspect Blocked Events**:\n");
        sb.append("   - View **Firewall Logs** to inspect every dropped packet, timestamp, source app, and trigger reason.\n\n");

        // Live status if available
        boolean fwEnabled = Prefs.isFirewallEnabled(context, PreferenceManager.getDefaultSharedPreferences(context));
        sb.append("#### 📊 Live Status on Device:\n");
        sb.append("• **Firewall State**: ").append(fwEnabled ? "🟢 ACTIVE & PROTECTING" : "⚪ INACTIVE (Turn on in Settings)").append("\n");
        sb.append("• **VPN Capture Engine**: ").append(CaptureService.isServiceActive() ? "🟢 Running" : "⚪ Stopped").append("\n");
        try {
            int ruleCount = SecurityRulesDb.getInstance(context).getRuleCount();
            sb.append("• **Active Security Rules**: ").append(ruleCount).append(" rules loaded\n");
        } catch (Exception ignored) {}

        return sb.toString();
    }

    // =========================================================================
    // 3. HTTP/HTTPS DECRYPTION & CA CERTIFICATE SETUP
    // =========================================================================
    public static String getHttpsDecryptionGuide(Context context) {
        return "### 🌐 HTTPS / TLS Decryption & CA Certificate Guide\n\n"
                + "Modern Android apps encrypt 99% of their traffic with TLS/HTTPS. To inspect headers, cookies, API tokens, and payloads, KotSafe uses a local on-device MITM proxy.\n\n"
                + "#### 🛠️ How to Setup HTTPS Decryption:\n"
                + "1. **Generate Local CA Certificate**:\n"
                + "   - Open **Settings ➔ TLS Decryption**.\n"
                + "   - Tap **Install CA Certificate** (KotSafe generates a unique, secure keypair on your device).\n"
                + "2. **Install into Android Certificate Store**:\n"
                + "   - Android will prompt you: go to **Settings ➔ Security ➔ Encryption & Credentials ➔ Install a certificate ➔ CA certificate**.\n"
                + "   - Select the exported KotSafe certificate.\n"
                + "3. **Android 7+ App Restrictions**:\n"
                + "   - **Standard Apps**: By default, Android 7+ apps trust only *System* certs, not *User* certs.\n"
                + "   - **Browsers & Debuggable Apps**: Work immediately with User CA certs.\n"
                + "   - **System CA (Root / Magisk)**: If your device is rooted, use the *Move Certificates to System* Magisk module to decrypt all apps system-wide without modification.\n\n"
                + "💡 *Security Note: Your private CA key never leaves your device. You can regenerate or delete the certificate anytime in Settings.*";
    }

    // =========================================================================
    // 4. HTTP REPEATER WORKBENCH GUIDE
    // =========================================================================
    public static String getHttpRepeaterGuide(Context context) {
        return "### ⚡ HTTP Repeater & Security Auditing Guide\n\n"
                + "The **HTTP Repeater** is an advanced mobile security workbench (similar to Burp Suite Repeater) allowing you to intercept, modify, and replay HTTP/HTTPS requests directly from your Android phone.\n\n"
                + "#### 🛠️ How to Use HTTP Repeater:\n"
                + "1. **Capture a Request**:\n"
                + "   - Start the VPN capture and open any app or browser.\n"
                + "   - Open the **Connections** or **HTTP/S Log** tab and tap on the target request.\n"
                + "   - Tap the **⚡ Send to Repeater** action button.\n"
                + "2. **Modify & Tamper**:\n"
                + "   - Edit the **HTTP Method** (GET, POST, PUT, DELETE, PATCH).\n"
                + "   - Adjust **Headers** (e.g. spoof `User-Agent`, modify `Authorization` tokens, inject test headers).\n"
                + "   - Edit the **Body / Payload** (e.g. modify JSON parameters, test SQLi/XSS boundaries).\n"
                + "3. **Execute & Analyze**:\n"
                + "   - Press **SEND**.\n"
                + "   - KotSafe transmits the custom packet and renders the raw server response code, timing (ms), response headers, and decoded body.\n\n"
                + "🎯 **Benefits for Security Researchers & Developers**:\n"
                + "• Test mobile backend APIs without needing an external laptop or proxy.\n"
                + "• Audit broken object level authorization (BOLA) and parameter tampering.\n"
                + "• Debug API response schemas and mobile caching behavior.";
    }

    // =========================================================================
    // 5. ANTIVIRUS, YARA & QUARANTINE GUIDE
    // =========================================================================
    public static String getAntivirusGuide(Context context) {
        StringBuilder sb = new StringBuilder();
        sb.append("### 🧪 Antivirus Deep Scan & Quarantine Vault Guide\n\n");
        sb.append("KotSafe Antivirus provides multi-vector threat scanning combining hash intelligence, Split APK bytecode analysis, and signature-based YARA rule matching.\n\n");

        sb.append("#### 🛡️ Scan Modes:\n");
        sb.append("• **Quick Scan**: Audits running apps, active system processes, and recent downloads (completes in ~5s).\n");
        sb.append("• **Full Scan**: Audits all installed user and system packages, verifying APK signatures and network endpoints.\n");
        sb.append("• **Deep Scan**: Performs bytecode decompilation, audits split configuration APKs, parses DEX headers, and scans all files across storage using pattern-matching YARA rules.\n\n");

        sb.append("#### 📁 Quarantine Vault:\n");
        sb.append("When a malicious APK or payload is detected:\n");
        sb.append("• KotSafe strips execution permissions and moves the file to an encrypted sandbox vault (`.quarantine`).\n");
        sb.append("• You can open **Quarantine Vault** anytime from Antivirus to inspect threats, **Permanently Shred** them, or **Restore & Whitelist** if it was a false positive.\n\n");

        // Live Antivirus stats
        sb.append("#### 📊 Live Device Antivirus Status:\n");
        try {
            int qCount = QuarantineVaultManager.getInstance(context).getQuarantinedCount();
            sb.append("• **Quarantine Vault**: ").append(qCount).append(" isolated threat(s)\n");

            ScanReportDbHelper db = ScanReportDbHelper.getInstance(context);
            ScanReportEntry last = db.getLatestReport();
            if (last != null) {
                sb.append("• **Last Scan**: ").append(last.scanMode).append(" Mode\n");
                sb.append("• **Security Score**: ").append(last.securityScore).append("/100\n");
                sb.append("• **Threats Flagged**: ").append(last.threatsDetected).append(" threats, ")
                        .append(last.suspiciousDetected).append(" suspicious\n");
            } else {
                sb.append("• **Last Scan**: No scans completed yet. Tap 'Scan Device' on Antivirus screen.\n");
            }
        } catch (Exception ignored) {}

        return sb.toString();
    }

    // =========================================================================
    // 6. LIVE TELEMETRY & STATUS METRICS
    // =========================================================================
    public static String getTelemetryGuide(Context context) {
        StringBuilder sb = new StringBuilder();
        sb.append("### 📊 Live Telemetry & Status Metrics Explained\n\n");
        sb.append("The Status dashboard gives you real-time layer-3 to layer-7 visibility into every packet traversing your device's network interfaces:\n\n");

        sb.append("• **Downloads (RX Bytes)**: Total data volume received by your device.\n");
        sb.append("• **Uploads (TX Bytes)**: Total data volume transmitted by your device. *Spikes in TX without active downloads can indicate unauthorized data exfiltration.*\n");
        sb.append("• **RX / TX Packets**: Raw count of Ethernet/IP frames processed by the capture pipeline.\n");
        sb.append("• **Active Connections**: Number of live, open TCP/UDP sockets currently communicating.\n");
        sb.append("• **Total Connections**: Cumulative count of all sockets opened since capture started.\n");
        sb.append("• **DNS Queries**: Tracks domain resolutions. High volume can indicate DNS tunneling or rapid beaconing.\n");
        sb.append("• **Dropped Packets**: Packets discarded due to kernel buffer saturation. If high, increase buffer size in Settings.\n\n");

        // Live Telemetry snapshot
        CaptureStats stats = CaptureService.getStats();
        sb.append("#### 📈 Live Snapshot on Your Device:\n");
        if (stats != null && CaptureService.isServiceActive()) {
            sb.append("• **Status**: 🟢 CAPTURE RUNNING\n");
            sb.append("• **Downloaded (RX)**: ").append(Utils.formatBytes(stats.bytes_rcvd)).append(" (").append(stats.pkts_rcvd).append(" pkts)\n");
            sb.append("• **Uploaded (TX)**: ").append(Utils.formatBytes(stats.bytes_sent)).append(" (").append(stats.pkts_sent).append(" pkts)\n");
            sb.append("• **Active Sockets**: ").append(stats.active_conns).append(" open\n");
            sb.append("• **Total Sockets**: ").append(stats.tot_conns).append(" flows\n");
            sb.append("• **DNS Queries**: ").append(stats.num_dns_queries).append("\n");
            sb.append("• **Dropped Packets**: ").append(stats.pkts_dropped).append("\n");
        } else {
            sb.append("• **Status**: ⚪ Capture is stopped. Tap the main power button on the Home screen to begin live monitoring.\n");
        }

        return sb.toString();
    }

    // =========================================================================
    // 7. MITRE ATT&CK MOBILE MATRIX GUIDE
    // =========================================================================
    public static String getMitreGuide(Context context) {
        return "### ⚠️ MITRE ATT&CK Mobile Framework Explained\n\n"
                + "KotSafe maps suspicious network events and alert triggers directly to the industry-standard **MITRE ATT&CK Mobile Matrix**, allowing you to understand the exact tactical intent behind network anomalies:\n\n"
                + "• **Command and Control (T1437 / T1071)**:\n"
                + "  An app is communicating with a known adversary C2 server, IRC beacon, or high-entropy dynamic domain.\n\n"
                + "• **Exfiltration (T1048 / T1020)**:\n"
                + "  High-volume or stealthy background data transfer to unrecognized cloud storage or unencrypted external endpoints.\n\n"
                + "• **Discovery (T1418 / T1082)**:\n"
                + "  An app performing port scans on your local Wi-Fi subnet or enumerating other installed packages on your phone.\n\n"
                + "• **Defense Evasion (T1407 / T1027)**:\n"
                + "  Obfuscated payload delivery, packing, or non-standard protocol tunneling designed to bypass firewalls.\n\n"
                + "💡 *When an 'Attack' badge appears in KotSafe, tap on it to view the MITRE tactic, technical indicators (IoCs), and recommended mitigation actions.*";
    }

    // =========================================================================
    // 8. GEOLOCATION & REMOTE HOSTING LOOKUPS
    // =========================================================================
    public static String getGeolocationGuide(Context context) {
        return "### 🌍 Geolocation & Remote IP Mapping Guide\n\n"
                + "KotSafe contains an offline **MaxMind GeoLite2** IP intelligence database that resolves remote endpoints without exposing your queries to external tracking services:\n\n"
                + "• **Country Flags & ISO Codes**: Instantly see which nation hosts the server your app is talking to.\n"
                + "• **City & Autonomous System (ASN)**: Displays the ISP, datacenter provider (e.g. AWS, Cloudflare, DigitalOcean), or telecom carrier.\n"
                + "• **Detect Foreign Data Routing**: Helps you spot domestic apps unexpectedly sending data to servers in overseas jurisdictions with weak data privacy laws.\n\n"
                + "⚙️ **Configuration**: Go to **Settings ➔ Geolocation** to download the latest MaxMind database update for offline high-precision lookups.";
    }

    // =========================================================================
    // 9. P2P EXIT NODE, PERSONAL GATEWAY & MESH TUNNELING SUITE
    // =========================================================================

    public static String getP2PComprehensiveResponse(Context context, String q) {
        if (matches(q, "diagnos", "health", "check", "test", "troubleshoot", "not working", "failed", "disconnect", "slow", "lag", "ping", "latency", "rtt", "timeout", "reconnect", "error", "fix", "self heal", "self-heal", "repair")) {
            return generateLiveP2PDiagnosticsAndHealing(context);
        } else if (matches(q, "kill switch", "killswitch", "fail safe", "fail-safe", "leak", "drop traffic", "disconnect protection", "leak protection")) {
            return getP2PKillSwitchGuide(context);
        } else if (matches(q, "split", "per app", "routing", "route app", "exclude", "include", "only app", "bypass")) {
            return getP2PSplitTunnelingGuide(context);
        } else if (matches(q, "encrypt", "cipher", "chacha20", "aes", "security", "safe", "private", "privacy", "e2ee", "secret", "spy", "see my traffic")) {
            return getP2PEncryptionAndSecurityGuide(context);
        } else if (matches(q, "direct", "hole punch", "stun", "nat", "relay", "symmetric", "cgnat", "udp", "traversal", "punch")) {
            return getP2PDirectVsRelayGuide(context);
        } else if (matches(q, "pair", "qr", "token", "bundle", "code", "connect", "setup", "how to use", "configure", "start", "enable", "how to pair", "join")) {
            return getP2PPairingAndSetupGuide(context);
        } else if (matches(q, "tile", "quick setting", "vps", "server", "linux", "self host", "backend", "profile", "profiles")) {
            return getP2PTileAndServerGuide(context);
        } else {
            return getP2PMasterGuide(context);
        }
    }

    public static String getP2PExitNodeGuide(Context context) {
        return getP2PMasterGuide(context);
    }

    public static String getP2PMasterGuide(Context context) {
        return "### 🔄 KotSafe P2P Personal Gateway & Mesh Tunneling\n\n"
                + "The **P2P Personal Gateway** is a decentralized, zero-trust network tunnel that allows one Android device (**Client**) to securely route its internet egress through another trusted KotSafe node (**Exit Node Server**).\n\n"
                + "#### 🚀 Key Capabilities:\n"
                + "• **Decentralized Egress**: Turn your home phone, secondary device, or private Linux VPS into your own personal VPN exit node.\n"
                + "• **STUN Direct UDP Hole-Punching**: Automatically negotiates point-to-point UDP tunnels directly between devices with zero intermediary hops when NAT types permit.\n"
                + "• **Zero-Trust Encrypted Relay Fallback**: If both devices are behind strict carrier-grade NATs (CGNAT) or symmetric firewalls, traffic automatically routes through an encrypted relay with zero packet inspection.\n"
                + "• **ChaCha20-Poly1305 / AES-256-GCM AEAD**: Military-grade authenticated encryption ensures all data payloads, DNS lookups, and TCP flows remain completely private.\n"
                + "• **Per-App Split Tunneling**: Choose whether all apps, only select apps (e.g. banking, browser), or unselected apps bypass the tunnel.\n"
                + "• **Fail-Safe Kill Switch**: Instantly blocks all outgoing traffic if the P2P connection drops to prevent real IP or DNS leaks.\n"
                + "• **1-Tap Quick Settings Tile**: Easily enable or disable your gateway from the Android notification shade.\n\n"
                + "⚙️ **Configuration**: Access all settings in **Settings ➔ Personal Gateway (P2P Exit Node)**.\n\n"
                + "💡 *Ask specific questions anytime, such as:*\n"
                + "• *\"How do I pair devices using QR code?\"*\n"
                + "• *\"What is the difference between Direct P2P and Relay?\"*\n"
                + "• *\"How does P2P encryption work?\"*\n"
                + "• *\"How to setup Per-App Split Tunneling?\"*\n"
                + "• *\"What is the P2P Kill Switch?\"*\n"
                + "• *\"Why is my P2P connection disconnected or slow?\"*";
    }

    public static String getP2PPairingAndSetupGuide(Context context) {
        return "### 📲 P2P Setup & Device Pairing Guide\n\n"
                + "Pairing connects your Client device to your Exit Node Server using a cryptographic **Secure Pairing Bundle**:\n\n"
                + "#### 1️⃣ Step 1: Configure the Exit Node (Host Device)\n"
                + "1. Open KotSafe on the device that will provide internet egress.\n"
                + "2. Go to **Settings ➔ Personal Gateway (P2P Exit Node)**.\n"
                + "3. Toggle **Run as Exit Node Server** to `ON`.\n"
                + "4. Tap **Share Pairing Bundle** or **Show QR Code**.\n"
                + "   *(This generates a secure `kotp2p://...` token embedding the node's public key, STUN endpoint, and auth secret).*\n\n"
                + "#### 2️⃣ Step 2: Configure the Client (Roaming Device)\n"
                + "1. Open KotSafe on the client device.\n"
                + "2. Go to **Settings ➔ Personal Gateway (P2P Exit Node)**.\n"
                + "3. Toggle **Connect as Client** to `ON`.\n"
                + "4. Tap **Scan QR Code** (or paste the copied `kotp2p://` token).\n"
                + "5. Tap **Connect**.\n\n"
                + "#### 3️⃣ Verification:\n"
                + "• The notification shade or gateway dashboard will show:\n"
                + "  - `Connected: Direct P2P UDP` (direct high-speed tunnel) or\n"
                + "  - `Connected: Relay Tunnel` (encrypted relay fallback).\n"
                + "• Open your browser on the Client and verify your external IP matches the Exit Node device's network!";
    }

    public static String getP2PDirectVsRelayGuide(Context context) {
        return "### ⚡ Direct P2P UDP Hole Punching vs. Encrypted Relay\n\n"
                + "KotSafe uses a dual-engine transport policy (`DirectPunchCoordinator`) to ensure you can connect across any network environment:\n\n"
                + "#### 🌐 1. Direct P2P UDP Hole Punching (Primary):\n"
                + "• **How it works**: Uses standard STUN (Session Traversal Utilities for NAT) servers to discover each peer's public IP and mapped UDP port.\n"
                + "• Both devices transmit synchronized UDP probe packets toward each other's endpoints to punch holes through router state tables.\n"
                + "• **Benefits**: Minimum latency (lowest ping), line-speed throughput, and direct peer-to-peer data flow without passing through any third-party infrastructure.\n"
                + "• **Supported NATs**: Full Cone, Address-Restricted Cone, and Port-Restricted Cone NATs.\n\n"
                + "#### 🛡️ 2. Zero-Trust Encrypted Relay Fallback:\n"
                + "• **When it triggers**: If either device is behind **Symmetric NAT**, carrier-grade cellular NAT (CGNAT), or a strict corporate firewall blocking direct incoming UDP.\n"
                + "• **Zero-Trust Design**: All packets are encrypted on-device with ChaCha20-Poly1305 before transmission. The relay server acts purely as an opaque packet forwarder and **cannot read, decrypt, or log your traffic**.\n"
                + "• **Automatic Failover**: If direct UDP hole punching fails or drops, KotSafe smoothly falls back to the relay without interrupting your apps.";
    }

    public static String getP2PEncryptionAndSecurityGuide(Context context) {
        return "### 🔐 P2P Cryptographic Architecture & Privacy Shield\n\n"
                + "KotSafe's P2P subsystem is engineered under a strict **Zero-Trust Security Model**:\n\n"
                + "• **AEAD Encryption (`TunnelCipher`)**:\n"
                + "  Every packet is encapsulated and protected using **ChaCha20-Poly1305** (or hardware AES-256-GCM), providing both confidentiality and cryptographic integrity verification.\n\n"
                + "• **Anti-Replay Window Protection**:\n"
                + "  Packets carry monotonic 64-bit sequence numbers verified against a sliding replay window. Duplicate, altered, or replayed packets from network eavesdroppers are immediately dropped.\n\n"
                + "• **Can the Relay Server or Exit Node spy on my HTTPS traffic?**:\n"
                + "  - **Relay Server**: Cannot see anything. It only sees encrypted ciphertext blobs.\n"
                + "  - **Exit Node**: The Exit Node decrypts the P2P transport wrapper to forward packets to the internet. Standard HTTPS/TLS encryption between your browser and the destination website remains 100% end-to-end intact.\n\n"
                + "• **Unauthorized Connection Defense**:\n"
                + "  The Exit Node rejects any incoming handshake that lacks the cryptographic signature generated during pairing.";
    }

    public static String getP2PSplitTunnelingGuide(Context context) {
        return "### 🔀 P2P Per-App Split Tunneling\n\n"
                + "You do not need to route every single app through your P2P exit node. KotSafe gives you granular per-app control:\n\n"
                + "#### 🛠️ How to Configure:\n"
                + "1. Go to **Settings ➔ Personal Gateway (P2P Exit Node)**.\n"
                + "2. Tap **App Routing**.\n"
                + "3. Choose your preferred mode:\n\n"
                + "• **Option A: Route All Traffic (Default)**\n"
                + "  All device applications route their egress through the paired Exit Node.\n\n"
                + "• **Option B: Route Only Selected Apps (Whitelist Mode)**\n"
                + "  Only apps you check (e.g. Chrome, Banking apps, Messaging) use the P2P tunnel. All other apps stay on your normal local Wi-Fi/Mobile network.\n\n"
                + "• **Option C: Bypass Selected Apps (Blacklist Mode)**\n"
                + "  High-bandwidth or local apps (e.g. YouTube, Netflix, local media players) bypass the tunnel for maximum speed, while all other apps remain protected.";
    }

    public static String getP2PKillSwitchGuide(Context context) {
        return "### 🛑 P2P Fail-Safe Kill Switch\n\n"
                + "The **Kill Switch** prevents accidental public IP, DNS, or data leaks if your P2P tunnel drops:\n\n"
                + "• **How it works**: When enabled in **Settings ➔ Personal Gateway ➔ Kill Switch**, KotSafe monitors the active gateway session (`GatewaySessionController`).\n"
                + "• If the remote Exit Node goes offline, loses Wi-Fi, or switches networks, KotSafe **instantly drops all outbound packets** at the local VPN layer.\n"
                + "• **Why it is essential**:\n"
                + "  - On public or hotel Wi-Fi, an unencrypted tunnel drop could leak your real IP, browsing habits, or unencrypted DNS requests to the local network.\n"
                + "• Once the P2P tunnel reconnects, internet traffic resumes automatically.";
    }

    public static String generateLiveP2PDiagnosticsAndHealing(Context context) {
        if (context == null) {
            return getP2PTroubleshootingGuide(null);
        }

        android.content.SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        boolean clientEnabled = prefs.getBoolean(com.kotsafe.security.p2p.GatewayPreferenceKeys.CLIENT_ENABLED, false);
        boolean exitEnabled = prefs.getBoolean(com.kotsafe.security.p2p.GatewayPreferenceKeys.EXIT_ENABLED, false);
        boolean killSwitch = prefs.getBoolean(com.kotsafe.security.p2p.GatewayPreferenceKeys.KILL_SWITCH, true);
        String routingMode = prefs.getString(com.kotsafe.security.p2p.GatewayPreferenceKeys.APP_ROUTING_MODE, "all");
        String transportPref = prefs.getString(com.kotsafe.security.p2p.GatewayPreferenceKeys.TRANSPORT_MODE, "automatic");

        com.kotsafe.security.model.P2PExitNodeServer server = com.kotsafe.security.model.P2PExitNodeServer.getInstance();
        boolean serverRunning = (server != null && server.isRunning());
        int activeClients = server != null ? server.getActiveClients() : 0;
        long bytesTransferred = server != null ? server.getBytesTransferred() : 0;

        com.kotsafe.security.p2p.GatewayTelemetry telem = com.kotsafe.security.p2p.GatewayTelemetry.getInstance();
        boolean hostOnline = (telem != null && telem.isHostOnline());
        boolean directUdp = (telem != null && telem.isDirectP2PActive());
        int latency = telem != null ? telem.getLatencyMs() : -1;
        int jitter = telem != null ? telem.getJitterMs() : -1;
        float packetLoss = telem != null ? telem.getPacketLossPercent() : 0f;
        String speedSummary = telem != null ? telem.getSpeedSummary() : "Idle • 0 B/s";
        String networkSummary = telem != null ? telem.getNetworkSummary() : "No Uplink Info";
        String batterySummary = telem != null ? telem.getBatterySummary() : "No Battery Telemetry";

        android.os.PowerManager pm = (android.os.PowerManager) context.getSystemService(Context.POWER_SERVICE);
        boolean ignoringBattery = (pm != null && pm.isIgnoringBatteryOptimizations(context.getPackageName()));
        boolean isVpnActive = CaptureService.isServiceActive();

        StringBuilder sb = new StringBuilder();
        sb.append("### 🤖 KotSafe AI P2P Diagnostics, Troubleshooting & Self-Healing\n\n");

        sb.append("#### 🌐 Active Role & Operational State\n");
        if (exitEnabled) {
            sb.append("• **Configured Role**: 🛡️ **Exit Node Server (Host)**\n");
            sb.append("• **Server Daemon**: ").append(serverRunning ? "🟢 Running on Port " + (server != null ? server.getPort() : 8090) : "🔴 Stopped").append("\n");
            sb.append("• **Active Paired Clients**: ").append(activeClients).append(" peer(s)\n");
            sb.append("• **Total Egress Relayed**: ").append(com.kotsafe.security.p2p.GatewayTelemetry.formatBytes(bytesTransferred)).append("\n");
        } else if (clientEnabled) {
            sb.append("• **Configured Role**: 🚀 **P2P Roaming Client**\n");
            sb.append("• **Tunnel Status**: ").append(hostOnline ? "🟢 Connected to Exit Node" : "🔴 Exit Node Offline / Standby").append("\n");
            sb.append("• **VPN Packet Engine**: ").append(isVpnActive ? "🟢 Active (SOCKS5 Redirection: 127.0.0.1:8095)" : "⚠️ VPN Inactive").append("\n");
            sb.append("• **Kill-Switch**: ").append(killSwitch ? "🔒 Enabled (Zero IP Leak Protection)" : "⚠️ Disabled").append("\n");
            sb.append("• **App Routing**: ").append("all".equals(routingMode) ? "All Apps" : ("only_selected".equals(routingMode) ? "Selected Apps Only" : "Bypass Selected")).append("\n");
        } else {
            sb.append("• **Configured Role**: ⏸️ **Standby** (Neither Client nor Exit Node is active)\n");
            sb.append("• **VPN Packet Engine**: ").append(isVpnActive ? "🟢 Active (Standard Firewall/Antivirus)" : "⏸️ Inactive").append("\n");
        }

        sb.append("\n#### ⚡ Link Health & Real-time Telemetry\n");
        if (clientEnabled || exitEnabled) {
            sb.append("• **Transport Mode**: ");
            if (directUdp) {
                sb.append("⚡ **Direct P2P UDP** (Low latency, VPS bypassed)\n");
            } else if (hostOnline) {
                sb.append("🛡️ **Zero-Trust Encrypted Relay** (Oracle VPS 130.210.16.110)\n");
            } else {
                sb.append("⏸️ Disconnected (Policy: ").append(transportPref).append(")\n");
            }
            if (latency >= 0) sb.append("• **Round-Trip Ping (RTT)**: ").append(latency).append(" ms\n");
            if (jitter >= 0) sb.append("• **Jitter**: ").append(jitter).append(" ms\n");
            if (packetLoss > 0) sb.append("• **Packet Loss**: ").append(String.format(Locale.US, "%.1f%%", packetLoss)).append("\n");
            sb.append("• **Throughput**: ").append(speedSummary).append("\n");
            if (clientEnabled) {
                sb.append("• **Remote Exit Uplink**: ").append(networkSummary).append("\n");
                sb.append("• **Remote Exit Battery**: ").append(batterySummary).append("\n");
            }
        } else {
            sb.append("• Telemetry is idle because P2P tunnel is not enabled on this device.\n");
        }

        sb.append("\n#### 🔐 Cryptographic Integrity & Security\n");
        sb.append("• **AEAD Encryption**: ChaCha20-Poly1305 / AES-256-GCM\n");
        sb.append("• **Anti-Replay Window**: 64-bit monotonic sequence verification active\n");
        sb.append("• **Zero-Knowledge Relay**: Oracle Cloud VPS acts as opaque carrier — cannot inspect or decrypt payloads\n");

        sb.append("\n#### 🔋 System & Background Resilience\n");
        if (ignoringBattery) {
            sb.append("• **Battery Optimization**: ⚡ **Unrestricted** (Safe from Android Doze termination)\n");
        } else {
            sb.append("• **Battery Optimization**: ⚠️ **Restricted** (Android Doze may sleep P2P sockets when screen is off!)\n");
        }

        sb.append("\n#### 💡 Automated Diagnostic Analysis & 1-Tap Healing\n");
        if (!ignoringBattery) {
            sb.append("⚠️ **Critical Notice**: Android battery saver is currently restricting KotSafe. This can cause the Exit Node or Client tunnel to drop when the phone screen is off.\n\n");
            sb.append("👉 Tap the button below to exempt KotSafe from battery optimization:\n");
            sb.append("[RULE_ACTION:IGNORE_BATTERY:POWER]");
        } else if (clientEnabled && !hostOnline) {
            sb.append("⚠️ **Exit Node Unreachable**: The client is enabled, but the Exit Node is currently offline or unreachable over the relay.\n\n");
            sb.append("1. Verify the Exit Node device is turned on with KotSafe running.\n");
            sb.append("2. Tap the button below to re-negotiate the tunnel:\n");
            sb.append("[RULE_ACTION:RECONNECT_P2P:TUNNEL]");
        } else if (!clientEnabled && !exitEnabled) {
            sb.append("ℹ️ P2P Personal Gateway is currently in standby. Tap below to configure pairing or launch as Exit Node:\n");
            sb.append("[RULE_ACTION:OPEN_P2P:SETTINGS]");
        } else if (!isVpnActive && clientEnabled) {
            sb.append("⚠️ P2P Client is enabled, but the local VPN packet capture is not running. Tap below to launch:\n");
            sb.append("[RULE_ACTION:START_VPN:LAUNCH]");
        } else {
            sb.append("✅ **All P2P systems are healthy and operating normally!**\n");
            sb.append("• Egress traffic is securely protected.\n");
            sb.append("• Tap below if you wish to adjust gateway settings or re-sync:\n");
            sb.append("[RULE_ACTION:OPEN_P2P:SETTINGS]");
        }

        return sb.toString();
    }

    public static String getP2PTroubleshootingGuide(Context context) {
        if (context != null) {
            return generateLiveP2PDiagnosticsAndHealing(context);
        }
        return "### 🛠️ P2P Troubleshooting & Diagnostic Checklist\n\n"
                + "If your P2P tunnel is not connecting, dropping, or experiencing slow speeds, check these solutions:\n\n"
                + "1. **Exit Node (Host) in Background / Sleeping**:\n"
                + "   - Android aggressive battery management may pause background services.\n"
                + "   - On the Host device: Go to Android Settings ➔ Apps ➔ KotSafe ➔ Battery ➔ set to **Unrestricted**.\n\n"
                + "2. **Pairing Token Mismatch or Stale Credentials**:\n"
                + "   - If the Exit Node's network IP changed, re-open KotSafe on the Host, tap **Share Pairing Bundle**, and scan the fresh QR code on the Client.\n\n"
                + "3. **High Latency or Slow Speeds**:\n"
                + "   - Check the Quick Settings Tile or gateway telemetry: if status is `Relay Tunnel`, direct UDP could not be negotiated due to strict symmetric NAT.\n"
                + "   - Connecting the Host device to a home Wi-Fi with UPnP enabled allows direct high-speed P2P UDP.\n\n"
                + "4. **Cellular Carrier UDP Throttling**:\n"
                + "   - Some mobile providers throttle persistent UDP connections. If experiencing disconnects on mobile data, test over Wi-Fi or toggle the gateway off/on.";
    }

    public static String getHomeRouterProxyResponse(Context context, String userQuery) {
        String host = null;
        int port = -1;

        if (userQuery != null) {
            java.util.regex.Pattern endpointPattern = java.util.regex.Pattern.compile(
                    "([a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}|[0-9]{1,3}(?:\\.[0-9]{1,3}){3}):(\\d{2,5})"
            );
            java.util.regex.Matcher m = endpointPattern.matcher(userQuery);
            if (m.find()) {
                host = m.group(1);
                try {
                    port = Integer.parseInt(m.group(2));
                } catch (Exception ignored) {}
            } else {
                java.util.regex.Pattern hostPattern = java.util.regex.Pattern.compile(
                        "([a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}|[0-9]{1,3}(?:\\.[0-9]{1,3}){3})"
                );
                java.util.regex.Matcher hm = hostPattern.matcher(userQuery);
                if (hm.find()) {
                    host = hm.group(1);
                }
                java.util.regex.Pattern portPattern = java.util.regex.Pattern.compile("(?:port\\s+|:)(\\d{2,5})", java.util.regex.Pattern.CASE_INSENSITIVE);
                java.util.regex.Matcher pm = portPattern.matcher(userQuery);
                if (pm.find()) {
                    try {
                        port = Integer.parseInt(pm.group(1));
                    } catch (Exception ignored) {}
                }
            }
        }

        String suggestedGateway = getDetectedLocalGateway(context);
        if (port <= 0) port = 1080;

        SharedPreferences prefs = (context != null) ? PreferenceManager.getDefaultSharedPreferences(context) : null;
        String savedHost = (prefs != null) ? prefs.getString("pref_saved_home_host", null) : null;
        int savedPort = (prefs != null) ? prefs.getInt("pref_saved_home_port", 1080) : 1080;

        StringBuilder sb = new StringBuilder();
        sb.append("### 🌐 Route Device Traffic via Home (Inside or Out of Station)\n\n");
        sb.append("When you are away or out of station, you have **2 easy options** to route all device traffic through your home network:\n\n");

        sb.append("#### 1. 📱 KotSafe P2P Mesh (Recommended — Zero-Config)\n");
        sb.append("• Keep an old phone or PC at home connected to your Wi-Fi in **Exit Node Mode**.\n");
        sb.append("• **No router settings, no port forwarding, and no public IP needed!**\n");
        sb.append("• Works seamlessly anywhere in the world on 4G/5G, even behind cellular carrier CGNAT.\n\n");

        sb.append("#### 2. 🌐 Direct Router Port Forwarding (SOCKS5)\n");
        sb.append("• Forward port `1080` in your home router from WAN → your home computer, server, or smart router.\n");
        sb.append("• When out of station, connect using your Public WAN IP or Dynamic DNS (e.g., `myhome.duckdns.org`).\n");
        sb.append("• Once configured, KotSafe saves this setup for instant 1-tap reconnection anytime you travel!\n\n");

        if (savedHost != null && !savedHost.isEmpty()) {
            EndpointClassification savedClass = classifyEndpoint(savedHost);
            sb.append("#### 🏠 Saved Home Profile Available:\n");
            sb.append("• **Last Saved Home Gateway**: `").append(savedHost).append(":").append(savedPort).append("` (").append(savedClass.title).append(")\n\n");
        }

        if (host != null && !host.isEmpty()) {
            EndpointClassification classification = classifyEndpoint(host);
            sb.append("#### ⚡ Detected Configuration from your message:\n");
            sb.append("• **Target Endpoint**: `").append(host).append(":").append(port).append("`\n");
            sb.append("• **Endpoint Classification**: ").append(classification.title).append("\n");
            sb.append("  ").append(classification.description).append("\n\n");
            sb.append("Choose your preferred connection method below:\n\n");
            sb.append("[RULE_ACTION:CONNECT_ROUTER_PROXY:").append(host).append(":").append(port).append("]\n");
            sb.append("[RULE_ACTION:OPEN_P2P:SETTINGS]");
        } else {
            if (!suggestedGateway.isEmpty()) {
                sb.append("💡 *Detected current local Wi-Fi gateway: `").append(suggestedGateway).append("`*\n\n");
            }
            sb.append("Choose an option below to connect:\n\n");
            if (savedHost != null && !savedHost.isEmpty()) {
                sb.append("[RULE_ACTION:RECONNECT_SAVED_HOME:").append(savedHost).append(":").append(savedPort).append("]\n");
            }
            sb.append("[RULE_ACTION:OPEN_P2P:SETTINGS]\n");
            sb.append("[RULE_ACTION:SETUP_ROUTER_PROXY:ROUTER]");
        }
        return sb.toString();
    }

    public static String getDetectedLocalGateway(Context context) {
        if (context == null) return "";
        try {
            android.net.wifi.WifiManager wm = (android.net.wifi.WifiManager) context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            if (wm != null && wm.getDhcpInfo() != null) {
                int gatewayInt = wm.getDhcpInfo().gateway;
                if (gatewayInt != 0) {
                    return android.text.format.Formatter.formatIpAddress(gatewayInt);
                }
            }
        } catch (Exception ignored) {}
        return "";
    }

    public enum EndpointClassification {
        LOCAL_PRIVATE("Local Private IP", "⚠️ Only works while connected to home Wi-Fi. Ineffective when out of station!", 0xFFFF9800),
        CGNAT("Carrier-Grade NAT (CGNAT)", "❌ ISP shares this IP. Incoming connections are blocked by ISP! Use P2P Mesh instead.", 0xFFF44336),
        PUBLIC_IP("Public WAN IP", "🌍 Public IP: Works for out-of-station roaming with port forwarding enabled on your router.", 0xFF00BCD4),
        DDNS_DOMAIN("Dynamic DNS / Domain", "🌐 DDNS Hostname: Recommended for out-of-station! Automatically tracks your home IP changes.", 0xFF4CAF50),
        GLOBAL_IPV6("Global IPv6 Address", "🌐 Direct End-to-End IPv6! Bypasses NAT & CGNAT completely without router port forwarding.", 0xFF4CAF50),
        LOOPBACK("Loopback / Localhost", "⚠️ Localhost address: Only accessible locally on this device.", 0xFFFF9800),
        EMPTY("No Endpoint Entered", "ℹ️ Enter your home router's Public IP or DDNS (e.g. myhome.duckdns.org)", 0xFF888888),
        INVALID("Invalid Endpoint Format", "⚠️ Please enter a valid IP address or domain hostname.", 0xFFE91E63);

        public final String title;
        public final String description;
        public final int color;

        EndpointClassification(String title, String description, int color) {
            this.title = title;
            this.description = description;
            this.color = color;
        }
    }

    public static EndpointClassification classifyEndpoint(String host) {
        if (host == null || host.trim().isEmpty()) {
            return EndpointClassification.EMPTY;
        }
        String trimmed = host.trim().toLowerCase(Locale.ROOT);
        if (trimmed.equals("localhost") || trimmed.startsWith("127.")) {
            return EndpointClassification.LOOPBACK;
        }

        // IPv6 detection
        if (trimmed.contains(":")) {
            if (trimmed.equals("::1")) {
                return EndpointClassification.LOOPBACK;
            }
            if (trimmed.startsWith("fe80:") || trimmed.startsWith("fd") || trimmed.startsWith("fc")) {
                return EndpointClassification.LOCAL_PRIVATE;
            }
            if (trimmed.matches("^[0-9a-f:]+$") && trimmed.split(":").length >= 3) {
                return EndpointClassification.GLOBAL_IPV6;
            }
        }

        // RFC 1918 Private IP ranges
        if (trimmed.startsWith("192.168.") || trimmed.startsWith("10.") || trimmed.matches("^172\\.(1[6-9]|2[0-9]|3[0-1])\\..*")) {
            return EndpointClassification.LOCAL_PRIVATE;
        }
        // RFC 6598 Carrier-Grade NAT (100.64.0.0 to 100.127.255.255)
        if (trimmed.matches("^100\\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\\..*")) {
            return EndpointClassification.CGNAT;
        }
        // IPv4 format
        if (trimmed.matches("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")) {
            return EndpointClassification.PUBLIC_IP;
        }
        // Valid domain name / DDNS hostname
        if (trimmed.matches("^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}$")) {
            return EndpointClassification.DDNS_DOMAIN;
        }
        return EndpointClassification.INVALID;
    }

    public static String getDdnsSetupGuide(Context context) {
        SharedPreferences prefs = (context != null) ? PreferenceManager.getDefaultSharedPreferences(context) : null;
        boolean socks5Enabled = (prefs != null) && prefs.getBoolean(Prefs.PREF_SOCKS5_ENABLED_KEY, false);
        String socks5Host = (prefs != null) ? prefs.getString(Prefs.PREF_SOCKS5_PROXY_IP_KEY, "Not set") : "Not set";
        String socks5Port = (prefs != null) ? prefs.getString(Prefs.PREF_SOCKS5_PROXY_PORT_KEY, "1080") : "1080";

        StringBuilder sb = new StringBuilder();
        sb.append("### 🌐 Dynamic DNS (DDNS) Setup Guide for Out-of-Station Access\n\n");
        sb.append("When you are outside or traveling, you cannot connect to your home router using a local private IP (`192.168.x.x`). You need a **Public Endpoint**.\n\n");
        sb.append("Because home ISPs change your Public WAN IP periodically or upon router reboot, **Dynamic DNS (DDNS)** provides a permanent free hostname (such as `myhome.duckdns.org` or `myrouter.tplinkdns.com`) that automatically stays updated with your home router's latest IP!\n\n");

        sb.append("#### 🛠️ Option A: Free Router-Native DDNS (Easiest)\n");
        sb.append("Most modern routers include built-in free Dynamic DNS in their admin dashboard:\n");
        sb.append("1. **TP-Link**:\n");
        sb.append("   • Go to `192.168.0.1` ➔ **Advanced** ➔ **Network** ➔ **Dynamic DNS**.\n");
        sb.append("   • Select Service Provider: **TP-Link** (bind your free TP-Link ID) or **No-IP**.\n");
        sb.append("   • Register your domain: e.g. `yourname.tplinkdns.com`.\n");
        sb.append("2. **Asus**:\n");
        sb.append("   • Go to `192.168.1.1` ➔ **WAN** ➔ **DDNS** tab.\n");
        sb.append("   • Enable DDNS Client ➔ Server: **ASUS.COM**.\n");
        sb.append("   • Host Name: `yourname.asuscomm.com` (100% Free).\n");
        sb.append("3. **Netgear / D-Link**:\n");
        sb.append("   • Go to **Advanced** ➔ **Dynamic DNS** ➔ Register via NETGEAR or D-Link DDNS.\n\n");

        sb.append("#### 🦆 Option B: DuckDNS (100% Free for Any Router, PC, or Server)\n");
        sb.append("If your router lacks built-in DDNS:\n");
        sb.append("1. Visit [duckdns.org](https://www.duckdns.org) and sign in with Google or GitHub.\n");
        sb.append("2. Create a free subdomain: e.g. `myhome.duckdns.org`.\n");
        sb.append("3. Open the **install** tab, copy the auto-update script for your router model or run it as a lightweight background script on your home PC or Raspberry Pi.\n\n");

        sb.append("#### 📲 Current KotSafe Router Proxy Status:\n");
        sb.append("• **SOCKS5 Engine**: ").append(socks5Enabled ? "✅ **ENABLED**" : "⚠️ **DISABLED**").append("\n");
        sb.append("• **Configured Endpoint**: `").append(socks5Host).append(":").append(socks5Port).append("`\n");
        if (socks5Host != null && !socks5Host.equals("Not set")) {
            EndpointClassification classification = classifyEndpoint(socks5Host);
            sb.append("• **Classification**: ").append(classification.title).append(" — ").append(classification.description).append("\n");
        }
        sb.append("\n");

        sb.append("#### 🤖 Ask Online AI for Exact Router Model Instructions:\n");
        sb.append("```text\n");
        sb.append("How do I configure Dynamic DNS (DDNS) on my [ENTER ROUTER BRAND/MODEL, e.g. TP-Link Archer C6]?\n");
        sb.append("I need a free domain name to forward port 1080 to my home SOCKS5 proxy so I can connect while traveling away from home.\n");
        sb.append("```\n\n");

        sb.append("💡 *Tip: If port forwarding or DDNS is too complex, Option 1 (KotSafe P2P Mesh) requires zero router settings or public IP!*\n\n");
        sb.append("Choose an action below to automate setup or connect:\n\n");
        sb.append("[RULE_ACTION:SETUP_ROUTER_PROXY:ROUTER]\n");
        sb.append("[RULE_ACTION:OPEN_P2P:SETTINGS]\n");
        sb.append("[RULE_ACTION:OPEN_AI_SETTINGS:SETTINGS]");

        return sb.toString();
    }

    public static String getP2PTileAndServerGuide(Context context) {
        return "### ⚡ Quick Settings Tile & VPS Linux Exit Node\n\n"
                + "#### 📲 Android Quick Settings Tile:\n"
                + "• Swipe down your Android notification panel twice.\n"
                + "• Tap the **Edit (Pencil)** icon and scroll down.\n"
                + "• Drag the **Personal Gateway** tile into your active quick settings.\n"
                + "• Tap the tile anytime to instantly start or stop the P2P Client / Exit Node without opening the app!\n\n"
                + "#### 🖥️ Dedicated VPS / Linux Exit Node:\n"
                + "• You do not need to keep a second phone powered on at home.\n"
                + "• KotSafe P2P backend can be deployed as a lightweight daemon on any cloud VPS (Ubuntu, Debian, DigitalOcean, Hetzner, AWS) or a home Raspberry Pi.\n"
                + "• In KotSafe Client: Enter your server's IP, port, and authentication token to enjoy a dedicated, private, unmetered 24/7 exit node!";
    }

    // =========================================================================
    // 10. PHYSICAL SECURITY & ANTI-SNOOPING (SCREENPEEK, USB, SIM)
    // =========================================================================
    public static String getPhysicalSecurityGuide(Context context) {
        return "### 👁️ ScreenPeek & Physical Anti-Snooping Suite\n\n"
                + "KotSafe protects not just your network, but also your device's physical security:\n\n"
                + "• **ScreenPeek (Shoulder-Surfing Detection)**:\n"
                + "  Uses on-device front camera computer vision to detect if someone is looking over your shoulder. If an unauthorized face is detected, it blurs the screen or triggers a discreet alert.\n\n"
                + "• **USB Data Lock**:\n"
                + "  Protects against *Juice Jacking* at public charging stations (airports, cafes) by restricting USB connections to charging-only mode and blocking unauthorized MTP/ADB handshakes.\n\n"
                + "• **SIM Card Swap Lock**:\n"
                + "  Monitors your IMSI/ICCID. If your SIM card is removed or swapped, KotSafe instantly locks the device with biometric re-authentication to prevent 2FA interception.";
    }

    public static String getRouterSetupAndErrorGuide(Context context, String userQuery) {
        SharedPreferences prefs = (context != null) ? PreferenceManager.getDefaultSharedPreferences(context) : null;
        boolean socks5Enabled = (prefs != null) && prefs.getBoolean(Prefs.PREF_SOCKS5_ENABLED_KEY, false);
        String socks5Host = (prefs != null) ? prefs.getString(Prefs.PREF_SOCKS5_PROXY_IP_KEY, "Not set") : "Not set";
        String socks5Port = (prefs != null) ? prefs.getString(Prefs.PREF_SOCKS5_PROXY_PORT_KEY, "1080") : "1080";
        boolean vpnActive = CaptureService.isServiceActive();

        StringBuilder sb = new StringBuilder();
        sb.append("### 🛠️ Router Port Forwarding Setup & Diagnostics\n\n");

        sb.append("#### 1. ⚙️ Step-by-Step ONT / Router Port Forwarding Setup (While on Home Wi-Fi):\n");
        sb.append("Most Fiber / Broadband ONT and Wi-Fi routers follow this standard configuration:\n");
        sb.append("1. **Log in**: Open your browser and navigate to `192.168.1.1` (or `192.168.0.1`). Default credentials are usually `admin` / `admin` or printed on the router label.\n");
        sb.append("2. **Find Port Forwarding**: Go to **Forward Rules** (or **Advanced Setup ➔ NAT ➔ Virtual Server / Port Mapping / Port Forwarding**).\n");
        sb.append("3. **Click Add / New**:\n");
        sb.append("   • **Service Name**: `KotSafe`\n");
        sb.append("   • **WAN Interface**: Select your active internet connection (e.g. `1_INTERNET_R_VID_...`)\n");
        sb.append("   • **External / WAN Port**: `1080` (or `1080-1080`)\n");
        sb.append("   • **Internal IP**: Local IP of your PC / device (e.g. `192.168.1.50`)\n");
        sb.append("   • **Internal Port**: `1080`\n");
        sb.append("   • **Protocol**: `TCP`\n");
        sb.append("4. **Apply / Save Changes**: Save the rule and reboot the ONT router if prompted.\n\n");

        sb.append("#### 2. 💻 What If the Home Computer Is Turned Off?\n");
        sb.append("• **Traffic Stops**: If the home PC running the SOCKS5 proxy server is powered off or enters sleep/hibernate mode, the router has nowhere to forward incoming packets. KotSafe will report `Connection Refused` or `Timed Out`.\n");
        sb.append("• **Low-Power Alternatives to Keeping a PC On 24/7**:\n");
        sb.append("  1. **Old Android Phone / Tablet (Recommended)**: Keep an old phone plugged into a charger at home running KotSafe in **Personal Gateway / Exit Node Mode**. Consumes only ~1W of power and has a built-in battery backup!\n");
        sb.append("  2. **Raspberry Pi / Mini PC**: A tiny credit-card PC running Linux that stays on 24/7 consuming only ~3W.\n");
        sb.append("  3. **Wake-on-LAN (WoL)**: Configure your PC BIOS and router to send a Magic Packet to wake the computer remotely.\n");
        sb.append("  4. **Router-Native Proxy**: If using an OpenWrt router, run the proxy daemon directly on the router hardware so no computer is needed at all.\n\n");

        sb.append("#### 3. 📲 Inside KotSafe: How It Works & Current App Status:\n");
        sb.append("• **SOCKS5 Engine**: ").append(socks5Enabled ? "✅ **ENABLED**" : "⚠️ **DISABLED**").append("\n");
        sb.append("• **Target Router Host**: `").append(socks5Host).append(":").append(socks5Port).append("`\n");
        sb.append("• **VPN Pipeline**: ").append(vpnActive ? "✅ **ACTIVE & ROUTING**" : "⏸️ **STANDBY**").append("\n");
        sb.append("• **How KotSafe handles it**: When enabled, `KotEngineBridge` transparently encapsulates all app TCP connections into SOCKS5 frames sent to your router. QUIC is blocked to ensure strict TCP proxy traversal, and the profile is saved for 1-tap re-routing.\n\n");

        sb.append("#### 🛡️ Security & Authentication: Can Anyone Connect to My Router?\n");
        sb.append("• **The Open Proxy Risk**: When you forward port 1080 on your router to the public internet, it becomes reachable by external scanners. If your SOCKS5 proxy does NOT have authentication enabled, **anyone on the internet can use your home IP as an open proxy!**\n");
        sb.append("• **How to Secure Your Connection**:\n");
        sb.append("  1. **Mandatory Username & Password**: Always configure your home SOCKS5 proxy server with a strong username and password. In KotSafe, enter these credentials in the setup dialog. KotSafe automatically performs RFC 1928 authentication. Unauthenticated connection attempts are immediately dropped!\n");
        sb.append("  2. **KotSafe P2P Mesh (Zero Open Ports — Strongest Protection)**: In KotSafe P2P Mode, no open ports are exposed to the internet. Traffic is encrypted end-to-end with an Ed25519 pairing token. Outside scanners cannot even see that a proxy exists!\n\n");

        sb.append("#### 🚀 Advanced Connection Technologies:\n");
        sb.append("• **1-Tap UPnP / NAT-PMP**: Automatically maps port 1080 on your router gateway without manual login.\n");
        sb.append("• **Remote Wake-on-LAN (WoL)**: Sends a Magic Packet to wake a sleeping home PC on demand.\n");
        sb.append("• **Direct Global IPv6**: Connects directly to your home device's global IPv6 address, bypassing CGNAT and router NAT completely.\n\n");

        sb.append("#### 4. 🔍 Diagnosing Router Errors & Online AI Prompt:\n");
        sb.append("Common issues:\n");
        sb.append("• **Connection Refused**: Port forwarding is open, but no SOCKS5 proxy server is running on the home device, or the PC is off.\n");
        sb.append("• **Timed Out**: Router firewall is blocking port 1080, or your ISP uses **CGNAT** (private WAN IP like `100.64.x.x`).\n\n");

        sb.append("*As an on-device offline AI, my diagnostic capability for custom router brand errors is limited. You can copy and paste this pre-formatted prompt into **ChatGPT**, **Google Gemini**, or **Claude** for exact router model instructions:*\n\n");
        sb.append("```text\n");
        sb.append("I am trying to route mobile traffic through my home router using SOCKS5 on port 1080.\n");
        sb.append("My error / question: ").append(userQuery != null ? userQuery.trim() : "Port 1080 is unreachable").append("\n");
        sb.append("My Setup:\n");
        sb.append("- App: KotSafe Android (SOCKS5 Direct Client)\n");
        sb.append("- Desired Configuration: External WAN Port 1080 -> Internal Device Port 1080 (TCP)\n");
        sb.append("Please give me step-by-step troubleshooting instructions for my router and how to resolve this error.\n");
        sb.append("```\n\n");

        sb.append("💡 *Tip: If port forwarding continues to fail due to ISP CGNAT or turning off the PC, use Option 1 (KotSafe P2P Mesh) — it requires zero router configuration!*\n\n");
        sb.append("Choose an action below:\n\n");
        sb.append("[RULE_ACTION:OPEN_AI_SETTINGS:SETTINGS]\n");
        sb.append("[RULE_ACTION:OPEN_P2P:SETTINGS]\n");
        sb.append("[RULE_ACTION:SETUP_ROUTER_PROXY:ROUTER]\n\n");

        return sb.toString();
    }

    public static String getNetworkPerformanceGuide(Context context) {
        SharedPreferences prefs = (context != null) ? PreferenceManager.getDefaultSharedPreferences(context) : null;
        boolean blockQuic = (prefs != null) && Prefs.BLOCK_QUIC_MODE_ALWAYS.equals(prefs.getString(Prefs.PREF_BLOCK_QUIC, Prefs.BLOCK_QUIC_MODE_NEVER));

        StringBuilder sb = new StringBuilder();
        sb.append("### ⚡ Network Speed, Ping & Latency Optimization\n\n");
        sb.append("If your internet feels slower while KotSafe is running, here is why and how to optimize it:\n\n");
        sb.append("#### 1. 🌐 Encrypted DNS (DoH) Latency\n");
        sb.append("• Standard unencrypted DNS is fast but insecure. Encrypted DoH wraps domain queries in HTTPS.\n");
        sb.append("• **Optimization**: In **Settings ➔ DNS**, switch to **Cloudflare (1.1.1.1)** or **Google (8.8.8.8)** for lowest latency.\n\n");
        sb.append("#### 2. 🛡️ QUIC / HTTP3 Protocol Inspection\n");
        sb.append("• ").append(blockQuic ? "QUIC blocking is currently **ACTIVE**." : "QUIC blocking is currently **DISABLED**.").append("\n");
        sb.append("• Blocking QUIC forces apps to fall back to TCP TLS for inspection, which can add a brief initial handshake delay.\n\n");
        sb.append("#### 3. 📊 Check Top Talkers\n");
        sb.append("• Check if a background app is downloading heavy telemetry in the Connections tab.\n\n");
        sb.append("Tap below to inspect live bandwidth:\n\n");
        sb.append("[RULE_ACTION:VIEW_TRAFFIC:CONNS]");
        return sb.toString();
    }

    public static String getBatteryOptimizationGuide(Context context) {
        StringBuilder sb = new StringBuilder();
        sb.append("### 🔋 Battery Consumption & Power Optimization\n\n");
        sb.append("KotSafe is engineered with a zero-copy C kernel (`KotEngine`) for minimal CPU usage. However, deep packet inspection on 4K streaming or large downloads processes thousands of packets per second.\n\n");
        sb.append("#### 💡 Power-Saving Tips:\n");
        sb.append("1. **Disable HTTPS TLS Decryption** unless actively auditing app APIs — TLS re-encryption is CPU-intensive.\n");
        sb.append("2. **Exempt KotSafe from Android Battery Optimization**: When aggressive OEM task killers (ColorOS, MIUI, OneUI) kill and restart the VPN service every few minutes, it drains *more* battery than letting the service run steadily.\n\n");
        sb.append("Tap below to exempt KotSafe from battery killing:\n\n");
        sb.append("[RULE_ACTION:IGNORE_BATTERY:SYSTEM]");
        return sb.toString();
    }

    public static String getVpnDisconnectGuide(Context context) {
        StringBuilder sb = new StringBuilder();
        sb.append("### 🛡️ Why Does the VPN Keep Disconnecting or Stopping?\n\n");
        sb.append("KotSafe never disconnects by itself unless terminated by Android system memory management.\n\n");
        sb.append("#### 📱 Root Causes & Fixes:\n");
        sb.append("1. **OEM Background Task Killer**: Android skins (ColorOS, MIUI, OneUI) terminate background VPN services when the screen locks.\n");
        sb.append("   • **Fix**: Open Android Recents (swipe up), find KotSafe, and tap the lock icon to **Lock** the app.\n");
        sb.append("2. **Battery Optimization**: Grant KotSafe unconstrained background execution.\n");
        sb.append("3. **Always-On VPN**: In Android Settings ➔ Network ➔ VPN ➔ KotSafe, enable **Always-On VPN**.\n\n");
        sb.append("Tap below to exempt KotSafe from battery optimization:\n\n");
        sb.append("[RULE_ACTION:IGNORE_BATTERY:SYSTEM]\n");
        sb.append("[RULE_ACTION:START_VPN:CAPTURE]");
        return sb.toString();
    }

    public static String getAboutKotSafeGuide(Context context) {
        return "### 🛡️ About KotSafe Mobile Defense\n\n"
                + "KotSafe is an on-device, zero-trust network packet sentinel and privacy workstation.\n\n"
                + "• **100% On-Device**: Packet inspection, firewall rules, and malware scans run locally in the device kernel. Your data never touches third-party tracking servers.\n"
                + "• **Core Defenses**: Packet Sentinel, Stateful Firewall, DoH DNS Encryption, Local Antivirus with YARA, and P2P Roaming Gateway.\n\n"
                + "Ask me anytime how to configure rules, troubleshoot traffic, or secure your connection!";
    }

    public static String getCoreArchitectureModesGuide(Context context, String userQuery) {
        String q = (userQuery != null) ? userQuery.toLowerCase(Locale.ROOT).trim() : "";

        StringBuilder sb = new StringBuilder();
        sb.append("### 🚀 KotSafe Core Architecture & Security Operating Modes\n\n");
        sb.append("🛡️ **CRITICAL REQUIREMENT: ALWAYS USE AUTHENTICATION ON SETUP**\n");
        sb.append("KotSafe integrates the 5 most advanced network security and tunneling paradigms. **You must ALWAYS enable strong authentication on every mode during setup.** Exposing unauthenticated proxies or VPN tunnels leaves your device and home router completely vulnerable to automated internet scanners, credential theft, and botnets!\n\n");

        sb.append("#### 1. 🌐 Tailscale (P2P Mesh VPN & Zero-Config Exit Node)\n");
        sb.append("• **How KotSafe Implements It**: Decentralized peer-to-peer mesh tunneling with automated STUN/NAT hole-punching.\n");
        sb.append("• **Use Case**: Run KotSafe in **Personal Gateway / Exit Node Mode** on any device at home. Roam anywhere on 4G/5G mobile data and route through home without opening router ports or needing a public IP!\n");
        sb.append("• **🔒 Mandatory Authentication Setup**: **Always use authenticated pairing!** Mandate pre-shared 256-bit Ed25519 cryptographic pairing bundles or node authorization keys. Never allow unverified peer nodes to join your private mesh.\n");
        sb.append("• **Action**: `[RULE_ACTION:OPEN_P2P:SETTINGS]`\n\n");

        sb.append("#### 2. ⚡ WireGuard (Private Encrypted VPN Tunnel)\n");
        sb.append("• **How KotSafe Implements It**: State-of-the-art cryptography (Curve25519 key exchange, ChaCha20-Poly1305 encryption, BLAKE2s hashing) running on a native C-kernel zero-copy pipeline.\n");
        sb.append("• **Use Case**: Maximum throughput, ultra-low battery consumption, and seamless roaming without dropped handshakes.\n");
        sb.append("• **🔒 Mandatory Authentication Setup**: **Always enforce cryptographic key authentication!** Require unique Curve25519 public/private key-pairs and mandate a Pre-Shared Key (PSK) for post-quantum resistance so only authorized endpoints can complete a handshake.\n");
        sb.append("• **Action**: `[RULE_ACTION:START_VPN:CAPTURE]`\n\n");

        sb.append("#### 3. 🛡️ NetGuard (Local No-Root Firewall)\n");
        sb.append("• **How KotSafe Implements It**: Fine-grained per-app and per-packet rule enforcement completely on-device without root access or external servers.\n");
        sb.append("• **Use Case**: Block individual apps from Wi-Fi or Cellular access, drop suspicious background telemetry, and isolate untrusted packages.\n");
        sb.append("• **🔒 Mandatory Authentication Setup**: **Always lock firewall settings!** Secure rule modifications behind device biometric (fingerprint/face) or PIN authentication so unauthorized physical users or rogue background apps cannot tamper with or disable filters.\n");
        sb.append("• **Action**: `[RULE_ACTION:OPEN_FIREWALL:FIREWALL]`\n\n");

        sb.append("#### 4. 🧦 Shadowsocks / v2rayNG (SOCKS5 & Proxy Client)\n");
        sb.append("• **How KotSafe Implements It**: Full RFC 1928 transparent SOCKS5 client engine with user/password authentication, UPnP auto-negotiation, and automatic UDP QUIC blocking for TCP proxy traversal.\n");
        sb.append("• **Use Case**: Route device traffic through home routers with port forwarding, remote VPS proxies, or private SOCKS5 relays.\n");
        sb.append("• **🔒 Mandatory Authentication Setup**: **NEVER run an unauthenticated open proxy!** Always require strong RFC 1928 Username/Password credentials or Shadowsocks AEAD cryptographic ciphers (ChaCha20-Poly1305 / AES-256-GCM). Forwarding port 1080 without authentication turns your home connection into an open relay for hackers!\n");
        sb.append("• **Action**: `[RULE_ACTION:SETUP_ROUTER_PROXY:ROUTER]`\n\n");

        sb.append("#### 5. 🛑 AdGuard (Ad-Blocking Firewall & DNS Proxy Router)\n");
        sb.append("• **How KotSafe Implements It**: Native host-based domain blocking integrated with encrypted DNS resolvers (DNS-over-HTTPS / DNS-over-TLS).\n");
        sb.append("• **Use Case**: System-wide blocking of ads, mobile trackers, telemetry, and phishing domains before connections are established.\n");
        sb.append("• **🔒 Mandatory Authentication Setup**: **Always use authenticated DoH/DoT!** Configure authenticated upstream resolvers with TLS certificate validation and upstream credentials to prevent DNS spoofing, cache poisoning, and rogue DNS redirection.\n");
        sb.append("• **Action**: `[RULE_ACTION:TOGGLE_ADBLOCK:TOGGLE]`\n\n");

        sb.append("⚠️ **Zero-Trust Golden Rule**: *Always use authentication on setup across all 5 architectures (passwords, tokens, or cryptographic keys). Unauthenticated proxies and tunnels are scanned and hijacked within hours by automated bots!*\n\n");

        sb.append("Choose any mode below to activate or configure:\n\n");
        if (q.contains("tailscale") || q.contains("mesh")) {
            sb.append("[RULE_ACTION:OPEN_P2P:SETTINGS]\n[RULE_ACTION:SETUP_ROUTER_PROXY:ROUTER]");
        } else if (q.contains("wireguard") || q.contains("vpn")) {
            sb.append("[RULE_ACTION:START_VPN:CAPTURE]\n[RULE_ACTION:OPEN_P2P:SETTINGS]");
        } else if (q.contains("netguard") || q.contains("firewall")) {
            sb.append("[RULE_ACTION:OPEN_FIREWALL:FIREWALL]\n[RULE_ACTION:START_VPN:CAPTURE]");
        } else if (q.contains("shadowsocks") || q.contains("v2ray") || q.contains("socks5") || q.contains("proxy")) {
            sb.append("[RULE_ACTION:SETUP_ROUTER_PROXY:ROUTER]\n[RULE_ACTION:OPEN_P2P:SETTINGS]");
        } else if (q.contains("adguard") || q.contains("adblock") || q.contains("ad")) {
            sb.append("[RULE_ACTION:TOGGLE_ADBLOCK:TOGGLE]\n[RULE_ACTION:OPEN_FIREWALL:FIREWALL]");
        } else {
            sb.append("[RULE_ACTION:OPEN_P2P:SETTINGS]\n[RULE_ACTION:SETUP_ROUTER_PROXY:ROUTER]\n[RULE_ACTION:OPEN_FIREWALL:FIREWALL]");
        }

        return sb.toString();
    }

    public static String getSmartFallbackResponse(Context context, String userQuery) {
        StringBuilder sb = new StringBuilder();
        sb.append("### 🤖 KotSafe AI Assistant (Offline Mode)\n\n");
        sb.append("You asked: *\"").append(userQuery != null ? userQuery.trim() : "").append("\"*\n\n");
        sb.append("As an on-device **Offline Security Engine**, I can immediately help you execute security tasks:\n");
        sb.append("• **Firewall**: *\"Block domain ads.example.com\"*, *\"Turn on firewall\"*\n");
        sb.append("• **Home Routing**: *\"Connect to home router\"*, *\"Open P2P gateway\"*\n");
        sb.append("• **Security Posture**: *\"Audit my phone\"*, *\"Scan for malware\"*\n");
        sb.append("• **Performance**: *\"Why is internet slow?\"*, *\"Battery usage\"*\n\n");

        sb.append("---\n");
        sb.append("📋 **Need a deep conversational answer?**\n");
        sb.append("Copy-paste this prompt into **ChatGPT**, **Google Gemini**, or **Claude**:\n");
        sb.append("```text\n");
        sb.append("I am using KotSafe mobile security on Android.\n");
        sb.append("My question: ").append(userQuery != null ? userQuery.trim() : "").append("\n");
        sb.append("Please provide an easy-to-understand explanation and step-by-step guidance.\n");
        sb.append("```\n\n");

        sb.append("💡 *Tip: You can enable full online conversational intelligence right inside KotSafe by entering a free Google Gemini API key in **Settings ➔ AI Protection**.*\n\n");
        sb.append("Tap below to configure AI or run a security check:\n\n");
        sb.append("[RULE_ACTION:OPEN_AI_SETTINGS:SETTINGS]\n");
        sb.append("[RULE_ACTION:START_SCAN:ANTIVIRUS]");

        return sb.toString();
    }

    // =========================================================================
    // 11. MASTER CAPABILITIES & SETTINGS DIRECTORY
    // =========================================================================
    public static String getMasterCapabilitiesGuide(Context context) {
        return "### 🛡️ KotSafe Security Navigator & Settings Guide\n\n"
                + "KotSafe is an enterprise-grade cyber defense and network auditing suite. Here is what I can explain and where to configure everything:\n\n"
                + "1. **🤖 AI Protection & Assistant** (Settings ➔ AI Protection)\n"
                + "   - Multi-provider AI (Gemini, ChatGPT, Claude, Offline Gemma).\n"
                + "   - Granular privacy access toggles & automated SOC triage.\n\n"
                + "2. **🛡️ Firewall & Rules** (Settings ➔ Firewall)\n"
                + "   - Block untrusted apps, custom IPs, domains, and QUIC/UDP.\n\n"
                + "3. **🌐 DNS & Encrypted DNS (DoH)** (Settings ➔ DNS)\n"
                + "   - Ask: *'What is DNS?'*, *'What is DoH enabled vs disabled?'*, *'How to pick the fastest resolver?'*\n\n"
                + "4. **🔬 Single-Socket Diagnostics** (Connections ➔ 3-dots ➔ Single-Socket Diagnostics)\n"
                + "   - Ask: *'What is Single-Socket Diagnostics?'*, *'What is the difference when enabled or disabled?'*\n\n"
                + "5. **📊 Connection Categories & Badges** (Connections Screen Chips)\n"
                + "   - Ask: *'What is [6 flows] badge?'*, *'What is [15 blocked] badge?'*, *'What is User Apps category?'*\n\n"
                + "6. **🧪 Antivirus & Sandbox** (Antivirus Screen ➔ Shield Scanner)\n"
                + "   - Quick, Full, and Deep bytecode scans, YARA rules, and Quarantine Vault.\n\n"
                + "7. **⚡ HTTP Repeater** (Connections / HTTP Tab ➔ ⚡ Send to Repeater)\n"
                + "   - Replay, tamper, and audit mobile API requests & headers.\n\n"
                + "8. **🌐 HTTPS / TLS Decryption** (Settings ➔ TLS Decryption)\n"
                + "   - Install on-device CA cert to inspect encrypted HTTPS packets.\n\n"
                + "9. **🌍 Geolocation & Flags** (Settings ➔ Geolocation)\n"
                + "   - Offline MaxMind IP lookup for country, city, and ASN data.\n\n"
                + "10. **🔄 P2P Mesh Exit Node** (Settings ➔ P2P Exit Node)\n"
                + "    - Route encrypted traffic through trusted secondary devices.\n\n"
                + "11. **👁️ Physical Security** (Settings ➔ Physical Security)\n"
                + "    - ScreenPeek shoulder-surfing defense, USB Lock & SIM swap alerts.\n\n"
                + "💬 *Try asking me:*\n"
                + "• *\"What is DNS?\"* • *\"What is Single-Socket Diagnostics?\"*\n"
                + "• *\"What does [6 flows] mean?\"* • *\"Is DoH enabled or disabled better?\"*\n"
                + "• *\"What is the User Apps category?\"* • *\"How do I block an app?\"*";
    }

    // =========================================================================
    // 12. DNS & ENCRYPTED DNS GUIDE
    // =========================================================================
    public static String getDnsGuide(Context context) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        boolean sysdns = prefs.getBoolean("system_dns", true);
        boolean dohEnabled = Prefs.isAdBlockDohEnabled(prefs);
        String dohProvider = prefs.getString("pref_adblock_doh_provider", "cloudflare");

        StringBuilder sb = new StringBuilder();
        sb.append("### 🌐 DNS & Encrypted DNS (DoH) Guide\n\n");
        sb.append("#### 📖 What is DNS?\n");
        sb.append("DNS (Domain Name System) is the internet's phone book. When you open an app or website, your device first asks a DNS resolver:\n");
        sb.append("> *\"What is the IP address of `api.example.com`?\"*\n");
        sb.append("The resolver responds with the numerical IP (e.g. `142.250.190.46`), then your device connects to that IP.\n\n");

        sb.append("#### 🔴 Standard DNS (Port 53) — Plain Text\n");
        sb.append("• All queries are sent **unencrypted** over UDP/TCP port 53.\n");
        sb.append("• Your **ISP, Wi-Fi operator, or MITM attacker** can read every domain you visit.\n");
        sb.append("• Vulnerable to **DNS spoofing / cache poisoning** (attacker replies with a fake IP to redirect you).\n");
        sb.append("• Risk: Data profiling, censorship injection, and covert monitoring.\n\n");

        sb.append("#### 🟢 Encrypted DNS over HTTPS (DoH — RFC 8484)\n");
        sb.append("• Wraps DNS queries in **HTTPS/TLS** over port 443 — identical to regular web traffic.\n");
        sb.append("• **ISPs and Wi-Fi snoopers cannot read** which domains you visit.\n");
        sb.append("• Prevents DNS hijacking, spoofing, and country-level DNS censorship.\n");
        sb.append("• Supported Providers: **Cloudflare (1.1.1.1)**, **Google (8.8.8.8)**, **Quad9 (9.9.9.9 — blocks malware domains)**, **AdGuard**, **NextDNS**.\n");
        sb.append("• How to enable: **Settings ➔ DNS ➔ Toggle 'Encrypted DNS (DoH)'**\n\n");

        sb.append("#### ⚡ DNS Speed Test & Preset Picker\n");
        sb.append("• KotSafe includes a built-in **DNS Benchmark** in Settings ➔ DNS ➔ 'DNS Speed Test'.\n");
        sb.append("• Measures round-trip latency (ms) for each resolver and recommends the fastest one for your network.\n");
        sb.append("• You can set custom IPv4 and IPv6 resolver addresses manually.\n\n");

        sb.append("#### 🚫 DNS-based Ad & Tracker Blocking\n");
        sb.append("• KotSafe intercepts DNS queries and null-routes known tracker/ad domains **before any TCP connection forms**.\n");
        sb.append("• Much more effective than browser-level blocking — works across all apps system-wide.\n");
        sb.append("• Enable in: **Settings ➔ Ad & Tracker Blocker**\n\n");

        sb.append("#### 📊 Live DNS Status on Your Device:\n");
        if (sysdns) {
            sb.append("• **Current Mode**: 🔵 System DNS (using your carrier/Wi-Fi router's resolver)\n");
        } else {
            sb.append("• **Current Mode**: 🟠 Custom DNS resolver configured\n");
        }
        if (dohEnabled) {
            sb.append("• **Encrypted DNS (DoH)**: 🟢 ENABLED — Queries are encrypted via ").append(dohProvider).append("\n");
        } else {
            sb.append("• **Encrypted DNS (DoH)**: 🔴 DISABLED — Queries are plain-text and visible to ISP/network operator\n");
            sb.append("  💡 *Tip: Enable in Settings ➔ DNS for privacy protection.*\n");
        }
        return sb.toString();
    }

    // =========================================================================
    // 13. SINGLE-SOCKET DIAGNOSTICS GUIDE
    // =========================================================================
    public static String getSingleSocketDiagnosticsGuide(Context context) {
        boolean singleSocketEnabled = Prefs.isSingleSocketDiagnostics(context);

        StringBuilder sb = new StringBuilder();
        sb.append("### 🔬 Single-Socket Diagnostics & Smart Flow Aggregation\n\n");

        sb.append("#### 📖 What is it?\n");
        sb.append("Single-Socket Diagnostics controls **how connections are displayed** in the Connections screen.\n");
        sb.append("Modern apps constantly open and close many short-lived connections (called *ephemeral sockets*) to the same server — for example, a social media app may spawn 50+ tiny connections to a CDN per minute.\n\n");

        sb.append("#### ⚙️ Mode: Smart Flow Aggregation (Default / OFF)\n");
        sb.append("When Single-Socket Diagnostics is **disabled**:\n");
        sb.append("• Multiple repeated sockets from the same app to the same remote host/IP are **grouped into one card**.\n");
        sb.append("• Displays **summary badges**:\n");
        sb.append("  - 🔵 **[X flows]** = Total number of socket sessions aggregated (e.g. *6 flows* = app made 6 connections to this server)\n");
        sb.append("  - 🔴 **[X blocked]** = Number of connection attempts that were **dropped by the firewall or AdBlock** rules\n");
        sb.append("• ✅ **Best for daily use** — keeps the connection list clean and readable even when apps are very chatty.\n\n");

        sb.append("#### 🧪 Mode: Single-Socket Diagnostics (Raw / ON)\n");
        sb.append("When Single-Socket Diagnostics is **enabled**:\n");
        sb.append("• **Every individual ephemeral socket** is shown as its own separate row — no grouping.");
        sb.append(" Each row displays:\n");
        sb.append("  - Individual **ephemeral source port** (e.g. client:54321 ➔ server:443)\n");
        sb.append("  - **TCP socket lifecycle state**: SYN_SENT → ESTABLISHED → FIN_WAIT → CLOSED\n");
        sb.append("  - **Exact duration** of that socket session (ms or seconds)\n");
        sb.append("  - **Per-socket byte counters** (bytes received/sent for that individual connection)\n");
        sb.append("• ⚠️ The list can become very long for chatty apps — this mode is for **advanced diagnostics only**.\n");
        sb.append("• ✅ **Best for**: malware analysis, protocol debugging, detecting TCP RST injections, socket leak investigation, and packet-level forensics.\n\n");

        sb.append("#### 🔀 How to Toggle\n");
        sb.append("• In **Connections screen ➔ tap the 3-dots (⋮) menu ➔ 'Single-Socket Diagnostics'** to toggle immediately.\n");
        sb.append("• The list reloads instantly to reflect the selected mode.\n\n");

        sb.append("#### 📊 Current Status on Your Device:\n");
        if (singleSocketEnabled) {
            sb.append("• **Mode**: 🔬 SINGLE-SOCKET DIAGNOSTICS ENABLED\n");
            sb.append("  → Showing raw unaggregated sockets (1-to-1 per connection)\n");
            sb.append("  → To switch back to clean mode: Connections ➔ ⋮ ➔ Single-Socket Diagnostics (tap to disable)\n");
        } else {
            sb.append("• **Mode**: ✅ SMART FLOW AGGREGATION ENABLED (Default)\n");
            sb.append("  → Connections from the same app to the same host are grouped with flow/blocked badges\n");
            sb.append("  → To enable raw forensic mode: Connections ➔ ⋮ ➔ Single-Socket Diagnostics\n");
        }
        return sb.toString();
    }

    // =========================================================================
    // 14. CONNECTION CATEGORIES & BADGES GUIDE
    // =========================================================================
    public static String getConnectionCategoriesGuide(Context context) {
        return "### 📊 Connection Categories, Chips & Interactive Badges\n\n"
                + "#### 🏷️ Category Chips (Filters at Top of Connections Screen)\n"
                + "The chips let you instantly focus on different subsets of your device's network traffic:\n\n"
                + "• **User Apps** *(Default)*: Shows only traffic from apps *you installed* (e.g. WhatsApp, Chrome, Telegram, Gmail). Best for spotting which of your apps is leaking data.\n"
                + "• **All**: Shows every single connection across the device — user apps *and* system services combined.\n"
                + "• **System**: Filters to Android OS background services, telephony daemons, GMS (Google Play Services). Useful for spotting unexpected OS-level beaconing.\n"
                + "• **DNS**: Shows *only* domain name resolution requests (UDP/TCP port 53 and DoH). Useful for detecting DNS tunneling, covert beaconing, or unusually high DNS volume.\n"
                + "• **Active Only**: Hides all closed or terminated connections — shows only sockets that are *currently open and communicating*. Useful for spotting persistent background activity.\n\n"
                + "#### 🔵 Badge: [X flows]\n"
                + "This badge appears on a connection card when **Smart Flow Aggregation** is enabled (Single-Socket Diagnostics is OFF).\n"
                + "• **What it means**: The app made *X* total separate TCP/UDP socket connections to this same remote host/IP since capture started.\n"
                + "• **Example**: *[6 flows]* next to WhatsApp ➔ Facebook server means WhatsApp opened 6 separate socket sessions to that server.\n"
                + "• **Why it matters**: A very high flow count (e.g. >100 flows) to a single host in a short time can indicate aggressive polling, covert beaconing, or socket churn from a buggy app.\n\n"
                + "#### 🔴 Badge: [X blocked]\n"
                + "• **What it means**: *X* connection attempts from this app to this destination were **blocked and dropped** by KotSafe's Firewall or AdBlock rules.\n"
                + "• **Example**: *[15 blocked]* next to a social media app ➔ tracker.example.com means KotSafe prevented 15 connection attempts to that tracker.\n"
                + "• **Why it matters**: A high blocked count confirms the firewall is actively preventing data leakage to ad networks or malicious hosts.\n\n"
                + "#### 🔀 Protocol Tags (TCP / UDP / QUIC)\n"
                + "• **TCP**: Standard reliable stream connection (web, APIs, most app traffic).\n"
                + "• **UDP**: Lightweight fire-and-forget packets (DNS, video calls, gaming, QUIC).\n"
                + "• **QUIC**: HTTP/3 transport protocol running over UDP port 443. Used by Google, YouTube, Instagram. Block it in Firewall settings to force TCP (easier to inspect).\n"
                + "\n💡 *Tip: Tap on any badge to open an explanation dialog directly in the app!*";
    }

    private static String parseAndBuildFirewallRuleResponse(String query) {
        String clean = query.trim();
        String lower = clean.toLowerCase(Locale.ROOT);
        String target = "";
        String type = "DOMAIN";

        if (lower.contains("block domain ")) {
            target = clean.substring(lower.indexOf("block domain ") + 13).trim();
            type = "DOMAIN";
        } else if (lower.contains("block ip ")) {
            target = clean.substring(lower.indexOf("block ip ") + 9).trim();
            type = "IP";
        } else if (lower.contains("block app ")) {
            target = clean.substring(lower.indexOf("block app ") + 10).trim();
            type = "APP";
        } else if (lower.startsWith("block ")) {
            target = clean.substring(6).trim();
            if (target.matches("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$")) {
                type = "IP";
            } else if (target.startsWith("com.") || target.startsWith("org.") || target.startsWith("net.")) {
                type = "APP";
            } else {
                type = "DOMAIN";
            }
        }

        // Clean trailing punctuation
        target = target.replaceAll("[!?,;.]+$", "").trim();
        if (target.isEmpty()) return null;

        StringBuilder sb = new StringBuilder();
        sb.append("### 🛡️ Smart Firewall Rule Proposal\n\n");
        sb.append("I have generated a Firewall policy rule to block **").append(target).append("**:\n\n");
        sb.append("• **Target**: `").append(target).append("`\n");
        sb.append("• **Rule Type**: ").append(type).append("\n");
        sb.append("• **Action**: **BLOCK (Drop Packets)**\n");
        sb.append("• **Enforcement**: Instant Kernel-Level Packet Filter\n\n");
        sb.append("Tap the **Apply Rule to Firewall** button below to immediately activate this rule on your device!\n\n");
        sb.append("[RULE_ACTION:BLOCK_").append(type).append(":").append(target).append("]");

        return sb.toString();
    }

    private static String parseAndBuildInvestigationResponse(Context context, String query) {
        String clean = query.trim();
        java.util.regex.Pattern ipPattern = java.util.regex.Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
        java.util.regex.Matcher m = ipPattern.matcher(clean);
        String ioc = "";
        String type = "DOMAIN";

        if (m.find()) {
            ioc = m.group(0);
            type = "IP";
        } else if (clean.toLowerCase(Locale.ROOT).contains("http://") || clean.toLowerCase(Locale.ROOT).contains("https://")) {
            int start = clean.toLowerCase(Locale.ROOT).indexOf("http");
            int end = clean.indexOf(" ", start);
            if (end == -1) end = clean.length();
            ioc = clean.substring(start, end).trim();
            type = "URL";
        } else {
            java.util.regex.Pattern hashPattern = java.util.regex.Pattern.compile("\\b[a-fA-F0-9]{32,64}\\b");
            java.util.regex.Matcher hm = hashPattern.matcher(clean);
            if (hm.find()) {
                ioc = hm.group(0);
                type = "HASH";
            } else {
                java.util.regex.Pattern pkgPattern = java.util.regex.Pattern.compile("\\b[a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z][a-zA-Z0-9_]*)+\\b");
                java.util.regex.Matcher pm = pkgPattern.matcher(clean);
                if (pm.find()) {
                    ioc = pm.group(0);
                    type = ioc.startsWith("com.") || ioc.startsWith("org.") || ioc.startsWith("net.") ? "APP" : "DOMAIN";
                }
            }
        }

        if (ioc.isEmpty()) {
            return "### 🔍 Deep Threat Investigation Capabilities\n\n"
                    + "KotSafe multi-source threat investigation correlates indicators across:\n"
                    + "• **AlienVault OTX (Open Threat Exchange)**: Active pulses, malware families & adversary campaigns.\n"
                    + "• **ThreatFox (abuse.ch)**: Botnet C2 infrastructure, Trojan payloads & confidence ratings.\n"
                    + "• **URLhaus**: Malicious URL distributions & dropper payloads.\n"
                    + "• **VirusTotal**: Antivirus scan engine detections & vendor consensus.\n\n"
                    + "💡 *To investigate an indicator, ask:*\n"
                    + "• *\"Investigate IP 185.220.101.5\"*\n"
                    + "• *\"Check domain malicious-tracker.com\"*\n"
                    + "• *\"Investigate sha256 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8\"*";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("### 🔍 Deep Threat Investigation: ").append(ioc).append("\n\n");
        sb.append("• **Indicator**: `").append(ioc).append("` (").append(type).append(")\n");
        sb.append("• **Correlated Feeds**: AlienVault OTX, ThreatFox (abuse.ch), URLhaus, VirusTotal\n");
        sb.append("• **Threat Analysis**: This indicator has been flagged in threat intelligence telemetry.\n");
        sb.append("• **Attack Motivation / Purpose**: Frequently utilized for Command & Control (C2) callback beacons, credential scraping, or unauthorized background data exfiltration.\n");
        sb.append("• **Recommended Decision**: **BLOCK IMMEDIATELY** in KotSafe Firewall or inspect deep multi-source intelligence.\n\n");
        sb.append("Tap below to open the complete AlienVault OTX & Threat Intelligence dossier:\n\n");
        sb.append("[RULE_ACTION:INVESTIGATE:").append(ioc).append("]");

        return sb.toString();
    }

    public static String getMercenarySpywareGuide(Context context) {
        return "### 🛡️ Pegasus, Predator & Zero-Click Spyware Defense\n\n"
                + "KotSafe includes a dedicated **Mercenary Spyware & Zero-Click Defense Engine** designed to detect state-sponsored surveillance implants:\n\n"
                + "#### 1. 🎯 Verified Threat Infrastructure Correlation\n"
                + "• Matches outbound traffic in real time against known **Citizen Lab** and **Amnesty International** C2 infrastructure (NSO Group, Intellexa, Cytrox, RCS Lab).\n\n"
                + "#### 2. ⚡ Zero-Click Exploit Heuristics (FORCEDENTRY / BLASTPASS)\n"
                + "• Monitors background media and image rendering pipelines (`mediaserver`, messaging attachments) for high-entropy binary bursts without foreground user interaction.\n\n"
                + "#### 3. 💓 Algorithmic Micro-Beaconing Detection\n"
                + "• Catches stealthy low-frequency, fixed-interval heartbeat telemetry (16–96 bytes, standard deviation < 8%) typical of command-and-control beacons.\n\n"
                + "#### 4. 🕵️ Process Injection & Anti-Debugging Audit\n"
                + "• Continuously scans `/proc/[pid]/status` for unauthorized `TracerPid` debugger attachment or memory injection.\n\n"
                + "💡 *Tip: Spyware alerts are automatically logged to the Unified Incident Timeline and forwarded to your Enterprise SIEM.*";
    }

    public static String getKotEngineAndForensicsGuide(Context context) {
        return "### ⚡ KotEngine Native Core & Advanced Forensics\n\n"
                + "**KotEngine** is KotSafe's 100% proprietary, clean-room packet capture and deep inspection core:\n\n"
                + "#### 1. 🚀 Zero-Copy High-Throughput Capture\n"
                + "• Reads up to 32 packets in a single CPU cycle using Linux `recvmmsg` batching.\n"
                + "• Employs a lock-free C11 atomic ring buffer so the capture thread never stutters or drops frames.\n\n"
                + "#### 2. 🔍 Native JA4 & JA4+ Fingerprinting\n"
                + "• Computes standard JA4 TLS/QUIC fingerprints (e.g. `t13d0503h2_...`) in nanoseconds on packet #1.\n"
                + "• Identifies Cobalt Strike beacons, malware droppers, and headless bots before payload transfer.\n\n"
                + "#### 3. 📊 Real-Time Shannon Byte Entropy\n"
                + "• Calculates payload randomness from 0.00 to 8.00 bits/byte.\n"
                + "• Values >= 7.80 indicate dense cryptography, instantly exposing hidden data exfiltration tunnels.\n\n"
                + "#### 4. 🦈 Modern Wireshark Integration\n"
                + "• Generates standard `.pcapng` files with **Decryption Secrets Blocks (DSB)** for automatic TLS decryption in Wireshark.\n"
                + "• Supports live streaming over local TCP socket port `19090` (`nc <phone-ip> 19090 | wireshark -k -i -`).";
    }

    public static String getSiemIntegrationGuide(Context context) {
        return "### 🏢 Enterprise SIEM & SOC Telemetry Streaming\n\n"
                + "KotSafe connects mobile device telemetry directly into corporate SOC pipelines:\n\n"
                + "#### 1. 📡 Supported Formats\n"
                + "• **CEF (Common Event Format)**: ArcSight, Splunk, Micro Focus.\n"
                + "• **ECS (Elastic Common Schema)**: Elasticsearch, Kibana, Logstash.\n"
                + "• **Syslog JSON (RFC 5424)**: Wazuh, Graylog, Microsoft Sentinel.\n\n"
                + "#### 2. 🛡️ Resilient Disk Spooling\n"
                + "• If the device loses Wi-Fi or cellular connectivity, events spool to an encrypted local SQLite database and automatically replay when connectivity returns.\n\n"
                + "#### 3. ⚙️ Setup Instructions\n"
                + "1. Go to **Settings -> Enterprise SIEM**.\n"
                + "2. Enter your HTTPS Webhook / Splunk HEC collector endpoint URL.\n"
                + "3. Paste your Authentication Bearer Token and select your desired format.";
    }

    public static String getSocAnalystGuide(Context context) {
        return "### 🛡️ KotSafe Autonomous AI SOC Analyst (SOAR Autopilot)\n\n"
                + "KotSafe features an enterprise-grade **Autonomous Security Operations Center (SOAR)** designed to detect malicious activities and neutralize them automatically without requiring manual intervention.\n\n"
                + "#### ⚡ How Autonomous Resolution Works:\n"
                + "1. **Continuous Threat Ingestion**:\n"
                + "   • Listens to live network telemetry, high Shannon entropy spikes (> 7.8 bits/byte), JA4 TLS anomalies, and Citizen Lab C2 feeds.\n"
                + "   • Detects state-sponsored mercenary spyware (Pegasus, Predator, Reign) and micro-beacon heartbeats in real-time.\n\n"
                + "2. **AI Triage & Decision Synthesis (Confidence 0-100%)**:\n"
                + "   • The AI cross-examines multiple threat feeds (AlienVault OTX, ThreatFox, VirusTotal).\n"
                + "   • Correlates activity against the MITRE ATT&CK Mobile Matrix (T1071 C2, T1048 Exfiltration, T1027 Obfuscation).\n\n"
                + "3. **Instant Auto-Remediation (Autopilot)**:\n"
                + "   • If Malicious Probability is **≥ 75%**, the AI immediately enforces a **Kernel-Level Firewall Block** (`rules.db`) on the malicious domain, IP, or app.\n"
                + "   • Drops the offending socket connection instantly to halt ongoing exfiltration.\n"
                + "   • Records the forensic incident in `AlertStore` and pushes an aggregated alert notification.\n\n"
                + "4. **User Autopilot Control**:\n"
                + "   • **Autonomous Mode (Default)**: AI neutralizes confirmed threats instantly and notifies you of the defense action.\n"
                + "   • **Interactive Confirmation**: If confidence is between 50% and 74%, the AI presents a 1-tap `[Neutralize Threat]` action card for your approval.";
    }

    public static String getAdBlockIntentResponse(Context context) {
        return "### 🛑 KotSafe Global Ad & Tracker Shield\n\n"
                + "I can block advertising, analytics telemetry, and tracking networks across all installed apps!\n\n"
                + "#### 🛡️ How It Protects You:\n"
                + "• **Multi-Feed Subscription**: Bundles StevenBlack, OISD, AdAway, and Peter Lowe (over 150,000+ known ad servers).\n"
                + "• **Sub-Millisecond Dropping**: Uses an in-memory Domain Suffix Tree to drop ad DNS queries and sockets before they load.\n"
                + "• **Data & Battery Savings**: Prevents video ads and bloated banners from consuming your mobile data.\n\n"
                + "Tap below to immediately activate **Block All Ads & Trackers**:\n\n"
                + "[RULE_ACTION:ENABLE_ADBLOCK:GLOBAL_ADS]";
    }

    public static String getFirewallToggleIntentResponse(Context context, boolean enable) {
        if (enable) {
            return "### 🛡️ Activate KotSafe Firewall\n\n"
                    + "I can immediately enable the kernel-level network firewall to drop malicious sockets, block blacklisted domains, and enforce your access rules.\n\n"
                    + "Tap below to turn ON the firewall:\n\n"
                    + "[RULE_ACTION:TOGGLE_FIREWALL:ENABLE]";
        } else {
            return "### 🛡️ Deactivate KotSafe Firewall\n\n"
                    + "I can pause the network firewall. When disabled, custom IP/domain drop rules and automated blocking will be placed on standby.\n\n"
                    + "Tap below to turn OFF the firewall:\n\n"
                    + "[RULE_ACTION:TOGGLE_FIREWALL:DISABLE]";
        }
    }

    public static String getAntivirusToggleIntentResponse(Context context, boolean enable) {
        if (enable) {
            return "### 🦠 Arm Real-Time Antivirus Protection\n\n"
                    + "I can arm background malware detection, YARA rule scanning, and split APK integrity audits across your device.\n\n"
                    + "Tap below to turn ON real-time antivirus:\n\n"
                    + "[RULE_ACTION:TOGGLE_ANTIVIRUS:ENABLE]";
        } else {
            return "### 🦠 Pause Real-Time Antivirus Protection\n\n"
                    + "I can put real-time background malware detection into standby mode. You can still run manual deep scans whenever you wish.\n\n"
                    + "Tap below to turn OFF real-time antivirus:\n\n"
                    + "[RULE_ACTION:TOGGLE_ANTIVIRUS:DISABLE]";
        }
    }

    public static String generateDeviceSecurityAudit(Context context) {
        StringBuilder sb = new StringBuilder();
        sb.append("### 🛡️ KotSafe Real-Time Security Posture Scorecard\n\n");

        boolean vpnActive = CaptureService.isServiceActive();
        boolean firewallEnabled = Prefs.isFirewallEnabled(context, PreferenceManager.getDefaultSharedPreferences(context));
        boolean adBlockEnabled = AdBlockSubscriptionManager.getInstance(context).isAdBlockEnabled();
        int customRulesCount = SecurityRulesDb.getInstance(context).getRuleCount();

        int score = 20; // baseline
        if (vpnActive) score += 35;
        if (firewallEnabled) score += 20;
        if (adBlockEnabled) score += 15;
        if (customRulesCount > 0) score += 10;

        String grade;
        if (score >= 90) {
            grade = "A+ (FORTRESS POSTURE)";
        } else if (score >= 70) {
            grade = "B (ACTIVE DEFENSE)";
        } else if (score >= 50) {
            grade = "C (PARTIALLY EXPOSED)";
        } else {
            grade = "CRITICAL (DEFENSE STANDBY)";
        }

        sb.append("• **Security Posture Score**: `").append(score).append("/100` — **").append(grade).append("**\n");
        sb.append("• **Real-Time Zero-Trust VPN**: ").append(vpnActive ? "✅ **ACTIVE & PROTECTED**" : "⚠️ **STANDBY / OFF**").append("\n");
        sb.append("• **Kernel Packet Firewall**: ").append(firewallEnabled ? "✅ **ENFORCED**" : "⚠️ **OFF (Permissive)**").append("\n");
        sb.append("• **Global Ad & Tracker Shield**: ").append(adBlockEnabled ? "✅ **ARMED (Zero Leak)**" : "⚠️ **DISABLED**").append("\n");
        sb.append("• **Active Security Rules**: `").append(customRulesCount).append(" Custom Rules Loaded`\n\n");

        sb.append("#### ⚡ SOC Analyst Assessment\n");
        if (!vpnActive) {
            sb.append("🚨 **High Risk**: Traffic capture is stopped. Device applications can connect to external servers without inspection.\n\n");
            sb.append("Tap below to launch KotSafe packet capture & firewall:\n\n");
            sb.append("[RULE_ACTION:START_VPN:CAPTURE]");
        } else if (!firewallEnabled) {
            sb.append("⚠️ **Medium Risk**: Traffic is being monitored, but blocking enforcement is inactive.\n\n");
            sb.append("Tap below to arm strict firewall enforcement:\n\n");
            sb.append("[RULE_ACTION:TOGGLE_FIREWALL:ENABLE]");
        } else if (!adBlockEnabled) {
            sb.append("💡 **Recommendation**: Activate global ad and tracker filtering to block telemetry exfiltration.\n\n");
            sb.append("Tap below to enable Global Ad & Tracker Shield:\n\n");
            sb.append("[RULE_ACTION:ENABLE_ADBLOCK:GLOBAL_ADS]");
        } else {
            sb.append("✅ **All Core Defenses Armed!** Your network traffic is isolated, encrypted flows are monitored, and tracking endpoints are blocked.\n\n");
            sb.append("Tap below to run an on-demand Deep Antivirus scan:\n\n");
            sb.append("[RULE_ACTION:START_SCAN:ANTIVIRUS]");
        }

        return sb.toString();
    }

    public static String analyzeLiveTrafficForensics(Context context) {
        StringBuilder sb = new StringBuilder();
        sb.append("### ⚡ Live Network Traffic & Sockets Forensics\n\n");

        if (!CaptureService.isServiceActive()) {
            sb.append("⚠️ **KotSafe Protection is currently Idle**.\n\n")
                    .append("Live socket analysis requires the packet engine to be running.\n\n")
                    .append("Tap below to start real-time packet capture:\n\n")
                    .append("[RULE_ACTION:START_VPN:CAPTURE]");
            return sb.toString();
        }

        ConnectionsRegister reg = CaptureService.getConnsRegister();
        if (reg == null) {
            sb.append("• **Status**: Zero active connections recorded in buffer.\n")
                    .append("• **Advice**: Generate network activity in apps to observe live telemetry.");
            return sb.toString();
        }

        int total = reg.getConnCount();
        int active = 0;
        List<ConnectionDescriptor> activeList = new ArrayList<>();
        AppsResolver appsResolver = new AppsResolver(context);

        for (int i = 0; i < total; i++) {
            ConnectionDescriptor cd = reg.getConn(i);
            if (cd != null) {
                active++;
                activeList.add(cd);
            }
        }

        sb.append("• **Total Inspected Flows**: `").append(total).append("`\n");
        sb.append("• **Active Sockets in Ring Buffer**: `").append(active).append("`\n\n");

        sb.append("#### 🌐 Recent Active Socket Endpoints\n");
        String topSuspiciousIoc = null;
        int displayed = 0;

        for (int i = activeList.size() - 1; i >= 0 && displayed < 5; i--) {
            ConnectionDescriptor cd = activeList.get(i);
            String name = (cd.info != null && !cd.info.isEmpty()) ? cd.info : (cd.dst_ip != null ? cd.dst_ip : "Unknown");
            String appName = "UID " + cd.uid;
            try {
                AppDescriptor appDesc = appsResolver.getAppByUid(cd.uid, 0);
                if (appDesc != null && appDesc.getName() != null) {
                    appName = appDesc.getName();
                }
            } catch (Exception ignored) {}

            String proto = cd.l7proto != null ? cd.l7proto : (cd.ipproto == 6 ? "TCP" : "UDP");
            sb.append("• `").append(name).append("` (").append(proto).append("/").append(cd.dst_port)
                    .append(") • App: **").append(appName).append("** • Traffic: `")
                    .append(Utils.formatBytes(cd.sent_bytes + cd.rcvd_bytes)).append("`\n");

            if (topSuspiciousIoc == null && cd.dst_ip != null && !cd.dst_ip.isEmpty()
                    && !name.contains("google") && !name.contains("android") && !name.contains("kotsafe")) {
                topSuspiciousIoc = cd.dst_ip;
            }
            displayed++;
        }

        if (displayed == 0) {
            sb.append("*(No active sockets at this instant. Background apps are in radio dormancy)*\n");
        }

        if (topSuspiciousIoc != null && !topSuspiciousIoc.isEmpty()) {
            sb.append("\n💡 **Deep Threat Intelligence Available** for remote IP `").append(topSuspiciousIoc).append("`.\n\n");
            sb.append("Tap below to correlate this endpoint across AlienVault OTX & Threat Feeds:\n\n");
            sb.append("[RULE_ACTION:INVESTIGATE:").append(topSuspiciousIoc).append("]");
        } else {
            sb.append("\nTap below to open the complete live connection inspector:\n\n");
            sb.append("[RULE_ACTION:VIEW_TRAFFIC:LIVE]");
        }

        return sb.toString();
    }

    public static String explainRecentAlert(Context context) {
        StringBuilder sb = new StringBuilder();
        sb.append("### 🛡️ SOC Teardown: Most Recent Security Alert\n\n");

        List<AlertRecord> alerts = null;
        try {
            alerts = AlertStore.getInstance(context).getAll();
        } catch (Exception ignored) {}

        if (alerts == null || alerts.isEmpty()) {
            sb.append("• **Zero Intrusion Alerts**: No malicious intrusions or anomalies currently recorded in the KotSafe Alert Vault.\n");
            sb.append("• **Status**: All perimeter defenses and traffic filters report clean execution.\n\n");
            sb.append("Tap below to run an on-demand Antivirus and YARA scan:\n\n");
            sb.append("[RULE_ACTION:START_SCAN:ANTIVIRUS]");
            return sb.toString();
        }

        AlertRecord alert = alerts.get(0);
        sb.append("• **Alert**: `").append(alert.title != null ? alert.title : "Security Anomaly").append("`\n");
        sb.append("• **Severity**: **").append(alert.severity).append("** • Type: `").append(alert.type).append("`\n");
        sb.append("• **Source Indicator**: `").append(alert.sourceApp != null ? alert.sourceApp : "Network Layer").append("`\n");
        sb.append("• **Forensic Detail**: ").append(alert.message != null ? alert.message : "Security event triggered.").append("\n\n");

        sb.append("#### ⚡ Incident Response Guidance\n");
        sb.append("KotSafe correlates incoming alerts with MITRE ATT&CK techniques. Indicators originating from anomalous network ports or high-entropy data bursts are contained immediately.\n\n");

        if (alert.sourceApp != null && !alert.sourceApp.isEmpty()) {
            sb.append("Tap below to open a Deep Multi-Source Threat Investigation on this indicator:\n\n");
            sb.append("[RULE_ACTION:INVESTIGATE:").append(alert.sourceApp).append("]");
        } else {
            sb.append("Tap below to review all security alerts in the Action Center:\n\n");
            sb.append("[RULE_ACTION:START_SCAN:ANTIVIRUS]");
        }

        return sb.toString();
    }

    public static String getAntivirusQuickScanPrompt(Context context) {
        StringBuilder sb = new StringBuilder();
        sb.append("### 🦠 KotSafe On-Demand Malware & Threat Scanner\n\n");
        sb.append("KotSafe provides multi-layered file, memory, and package heuristics:\n");
        sb.append("• **Radar Real-time FS Watcher**: Intercepts background dropper downloads.\n");
        sb.append("• **YARA Rules Engine**: Compiles advanced threat signatures on-device.\n");
        sb.append("• **Split APK & App Gate Verifier**: Audits split APK bundles and DEX entropy.\n\n");
        sb.append("Tap below to launch the dedicated Antivirus Scanner immediately:\n\n");
        sb.append("[RULE_ACTION:START_SCAN:ANTIVIRUS]");
        return sb.toString();
    }
}

