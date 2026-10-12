/*
 * This file is part of KotSafe / KotSafe Cyber Security Project.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.ai;

import android.content.Context;
import androidx.preference.PreferenceManager;
import androidx.test.core.app.ApplicationProvider;

import com.kotsafe.security.model.AlertRecord;
import com.kotsafe.security.model.Prefs;

import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@RunWith(RobolectricTestRunner.class)
public class AiAssistantSubsystemTest {

    private Context context;

    @Before
    public void setUp() {
        context = ApplicationProvider.getApplicationContext();
    }

    @Test
    public void testKnowledgeBaseActionProtocolPresent() {
        assertNotNull(KnowledgeBase.APP_SYSTEM_PROMPT);
        assertTrue(KnowledgeBase.APP_SYSTEM_PROMPT.contains("[ACTION:"));
        assertTrue(KnowledgeBase.APP_SYSTEM_PROMPT.contains("BLOCK_APP"));
        assertTrue(KnowledgeBase.APP_SYSTEM_PROMPT.contains("BLOCK_DOMAIN"));
        assertTrue(KnowledgeBase.APP_SYSTEM_PROMPT.contains("BLOCK_IP"));
        assertTrue(KnowledgeBase.APP_SYSTEM_PROMPT.contains("START_SCAN"));
        assertTrue(KnowledgeBase.APP_SYSTEM_PROMPT.contains("TOGGLE_FIREWALL"));
        assertTrue(KnowledgeBase.APP_SYSTEM_PROMPT.contains("TOGGLE_ADBLOCK"));
    }

    @Test
    public void testRAGTelemetryContextInjection() {
        PreferenceManager.getDefaultSharedPreferences(context)
                .edit()
                .putBoolean(Prefs.PREF_FIREWALL, true)
                .putBoolean(AiConfig.PREF_AI_ENABLED, true)
                .putBoolean(AiConfig.PREF_ACCESS_STATUS, true)
                .apply();

        AiAccessController controller = new AiAccessController(context);

        String contextPrompt = controller.buildContextForQuery("what is my network status and top talkers?");

        assertNotNull(contextPrompt);
        assertTrue(contextPrompt.contains("LIVE SNAPSHOT (RAG TELEMETRY)"));
        assertTrue(contextPrompt.contains("[PROTECTION_STATE]"));
        assertTrue(contextPrompt.contains("Firewall: ACTIVE"));
    }

    @Test
    public void testActionTagRegexParsing() {
        Pattern actionPattern = Pattern.compile("\\[ACTION:([A-Z_]+)(?::([^\\]]+))?\\]");
        String aiResponse = "I recommend blocking this domain.\n[ACTION:BLOCK_DOMAIN:evil-tracker.com]\nAlso start an immediate device scan:\n[ACTION:START_SCAN]";

        Matcher matcher = actionPattern.matcher(aiResponse);
        assertTrue(matcher.find());
        assertEquals("BLOCK_DOMAIN", matcher.group(1));
        assertEquals("evil-tracker.com", matcher.group(2));

        assertTrue(matcher.find());
        assertEquals("START_SCAN", matcher.group(1));

        String cleaned = actionPattern.matcher(aiResponse).replaceAll("").trim();
        assertFalse(cleaned.contains("[ACTION:"));
        assertTrue(cleaned.contains("I recommend blocking this domain."));
    }

    @Test
    public void testAutonomousSocPreTriageAndAlertRecordSerialization() throws Exception {
        AlertRecord alert = new AlertRecord(
                "alert-test-01",
                System.currentTimeMillis(),
                AlertRecord.Severity.HIGH,
                AlertRecord.AlertType.MALWARE,
                "Trojan C2 Beacon Detected",
                "App contacting known adversary command and control node",
                "com.suspicious.app"
        );

        AutonomousSocAnalyst analyst = AutonomousSocAnalyst.getInstance(context);
        analyst.preTriageAlert(alert);

        assertNotNull(alert.aiAssessment);
        assertTrue(alert.aiMaliciousProbability >= 70);

        // Test JSON Serialization / Deserialization
        JSONObject json = alert.toJson();
        assertEquals(alert.aiAssessment, json.optString("aiAssess"));
        assertEquals(alert.aiMaliciousProbability, json.optInt("aiProb", -1));

        AlertRecord restored = AlertRecord.fromJson(json);
        assertNotNull(restored);
        assertEquals(alert.aiAssessment, restored.aiAssessment);
        assertEquals(alert.aiMaliciousProbability, restored.aiMaliciousProbability);
    }

    @Test
    public void testHomeRouterProxyDetectionAndActionTag() {
        // Test query with explicit host:port
        String responseWithHostPort = OfflineKnowledgeEngine.getHomeRouterProxyResponse(context, "connect to home router 192.168.1.50:1080");
        assertNotNull(responseWithHostPort);
        assertTrue(responseWithHostPort.contains("Route Device Traffic via Home"));
        assertTrue(responseWithHostPort.contains("[RULE_ACTION:CONNECT_ROUTER_PROXY:192.168.1.50:1080]"));
        assertTrue(responseWithHostPort.contains("[RULE_ACTION:OPEN_P2P:SETTINGS]"));

        // Test query with DDNS and port
        String responseWithDdns = OfflineKnowledgeEngine.getHomeRouterProxyResponse(context, "route traffic to router myhome.ddns.net port 8888");
        assertNotNull(responseWithDdns);
        assertTrue(responseWithDdns.contains("[RULE_ACTION:CONNECT_ROUTER_PROXY:myhome.ddns.net:8888]"));
        assertTrue(responseWithDdns.contains("[RULE_ACTION:OPEN_P2P:SETTINGS]"));

        // Test generic query without host:port -> shows both P2P and Router setup
        String responseGeneric = OfflineKnowledgeEngine.getHomeRouterProxyResponse(context, "connect to home router");
        assertNotNull(responseGeneric);
        assertTrue(responseGeneric.contains("[RULE_ACTION:SETUP_ROUTER_PROXY:ROUTER]"));
        assertTrue(responseGeneric.contains("[RULE_ACTION:OPEN_P2P:SETTINGS]"));

        // Test saved profile detection
        PreferenceManager.getDefaultSharedPreferences(context)
                .edit()
                .putString("pref_saved_home_host", "myhome.duckdns.org")
                .putInt("pref_saved_home_port", 1080)
                .apply();
        String responseSaved = OfflineKnowledgeEngine.getHomeRouterProxyResponse(context, "connect to home router");
        assertNotNull(responseSaved);
        assertTrue(responseSaved.contains("[RULE_ACTION:RECONNECT_SAVED_HOME:myhome.duckdns.org:1080]"));
    }

    @Test
    public void testHomeRouterInstantEligibility() {
        assertTrue(OfflineKnowledgeEngine.isInstantOfflineEligible("connect to home router"));
        assertTrue(OfflineKnowledgeEngine.isInstantOfflineEligible("route through router 192.168.1.1:1080"));
        assertTrue(OfflineKnowledgeEngine.isInstantOfflineEligible("use home wifi outside"));
        assertTrue(OfflineKnowledgeEngine.isInstantOfflineEligible("out of station"));
        assertTrue(OfflineKnowledgeEngine.isInstantOfflineEligible("why is internet slow"));
        assertTrue(OfflineKnowledgeEngine.isInstantOfflineEligible("battery drain fast"));
        assertTrue(OfflineKnowledgeEngine.isInstantOfflineEligible("vpn keeps disconnecting"));
        assertTrue(OfflineKnowledgeEngine.isInstantOfflineEligible("what is kotsafe"));
    }

    @Test
    public void testRouterSetupAndErrorGuide() {
        String res = OfflineKnowledgeEngine.answerQuestion(context, "how to setup in router", null, null);
        assertNotNull(res);
        assertTrue(res.contains("Router Port Forwarding Setup & Diagnostics"));
        assertTrue(res.contains("External / WAN Port"));
        assertTrue(res.contains("Forward Rules"));
        assertTrue(res.contains("What If the Home Computer Is Turned Off?"));
        assertTrue(res.contains("SOCKS5 Engine"));
        assertTrue(res.contains("copy and paste this pre-formatted prompt into **ChatGPT**, **Google Gemini**, or **Claude**"));
        assertTrue(res.contains("[RULE_ACTION:OPEN_AI_SETTINGS:SETTINGS]"));

        // Must not contain hardcoded telecom company names
        assertFalse(res.contains("Jio"));
        assertFalse(res.contains("BSNL"));
        assertFalse(res.contains("Airtel"));

        // Test querying about computer turned off
        assertTrue(OfflineKnowledgeEngine.isInstantOfflineEligible("what if computer is off"));
        String pcOffRes = OfflineKnowledgeEngine.answerQuestion(context, "what if computer is off", null, null);
        assertNotNull(pcOffRes);
        assertTrue(pcOffRes.contains("What If the Home Computer Is Turned Off?"));
        assertTrue(pcOffRes.contains("Traffic Stops"));
        assertTrue(pcOffRes.contains("Personal Gateway / Exit Node Mode"));
    }

    @Test
    public void testSpecificInquiriesDoNotDumpAllFeatures() {
        // Slow internet query
        String slowRes = OfflineKnowledgeEngine.answerQuestion(context, "why is internet slow", null, null);
        assertNotNull(slowRes);
        assertTrue(slowRes.contains("Network Speed, Ping & Latency Optimization"));
        assertFalse(slowRes.contains("KotSafe Security Navigator & Settings Guide"));

        // Battery query
        String batRes = OfflineKnowledgeEngine.answerQuestion(context, "battery drain fast", null, null);
        assertNotNull(batRes);
        assertTrue(batRes.contains("Battery Consumption & Power Optimization"));
        assertFalse(batRes.contains("KotSafe Security Navigator & Settings Guide"));

        // VPN Disconnect query
        String vpnRes = OfflineKnowledgeEngine.answerQuestion(context, "vpn keeps disconnecting", null, null);
        assertNotNull(vpnRes);
        assertTrue(vpnRes.contains("Why Does the VPN Keep Disconnecting"));
        assertFalse(vpnRes.contains("KotSafe Security Navigator & Settings Guide"));

        // About KotSafe
        String aboutRes = OfflineKnowledgeEngine.answerQuestion(context, "what is kotsafe", null, null);
        assertNotNull(aboutRes);
        assertTrue(aboutRes.contains("About KotSafe Mobile Defense"));
        assertFalse(aboutRes.contains("KotSafe Security Navigator & Settings Guide"));
    }

    @Test
    public void testSmartFallbackForUnrecognizedQueryDoesNotDumpAllFeatures() {
        String fallbackRes = OfflineKnowledgeEngine.answerQuestion(context, "can somebody hack my smart television through my microwave?", null, null);
        assertNotNull(fallbackRes);
        // Must address the user query respectfully
        assertTrue(fallbackRes.contains("can somebody hack my smart television through my microwave?"));
        // Must provide the online AI prompt
        assertTrue(fallbackRes.contains("Copy-paste this prompt into **ChatGPT**, **Google Gemini**, or **Claude**"));
        // Must contain action to configure AI key
        assertTrue(fallbackRes.contains("[RULE_ACTION:OPEN_AI_SETTINGS:SETTINGS]"));
        // MUST NOT dump the generic 11-feature manual!
        assertFalse(fallbackRes.contains("KotSafe Security Navigator & Settings Guide"));
    }

    @Test
    public void testEndpointClassification() {
        assertEquals(OfflineKnowledgeEngine.EndpointClassification.LOCAL_PRIVATE,
                OfflineKnowledgeEngine.classifyEndpoint("192.168.1.1"));
        assertEquals(OfflineKnowledgeEngine.EndpointClassification.LOCAL_PRIVATE,
                OfflineKnowledgeEngine.classifyEndpoint("10.0.0.1"));
        assertEquals(OfflineKnowledgeEngine.EndpointClassification.LOCAL_PRIVATE,
                OfflineKnowledgeEngine.classifyEndpoint("172.20.10.5"));

        assertEquals(OfflineKnowledgeEngine.EndpointClassification.CGNAT,
                OfflineKnowledgeEngine.classifyEndpoint("100.64.0.1"));
        assertEquals(OfflineKnowledgeEngine.EndpointClassification.CGNAT,
                OfflineKnowledgeEngine.classifyEndpoint("100.100.1.50"));

        assertEquals(OfflineKnowledgeEngine.EndpointClassification.LOOPBACK,
                OfflineKnowledgeEngine.classifyEndpoint("127.0.0.1"));
        assertEquals(OfflineKnowledgeEngine.EndpointClassification.LOOPBACK,
                OfflineKnowledgeEngine.classifyEndpoint("localhost"));

        assertEquals(OfflineKnowledgeEngine.EndpointClassification.PUBLIC_IP,
                OfflineKnowledgeEngine.classifyEndpoint("49.36.12.18"));
        assertEquals(OfflineKnowledgeEngine.EndpointClassification.PUBLIC_IP,
                OfflineKnowledgeEngine.classifyEndpoint("8.8.8.8"));

        assertEquals(OfflineKnowledgeEngine.EndpointClassification.DDNS_DOMAIN,
                OfflineKnowledgeEngine.classifyEndpoint("myhome.duckdns.org"));
        assertEquals(OfflineKnowledgeEngine.EndpointClassification.DDNS_DOMAIN,
                OfflineKnowledgeEngine.classifyEndpoint("myrouter.tplinkdns.com"));
        assertEquals(OfflineKnowledgeEngine.EndpointClassification.DDNS_DOMAIN,
                OfflineKnowledgeEngine.classifyEndpoint("home.asuscomm.com"));

        assertEquals(OfflineKnowledgeEngine.EndpointClassification.EMPTY,
                OfflineKnowledgeEngine.classifyEndpoint(""));
        assertEquals(OfflineKnowledgeEngine.EndpointClassification.EMPTY,
                OfflineKnowledgeEngine.classifyEndpoint("   "));
        assertEquals(OfflineKnowledgeEngine.EndpointClassification.EMPTY,
                OfflineKnowledgeEngine.classifyEndpoint(null));

        assertEquals(OfflineKnowledgeEngine.EndpointClassification.INVALID,
                OfflineKnowledgeEngine.classifyEndpoint("invalid!host"));

        // Test IPv6 classifications
        assertEquals(OfflineKnowledgeEngine.EndpointClassification.GLOBAL_IPV6,
                OfflineKnowledgeEngine.classifyEndpoint("2405:201:dead:beef::1"));
        assertEquals(OfflineKnowledgeEngine.EndpointClassification.GLOBAL_IPV6,
                OfflineKnowledgeEngine.classifyEndpoint("2001:4860:4860::8888"));
        assertEquals(OfflineKnowledgeEngine.EndpointClassification.LOCAL_PRIVATE,
                OfflineKnowledgeEngine.classifyEndpoint("fe80::1"));
        assertEquals(OfflineKnowledgeEngine.EndpointClassification.LOOPBACK,
                OfflineKnowledgeEngine.classifyEndpoint("::1"));
    }

    @Test
    public void testWakeOnLanHelper() {
        byte[] macBytes = com.kotsafe.security.util.WakeOnLanHelper.parseMacAddress("AA:BB:CC:DD:EE:FF");
        assertEquals(6, macBytes.length);
        assertEquals((byte) 0xAA, macBytes[0]);
        assertEquals((byte) 0xFF, macBytes[5]);

        byte[] magic = com.kotsafe.security.util.WakeOnLanHelper.buildMagicPacket(macBytes);
        assertEquals(102, magic.length);
        // First 6 bytes must be 0xFF
        for (int i = 0; i < 6; i++) {
            assertEquals((byte) 0xFF, magic[i]);
        }
        // Next bytes repeat the MAC address
        assertEquals((byte) 0xAA, magic[6]);
        assertEquals((byte) 0xBB, magic[7]);
        assertEquals((byte) 0xFF, magic[11]);
    }

    @Test
    public void testDdnsSetupGuide() {
        assertTrue(OfflineKnowledgeEngine.isInstantOfflineEligible("how to setup dynamic dns"));
        assertTrue(OfflineKnowledgeEngine.isInstantOfflineEligible("setup ddns"));
        assertTrue(OfflineKnowledgeEngine.isInstantOfflineEligible("duckdns"));

        String ddnsRes = OfflineKnowledgeEngine.answerQuestion(context, "how to setup dynamic dns?", null, null);
        assertNotNull(ddnsRes);
        assertTrue(ddnsRes.contains("Dynamic DNS (DDNS) Setup Guide for Out-of-Station Access"));
        assertTrue(ddnsRes.contains("TP-Link"));
        assertTrue(ddnsRes.contains("Asus"));
        assertTrue(ddnsRes.contains("DuckDNS"));
        assertTrue(ddnsRes.contains("How do I configure Dynamic DNS (DDNS) on my"));
        assertTrue(ddnsRes.contains("[RULE_ACTION:SETUP_ROUTER_PROXY:ROUTER]"));
        assertTrue(ddnsRes.contains("[RULE_ACTION:OPEN_P2P:SETTINGS]"));
    }

    @Test
    public void testCoreArchitectureModesGuide() {
        assertTrue(OfflineKnowledgeEngine.isInstantOfflineEligible("tailscale"));
        assertTrue(OfflineKnowledgeEngine.isInstantOfflineEligible("wireguard"));
        assertTrue(OfflineKnowledgeEngine.isInstantOfflineEligible("netguard"));
        assertTrue(OfflineKnowledgeEngine.isInstantOfflineEligible("shadowsocks"));
        assertTrue(OfflineKnowledgeEngine.isInstantOfflineEligible("adguard"));

        String res = OfflineKnowledgeEngine.answerQuestion(context, "explain tailscale wireguard netguard shadowsocks adguard", null, null);
        assertNotNull(res);
        assertTrue(res.contains("KotSafe Core Architecture & Security Operating Modes"));
        assertTrue(res.contains("Tailscale (P2P Mesh VPN & Zero-Config Exit Node)"));
        assertTrue(res.contains("WireGuard (Private Encrypted VPN Tunnel)"));
        assertTrue(res.contains("NetGuard (Local No-Root Firewall)"));
        assertTrue(res.contains("Shadowsocks / v2rayNG (SOCKS5 & Proxy Client)"));
        assertTrue(res.contains("AdGuard (Ad-Blocking Firewall & DNS Proxy Router)"));
        assertTrue(res.contains("[RULE_ACTION:OPEN_P2P:SETTINGS]"));
        assertTrue(res.contains("[RULE_ACTION:SETUP_ROUTER_PROXY:ROUTER]"));
        assertTrue(res.contains("[RULE_ACTION:OPEN_FIREWALL:FIREWALL]"));

        // Verify individual query routing
        String tailscaleRes = OfflineKnowledgeEngine.answerQuestion(context, "tailscale mode", null, null);
        assertNotNull(tailscaleRes);
        assertTrue(tailscaleRes.contains("Tailscale"));

        String netguardRes = OfflineKnowledgeEngine.answerQuestion(context, "netguard mode", null, null);
        assertNotNull(netguardRes);
        assertTrue(netguardRes.contains("NetGuard"));
        assertTrue(netguardRes.contains("[RULE_ACTION:OPEN_FIREWALL:FIREWALL]"));

        // Verify mandatory authentication guidance on all 5 modes
        assertTrue(res.contains("ALWAYS USE AUTHENTICATION ON SETUP"));
        assertTrue(res.contains("Always use authenticated pairing"));
        assertTrue(res.contains("Always enforce cryptographic key authentication"));
        assertTrue(res.contains("Always lock firewall settings"));
        assertTrue(res.contains("NEVER run an unauthenticated open proxy"));
        assertTrue(res.contains("Always use authenticated DoH/DoT"));

        // Verify query by authentication query phrase
        assertTrue(OfflineKnowledgeEngine.isInstantOfflineEligible("always use authentication"));
        String authRes = OfflineKnowledgeEngine.answerQuestion(context, "suggest always use authentication on setup", null, null);
        assertNotNull(authRes);
        assertTrue(authRes.contains("ALWAYS USE AUTHENTICATION ON SETUP"));
    }
}
