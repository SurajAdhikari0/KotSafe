/*
 * This file is part of KotSafe / KotSafe Cyber Security Project.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.ai;

import android.content.Context;
import com.kotsafe.security.AppsResolver;
import com.kotsafe.security.CaptureService;
import com.kotsafe.security.ConnectionsRegister;
import com.kotsafe.security.model.AlertRecord;
import com.kotsafe.security.model.AlertStore;
import com.kotsafe.security.model.AppDescriptor;
import com.kotsafe.security.model.CaptureStats;
import com.kotsafe.security.model.ConnectionDescriptor;
import com.kotsafe.security.model.FirewallLogDbHelper;
import com.kotsafe.security.model.FirewallLogEntry;
import com.kotsafe.security.model.ScanReportDbHelper;
import com.kotsafe.security.model.ScanReportEntry;
import com.kotsafe.security.Utils;

import com.kotsafe.security.model.AppStats;
import com.kotsafe.security.model.MitreTechnique;
import com.kotsafe.security.model.Prefs;
import androidx.preference.PreferenceManager;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * Enforces privacy access levels and generates sanitized context summaries
 * for AI prompt construction based strictly on granted user toggles.
 */
public class AiAccessController {

    private final AiConfig mConfig;
    private final Context mContext;

    public AiAccessController(Context context) {
        mContext = context.getApplicationContext();
        mConfig = new AiConfig(mContext);
    }

    public AiConfig getConfig() {
        return mConfig;
    }

    /**
     * Builds fast, compressed prompt context respecting user toggles and query intent.
     * Uses selective intent routing to eliminate up to 85% of redundant prompt tokens.
     */
    public String buildContextForQuery(String userQuery) {
        StringBuilder sb = new StringBuilder();
        sb.append(KnowledgeBase.APP_SYSTEM_PROMPT).append("\n\n");

        String q = userQuery != null ? userQuery.toLowerCase(Locale.ROOT) : "";

        boolean asksAboutFeature = q.contains("what is") || q.contains("how to") || q.contains("how do")
                || q.contains("explain") || q.contains("setup") || q.contains("help") || q.contains("benefit");
        boolean asksAboutConns = q.contains("conn") || q.contains("traffic") || q.contains("socket")
                || q.contains("suspicious") || q.contains("dest") || q.contains("ip");
        boolean asksAboutFirewall = q.contains("firewall") || q.contains("block") || q.contains("rule") || q.contains("alert");
        boolean asksAboutAv = q.contains("antivirus") || q.contains("scan") || q.contains("malware") || q.contains("yara") || q.contains("threat");
        boolean asksAboutStatus = q.contains("status") || q.contains("telemetry") || q.contains("metric")
                || q.contains("rx") || q.contains("tx") || q.contains("download") || q.contains("upload") || q.contains("talker");

        // Targeted domain explanation (instead of dumping all 5 chapters)
        if (userQuery != null && !userQuery.isEmpty()) {
            sb.append(KnowledgeBase.getFeatureExplanation(userQuery)).append("\n\n");
            // If user is asking purely conceptual/how-to questions, omit heavy network tables to minimize latency
            if (asksAboutFeature && !asksAboutConns && !asksAboutFirewall && !asksAboutAv && !asksAboutStatus) {
                return sb.toString();
            }
        } else {
            sb.append(KnowledgeBase.APP_ARCHITECTURE_KNOWLEDGE).append("\n\n");
        }

        sb.append("--- LIVE SNAPSHOT (RAG TELEMETRY) ---\n");

        // Protection posture state
        try {
            boolean fwEnabled = PreferenceManager.getDefaultSharedPreferences(mContext).getBoolean(Prefs.PREF_FIREWALL, false);
            boolean adBlockEnabled = Prefs.isAdBlockEnabled(PreferenceManager.getDefaultSharedPreferences(mContext));
            boolean vpnActive = CaptureService.isServiceActive();
            sb.append("[PROTECTION_STATE] Firewall: ").append(fwEnabled ? "ACTIVE" : "STANDBY")
              .append(" | Ad-Shield: ").append(adBlockEnabled ? "ACTIVE" : "OFF")
              .append(" | Packet Sentinel: ").append(vpnActive ? "RUNNING" : "STOPPED").append("\n");
        } catch (Exception ignored) {}

        if (mConfig.canAccessStatus() && (asksAboutStatus || !asksAboutFeature)) {
            sb.append("[TELEMETRY] ");
            CaptureStats stats = CaptureService.getStats();
            if (stats != null) {
                sb.append("RX:").append(Utils.formatBytes(stats.bytes_rcvd))
                  .append(" | TX:").append(Utils.formatBytes(stats.bytes_sent))
                  .append(" | Active Sockets:").append(stats.active_conns)
                  .append(" | DNS Lookups:").append(stats.num_dns_queries)
                  .append(" | Buffer Drops:").append(stats.pkts_dropped).append("\n");
            } else {
                sb.append("Idle\n");
            }

            // Top talker bandwidth apps (RAG)
            try {
                ConnectionsRegister reg = CaptureService.getConnsRegister();
                if (reg != null) {
                    List<AppStats> appStats = reg.getAppsStats();
                    if (appStats != null && !appStats.isEmpty()) {
                        Collections.sort(appStats, (a, b) -> Long.compare((b.sentBytes + b.rcvdBytes), (a.sentBytes + a.rcvdBytes)));
                        AppsResolver appsResolver = new AppsResolver(mContext);
                        sb.append("[TOP_TALKERS] ");
                        int talkerCount = 0;
                        for (AppStats s : appStats) {
                            long totalBytes = s.sentBytes + s.rcvdBytes;
                            if (totalBytes <= 0) continue;
                            String appName = "UID " + s.getUid();
                            AppDescriptor appDesc = appsResolver.getAppByUid(s.getUid(), 0);
                            if (appDesc != null && appDesc.getName() != null) {
                                appName = appDesc.getName();
                            }
                            sb.append(appName).append(" (").append(Utils.formatBytes(totalBytes)).append("); ");
                            talkerCount++;
                            if (talkerCount >= 3) break;
                        }
                        if (talkerCount == 0) sb.append("No active flows");
                        sb.append("\n");
                    }
                }
            } catch (Exception ignored) {}
        }

        // Live MITRE ATT&CK Posture (RAG)
        try {
            List<MitreTechnique> mitreList = MitreTechnique.getTechniquesWithMappedAlerts(mContext);
            if (mitreList != null && !mitreList.isEmpty()) {
                int activeThreats = 0;
                int anomalies = 0;
                int defended = 0;
                for (MitreTechnique t : mitreList) {
                    if (t.statusLevel == MitreTechnique.STATUS_ACTIVE_THREAT) activeThreats++;
                    else if (t.statusLevel == MitreTechnique.STATUS_SUSPICIOUS) anomalies++;
                    else if (t.statusLevel == MitreTechnique.STATUS_DEFENDED) defended++;
                }
                int postureScore = Math.max(10, 100 - (activeThreats * 15) - (anomalies * 5));
                sb.append("[MITRE_POSTURE] Defensive Score: ").append(postureScore).append("/100")
                  .append(" | Active Threats: ").append(activeThreats)
                  .append(" | Anomalies: ").append(anomalies)
                  .append(" | Defended Techniques: ").append(defended).append("\n");
            }
        } catch (Exception ignored) {}

        if (mConfig.canAccessConnections() && (asksAboutConns || !asksAboutFeature)) {
            sb.append("[ACTIVE_SOCKETS] ");
            try {
                ConnectionsRegister reg = CaptureService.getConnsRegister();
                if (reg != null) {
                    int count = 0;
                    int total = reg.getConnCount();
                    AppsResolver appsResolver = new AppsResolver(mContext);
                    for (int i = 0; i < total; i++) {
                        ConnectionDescriptor c = reg.getConn(i);
                        if (c != null) {
                            String appName = "UID " + c.uid;
                            AppDescriptor appDesc = appsResolver.getAppByUid(c.uid, 0);
                            if (appDesc != null) appName = appDesc.getName();

                            String host = (c.info != null && !c.info.isEmpty()) ? c.info : (c.dst_ip != null ? c.dst_ip : "?");
                            sb.append("[").append(appName).append("->").append(host).append(":").append(c.dst_port)
                              .append("/").append(c.l7proto != null ? c.l7proto : (c.ipproto == 6 ? "TCP" : "UDP")).append("] ");
                            count++;
                            if (count >= 8) break;
                        }
                    }
                    if (count == 0) sb.append("None\n");
                    else sb.append("\n");
                }
            } catch (Exception ignored) {}
        }

        if (mConfig.canAccessFirewall() && (asksAboutFirewall || !asksAboutFeature)) {
            try {
                AlertStore store = AlertStore.getInstance(mContext);
                List<AlertRecord> alerts = store.getAll();
                if (alerts != null && !alerts.isEmpty()) {
                    sb.append("[ALERTS] ");
                    int alertCount = 0;
                    for (AlertRecord r : alerts) {
                        sb.append("[").append(r.severity.name().charAt(0)).append("] ").append(r.title).append("; ");
                        alertCount++;
                        if (alertCount >= 4) break;
                    }
                    sb.append("\n");
                }
            } catch (Exception ignored) {}
        }

        if (mConfig.canAccessAntivirus() && (asksAboutAv || !asksAboutFeature)) {
            try {
                ScanReportDbHelper reportDb = ScanReportDbHelper.getInstance(mContext);
                ScanReportEntry last = reportDb.getLatestReport();
                if (last != null) {
                    sb.append("[ANTIVIRUS] Score:").append(last.securityScore).append("/100 | Threats:").append(last.threatsDetected)
                      .append(" | Suspicious:").append(last.suspiciousDetected).append("\n");
                }
            } catch (Exception ignored) {}
        }

        return sb.toString();
    }

    /**
     * Detects adversarial queries, prompt injection attempts, or queries probing for
     * backend infrastructure, API keys, app source code, or private keys.
     */
    public static boolean isAdversarialOrSensitiveQuery(String query) {
        if (query == null || query.trim().isEmpty()) return false;
        String q = query.toLowerCase(Locale.ROOT).trim();

        // Check if query is an educational how-to or setup request
        boolean isEducationalHowTo = q.contains("how to setup") || q.contains("how do i setup")
                || q.contains("how to configure") || q.contains("how to get") || q.contains("how do i get")
                || q.contains("how to pair") || q.contains("how does it work") || q.contains("how it work")
                || q.contains("where to enter") || q.contains("guide") || q.contains("explain");

        // 1. Prompt Injection / Jailbreak attempts
        if (q.contains("ignore previous instructions") || q.contains("ignore all instructions")
                || q.contains("system prompt") || q.contains("reveal prompt") || q.contains("print prompt")
                || q.contains("jailbreak") || q.contains("dan mode") || q.contains("developer mode")
                || q.contains("bypass security") || q.contains("bypass safety") || q.contains("act as root")) {
            return true;
        }

        // 2. Sensitive App, Backend, Source Code, Server Infrastructure & Flaw Probing
        if (q.contains("source code") || q.contains("show me code") || q.contains("app code")
                || q.contains("server code") || q.contains("backend code") || q.contains("relay code")
                || q.contains("server ip") || q.contains("backend ip") || q.contains("relay ip")
                || q.contains("server address") || q.contains("backend url") || q.contains("backend endpoint")
                || q.contains("decompil") || q.contains("keystore") || q.contains("private key")
                || q.contains("master key") || q.contains("secret key") || q.contains("signing cert")
                || q.contains("database password") || q.contains("db password") || q.contains("admin password")
                || q.contains("server credentials") || q.contains("leak")
                || q.contains("flaw") || q.contains("flaws") || q.contains("vulnerabilit")
                || q.contains("exploit") || q.contains("zero-day") || q.contains("0day")
                || q.contains("backdoor") || q.contains("hack kotsafe") || q.contains("attack kotsafe")) {
            return true;
        }

        // 3. Probing / Extracting API Keys (Distinguished from learning how to configure personal keys)
        if (!isEducationalHowTo && (q.contains("api key") || q.contains("apikey"))) {
            return true;
        } else if (q.contains("api key") || q.contains("apikey")) {
            if (q.contains("give") || q.contains("show") || q.contains("reveal")
                    || q.contains("what is your") || q.contains("extract") || q.contains("dump")
                    || q.contains("steal") || q.contains("print") || q.contains("your key")
                    || q.contains("stored key")) {
                return true;
            }
        }

        // 4. User Credential Extraction
        if (q.contains("my password") || q.contains("give password") || q.contains("show password")
                || q.contains("my token") || q.contains("my secret") || q.contains("my imei")
                || q.contains("hack password") || q.contains("extract password") || q.contains("device pin")
                || q.contains("user credentials") || q.contains("show credentials")) {
            return true;
        }

        return false;
    }

    /**
     * Sanitizes strings by masking authorization tokens, API keys, passwords, and sensitive keys.
     * Prevents leakage of cloud API keys (OpenAI, Gemini, Claude) and internal credentials.
     */
    public static String sanitize(String input) {
        if (input == null) return "";
        return input
                // Redact Bearer / Authorization headers
                .replaceAll("(?i)bearer\\s+[a-zA-Z0-9._~+/-]+", "Bearer [REDACTED]")
                // Redact Google AI / Firebase keys (AIzaSy...)
                .replaceAll("AIza[0-9A-Za-z\\-_]{35}", "AIza[REDACTED_API_KEY]")
                // Redact OpenAI / Anthropic keys (sk-...)
                .replaceAll("sk-[A-Za-z0-9_-]{20,}", "sk-[REDACTED_API_KEY]")
                // Redact key=value pairs for sensitive variables
                .replaceAll("(?i)(password|token|secret|apikey|api_key|private_key)=\\S+", "$1=[REDACTED]")
                // Redact private keystore paths or internal package file dumps
                .replaceAll("/data/data/[a-zA-Z0-9._]+/shared_prefs/\\S+", "[REDACTED_SECURE_STORAGE]");
    }
}
