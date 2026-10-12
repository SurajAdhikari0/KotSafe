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
 */

package com.kotsafe.security.server;

import android.content.Context;
import android.util.Base64;

import com.kotsafe.security.Log;
import com.kotsafe.security.Utils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Embedded HTTP server listening on port 8090 (like enterprise firewalls, e.g. Sophos XG/UTM)
 * to serve the Firewall Block Alert page directly in browsers (Chrome, Brave, Firefox, etc.)
 * whenever a user visits a blocked website, domain, or URL.
 */
public class FirewallBlockHttpServer implements Runnable {
    private static final String TAG = "FirewallBlockHttpServer";
    public static final int HTTP_PORT = 8088;

    private static volatile FirewallBlockHttpServer sInstance;
    private final Context mContext;
    private ServerSocket mServerSocket;
    private Thread mServerThread;
    private ExecutorService mThreadPool;
    private volatile boolean mRunning;

    public static FirewallBlockHttpServer getInstance(Context context) {
        if (sInstance == null) {
            synchronized (FirewallBlockHttpServer.class) {
                if (sInstance == null) {
                    sInstance = new FirewallBlockHttpServer(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    private FirewallBlockHttpServer(Context context) {
        mContext = context;
    }

    public synchronized boolean start() {
        if (mRunning && mServerSocket != null && !mServerSocket.isClosed()) return true;
        try {
            if (mServerSocket != null) {
                Utils.safeClose(mServerSocket);
                mServerSocket = null;
            }
            mServerSocket = new ServerSocket();
            mServerSocket.setReuseAddress(true);
            mServerSocket.bind(new InetSocketAddress("0.0.0.0", HTTP_PORT), 64);
            mRunning = true;
            if (mThreadPool == null || mThreadPool.isShutdown()) {
                mThreadPool = Executors.newFixedThreadPool(8);
            }
            if (mServerThread == null || !mServerThread.isAlive()) {
                mServerThread = new Thread(this, "FirewallBlockHttpServer");
                mServerThread.start();
            }
            Log.i(TAG, "Firewall Block HTTP Server started on 0.0.0.0:" + HTTP_PORT);
            return true;
        } catch (IOException e) {
            Log.e(TAG, "Failed to bind Firewall Block HTTP Server to 0.0.0.0:" + HTTP_PORT + ": " + e.getMessage());
            try {
                mServerSocket = new ServerSocket();
                mServerSocket.setReuseAddress(true);
                mServerSocket.bind(new InetSocketAddress("127.0.0.1", HTTP_PORT), 64);
                mRunning = true;
                if (mThreadPool == null || mThreadPool.isShutdown()) {
                    mThreadPool = Executors.newFixedThreadPool(8);
                }
                if (mServerThread == null || !mServerThread.isAlive()) {
                    mServerThread = new Thread(this, "FirewallBlockHttpServer");
                    mServerThread.start();
                }
                Log.i(TAG, "Firewall Block HTTP Server started on 127.0.0.1:" + HTTP_PORT);
                return true;
            } catch (IOException e2) {
                Log.e(TAG, "Fallback bind to 127.0.0.1:" + HTTP_PORT + " also failed: " + e2.getMessage());
                stop();
                return false;
            }
        }
    }

    public synchronized void stop() {
        mRunning = false;
        Utils.safeClose(mServerSocket);
        mServerSocket = null;

        if (mThreadPool != null) {
            mThreadPool.shutdownNow();
            mThreadPool = null;
        }

        if (mServerThread != null) {
            mServerThread.interrupt();
            mServerThread = null;
        }
        Log.i(TAG, "Firewall Block HTTP Server stopped");
    }

    public boolean isRunning() {
        return mRunning;
    }

    @Override
    public void run() {
        while (mRunning && mServerSocket != null && !mServerSocket.isClosed()) {
            try {
                Socket client = mServerSocket.accept();
                if (!mRunning) {
                    Utils.safeClose(client);
                    break;
                }
                if (mThreadPool != null && !mThreadPool.isShutdown()) {
                    mThreadPool.execute(() -> handleConnection(client));
                } else {
                    Utils.safeClose(client);
                }
            } catch (IOException e) {
                if (mRunning) {
                    Log.d(TAG, "Accept error: " + e.getMessage());
                }
            }
        }
    }

    private void handleConnection(Socket socket) {
        try {
            socket.setSoTimeout(5000);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            OutputStream out = socket.getOutputStream();

            String requestLine = in.readLine();
            if (requestLine == null || requestLine.isEmpty()) {
                Utils.safeClose(socket);
                return;
            }

            String[] parts = requestLine.split(" ");
            if (parts.length < 2) {
                Utils.safeClose(socket);
                return;
            }

            String method = parts[0];
            String rawUri = parts[1];

            // Parse path and query
            String path = rawUri;
            String queryString = "";
            int qIdx = rawUri.indexOf('?');
            if (qIdx != -1) {
                path = rawUri.substring(0, qIdx);
                queryString = rawUri.substring(qIdx + 1);
            }

            Map<String, String> queryParams = parseQuery(queryString);

            // Routing: always serve the block alert page (matching /ips/block/webcat)
            handleBlockPageRequest(out, queryParams);
        } catch (Exception e) {
            Log.d(TAG, "Client handle exception: " + e.getMessage());
        } finally {
            Utils.safeClose(socket);
        }
    }

    private Map<String, String> parseQuery(String queryString) {
        Map<String, String> map = new HashMap<>();
        if (queryString == null || queryString.isEmpty()) return map;

        String[] pairs = queryString.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            try {
                if (idx > 0) {
                    String key = URLDecoder.decode(pair.substring(0, idx), "UTF-8");
                    String val = URLDecoder.decode(pair.substring(idx + 1), "UTF-8");
                    map.put(key, val);
                } else if (idx == -1 && !pair.isEmpty()) {
                    map.put(URLDecoder.decode(pair, "UTF-8"), "");
                }
            } catch (Exception ignored) {}
        }
        return map;
    }

    private void handleBlockPageRequest(OutputStream out, Map<String, String> params) throws IOException {
        String rawUrl = params.get("url");
        if (rawUrl == null || rawUrl.isEmpty()) {
            rawUrl = params.get("target");
        }
        String targetUrl = decodeTargetUrl(rawUrl != null ? rawUrl : "example.com");

        String catParam = params.get("cat");
        String category = resolveCategoryName(catParam, params.get("reason"));

        String appName = params.get("app");
        if (appName == null || appName.isEmpty()) {
            appName = "Web Browser (Chrome)";
        }

        String targetType = params.get("type");
        if (targetType == null || targetType.isEmpty()) {
            targetType = "SITE";
        }

        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date());

        String html = generateBlockHtml(targetUrl, category, appName, timestamp, targetType);
        byte[] bodyBytes = html.getBytes(StandardCharsets.UTF_8);

        String header = "HTTP/1.1 200 OK\r\n"
                + "Content-Type: text/html; charset=UTF-8\r\n"
                + "Content-Length: " + bodyBytes.length + "\r\n"
                + "Cache-Control: no-cache, no-store, must-revalidate\r\n"
                + "Connection: close\r\n\r\n";

        out.write(header.getBytes(StandardCharsets.UTF_8));
        out.write(bodyBytes);
        out.flush();
    }

    private String decodeTargetUrl(String input) {
        if (input == null) return "unknown";
        // Check if Base64 encoded (Sophos XG standard parameter format)
        if (input.length() > 6 && !input.contains(" ") && !input.startsWith("http://") && !input.startsWith("https://")) {
            try {
                byte[] decoded = Base64.decode(input, Base64.DEFAULT);
                String str = new String(decoded, StandardCharsets.UTF_8);
                if (str.startsWith("http://") || str.startsWith("https://") || str.contains(".")) {
                    input = str;
                }
            } catch (Exception ignored) {}
        }
        if (input.endsWith(":53")) {
            input = input.substring(0, input.length() - 3);
        }
        return input;
    }

    private String resolveCategoryName(String cat, String reason) {
        if (reason != null && !reason.trim().isEmpty()) {
            return reason;
        }
        if (cat == null || cat.isEmpty()) {
            return "Security Threat / Restricted Sites";
        }
        switch (cat) {
            case "66":
                return "Search Engines";
            case "1":
                return "Malware & Security Threats";
            case "2":
                return "Phishing & Fraud";
            case "3":
                return "Command and Control (C2)";
            case "4":
                return "Cryptomining";
            case "5":
                return "Adult & Explicit Content";
            case "6":
                return "Gambling";
            case "7":
                return "Social Networking";
            case "8":
                return "Streaming Media";
            case "9":
                return "Advertising & Tracking";
            default:
                return cat;
        }
    }

    /**
     * Generates modern security block page with Guard bot mascot and KotSafe branding.
     */
    public String generateBlockHtml(String targetUrl, String category, String appName, String timestamp) {
        return generateBlockHtml(targetUrl, category, appName, timestamp, "SITE");
    }

    /**
     * Generates modern security block page with Guard bot mascot and KotSafe branding.
     */
    public String generateBlockHtml(String targetUrl, String category, String appName, String timestamp, String targetType) {
        // Safe escapes
        String safeUrl = targetUrl.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
        String safeCat = category.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
        String safeApp = appName.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");

        String clean = safeUrl;
        if (clean.startsWith("http://")) clean = clean.substring(7);
        else if (clean.startsWith("https://")) clean = clean.substring(8);
        int slashIdx = clean.indexOf('/');
        String hostPart = slashIdx != -1 ? clean.substring(0, slashIdx) : clean;
        String pathPart = slashIdx != -1 ? clean.substring(slashIdx) : "";
        if (hostPart.endsWith(":53")) {
            hostPart = hostPart.substring(0, hostPart.length() - 3);
        }

        String pageTitle = "Site Blocked by Administrator";
        String mainHeading = "This site is blocked by your administrator";
        String targetKey = "domain";
        String entityDesc = "Your network administrator has restricted access to this domain in accordance with security policy. Contact your network administrator if you believe this is in error.";

        if ("IP".equalsIgnoreCase(targetType)) {
            pageTitle = "IP Address Blocked by Administrator";
            mainHeading = "This IP address is blocked by your administrator";
            targetKey = "ip address";
            entityDesc = "Your network administrator has restricted access to this IP address. Contact your administrator if you need assistance.";
        } else if ("FILE".equalsIgnoreCase(targetType) || "HASH".equalsIgnoreCase(targetType)) {
            pageTitle = "File Blocked by Administrator";
            mainHeading = "This file is blocked by your administrator";
            targetKey = "file hash";
            entityDesc = "This file signature matched a blocked threat definition. Contact your administrator if you believe this is in error.";
        } else if ("APP".equalsIgnoreCase(targetType)) {
            pageTitle = "Application Blocked by Administrator";
            mainHeading = "This application is blocked by your administrator";
            targetKey = "application";
            entityDesc = "Your device administrator has restricted network access for this application. Contact your administrator for more information.";
        } else if ("URL".equalsIgnoreCase(targetType)) {
            pageTitle = "URL Blocked by Administrator";
            mainHeading = "This site is blocked by your administrator";
            targetKey = "url";
            entityDesc = "Your network administrator has restricted access to this URL. Contact your administrator if you think this site was blocked by mistake.";
        }

        return "<!DOCTYPE html>\n"
                + "<html lang=\"en\">\n"
                + "<head>\n"
                + "<meta charset=\"UTF-8\">\n"
                + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0, maximum-scale=5.0, user-scalable=yes\">\n"
                + "<title>KotSafe — " + pageTitle + "</title>\n"
                + "<style>\n"
                + "  @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;700&family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap');\n"
                + "\n"
                + "  :root{\n"
                + "    --bg: #0b0f14;\n"
                + "    --panel: #141b22;\n"
                + "    --panel-raised: #182029;\n"
                + "    --line: #232d38;\n"
                + "    --line-soft: #1b232c;\n"
                + "    --red: #ff4757;\n"
                + "    --red-dim: #7a2530;\n"
                + "    --amber: #ffb020;\n"
                + "    --text: #e6edf3;\n"
                + "    --muted: #7c8a9a;\n"
                + "    --muted-dim: #4d5866;\n"
                + "  }\n"
                + "\n"
                + "  *{ box-sizing: border-box; margin:0; padding:0; }\n"
                + "\n"
                + "  html, body{\n"
                + "    width: 100%;\n"
                + "    margin: 0;\n"
                + "    padding: 0;\n"
                + "    overflow-x: hidden;\n"
                + "    -webkit-text-size-adjust: 100%;\n"
                + "  }\n"
                + "\n"
                + "  body{\n"
                + "    min-height: 100vh;\n"
                + "    background:\n"
                + "      radial-gradient(circle at 15% 10%, rgba(255,71,87,.08), transparent 45%),\n"
                + "      radial-gradient(circle at 85% 90%, rgba(255,176,32,.06), transparent 45%),\n"
                + "      var(--bg);\n"
                + "    color: var(--text);\n"
                + "    font-family: 'IBM Plex Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;\n"
                + "    display: flex;\n"
                + "    align-items: center;\n"
                + "    justify-content: center;\n"
                + "    padding: 24px 14px;\n"
                + "    box-sizing: border-box;\n"
                + "  }\n"
                + "\n"
                + "  .page{\n"
                + "    width: 100%;\n"
                + "    max-width: 580px;\n"
                + "    margin: 0 auto;\n"
                + "    box-sizing: border-box;\n"
                + "  }\n"
                + "\n"
                + "  /* Address bar */\n"
                + "  .addressbar{\n"
                + "    display: flex;\n"
                + "    align-items: center;\n"
                + "    gap: 10px;\n"
                + "    background: var(--panel);\n"
                + "    border: 1px solid var(--line);\n"
                + "    border-radius: 12px;\n"
                + "    padding: 10px 14px;\n"
                + "    margin-bottom: 20px;\n"
                + "    width: 100%;\n"
                + "    box-sizing: border-box;\n"
                + "    min-width: 0;\n"
                + "  }\n"
                + "\n"
                + "  .addressbar .dots{ display:flex; gap:6px; flex-shrink:0; }\n"
                + "  .addressbar .dots span{ width:8px; height:8px; border-radius:50%; background: var(--line); }\n"
                + "\n"
                + "  .addressbar .lock{\n"
                + "    flex-shrink: 0;\n"
                + "    color: var(--red);\n"
                + "    font-size: 13px;\n"
                + "  }\n"
                + "\n"
                + "  .addressbar .url{\n"
                + "    font-family: 'IBM Plex Mono', monospace;\n"
                + "    font-size: 12.5px;\n"
                + "    color: var(--muted);\n"
                + "    overflow: hidden;\n"
                + "    text-overflow: ellipsis;\n"
                + "    white-space: nowrap;\n"
                + "    flex: 1;\n"
                + "    min-width: 0;\n"
                + "  }\n"
                + "\n"
                + "  .addressbar .url b{ color: var(--text); font-weight: 500; }\n"
                + "\n"
                + "  /* Card */\n"
                + "  .card{\n"
                + "    background: var(--panel);\n"
                + "    border: 1px solid var(--line);\n"
                + "    border-radius: 18px;\n"
                + "    overflow: hidden;\n"
                + "    box-shadow: 0 16px 40px rgba(0,0,0,.5);\n"
                + "    width: 100%;\n"
                + "    box-sizing: border-box;\n"
                + "  }\n"
                + "\n"
                + "  .hazard-strip{\n"
                + "    height: 5px;\n"
                + "    width: 100%;\n"
                + "    background: repeating-linear-gradient(-45deg, var(--red) 0 14px, var(--amber) 14px 28px);\n"
                + "  }\n"
                + "\n"
                + "  .card-inner{ padding: 28px 24px 24px; box-sizing: border-box; }\n"
                + "\n"
                + "  .top-row{\n"
                + "    display: flex;\n"
                + "    align-items: center;\n"
                + "    justify-content: space-between;\n"
                + "    gap: 12px;\n"
                + "  }\n"
                + "\n"
                + "  .wordmark{\n"
                + "    font-family: 'Space Grotesk', sans-serif;\n"
                + "    font-weight: 700;\n"
                + "    font-size: 15px;\n"
                + "    letter-spacing: -0.2px;\n"
                + "    color: var(--muted);\n"
                + "  }\n"
                + "\n"
                + "  .wordmark b{ color: var(--red); }\n"
                + "\n"
                + "  .globe{\n"
                + "    width: 28px;\n"
                + "    height: 28px;\n"
                + "    border-radius: 8px;\n"
                + "    border: 1px solid var(--red-dim);\n"
                + "    background: var(--panel-raised);\n"
                + "    display: grid;\n"
                + "    place-items: center;\n"
                + "    flex-shrink: 0;\n"
                + "  }\n"
                + "\n"
                + "  .globe svg{ width: 15px; height: 15px; }\n"
                + "\n"
                + "  /* Guard bot mascot */\n"
                + "  .mascot-stage{\n"
                + "    display: flex;\n"
                + "    justify-content: center;\n"
                + "    padding: 8px 0 4px;\n"
                + "    position: relative;\n"
                + "  }\n"
                + "\n"
                + "  .mascot{\n"
                + "    width: 124px;\n"
                + "    height: 124px;\n"
                + "    max-width: 100%;\n"
                + "    animation: botDrop .7s cubic-bezier(.34,1.56,.64,1) both,\n"
                + "               idleBob 2.6s ease-in-out 1.1s infinite;\n"
                + "  }\n"
                + "\n"
                + "  @keyframes botDrop{\n"
                + "    0%   { transform: translateY(-50px) scale(.9); opacity: 0; }\n"
                + "    60%  { transform: translateY(5px) scale(1.03); opacity: 1; }\n"
                + "    100% { transform: translateY(0) scale(1); }\n"
                + "  }\n"
                + "\n"
                + "  @keyframes idleBob{\n"
                + "    0%, 100% { transform: translateY(0); }\n"
                + "    50%      { transform: translateY(-4px); }\n"
                + "  }\n"
                + "\n"
                + "  .bot-eye{\n"
                + "    animation: blink 3.4s ease-in-out .9s infinite;\n"
                + "    transform-origin: center;\n"
                + "  }\n"
                + "\n"
                + "  @keyframes blink{\n"
                + "    0%, 92%, 100% { transform: scaleY(1); }\n"
                + "    96%           { transform: scaleY(.12); }\n"
                + "  }\n"
                + "\n"
                + "  .bot-arm{\n"
                + "    transform-origin: 96px 74px;\n"
                + "    animation: armSlam .6s cubic-bezier(.36,1.8,.4,1) .55s both;\n"
                + "  }\n"
                + "\n"
                + "  @keyframes armSlam{\n"
                + "    0%   { transform: rotate(-55deg); }\n"
                + "    65%  { transform: rotate(8deg); }\n"
                + "    85%  { transform: rotate(-4deg); }\n"
                + "    100% { transform: rotate(0deg); }\n"
                + "  }\n"
                + "\n"
                + "  .impact-line{\n"
                + "    opacity: 0;\n"
                + "    animation: impactBurst .5s ease-out .95s both;\n"
                + "    transform-origin: 100px 92px;\n"
                + "  }\n"
                + "\n"
                + "  @keyframes impactBurst{\n"
                + "    0%   { opacity: 0; transform: scale(.4); }\n"
                + "    35%  { opacity: 1; transform: scale(1.15); }\n"
                + "    100% { opacity: 0; transform: scale(1.5); }\n"
                + "  }\n"
                + "\n"
                + "  .stamp{\n"
                + "    opacity: 0;\n"
                + "    animation: stampPop .45s cubic-bezier(.36,1.8,.4,1) 1.05s both;\n"
                + "    transform-origin: center;\n"
                + "  }\n"
                + "\n"
                + "  @keyframes stampPop{\n"
                + "    0%   { opacity: 0; transform: translate(-50%,-6px) scale(1.6) rotate(-14deg); }\n"
                + "    60%  { opacity: 1; transform: translate(-50%,0) scale(.92) rotate(-8deg); }\n"
                + "    100% { opacity: 1; transform: translate(-50%,0) scale(1) rotate(-8deg); }\n"
                + "  }\n"
                + "\n"
                + "  @media (prefers-reduced-motion: reduce){\n"
                + "    .mascot, .bot-eye, .bot-arm, .impact-line, .stamp{ animation: none !important; opacity: 1 !important; }\n"
                + "  }\n"
                + "\n"
                + "  .title{\n"
                + "    margin-top: 20px;\n"
                + "  }\n"
                + "\n"
                + "  .title h1{\n"
                + "    font-family: 'Space Grotesk', sans-serif;\n"
                + "    font-weight: 700;\n"
                + "    font-size: 26px;\n"
                + "    letter-spacing: -0.4px;\n"
                + "    line-height: 1.15;\n"
                + "    word-break: break-word;\n"
                + "  }\n"
                + "\n"
                + "  .title p{\n"
                + "    margin-top: 8px;\n"
                + "    color: var(--muted);\n"
                + "    font-size: 14.5px;\n"
                + "    line-height: 1.5;\n"
                + "    word-break: break-word;\n"
                + "  }\n"
                + "\n"
                + "  /* Detection log */\n"
                + "  .log{\n"
                + "    margin-top: 22px;\n"
                + "    border: 1px solid var(--line);\n"
                + "    border-radius: 12px;\n"
                + "    overflow: hidden;\n"
                + "    background: var(--panel-raised);\n"
                + "    width: 100%;\n"
                + "    box-sizing: border-box;\n"
                + "  }\n"
                + "\n"
                + "  .log-head{\n"
                + "    display: flex;\n"
                + "    align-items: center;\n"
                + "    gap: 8px;\n"
                + "    padding: 10px 14px;\n"
                + "    background: #10161e;\n"
                + "    border-bottom: 1px solid var(--line);\n"
                + "  }\n"
                + "\n"
                + "  .dot{ width: 7px; height: 7px; border-radius: 50%; background: var(--red); flex-shrink: 0; }\n"
                + "\n"
                + "  .log-head span{\n"
                + "    font-family: 'IBM Plex Mono', monospace;\n"
                + "    font-size: 11.5px;\n"
                + "    color: var(--muted);\n"
                + "    letter-spacing: 0.5px;\n"
                + "  }\n"
                + "\n"
                + "  .log-body{\n"
                + "    padding: 14px;\n"
                + "    font-family: 'IBM Plex Mono', monospace;\n"
                + "    font-size: 12px;\n"
                + "    line-height: 1.85;\n"
                + "    box-sizing: border-box;\n"
                + "  }\n"
                + "\n"
                + "  .log-row{\n"
                + "    display: flex;\n"
                + "    justify-content: space-between;\n"
                + "    align-items: baseline;\n"
                + "    gap: 10px;\n"
                + "    margin-bottom: 4px;\n"
                + "  }\n"
                + "\n"
                + "  .log-key{\n"
                + "    color: var(--muted-dim);\n"
                + "    flex-shrink: 0;\n"
                + "    text-transform: uppercase;\n"
                + "    font-size: 11px;\n"
                + "    letter-spacing: 0.5px;\n"
                + "  }\n"
                + "\n"
                + "  .log-val{\n"
                + "    color: var(--text);\n"
                + "    text-align: right;\n"
                + "    word-break: break-word;\n"
                + "    overflow-wrap: anywhere;\n"
                + "    min-width: 0;\n"
                + "    flex: 1;\n"
                + "  }\n"
                + "\n"
                + "  .log-val.flag{ color: var(--red); font-weight: 600; }\n"
                + "\n"
                + "  .log-divider{ height: 1px; background: var(--line-soft); margin: 9px 0; }\n"
                + "\n"
                + "  .log-note{\n"
                + "    font-family: 'IBM Plex Sans', sans-serif;\n"
                + "    font-size: 12.5px;\n"
                + "    line-height: 1.5;\n"
                + "    color: var(--muted);\n"
                + "    word-break: break-word;\n"
                + "  }\n"
                + "\n"
                + "  /* Meaning list */\n"
                + "  .meaning{\n"
                + "    margin-top: 20px;\n"
                + "    display: flex;\n"
                + "    flex-direction: column;\n"
                + "    gap: 11px;\n"
                + "  }\n"
                + "\n"
                + "  .meaning-row{ display: flex; align-items: flex-start; gap: 10px; }\n"
                + "\n"
                + "  .meaning-mark{\n"
                + "    flex-shrink: 0;\n"
                + "    width: 20px; height: 20px;\n"
                + "    border-radius: 6px;\n"
                + "    background: var(--panel-raised);\n"
                + "    border: 1px solid var(--line);\n"
                + "    display: grid; place-items: center;\n"
                + "    font-size: 11px;\n"
                + "    color: var(--amber);\n"
                + "    margin-top: 1px;\n"
                + "  }\n"
                + "\n"
                + "  .meaning-row p{ font-size: 13px; line-height: 1.45; color: var(--text); min-width: 0; flex: 1; word-break: break-word; }\n"
                + "  .meaning-row p b{ font-weight: 600; }\n"
                + "\n"
                + "  /* Actions */\n"
                + "  .actions{\n"
                + "    margin-top: 24px;\n"
                + "    display: flex;\n"
                + "    gap: 10px;\n"
                + "    flex-wrap: wrap;\n"
                + "    width: 100%;\n"
                + "  }\n"
                + "\n"
                + "  .btn{\n"
                + "    flex: 1;\n"
                + "    min-width: 140px;\n"
                + "    height: 46px;\n"
                + "    border-radius: 11px;\n"
                + "    font-size: 14px;\n"
                + "    font-weight: 600;\n"
                + "    cursor: pointer;\n"
                + "    border: 0;\n"
                + "    display: inline-flex;\n"
                + "    align-items: center;\n"
                + "    justify-content: center;\n"
                + "  }\n"
                + "\n"
                + "  .btn-primary{ background: var(--text); color: var(--bg); }\n"
                + "  .btn-primary:hover{ opacity: .92; }\n"
                + "\n"
                + "  .btn-secondary{\n"
                + "    background: transparent;\n"
                + "    color: var(--text);\n"
                + "    border: 1px solid var(--line);\n"
                + "  }\n"
                + "  .btn-secondary:hover{ background: var(--panel-raised); }\n"
                + "\n"
                + "  .btn:focus-visible{ outline: 2px solid var(--amber); outline-offset: 2px; }\n"
                + "\n"
                + "  .footer{\n"
                + "    text-align: center;\n"
                + "    margin-top: 20px;\n"
                + "    color: var(--muted-dim);\n"
                + "    font-family: 'IBM Plex Mono', monospace;\n"
                + "    font-size: 10px;\n"
                + "    letter-spacing: 0.5px;\n"
                + "  }\n"
                + "\n"
                + "  @media (max-width: 480px){\n"
                + "    body{ padding: 14px 10px; }\n"
                + "    .card-inner{ padding: 20px 15px 18px; }\n"
                + "    .title h1{ font-size: 22px; }\n"
                + "    .title p{ font-size: 13.5px; }\n"
                + "    .actions{ flex-direction: column; }\n"
                + "    .btn{ width: 100%; min-width: 0; }\n"
                + "  }\n"
                + "</style>\n"
                + "</head>\n"
                + "<body>\n"
                + "\n"
                + "<div class=\"page\">\n"
                + "\n"
                + "  <div class=\"addressbar\">\n"
                + "    <div class=\"dots\"><span></span><span></span><span></span></div>\n"
                + "    <span class=\"lock\">&#x26D4;</span>\n"
                + "    <span class=\"url\"><b>" + hostPart + "</b>" + pathPart + "</span>\n"
                + "  </div>\n"
                + "\n"
                + "  <div class=\"card\">\n"
                + "    <div class=\"hazard-strip\"></div>\n"
                + "\n"
                + "    <div class=\"card-inner\">\n"
                + "\n"
                + "      <div class=\"top-row\">\n"
                + "        <div class=\"wordmark\">KotSafe <b>SHIELD</b> FIREWALL</div>\n"
                + "      </div>\n"
                + "\n"
                + "      <div class=\"mascot-stage\">\n"
                + "        <svg class=\"mascot\" viewBox=\"0 0 200 160\" xmlns=\"http://www.w3.org/2000/svg\">\n"
                + "          <!-- antenna -->\n"
                + "          <line x1=\"100\" y1=\"18\" x2=\"100\" y2=\"4\" stroke=\"#3a4757\" stroke-width=\"3\" stroke-linecap=\"round\"/>\n"
                + "          <circle cx=\"100\" cy=\"4\" r=\"4\" fill=\"var(--amber)\"/>\n"
                + "\n"
                + "          <!-- head -->\n"
                + "          <rect x=\"66\" y=\"18\" width=\"68\" height=\"46\" rx=\"14\" fill=\"var(--panel-raised)\" stroke=\"var(--line)\" stroke-width=\"2\"/>\n"
                + "          <rect class=\"bot-eye\" x=\"80\" y=\"34\" width=\"14\" height=\"14\" rx=\"4\" fill=\"var(--amber)\"/>\n"
                + "          <rect class=\"bot-eye\" x=\"106\" y=\"34\" width=\"14\" height=\"14\" rx=\"4\" fill=\"var(--amber)\"/>\n"
                + "\n"
                + "          <!-- body -->\n"
                + "          <rect x=\"58\" y=\"66\" width=\"84\" height=\"56\" rx=\"16\" fill=\"var(--panel-raised)\" stroke=\"var(--line)\" stroke-width=\"2\"/>\n"
                + "          <circle cx=\"100\" cy=\"94\" r=\"12\" fill=\"none\" stroke=\"var(--red)\" stroke-width=\"3\"/>\n"
                + "          <line x1=\"91.5\" y1=\"85.5\" x2=\"108.5\" y2=\"102.5\" stroke=\"var(--red)\" stroke-width=\"3\" stroke-linecap=\"round\"/>\n"
                + "\n"
                + "          <!-- static arm -->\n"
                + "          <rect x=\"40\" y=\"78\" width=\"18\" height=\"14\" rx=\"7\" fill=\"var(--panel-raised)\" stroke=\"var(--line)\" stroke-width=\"2\"/>\n"
                + "\n"
                + "          <!-- swinging arm + stop sign -->\n"
                + "          <g class=\"bot-arm\">\n"
                + "            <rect x=\"128\" y=\"66\" width=\"16\" height=\"30\" rx=\"7\" fill=\"var(--panel-raised)\" stroke=\"var(--line)\" stroke-width=\"2\"/>\n"
                + "            <g transform=\"translate(150,44)\">\n"
                + "              <polygon points=\"20,0 34,0 44,10 44,24 34,34 20,34 10,24 10,10\"\n"
                + "                       fill=\"var(--red)\" stroke=\"#3a0b0f\" stroke-width=\"1.5\"/>\n"
                + "              <text x=\"27\" y=\"21\" text-anchor=\"middle\" font-family=\"IBM Plex Mono, monospace\"\n"
                + "                    font-size=\"9\" font-weight=\"700\" fill=\"#fff\">STOP</text>\n"
                + "            </g>\n"
                + "          </g>\n"
                + "\n"
                + "          <!-- impact lines -->\n"
                + "          <g class=\"impact-line\" stroke=\"var(--amber)\" stroke-width=\"3\" stroke-linecap=\"round\">\n"
                + "            <line x1=\"150\" y1=\"60\" x2=\"162\" y2=\"50\"/>\n"
                + "          </g>\n"
                + "          <g class=\"impact-line\" style=\"animation-delay:1s\" stroke=\"var(--amber)\" stroke-width=\"3\" stroke-linecap=\"round\">\n"
                + "            <line x1=\"158\" y1=\"80\" x2=\"172\" y2=\"80\"/>\n"
                + "          </g>\n"
                + "          <g class=\"impact-line\" style=\"animation-delay:1.05s\" stroke=\"var(--amber)\" stroke-width=\"3\" stroke-linecap=\"round\">\n"
                + "            <line x1=\"150\" y1=\"100\" x2=\"162\" y2=\"110\"/>\n"
                + "          </g>\n"
                + "\n"
                + "          <!-- legs -->\n"
                + "          <rect x=\"72\" y=\"122\" width=\"14\" height=\"16\" rx=\"5\" fill=\"var(--panel-raised)\" stroke=\"var(--line)\" stroke-width=\"2\"/>\n"
                + "          <rect x=\"114\" y=\"122\" width=\"14\" height=\"16\" rx=\"5\" fill=\"var(--panel-raised)\" stroke=\"var(--line)\" stroke-width=\"2\"/>\n"
                + "        </svg>\n"
                + "\n"
                + "        <div class=\"stamp\" style=\"position:absolute; left:50%; top:2px; background:var(--red); color:#fff; font-family:'Space Grotesk',sans-serif; font-weight:700; font-size:12px; letter-spacing:1px; padding:4px 12px; border-radius:4px; border:2px solid #fff2; box-shadow:0 4px 14px rgba(255,71,87,.35);\">\n"
                + "          BLOCKED BY ADMINISTRATOR\n"
                + "        </div>\n"
                + "      </div>\n"
                + "\n"
                + "      <div class=\"title\">\n"
                + "        <h1>" + mainHeading + "</h1>\n"
                + "        <p>Your network administrator doesn't allow access to this site. Contact your network administrator for assistance or if you think this site was blocked by mistake.</p>\n"
                + "      </div>\n"
                + "\n"
                + "      <div class=\"log\">\n"
                + "        <div class=\"log-head\"><span class=\"dot\"></span><span>FIREWALL_LOG</span></div>\n"
                + "        <div class=\"log-body\">\n"
                + "          <div class=\"log-row\"><span class=\"log-key\">" + targetKey + "</span><span class=\"log-val flag\" id=\"targetDisplay\">" + safeUrl + "</span></div>\n"
                + "          <div class=\"log-row\"><span class=\"log-key\">category</span><span class=\"log-val flag\">" + safeCat + "</span></div>\n"
                + "          <div class=\"log-row\"><span class=\"log-key\">app</span><span class=\"log-val\">" + safeApp + "</span></div>\n"
                + "          <div class=\"log-row\"><span class=\"log-key\">action</span><span class=\"log-val\">blocked by administrator</span></div>\n"
                + "          <div class=\"log-row\"><span class=\"log-key\">rule</span><span class=\"log-val\">enterprise security policy</span></div>\n"
                + "          <div class=\"log-row\"><span class=\"log-key\">timestamp</span><span class=\"log-val\">" + timestamp + "</span></div>\n"
                + "          <div class=\"log-divider\"></div>\n"
                + "          <p class=\"log-note\">" + entityDesc + "</p>\n"
                + "        </div>\n"
                + "      </div>\n"
                + "\n"
                + "      <div class=\"meaning\">\n"
                + "        <div class=\"meaning-row\">\n"
                + "          <span class=\"meaning-mark\">&#x2713;</span>\n"
                + "          <p><b>Access restricted by administrator.</b> Your network administrator or organization policy prevents access to this destination.</p>\n"
                + "        </div>\n"
                + "        <div class=\"meaning-row\">\n"
                + "          <span class=\"meaning-mark\">&#x25D0;</span>\n"
                + "          <p><b>No data transferred.</b> The connection was terminated by the firewall before any content was loaded.</p>\n"
                + "        </div>\n"
                + "        <div class=\"meaning-row\">\n"
                + "          <span class=\"meaning-mark\">&#x21BA;</span>\n"
                + "          <p><b>Need access or think this is wrong?</b> Contact your network administrator to request access or report a false positive.</p>\n"
                + "        </div>\n"
                + "      </div>\n"
                + "\n"
                + "      <div class=\"actions\">\n"
                + "        <button class=\"btn btn-primary\" onclick=\"history.back()\">Go back (Recommended)</button>\n"
                + "        <button class=\"btn btn-secondary\" type=\"button\" onclick=\"contactAdmin()\">Contact administrator</button>\n"
                + "      </div>\n"
                + "\n"
                + "    </div>\n"
                + "  </div>\n"
                + "\n"
                + "  <div class=\"footer\">KotSafe · SHIELD FIREWALL</div>\n"
                + "\n"
                + "</div>\n"
                + "\n"
                + "<script>\n"
                + "  function contactAdmin() {\n"
                + "    var t = document.getElementById('targetDisplay') ? document.getElementById('targetDisplay').innerText : location.href;\n"
                + "    var info = 'ADMINISTRATIVE BLOCK NOTICE\\n\\n'\n"
                + "      + 'Destination: ' + t + '\\n'\n"
                + "      + 'Status: Blocked by Administrator\\n'\n"
                + "      + 'Policy: KotSafe Security Policy\\n\\n'\n"
                + "      + 'Contact: Network Security Administrator\\n'\n"
                + "      + 'Email: admin@organization.local\\n\\n'\n"
                + "      + 'Please provide the destination address above to your administrator to request access.';\n"
                + "    alert(info);\n"
                + "  }\n"
                + "</script>\n"
                + "</body>\n"
                + "</html>\n";
    }
}
