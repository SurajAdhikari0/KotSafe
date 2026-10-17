/*
 * This file is part of KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * v2.0 - corrected relay transport.
 *
 * Fixes vs v1:
 *  1. ROLE IS EXPLICIT AND STICKY. A device is a host or a client for a given
 *     pairing, and the WebSocket re-announces that role on every reconnect.
 *     v1 cached one future per token and the role of whoever opened it first.
 *  2. AUTO-RECONNECT WITH BACKOFF. v1 removed the socket from the map on
 *     onFailure and never dialled again, so the exit node went permanently
 *     offline after the first network blip.
 *  3. VPN SOCKET PROTECTION. Every socket this class opens (including the
 *     OkHttp WebSocket to the relay) is passed through CaptureService.protect().
 *     Without this, once SOCKS5 redirection is on, the app's own relay socket
 *     is captured by tun0 and routed back into 127.0.0.1:8095 -> infinite
 *     recursion, which is exactly how "client connects but no traffic flows"
 *     presents.
 *  4. BINARY FRAMES instead of JSON+Base64 (~35% less bandwidth, no per-chunk
 *     JSONObject allocation).
 *  5. CREDIT-BASED FLOW CONTROL. v1 called webSocket.send() in a tight read
 *     loop with no regard for queueSize, so a large download queued unbounded
 *     bytes in OkHttp's writer and OOM'd the phone.
 *  6. IDEMPOTENT startRelayLoopback(). v1 called stopRelayLoopback() on entry,
 *     and the UI re-invoked it on every candidate push (every 15s), which
 *     killed every in-flight connection on a 15-second cycle.
 */

package com.kotsafe.security.model.backend;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.annotation.NonNull;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.CaptureService;
import com.kotsafe.security.Log;
import com.kotsafe.security.model.BackendProvider;
import com.kotsafe.security.model.Candidate;

import java.nio.charset.StandardCharsets;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.SocketFactory;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.WebSocket;
import okhttp3.WebSocketListener;
import okio.ByteString;

public class CustomHttpProvider implements BackendProvider {

    private static final String TAG = "CustomHttpProvider";

    /** Redacts a pairing/relay token for safe logging. Shows first 4 chars + *** only. */
    private static String redactToken(String token) {
        if (token == null) return "<null>";
        if (token.length() <= 4) return "****";
        return token.substring(0, 4) + "***";
    }

    /** Binary wire format: [0]=magic [1]=opcode [2..17]=stream UUID [18..]=payload */
    private static final byte MAGIC = (byte) 0xA7;
    private static final byte OP_DATA = 0x01;
    private static final byte FLAG_PLAIN = 0x00;
    private static final byte FLAG_ENCRYPTED = 0x01;
    private static final int HEADER_LEN = 18;
    /** 64 KB relay chunk — optimal high-speed framing without TLS fragmentation */
    private static final int CHUNK = 64 * 1024;
    /** 1350 B MTU-safe chunk for Direct P2P UDP datagrams to avoid fragmentation and EMSGSIZE */
    private static final int DIRECT_UDP_CHUNK = 1350;

    /** Per-direction, per-stream credit window (32MB). Prevents artificial latency stalls. */
    private static final int FLOW_WINDOW = 32 * 1024 * 1024;
    /** Hard ceiling on bytes queued inside OkHttp for one socket (64MB). */
    private static final long WS_QUEUE_LIMIT = 64L * 1024 * 1024;

    private static final int EXIT_NODE_LOOPBACK_PORT = 8090;

    private static volatile com.kotsafe.security.p2p.TunnelCipher sTunnelCipher = null;

    public static synchronized void configureCipher(String room, String secret) {
        if (room != null && !room.isEmpty() && secret != null && secret.length() >= 32) {
            try {
                sTunnelCipher = new com.kotsafe.security.p2p.TunnelCipher(secret.getBytes(StandardCharsets.UTF_8), room);
                Log.i(TAG, "End-to-End Encryption (E2EE) activated for room=" + room);
            } catch (Exception e) {
                Log.e(TAG, "Failed to configure TunnelCipher: " + e.getMessage());
                sTunnelCipher = null;
            }
        } else {
            sTunnelCipher = null;
            Log.i(TAG, "TunnelCipher cleared (unencrypted mode)");
        }
    }

    public static com.kotsafe.security.p2p.TunnelCipher getTunnelCipher() {
        return sTunnelCipher;
    }

    public static void ensureCipherConfigured(Context context) {
        if (sTunnelCipher != null || context == null) return;
        try {
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
            String bundleUri = prefs.getString(com.kotsafe.security.p2p.GatewayPreferenceKeys.PAIRING_BUNDLE, "");
            if (!bundleUri.isEmpty()) {
                com.kotsafe.security.p2p.SecurePairingBundle bundle =
                        com.kotsafe.security.p2p.SecurePairingBundle.parse(bundleUri);
                configureCipher(bundle.room, bundle.pairingSecret);
            }
        } catch (Exception ignored) {}
    }

    // ------------------------------------------------------------ VPN protection

    /**
     * Implemented by CaptureService. MUST be installed once at app start:
     *
     *   CustomHttpProvider.setSocketProtector(s -> {
     *       CaptureService vpn = CaptureService.getInstance();
     *       return vpn == null || vpn.protect(s);
     *   });
     */
    public interface SocketProtector {
        boolean protect(Socket socket);
    }

    private static volatile SocketProtector sProtector;

    public static void setSocketProtector(SocketProtector protector) {
        sProtector = protector;
    }

    private static void protect(Socket s) {
        SocketProtector p = sProtector;
        if (p != null) {
            try { p.protect(s); } catch (Exception e) {
                Log.w(TAG, "socket protect failed: " + e.getMessage());
            }
        }
    }

    /** Makes OkHttp create protected sockets so the relay link never re-enters tun0. */
    private static final class ProtectedSocketFactory extends SocketFactory {
        @Override public Socket createSocket() throws IOException {
            Socket s = new Socket();
            protect(s);
            return s;
        }
        @Override public Socket createSocket(String host, int port) throws IOException {
            Socket s = createSocket();
            s.connect(new InetSocketAddress(host, port));
            return s;
        }
        @Override public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
            Socket s = createSocket();
            s.bind(new InetSocketAddress(localHost, localPort));
            s.connect(new InetSocketAddress(host, port));
            return s;
        }
        @Override public Socket createSocket(InetAddress host, int port) throws IOException {
            Socket s = createSocket();
            s.connect(new InetSocketAddress(host, port));
            return s;
        }
        @Override public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
            Socket s = createSocket();
            s.bind(new InetSocketAddress(localAddress, localPort));
            s.connect(new InetSocketAddress(address, port));
            return s;
        }
    }

    // ------------------------------------------------------------ stream state

    private static final class Stream {
        final String id;
        final WebSocket ws;
        final String token;
        final AtomicInteger unacked = new AtomicInteger();
        final Object credit = new Object();
        final Object writeLock = new Object();
        final Queue<byte[]> pendingWrites = new ConcurrentLinkedQueue<>();
        final AtomicBoolean isFlushing = new AtomicBoolean(false);
        volatile Socket socket;
        volatile boolean closeRequested;
        volatile boolean closed;

        Stream(String id, Socket socket, WebSocket ws, String token) {
            this.id = id; this.socket = socket; this.ws = ws; this.token = token;
        }

        void setConnectedSocket(Socket s) {
            this.socket = s;
            if (closeRequested) {
                closed = true;
                if (s != null) try { s.close(); } catch (Exception ignored) {}
                return;
            }
            flushPendingWrites();
        }

        void enqueueWrite(byte[] b, int offset, int len) {
            if (closed) return;
            byte[] chunk = Arrays.copyOfRange(b, offset, offset + len);
            pendingWrites.add(chunk);
            flushPendingWrites();
        }

        void flushPendingWrites() {
            if (closed) return;
            if (socket == null) {
                // SOCKS bridge socket is still connecting asynchronously in background thread;
                // do not flush yet and do NOT mark closed.
                return;
            }
            if (pendingWrites.isEmpty() && !closeRequested) return;
            if (!isFlushing.compareAndSet(false, true)) return;
            sRelayExecutor.execute(() -> {
                try {
                    synchronized (writeLock) {
                        if (closed) return;
                        if (socket == null) return;
                        if (!socket.isConnected() || socket.isClosed()) {
                            closed = true;
                            return;
                        }
                        try {
                            OutputStream out = socket.getOutputStream();
                            byte[] chunk;
                            int totalWritten = 0;
                            while ((chunk = pendingWrites.poll()) != null) {
                                out.write(chunk);
                                totalWritten += chunk.length;
                            }
                            out.flush();
                            if (ws != null && totalWritten > 0) {
                                // Build ack as a literal string to avoid JSONObject allocation
                                // on every 64KB data frame. Saves 2-3 GC-able objects per chunk.
                                ws.send("{\"type\":\"pipe_ack\",\"token\":\"" + token
                                        + "\",\"streamId\":\"" + id
                                        + "\",\"n\":" + totalWritten + "}");
                            }
                            if (closeRequested && pendingWrites.isEmpty()) {
                                closed = true;
                                Socket s = socket;
                                if (s != null && !s.isClosed()) {
                                    try { s.shutdownOutput(); } catch (Exception ignored) {}
                                    try { s.close(); } catch (Exception ignored) {}
                                }
                            }
                        } catch (Exception e) {
                            Log.w(TAG, "write to stream " + id + " failed: " + e.getMessage());
                            sStreams.remove(id);
                            closed = true;
                            if (ws != null) {
                                sendClose(ws, token, id);
                            }
                            Socket s = socket;
                            if (s != null) try { s.close(); } catch (Exception ignored) {}
                        }
                    }
                } finally {
                    isFlushing.set(false);
                    if (!pendingWrites.isEmpty() || (closeRequested && !closed)) {
                        flushPendingWrites();
                    }
                }
            });
        }

        /** Block the reader until the far side has drained enough of the window. */
        void acquire(int n) {
            synchronized (credit) {
                long deadline = System.currentTimeMillis() + 30_000;
                while (!closed && !closeRequested && unacked.get() >= FLOW_WINDOW) {
                    long wait = deadline - System.currentTimeMillis();
                    if (wait <= 0) break;
                    try { credit.wait(Math.min(wait, 500)); } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
            }
            unacked.addAndGet(n);
        }

        void ack(int n) {
            unacked.addAndGet(-n);
            synchronized (credit) { credit.notifyAll(); }
        }

        void markClosed() {
            closeRequested = true;
            synchronized (credit) { credit.notifyAll(); }
            flushPendingWrites();
        }
    }

    // ------------------------------------------------------------ static state

    /** One managed connection per pairing token. */
    private static final Map<String, Link> sLinks = new ConcurrentHashMap<>();
    /** All live streams on this device, host-side and client-side alike. */
    private static final Map<String, Stream> sStreams = new ConcurrentHashMap<>();

    private static final ExecutorService sRelayExecutor = Executors.newCachedThreadPool();
    private static final ScheduledExecutorService sScheduler = Executors.newSingleThreadScheduledExecutor();

    private static volatile ServerSocket sRelayServerSocket;
    private static volatile boolean sRelayServerRunning = false;
    private static volatile String sRelayToken = null;
    private static volatile int sRelayPort = 0;

    private static android.net.wifi.WifiManager.WifiLock sClientWifiLock = null;
    private static android.os.PowerManager.WakeLock sClientWakeLock = null;

    private static synchronized void acquireClientSpeedLocks(Context context) {
        if (context == null) return;
        try {
            if (sClientWakeLock == null) {
                android.os.PowerManager pm = (android.os.PowerManager) context.getSystemService(Context.POWER_SERVICE);
                if (pm != null) {
                    sClientWakeLock = pm.newWakeLock(android.os.PowerManager.PARTIAL_WAKE_LOCK, "kotsafe:p2p_client_speed_wakelock");
                    sClientWakeLock.acquire();
                }
            }
            if (sClientWifiLock == null) {
                android.net.wifi.WifiManager wm = (android.net.wifi.WifiManager) context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
                if (wm != null) {
                    int mode = (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q)
                            ? android.net.wifi.WifiManager.WIFI_MODE_FULL_LOW_LATENCY
                            : android.net.wifi.WifiManager.WIFI_MODE_FULL_HIGH_PERF;
                    sClientWifiLock = wm.createWifiLock(mode, "kotsafe:p2p_client_speed_wifilock");
                    sClientWifiLock.acquire();
                }
            }
            Log.i(TAG, "⚡ Client maximum speed locks (Low-Latency WifiLock + WakeLock) engaged");
        } catch (Exception e) {
            Log.w(TAG, "Could not acquire client speed locks: " + e.getMessage());
        }
    }

    private static synchronized void releaseClientSpeedLocks() {
        if (sClientWakeLock != null) {
            try { if (sClientWakeLock.isHeld()) sClientWakeLock.release(); } catch (Exception ignored) {}
            sClientWakeLock = null;
        }
        if (sClientWifiLock != null) {
            try { if (sClientWifiLock.isHeld()) sClientWifiLock.release(); } catch (Exception ignored) {}
            sClientWifiLock = null;
        }
        Log.i(TAG, "Client maximum speed locks released");
    }

    /**
     * Completely resets all active relay links and streams across the entire app.
     * Called when the user changes relay mode or server URL mid-connection.
     */
    public static synchronized void resetAllConnections() {
        Log.i(TAG, "resetAllConnections: cycling all P2P relay links and active streams");
        for (Map.Entry<String, Link> entry : sLinks.entrySet()) {
            Link l = entry.getValue();
            if (l != null) {
                try { l.close(); } catch (Exception ignored) {}
            }
        }
        sLinks.clear();

        for (Map.Entry<String, Stream> entry : sStreams.entrySet()) {
            Stream st = entry.getValue();
            if (st != null) {
                try { st.markClosed(); } catch (Exception ignored) {}
            }
        }
        sStreams.clear();

        try {
            com.kotsafe.security.p2p.DirectPunchCoordinator.getInstance().stop();
        } catch (Exception ignored) {}
    }

    public static void sendImmediatePing() {
        for (Map.Entry<String, Link> entry : sLinks.entrySet()) {
            Link l = entry.getValue();
            if (l != null && !l.isHost && l.ws != null) {
                try {
                    l.ws.send(new org.json.JSONObject().put("type", "ping").put("t", System.currentTimeMillis()).toString());
                } catch (Exception ignored) {}
            }
        }
    }

    // ------------------------------------------------------------ instance

    private final String mServerUrl;
    private final String mSharedSecret;
    private final OkHttpClient mHttp;

    public CustomHttpProvider(String serverUrl, String sharedSecret) {
        mServerUrl = serverUrl;
        mSharedSecret = sharedSecret;
        mHttp = new OkHttpClient.Builder()
                .socketFactory(new ProtectedSocketFactory())
                .dns(hostname -> {
                    try {
                        return okhttp3.Dns.SYSTEM.lookup(hostname);
                    } catch (UnknownHostException e) {
                        if (hostname != null && (hostname.endsWith(".trycloudflare.com") || hostname.endsWith(".kotsafe.com") || hostname.equals("kotsafe.com"))) {
                            List<InetAddress> anycast = new ArrayList<>();
                            try {
                                anycast.add(InetAddress.getByName("104.16.230.132"));
                                anycast.add(InetAddress.getByName("104.16.231.132"));
                                return anycast;
                            } catch (Exception ignored) {}
                        }
                        throw e;
                    }
                })
                .connectTimeout(15, TimeUnit.SECONDS)
                .readTimeout(0, TimeUnit.MILLISECONDS)
                .pingInterval(15, TimeUnit.SECONDS)
                .retryOnConnectionFailure(true)
                .build();
    }

    private String wsUrl() {
        String base = mServerUrl.trim();
        if (base.startsWith("http://")) base = "ws://" + base.substring(7);
        else if (base.startsWith("https://")) base = "wss://" + base.substring(8);
        else if (!base.startsWith("ws://") && !base.startsWith("wss://")) {
            if (base.contains(":8081") || base.contains(":8080") || base.contains(":8000")
                    || base.matches("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+(:[0-9]+)?.*")) {
                base = "ws://" + base;
            } else {
                base = "wss://" + base;
            }
        }
        while (base.endsWith("/")) base = base.substring(0, base.length() - 1);
        if (!base.endsWith("/ws")) base = base + "/ws";
        return base;
    }

    private String httpBase() {
        String base = mServerUrl.trim();
        if (base.startsWith("ws://")) base = "http://" + base.substring(5);
        else if (base.startsWith("wss://")) base = "https://" + base.substring(6);
        else if (!base.startsWith("http://") && !base.startsWith("https://")) {
            if (base.contains(":8081") || base.contains(":8080") || base.contains(":8000")
                    || base.matches("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+(:[0-9]+)?.*")) {
                base = "http://" + base;
            } else {
                base = "https://" + base;
            }
        }
        while (base.endsWith("/")) base = base.substring(0, base.length() - 1);
        if (base.endsWith("/ws")) base = base.substring(0, base.length() - 3);
        return base;
    }

    // ------------------------------------------------------------ Link: self-healing WS

    /**
     * A persistent, self-healing WebSocket bound to one pairing token and one
     * role. Reconnects with exponential backoff and re-announces its role every
     * time, which is what keeps the exit node reachable across Wi-Fi/LTE handoff,
     * doze wakeups and relay restarts.
     */
    private final class Link {
        final String token;
        final boolean isHost;
        final String serverUrl;
        volatile WebSocket ws;
        volatile CandidateListener listener;
        volatile List<Candidate> pendingCandidates;
        final AtomicBoolean connecting = new AtomicBoolean(false);
        final AtomicBoolean shutdown = new AtomicBoolean(false);
        volatile int backoffMs = 1000;

        Link(String token, boolean isHost) {
            this.token = token;
            this.isHost = isHost;
            this.serverUrl = mServerUrl;
        }

        void ensureConnected() {
            if (shutdown.get() || ws != null) return;
            if (!connecting.compareAndSet(false, true)) return;
            dial();
        }

        private void dial() {
            Request request = new Request.Builder()
                    .url(wsUrl())
                    .header("Authorization", "Bearer " + mSharedSecret)
                    .build();

            mHttp.newWebSocket(request, new WebSocketListener() {
                @Override
                public void onOpen(@NonNull WebSocket webSocket, @NonNull Response response) {
                    Log.i(TAG, "Relay link open (token=" + redactToken(token) + ", host=" + isHost + ")");
                    ws = webSocket;
                    connecting.set(false);
                    backoffMs = 1000;
                    if (!isHost) {
                        com.kotsafe.security.p2p.GatewayTelemetry.getInstance().setHostOnline(true);
                    }
                    announce(webSocket);
                    startPing(webSocket);
                }

                @Override
                public void onMessage(@NonNull WebSocket webSocket, @NonNull String text) {
                    handleControl(webSocket, text);
                }

                @Override
                public void onMessage(@NonNull WebSocket webSocket, @NonNull ByteString bytes) {
                    handleData(bytes);
                }

                @Override
                public void onClosed(@NonNull WebSocket webSocket, int code, @NonNull String reason) {
                    Log.i(TAG, "Relay link closed: " + code + " " + reason);
                    stopPing();
                    ws = null;
                    connecting.set(false);
                    scheduleReconnect();
                }

                @Override
                public void onFailure(@NonNull WebSocket webSocket, @NonNull Throwable t, Response response) {
                    Log.w(TAG, "Relay link failure: " + t.getMessage());
                    stopPing();
                    ws = null;
                    connecting.set(false);
                    CandidateListener l = listener;
                    if (l != null) l.onError("Relay unreachable: " + t.getMessage());
                    scheduleReconnect();
                }
            });
        }

        private java.util.concurrent.ScheduledFuture<?> pingTask;

        private void startPing(WebSocket sock) {
            stopPing();
            if (isHost) return;
            pingTask = sScheduler.scheduleAtFixedRate(() -> {
                WebSocket active = ws;
                if (active != null && !isHost) {
                    try {
                        active.send(new JSONObject().put("type", "ping").put("t", System.currentTimeMillis()).toString());
                    } catch (Exception ignored) {}
                }
            }, 3, 10, TimeUnit.SECONDS);
        }

        private void stopPing() {
            if (pingTask != null) {
                pingTask.cancel(true);
                pingTask = null;
            }
        }

        private void scheduleReconnect() {
            if (shutdown.get()) return;
            int delay = backoffMs;
            backoffMs = Math.min(backoffMs * 2, 30_000);
            sScheduler.schedule(() -> {
                if (shutdown.get()) return;
                if (connecting.compareAndSet(false, true)) dial();
            }, delay, TimeUnit.MILLISECONDS);
        }

        private void announce(WebSocket sock) {
            try {
                if (isHost) {
                    JSONObject msg = new JSONObject()
                            .put("type", "register_host")
                            .put("token", token);
                    List<Candidate> c = pendingCandidates;
                    if (c != null) msg.put("candidates", encodeCandidates(c));
                    sock.send(msg.toString());
                } else {
                    sock.send(new JSONObject().put("type", "subscribe").put("token", token).toString());
                }
            } catch (JSONException e) {
                Log.w(TAG, "announce failed: " + e.getMessage());
            }
        }

        void publish(List<Candidate> candidates) {
            pendingCandidates = candidates;
            WebSocket sock = ws;
            if (sock == null) { ensureConnected(); return; }
            try {
                sock.send(new JSONObject()
                        .put("type", "publish")
                        .put("token", token)
                        .put("candidates", encodeCandidates(candidates))
                        .toString());
            } catch (JSONException e) {
                Log.w(TAG, "publish encode failed: " + e.getMessage());
            }
        }

        void close() {
            shutdown.set(true);
            stopPing();
            WebSocket sock = ws;
            ws = null;
            if (sock != null) sock.close(1000, "closed");
        }

        void forceReconnect() {
            if (shutdown.get()) return;
            Log.i(TAG, "Link.forceReconnect: cycling WebSocket for token=" + redactToken(token));
            WebSocket oldWs = ws;
            ws = null;
            connecting.set(false);
            backoffMs = 1000;
            stopPing();
            if (oldWs != null) {
                try { oldWs.cancel(); } catch (Exception ignored) {}
            }
            for (Map.Entry<String, Stream> e : sStreams.entrySet()) {
                Stream st = e.getValue();
                if (st != null && (st.ws == null || st.ws == oldWs)) {
                    st.markClosed();
                }
            }
            sStreams.clear();
            ensureConnected();
        }

        void sendControlMessage(JSONObject obj) {
            WebSocket sock = ws;
            if (sock != null) {
                try {
                    sock.send(obj.toString());
                } catch (Exception ignored) {}
            }
        }

        private void handleHostDropped() {
            Log.w(TAG, "Personal Gateway Exit Node disconnected!");
            for (Map.Entry<String, Stream> entry : sStreams.entrySet()) {
                Stream st = entry.getValue();
                if (st != null) {
                    st.markClosed();
                }
            }
            sStreams.clear();

            CaptureService vpn = CaptureService.getInstance();
            if (vpn != null && isKillSwitchEnabled(vpn)) {
                vpn.showKillSwitchActiveNotification();
            }
        }

        // -------------------------------------------------- inbound handling

        private void handleControl(WebSocket sock, String text) {
            try {
                JSONObject msg = new JSONObject(text);
                String type = msg.optString("type");

                switch (type) {
                    case "candidates": {
                        boolean online = msg.optBoolean("hostOnline", true);
                        com.kotsafe.security.p2p.GatewayTelemetry.getInstance()
                                .setHostOnline(online);
                        List<Candidate> result = new ArrayList<>();
                        JSONArray arr = msg.optJSONArray("candidates");
                        if (arr != null) {
                            for (int i = 0; i < arr.length(); i++) {
                                JSONObject c = arr.getJSONObject(i);
                                Candidate.Type t;
                                try { t = Candidate.Type.valueOf(c.optString("type", "STUN")); }
                                catch (IllegalArgumentException ex) { t = Candidate.Type.STUN; }
                                Candidate cand = new Candidate(t, c.getString("host"), c.getInt("port"));
                                cand.discoveredAt = c.optLong("discoveredAt", System.currentTimeMillis());
                                result.add(cand);
                                if (!this.isHost && (t == Candidate.Type.STUN || t == Candidate.Type.UPNP_PUBLIC)) {
                                    com.kotsafe.security.p2p.GatewayTelemetry.getInstance().setExitNodeIp(c.getString("host"));
                                }
                            }
                        }
                        CandidateListener l = listener;
                        if (l != null) {
                            l.onCandidatesUpdated(result);
                        }
                        if (!this.isHost && !result.isEmpty()) {
                            attemptDirectPunch(result);
                        }
                        return;
                    }

                    case "pong": {
                        long sentTime = msg.optLong("t", 0);
                        if (sentTime > 0) {
                            int rtt = (int) (System.currentTimeMillis() - sentTime);
                            com.kotsafe.security.p2p.GatewayTelemetry.getInstance().setLatencyMs(rtt);
                        }
                        return;
                    }

                    case "ping": {
                        long t = msg.optLong("t", 0);
                        try {
                            sock.send(new JSONObject().put("type", "pong").put("t", t).toString());
                        } catch (Exception ignored) {}
                        return;
                    }

                    case "host_status": {
                        boolean online = msg.optBoolean("online", false);
                        Log.i(TAG, "Relay host status: online=" + online);
                        com.kotsafe.security.p2p.GatewayTelemetry.getInstance().setHostOnline(online);
                        if (!online) {
                            handleHostDropped();
                        } else {
                            CaptureService vpn = CaptureService.getInstance();
                            if (vpn != null) vpn.restoreStatusNotification();
                        }
                        return;
                    }

                    case "telemetry": {
                        int battery = msg.optInt("battery", -1);
                        boolean charging = msg.optBoolean("charging", false);
                        String plug = msg.optString("plug", "");
                        String ssid = msg.optString("ssid", "");
                        int signal = msg.optInt("signal", -100);
                        int streams = msg.optInt("streams", 0);
                        long uptime = msg.optLong("uptime", 0);
                        String netType = msg.optString("networkType", "");
                        String carrier = msg.optString("carrier", "");
                        String exitIp = msg.optString("exitIp", "");
                        if (!exitIp.isEmpty() && exitIp.matches("^[0-9a-fA-F:.]+$")) {
                            com.kotsafe.security.p2p.GatewayTelemetry.getInstance().setExitNodeIp(exitIp);
                        }
                        com.kotsafe.security.p2p.GatewayTelemetry.getInstance().update(
                                battery, charging, plug, ssid, signal, streams, uptime, netType, carrier
                        );
                        return;
                    }

                    case "pipe_open": {
                        // Host side only: bridge this stream into the local SOCKS5 exit node.
                        String streamId = msg.optString("streamId");
                        if (streamId.isEmpty() || sStreams.containsKey(streamId)) return;
                        openHostStream(sock, token, streamId);
                        return;
                    }

                    case "pipe_ack": {
                        com.kotsafe.security.p2p.GatewayTelemetry.getInstance().setHostOnline(true);
                        Stream st = sStreams.get(msg.optString("streamId"));
                        if (st != null) st.ack(msg.optInt("n", 0));
                        return;
                    }

                    case "pipe_reject": {
                        String streamId = msg.optString("streamId");
                        Log.w(TAG, "Relay rejected stream " + streamId + ": " + msg.optString("reason"));
                        Stream st = sStreams.remove(streamId);
                        if (st != null) st.markClosed();
                        CandidateListener l = listener;
                        if ("no_host_online".equals(msg.optString("reason"))) {
                            com.kotsafe.security.p2p.GatewayTelemetry.getInstance().setHostOnline(false);
                            handleHostDropped();
                            if (l != null) l.onError("Exit Node device is offline — open KotSafe on the host phone.");
                        }
                        return;
                    }

                    case "pipe_close": {
                        Stream st = sStreams.remove(msg.optString("streamId"));
                        if (st != null) st.markClosed();
                        return;
                    }

                    case "error": {
                        String errMsg = msg.optString("message", "unknown_error");
                        Log.w(TAG, "Relay error: " + errMsg);
                        if ("unknown_or_expired_token".equals(errMsg)) {
                            com.kotsafe.security.p2p.TunnelCipher cipher = sTunnelCipher;
                            if (cipher != null && cipher.getRoom() != null && !cipher.getRoom().isEmpty()) {
                                String roomToken = (this.isHost ? "host_" : "client_") + cipher.getRoom();
                                if (!token.equals(roomToken)) {
                                    Log.i(TAG, "Self-healing: Reconnecting relay with room token: " + redactToken(roomToken));
                                    sScheduler.schedule(() -> {
                                        link(roomToken, this.isHost, listener);
                                    }, 300, TimeUnit.MILLISECONDS);
                                    return;
                                }
                            }
                        }
                        if (!"unknown_message_type".equals(errMsg)) {
                            CandidateListener l = listener;
                            if (l != null) l.onError(errMsg);
                        }
                        return;
                    }

                    case "client_status": {
                        boolean online = msg.optBoolean("online", false);
                        Log.i(TAG, "Relay client status update: online=" + online);
                        com.kotsafe.security.model.P2PExitNodeServer.getInstance().setClientPairedOnline(online);
                        return;
                    }

                    default:
                        // host_registered and anything else: nothing to do
                }
            } catch (JSONException e) {
                Log.w(TAG, "Malformed control message: " + e.getMessage());
            }
        }

        private void handleData(ByteString bytes) {
            if (bytes.size() < HEADER_LEN) return;
            com.kotsafe.security.p2p.GatewayTelemetry.getInstance().setHostOnline(true);
            com.kotsafe.security.p2p.GatewayTelemetry.getInstance().recordBytes(bytes.size(), 0);
            byte[] b = bytes.toByteArray();
            if (b[0] != MAGIC || b[1] != OP_DATA) return;
            String streamId = decodeStreamId(b);
            Stream st = sStreams.get(streamId);
            if (st == null || st.closed) return;

            if (b.length <= HEADER_LEN) return;

            byte flag = b[HEADER_LEN];
            if (flag == FLAG_ENCRYPTED) {
                com.kotsafe.security.p2p.TunnelCipher cipher = sTunnelCipher;
                if (cipher != null) {
                    String peerDirection = this.isHost ? com.kotsafe.security.p2p.TunnelCipher.CLIENT_TO_EXIT : com.kotsafe.security.p2p.TunnelCipher.EXIT_TO_CLIENT;
                    try {
                        int cipherLen = b.length - (HEADER_LEN + 1);
                        byte[] plaintext = cipher.openBytes(streamId, peerDirection, b, HEADER_LEN + 1, cipherLen);
                        if (plaintext != null) {
                            st.enqueueWrite(plaintext, 0, plaintext.length);
                        }
                    } catch (Exception e) {
                        Log.e(TAG, "Failed to decrypt E2EE frame on stream " + streamId + ": " + e.getMessage());
                        st.markClosed();
                        sStreams.remove(streamId);
                        sendClose(this.ws, this.token, streamId);
                    }
                } else {
                    Log.e(TAG, "Received encrypted E2EE frame on stream " + streamId + " but no TunnelCipher configured!");
                }
            } else if (flag == FLAG_PLAIN) {
                final int len = b.length - (HEADER_LEN + 1);
                st.enqueueWrite(b, HEADER_LEN + 1, len);
            } else {
                final int len = b.length - HEADER_LEN;
                st.enqueueWrite(b, HEADER_LEN, len);
            }
        }
    }

    // ------------------------------------------------------------ framing helpers

    private static JSONArray encodeCandidates(List<Candidate> candidates) throws JSONException {
        JSONArray arr = new JSONArray();
        for (Candidate c : new ArrayList<>(candidates)) {   // defensive copy: caller mutates
            arr.put(new JSONObject()
                    .put("type", c.type.name())
                    .put("host", c.host)
                    .put("port", c.port)
                    .put("discoveredAt", c.discoveredAt));
        }
        return arr;
    }

    private static byte[] frame(String streamId, byte[] buf, int len, boolean isHost) {
        com.kotsafe.security.p2p.TunnelCipher cipher = sTunnelCipher;
        if (cipher != null) {
            String direction = isHost ? com.kotsafe.security.p2p.TunnelCipher.EXIT_TO_CLIENT : com.kotsafe.security.p2p.TunnelCipher.CLIENT_TO_EXIT;
            try {
                byte[] ciphertext = cipher.sealBytes(streamId, direction, buf, 0, len);
                byte[] out = new byte[HEADER_LEN + 1 + ciphertext.length];
                out[0] = MAGIC;
                out[1] = OP_DATA;
                UUID u = UUID.fromString(streamId);
                ByteBuffer bb = ByteBuffer.wrap(out, 2, 16);
                bb.putLong(u.getMostSignificantBits());
                bb.putLong(u.getLeastSignificantBits());
                out[HEADER_LEN] = FLAG_ENCRYPTED;
                System.arraycopy(ciphertext, 0, out, HEADER_LEN + 1, ciphertext.length);
                return out;
            } catch (Exception e) {
                Log.e(TAG, "Cipher seal failed: " + e.getMessage());
            }
        }

        byte[] out = new byte[HEADER_LEN + 1 + len];
        out[0] = MAGIC;
        out[1] = OP_DATA;
        UUID u = UUID.fromString(streamId);
        ByteBuffer bb = ByteBuffer.wrap(out, 2, 16);
        bb.putLong(u.getMostSignificantBits());
        bb.putLong(u.getLeastSignificantBits());
        out[HEADER_LEN] = FLAG_PLAIN;
        System.arraycopy(buf, 0, out, HEADER_LEN + 1, len);
        return out;
    }

    private static String decodeStreamId(byte[] b) {
        ByteBuffer bb = ByteBuffer.wrap(b, 2, 16);
        return new UUID(bb.getLong(), bb.getLong()).toString();
    }

    private static void sendClose(WebSocket ws, String token, String streamId) {
        if (ws == null) return;
        try {
            ws.send(new JSONObject()
                    .put("type", "pipe_close")
                    .put("token", token)
                    .put("streamId", streamId)
                    .toString());
        } catch (Exception ignored) {}
    }

    /**
     * Pumps one socket into the relay with credit-based flow control.
     * Shared by both directions: host->relay and client->relay.
     */
    private static void pumpToRelay(Stream st, boolean isHost) {
        byte[] buf = new byte[CHUNK];
        try {
            while (!st.closed && st.socket == null) {
                try { Thread.sleep(20); } catch (InterruptedException e) { Thread.currentThread().interrupt(); return; }
            }
            if (st.closed || st.socket == null) return;
            try (InputStream in = st.socket.getInputStream()) {
                int read;
                while (!st.closed && (read = in.read(buf)) != -1) {
                    if (read == 0) continue;
                    st.acquire(read);
                    WebSocket sock = st.ws;
                    if (sock == null) break;
                    // Secondary guard: never let OkHttp's writer queue run away.
                    int spins = 0;
                    while (sock.queueSize() > WS_QUEUE_LIMIT && !st.closed && spins++ < 600) {
                        try { Thread.sleep(50); } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            return;
                        }
                    }
                    if (st.closed) break;
                    byte[] packet = frame(st.id, buf, read, isHost);
                    if (!sock.send(ByteString.of(packet, 0, packet.length))) break;
                    com.kotsafe.security.p2p.GatewayTelemetry.getInstance().recordBytes(0, read);
                }
            }
        } catch (Exception ignored) {
        } finally {
            sStreams.remove(st.id);
            com.kotsafe.security.p2p.TunnelCipher c = sTunnelCipher;
            if (c != null) c.closeStream(st.id);
            sendClose(st.ws, st.token, st.id);
            st.markClosed();
        }
    }

    /** Host side: a remote client opened a stream — wire it to the local SOCKS5 engine. */
    private static void openHostStream(WebSocket ws, String token, String streamId) {
        Stream st = new Stream(streamId, null, ws, token);
        sStreams.put(streamId, st);

        sRelayExecutor.execute(() -> {
            Socket exitNode = null;
            try {
                exitNode = new Socket();
                exitNode.setTcpNoDelay(true);
                exitNode.setKeepAlive(true);
                try {
                    exitNode.setSendBufferSize(1024 * 1024);
                    exitNode.setReceiveBufferSize(1024 * 1024);
                } catch (Exception ignored) {}
                int hostPort = EXIT_NODE_LOOPBACK_PORT;
                try {
                    com.kotsafe.security.model.P2PExitNodeServer srv = com.kotsafe.security.model.P2PExitNodeServer.getInstance();
                    if (srv != null && srv.isRunning() && srv.getPort() > 0) {
                        hostPort = srv.getPort();
                    }
                } catch (Throwable ignored) {}
                exitNode.connect(new InetSocketAddress("127.0.0.1", hostPort), 5000);

                st.setConnectedSocket(exitNode);
                Log.i(TAG, "Host bridged stream " + streamId + " -> 127.0.0.1:" + hostPort);
                st.flushPendingWrites();
                pumpToRelay(st, true);
            } catch (Exception e) {
                Log.w(TAG, "Host could not reach local exit node: " + e.getMessage());
                sStreams.remove(streamId);
                st.markClosed();
                sendClose(ws, token, streamId);
                if (exitNode != null) try { exitNode.close(); } catch (Exception ignored) {}
            }
        });
    }

    private static void attemptDirectPunch(List<Candidate> candidates) {
        Context ctx = (CaptureService.getInstance() != null)
                ? CaptureService.getInstance().getApplicationContext()
                : com.kotsafe.security.KotSafe.getInstance();
        if (ctx == null) return;
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ctx);
        String transportMode = prefs.getString(com.kotsafe.security.p2p.GatewayPreferenceKeys.TRANSPORT_MODE, "automatic");
        if ("relay_only".equalsIgnoreCase(transportMode)) {
            Log.i(TAG, "Transport mode is RELAY_ONLY; skipping direct STUN hole punch");
            return;
        }

        String bundleUri = prefs.getString(com.kotsafe.security.p2p.GatewayPreferenceKeys.PAIRING_BUNDLE, "");
        if (bundleUri.isEmpty()) return;
        try {
            com.kotsafe.security.p2p.SecurePairingBundle bundle =
                    com.kotsafe.security.p2p.SecurePairingBundle.parse(bundleUri);

            com.kotsafe.security.p2p.DirectPunchCoordinator.getInstance().startClientPunch(
                    candidates,
                    bundle.room,
                    bundle.pairingSecret,
                    new com.kotsafe.security.p2p.DirectPunchCoordinator.DirectPathListener() {
                        @Override
                        public void onDirectPathEstablished(InetSocketAddress remotePeerAddress) {
                            Log.i(TAG, "⚡ Direct UDP link established with Exit Node at " + remotePeerAddress);
                            com.kotsafe.security.p2p.GatewayTelemetry.getInstance().setDirectP2PActive(true);
                        }

                        @Override
                        public void onDirectPathLost(String reason) {
                            Log.w(TAG, "Direct UDP link lost (" + reason + "), falling back to VPS relay");
                            com.kotsafe.security.p2p.GatewayTelemetry.getInstance().setDirectP2PActive(false);
                        }

                        @Override
                        public void onDirectDataReceived(String streamId, byte[] encryptedData) {
                            handleDirectIncomingData(streamId, encryptedData, false);
                        }
                    }
            );
        } catch (Exception e) {
            Log.w(TAG, "Failed to start client punch: " + e.getMessage());
        }
    }

    public static void handleDirectIncomingData(String streamId, byte[] encryptedData, boolean isHost) {
        com.kotsafe.security.p2p.TunnelCipher cipher = sTunnelCipher;
        if (cipher == null) return;
        String peerDirection = isHost ? com.kotsafe.security.p2p.TunnelCipher.CLIENT_TO_EXIT : com.kotsafe.security.p2p.TunnelCipher.EXIT_TO_CLIENT;
        try {
            byte[] plaintext = cipher.openBytes(streamId, peerDirection, encryptedData, 0, encryptedData.length);
            Stream st = sStreams.get(streamId);
            if (plaintext == null || plaintext.length == 0) {
                // Stream close / FIN from peer
                if (st != null) {
                    st.markClosed();
                    sStreams.remove(streamId);
                }
                return;
            }
            if (st == null && isHost) {
                openHostStreamDirect(streamId, plaintext);
            } else if (st != null && !st.closed) {
                st.enqueueWrite(plaintext, 0, plaintext.length);
            }
        } catch (Exception e) {
            Log.w(TAG, "Direct decrypt failed for stream " + streamId + ": " + e.getMessage());
        }
    }

    private static void openHostStreamDirect(String streamId, byte[] initialPlaintext) {
        Stream st = new Stream(streamId, null, null, null);
        sStreams.put(streamId, st);
        if (initialPlaintext != null && initialPlaintext.length > 0) {
            st.enqueueWrite(initialPlaintext, 0, initialPlaintext.length);
        }
        sRelayExecutor.execute(() -> {
            Socket exitNode = null;
            try {
                exitNode = new Socket();
                exitNode.setTcpNoDelay(true);
                int hostPort = EXIT_NODE_LOOPBACK_PORT;
                com.kotsafe.security.model.P2PExitNodeServer srv = com.kotsafe.security.model.P2PExitNodeServer.getInstance();
                if (srv != null && srv.isRunning() && srv.getPort() > 0) {
                    hostPort = srv.getPort();
                }
                exitNode.connect(new InetSocketAddress("127.0.0.1", hostPort), 5000);
                st.setConnectedSocket(exitNode);
                st.flushPendingWrites();
                pumpToDirectUdp(st, true);
            } catch (Exception e) {
                Log.w(TAG, "Direct host bridge failed: " + e.getMessage());
                sStreams.remove(streamId);
                st.markClosed();
                if (exitNode != null) try { exitNode.close(); } catch (Exception ignored) {}
            }
        });
    }

    private static void pumpToDirectUdp(Stream st, boolean isHost) {
        byte[] buf = new byte[DIRECT_UDP_CHUNK];
        com.kotsafe.security.p2p.TunnelCipher cipher = sTunnelCipher;
        String direction = isHost ? com.kotsafe.security.p2p.TunnelCipher.EXIT_TO_CLIENT : com.kotsafe.security.p2p.TunnelCipher.CLIENT_TO_EXIT;

        try {
            Socket s = st.socket;
            if (s == null) return;
            InputStream in = s.getInputStream();
            while (!st.closed && com.kotsafe.security.p2p.DirectPunchCoordinator.getInstance().isDirectReady()) {
                int n = in.read(buf);
                if (n < 0) break;
                if (n == 0) continue;

                if (cipher != null) {
                    byte[] ciphertext = cipher.sealBytes(st.id, direction, buf, 0, n);
                    boolean sent = com.kotsafe.security.p2p.DirectPunchCoordinator.getInstance().sendDirectData(st.id, ciphertext);
                    if (!sent) {
                        Log.w(TAG, "Direct UDP send failed, breaking direct loop");
                        break;
                    }
                }
            }
            // Signal FIN / EOF to peer
            if (cipher != null && com.kotsafe.security.p2p.DirectPunchCoordinator.getInstance().isDirectReady()) {
                byte[] finCiphertext = cipher.sealBytes(st.id, direction, new byte[0], 0, 0);
                com.kotsafe.security.p2p.DirectPunchCoordinator.getInstance().sendDirectData(st.id, finCiphertext);
            }
        } catch (Exception e) {
            Log.d(TAG, "pumpToDirectUdp finished for stream " + st.id + ": " + e.getMessage());
        } finally {
            if (!st.closed) {
                st.markClosed();
                sStreams.remove(st.id);
            }
        }
    }

    private synchronized Link link(String token, boolean isHost, CandidateListener listener) {
        Link l = sLinks.get(token);
        if (l == null || l.isHost != isHost || (l.serverUrl != null && !l.serverUrl.equals(mServerUrl))) {
            if (l != null) { l.close(); sLinks.remove(token); }
            l = new Link(token, isHost);
            sLinks.put(token, l);
        }
        if (listener != null) l.listener = listener;
        l.ensureConnected();
        return l;
    }

    // ------------------------------------------------------------ BackendProvider

    @Override
    public void createPairing(String deviceId, PairingCallback callback) {
        createPairingBundle(deviceId, new PairingBundleCallback() {
            @Override
            public void onSuccess(String exitToken, com.kotsafe.security.p2p.SecurePairingBundle bundle) {
                callback.onPairingCreated(exitToken, System.currentTimeMillis() + 5 * 60 * 1000);
            }

            @Override
            public void onError(String message) {
                // Fallback to legacy /pairing if v1 endpoint is running
                Request request = new Request.Builder()
                        .url(httpBase() + "/pairing")
                        .header("Authorization", "Bearer " + mSharedSecret)
                        .post(RequestBody.create(new byte[0]))
                        .build();

                mHttp.newCall(request).enqueue(new Callback() {
                    @Override public void onFailure(@NonNull Call call, @NonNull IOException e) {
                        callback.onError("Unreachable: " + e.getMessage());
                    }
                    @Override public void onResponse(@NonNull Call call, @NonNull Response response) {
                        try (Response r = response) {
                            if (!r.isSuccessful() || r.body() == null) { callback.onError("HTTP " + r.code()); return; }
                            JSONObject json = new JSONObject(r.body().string());
                            callback.onPairingCreated(json.getString("token"), json.getLong("expiresAt"));
                        } catch (Exception e) {
                            callback.onError("Malformed response: " + e.getMessage());
                        }
                    }
                });
            }
        });
    }

    @Override
    public void createPairingBundle(String deviceId, PairingBundleCallback callback) {
        JSONObject body = new JSONObject();
        try {
            body.put("exitDeviceId", deviceId);
        } catch (JSONException ignored) {}

        Request.Builder rb = new Request.Builder()
                .url(httpBase() + "/v1/pairings")
                .post(RequestBody.create(body.toString(), okhttp3.MediaType.parse("application/json; charset=utf-8")));
        if (mSharedSecret != null && !mSharedSecret.isEmpty()) {
            rb.header("Authorization", "Bearer " + mSharedSecret);
        }

        mHttp.newCall(rb.build()).enqueue(new Callback() {
            @Override public void onFailure(@NonNull Call call, @NonNull IOException e) {
                Log.w(TAG, "Relay control server unreachable (" + e.getMessage() + "); generating standalone pairing bundle");
                String room = "room_" + com.kotsafe.security.Utils.genRandomString(20);
                String secret = com.kotsafe.security.Utils.genRandomString(48);
                String exitToken = "token_" + com.kotsafe.security.Utils.genRandomString(24);
                com.kotsafe.security.p2p.SecurePairingBundle fallback =
                        new com.kotsafe.security.p2p.SecurePairingBundle(room, secret, httpBase());
                configureCipher(room, secret);
                callback.onSuccess(exitToken, fallback);
            }
            @Override public void onResponse(@NonNull Call call, @NonNull Response response) {
                try (Response r = response) {
                    if (!r.isSuccessful() || r.body() == null) {
                        Log.w(TAG, "Relay returned HTTP " + r.code() + "; falling back to local pairing bundle");
                        String room = "room_" + com.kotsafe.security.Utils.genRandomString(20);
                        String secret = com.kotsafe.security.Utils.genRandomString(48);
                        String exitToken = "token_" + com.kotsafe.security.Utils.genRandomString(24);
                        com.kotsafe.security.p2p.SecurePairingBundle fallback =
                                new com.kotsafe.security.p2p.SecurePairingBundle(room, secret, httpBase());
                        configureCipher(room, secret);
                        callback.onSuccess(exitToken, fallback);
                        return;
                    }
                    JSONObject json = new JSONObject(r.body().string());
                    String room = json.optString("room", "");
                    String secret = json.optString("pairingSecret", "");
                    String exitToken = (room != null && !room.isEmpty()) ? ("host_" + room) : json.optString("exitToken", "");
                    JSONObject qr = json.optJSONObject("qr");
                    String controlUrl = httpBase();
                    if (controlUrl == null || controlUrl.isEmpty()) {
                        controlUrl = qr != null ? qr.optString("controlUrl", "") : "";
                    }

                    com.kotsafe.security.p2p.SecurePairingBundle bundle =
                            new com.kotsafe.security.p2p.SecurePairingBundle(room, secret, controlUrl);
                    configureCipher(room, secret);
                    callback.onSuccess(exitToken, bundle);
                } catch (Exception e) {
                    callback.onError("Malformed pairing response: " + e.getMessage());
                }
            }
        });
    }

    @Override
    public void claimPairing(com.kotsafe.security.p2p.SecurePairingBundle bundle, String clientDeviceId, ClaimCallback callback) {
        JSONObject body = new JSONObject();
        try {
            body.put("clientDeviceId", clientDeviceId);
            body.put("pairingSecret", bundle.pairingSecret);
        } catch (JSONException ignored) {}

        String url = bundle.controlUrl;
        while (url.endsWith("/")) url = url.substring(0, url.length() - 1);
        url = url + "/v1/pairings/" + bundle.room + "/claim";

        Request request = new Request.Builder()
                .url(url)
                .post(RequestBody.create(body.toString(), okhttp3.MediaType.parse("application/json; charset=utf-8")))
                .build();

        mHttp.newCall(request).enqueue(new Callback() {
            @Override public void onFailure(@NonNull Call call, @NonNull IOException e) {
                Log.w(TAG, "Relay claim endpoint unreachable (" + e.getMessage() + "); falling back to direct pairing token");
                configureCipher(bundle.room, bundle.pairingSecret);
                callback.onSuccess("client_" + bundle.room, 86400);
            }
            @Override public void onResponse(@NonNull Call call, @NonNull Response response) {
                try (Response r = response) {
                    if (!r.isSuccessful() || r.body() == null) {
                        Log.w(TAG, "Relay claim returned HTTP " + r.code() + "; falling back to direct pairing token");
                        configureCipher(bundle.room, bundle.pairingSecret);
                        callback.onSuccess("client_" + bundle.room, 86400);
                        return;
                    }
                    JSONObject json = new JSONObject(r.body().string());
                    String clientToken = (bundle.room != null && !bundle.room.isEmpty()) ? ("client_" + bundle.room) : json.optString("clientToken", "");
                    long expiresIn = json.optLong("expiresInSeconds", 86400);
                    configureCipher(bundle.room, bundle.pairingSecret);
                    callback.onSuccess(clientToken, expiresIn);
                } catch (Exception e) {
                    callback.onError("Pairing claim failed: " + e.getMessage());
                }
            }
        });
    }

    @Override
    public void publishCandidates(String pairingToken, List<Candidate> candidates) {
        link(pairingToken, true, null).publish(new ArrayList<>(candidates));
    }

    @Override
    public void subscribeToCandidates(String pairingToken, CandidateListener listener) {
        link(pairingToken, false, listener);
    }

    @Override
    public void unsubscribe(String pairingToken) {
        Link l = sLinks.remove(pairingToken);
        if (l != null) l.close();
    }

    @Override
    public void revokePairing(String pairingToken, RevokeCallback callback) {
        Request request = new Request.Builder()
                .url(httpBase() + "/pairing/" + pairingToken)
                .header("Authorization", "Bearer " + mSharedSecret)
                .delete()
                .build();
        mHttp.newCall(request).enqueue(new Callback() {
            @Override public void onFailure(@NonNull Call call, @NonNull IOException e) { callback.onResult(false); }
            @Override public void onResponse(@NonNull Call call, @NonNull Response response) {
                try (Response r = response) { callback.onResult(r.isSuccessful()); }
            }
        });
        unsubscribe(pairingToken);
    }

    @Override
    public void sendTelemetry(String pairingToken, JSONObject telemetry) {
        if (pairingToken == null || telemetry == null) return;
        Link l = link(pairingToken, true, null);
        l.sendControlMessage(telemetry);
    }

    @Override
    public Candidate getRelayCandidate() {
        String host = httpBase().replaceFirst("^https?://", "").replaceFirst("/.*$", "");
        if (host.isEmpty()) return null;
        // The relay path is the multiplexed WebSocket, not coturn. Port is nominal —
        // the client reaches it via startRelayLoopback(), not by dialling this directly.
        return new Candidate(Candidate.Type.RELAY, host, 0);
    }

    @Override
    public void testConnection(ConnectionTestCallback callback) {
        Request request = new Request.Builder().url(httpBase() + "/health").get().build();
        mHttp.newCall(request).enqueue(new Callback() {
            @Override public void onFailure(@NonNull Call call, @NonNull IOException e) {
                callback.onResult(false, "Unreachable: " + e.getMessage());
            }
            @Override public void onResponse(@NonNull Call call, @NonNull Response response) {
                try (Response r = response) {
                    callback.onResult(r.isSuccessful(), r.isSuccessful() ? "OK" : "HTTP " + r.code());
                }
            }
        });
    }

    // ------------------------------------------------------------ client loopback

    /**
     * Starts (or reuses) the local SOCKS5 loopback that tunnels to the exit node
     * over the relay.
     *
     * IMPORTANT: pairingToken here must be Prefs.PREF_P2P_BACKEND_PAIRING — the
     * BACKEND pairing token. Passing the SOCKS5 auth token (as v1 did) makes every
     * pipe_* message fail server-side with unknown_token_for_pipe while the UI
     * still reports success.
     *
     * Idempotent: calling it again with the same token and port is a no-op, so
     * repeated candidate pushes no longer tear down live connections.
     */
    @Override
    public synchronized int startRelayLoopback(String pairingToken, int localPort) {
        if (pairingToken == null || pairingToken.isEmpty()) {
            Log.e(TAG, "startRelayLoopback called with empty pairing token — refusing");
            return 0;
        }

        if (sTunnelCipher == null) {
            com.kotsafe.security.CaptureService vpn = com.kotsafe.security.CaptureService.getInstance();
            if (vpn != null) ensureCipherConfigured(vpn);
        }

        if (sRelayServerRunning && sRelayServerSocket != null && !sRelayServerSocket.isClosed()
                && sRelayPort == localPort) {
            sRelayToken = pairingToken;
            link(pairingToken, false, null);
            Log.i(TAG, "Relay loopback updated with active pairing: " + redactToken(pairingToken));
            return sRelayPort;
        }

        stopRelayLoopback();

        try {
            ServerSocket srv = null;
            for (int i = 0; i < 5; i++) {
                try {
                    srv = new ServerSocket();
                    srv.setReuseAddress(true);
                    srv.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), localPort), 128);
                    break;
                } catch (Exception e) {
                    if (srv != null) {
                        try { srv.close(); } catch (Exception ignored) {}
                        srv = null;
                    }
                    if (i == 4) throw e;
                    try { Thread.sleep(400); } catch (InterruptedException ignored) {}
                }
            }
            sRelayServerSocket = srv;
            sRelayServerRunning = true;
            sRelayToken = pairingToken;
            sRelayPort = srv.getLocalPort();

            link(pairingToken, false, null);

            Context appCtx = (com.kotsafe.security.CaptureService.getInstance() != null)
                    ? com.kotsafe.security.CaptureService.getInstance().getApplicationContext()
                    : com.kotsafe.security.KotSafe.getInstance();
            acquireClientSpeedLocks(appCtx);

            sRelayExecutor.execute(() -> {
                while (sRelayServerRunning) {
                    ServerSocket current = sRelayServerSocket;
                    if (current == null || current.isClosed()) break;
                    try {
                        Socket clientSock = current.accept();
                        clientSock.setTcpNoDelay(true);
                        clientSock.setKeepAlive(true);
                        try {
                            clientSock.setSendBufferSize(1024 * 1024);
                            clientSock.setReceiveBufferSize(1024 * 1024);
                        } catch (Exception ignored) {}
                        String currentToken = sRelayToken;
                        if (currentToken != null) {
                            Link activeLink = link(currentToken, false, null);
                            handleLocalConnection(activeLink, currentToken, clientSock);
                        } else {
                            clientSock.close();
                        }
                    } catch (Exception e) {
                        if (!sRelayServerRunning) break;
                    }
                }
            });

            Log.i(TAG, "Relay loopback listening on 127.0.0.1:" + sRelayPort + " (pairing " + redactToken(pairingToken) + ")");
            return sRelayPort;
        } catch (Exception e) {
            Log.e(TAG, "Failed to start relay loopback: " + e.getMessage());
            sRelayServerRunning = false;
            return 0;
        }
    }

    public static boolean isKillSwitchEnabled(Context context) {
        if (context == null) {
            CaptureService vpn = CaptureService.getInstance();
            if (vpn != null) context = vpn.getApplicationContext();
        }
        if (context == null) return false;
        try {
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
            return prefs.getBoolean(com.kotsafe.security.p2p.GatewayPreferenceKeys.KILL_SWITCH,
                    prefs.getBoolean(com.kotsafe.security.model.Prefs.PREF_PERSONAL_GATEWAY_KILL_SWITCH, true));
        } catch (Exception ignored) {
            return false;
        }
    }

    private void handleLocalConnection(Link clientLink, String pairingToken, Socket clientSock) {
        sRelayExecutor.execute(() -> {
            try {
                if (clientLink.ws == null) {
                    clientLink.ensureConnected();
                    for (int i = 0; i < 60 && clientLink.ws == null && sRelayServerRunning; i++) {
                        try {
                            Thread.sleep(100);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            try { clientSock.close(); } catch (Exception ignored) {}
                            return;
                        }
                    }
                }

                WebSocket sock = clientLink.ws;
                if (sock == null) {
                    Log.w(TAG, "Relay link could not connect; dropping client connection");
                    try { clientSock.close(); } catch (Exception ignored) {}
                    return;
                }

                if (isKillSwitchEnabled(null) && !com.kotsafe.security.p2p.GatewayTelemetry.getInstance().isHostReachableOrGrace()) {
                    Log.w(TAG, "Kill Switch active: Exit Node is confirmed offline, blocking local traffic to prevent leak.");
                    try { clientSock.close(); } catch (Exception ignored) {}
                    return;
                }

                String streamId = UUID.randomUUID().toString();
                beginClientStream(sock, pairingToken, streamId, clientSock);
            } catch (Exception e) {
                Log.w(TAG, "handleLocalConnection error: " + e.getMessage());
                try { clientSock.close(); } catch (Exception ignored) {}
            }
        });
    }

    @Override
    public void reconnectTunnel(String pairingToken) {
        if (pairingToken == null || pairingToken.isEmpty()) return;
        Link l = sLinks.get(pairingToken);
        if (l != null) {
            Log.i(TAG, "Force-reconnecting relay link for token=" + redactToken(pairingToken));
            l.forceReconnect();
        }
        com.kotsafe.security.p2p.DirectPunchCoordinator.getInstance().stop();
    }

    private void beginClientStream(WebSocket sock, String pairingToken, String streamId, Socket clientSock) {
        try {
            Stream st = new Stream(streamId, clientSock, sock, pairingToken);
            sStreams.put(streamId, st);

            if (com.kotsafe.security.p2p.DirectPunchCoordinator.getInstance().isDirectReady()) {
                Log.i(TAG, "⚡ Routing stream " + streamId + " directly over P2P UDP (VPS Bypassed)");
                sRelayExecutor.execute(() -> pumpToDirectUdp(st, false));
            } else {
                sock.send(new JSONObject()
                        .put("type", "pipe_open")
                        .put("token", pairingToken)
                        .put("streamId", streamId)
                        .toString());
                sRelayExecutor.execute(() -> pumpToRelay(st, false));
            }
        } catch (Exception e) {
            Log.w(TAG, "pipe_open failed: " + e.getMessage());
            sStreams.remove(streamId);
            try { clientSock.close(); } catch (Exception ignored) {}
        }
    }

    @Override
    public synchronized void stopRelayLoopback() {
        sRelayServerRunning = false;
        sRelayToken = null;
        sRelayPort = 0;
        ServerSocket srv = sRelayServerSocket;
        sRelayServerSocket = null;
        if (srv != null) try { srv.close(); } catch (Exception ignored) {}

        com.kotsafe.security.p2p.DirectPunchCoordinator.getInstance().stop();
        releaseClientSpeedLocks();

        for (Map.Entry<String, Stream> e : sStreams.entrySet()) {
            e.getValue().markClosed();
        }
        sStreams.clear();
    }
}
