/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * InboundScanDetector
 * ===================
 * Detects someone scanning your device for open ports or probing it for
 * vulnerabilities, on the local network or from the internet.
 *
 * WHY THIS COULD NOT BE BUILT ON TOP OF CaptureService
 *
 *   The current architecture has no inbound detection at all, and that is not
 *   an oversight that can be patched inside the VPN — it is a property of
 *   VpnService.
 *
 *   tun0 receives packets that the device's own apps SEND, plus the replies to
 *   those packets. An unsolicited inbound SYN from a stranger scanning your
 *   phone is delivered by the kernel to whatever socket is listening on that
 *   port — or answered with a RST if nothing is listening. It never traverses
 *   tun0, so CaptureService cannot see it. No amount of work in capture_vpn.c
 *   changes that.
 *
 *   Reading raw inbound packets would need CAP_NET_RAW, which an unprivileged
 *   Android app does not have.
 *
 *   What an app CAN do is bind listening sockets itself. If a stranger's
 *   scanner touches one, the app sees the connection directly. That is what
 *   this class does: it is a tarpit / honeypot, and it is the standard and
 *   honest approach on unrooted Android.
 *
 * WHAT IT ACTUALLY CATCHES
 *
 *   - Someone on the same Wi-Fi running nmap / Fing / a router scan against you
 *   - Worms and IoT botnets sweeping the local subnet for telnet/adb/http
 *   - An attacker probing the exit-node ports exposed by the P2P feature
 *
 *   It does NOT catch: stealth scans that only send SYN to ports we are not
 *   listening on, or pure passive reconnaissance. Nothing unprivileged can.
 *   The UI must not claim otherwise.
 *
 * SAFETY
 *
 *   These sockets accept a connection, record the peer, and close immediately.
 *   They never read attacker-supplied data into a parser, never echo anything,
 *   and never execute anything. The honeypot is a doorbell, not a service.
 *   Ports are bound on the wildcard address only while the feature is on.
 */

package com.kotsafe.security.model;

import android.content.Context;

import com.kotsafe.security.Log;

import java.io.Closeable;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

public class InboundScanDetector {
    private static final String TAG = "InboundScanDetector";

    /**
     * Ports chosen because a scanner looking for something exploitable will hit
     * them, and because nothing legitimate on a phone listens there. Deliberately
     * NOT including ports the app itself uses (8088 block page, 8090 exit node,
     * 8095 relay loopback) — those are real services and are monitored separately.
     */
    private static final int[] HONEYPOT_PORTS = {
            5060,   // SIP/VoIP — heavily scanned by botnets (unprivileged)
            2323,   // telnet alt
            2222,   // ssh alt
            5555,   // adb over TCP; heavily scanned, and a real compromise vector
            7547,   // TR-069 CWMP; Mirai's favourite
            8081,   // common alt-http
            9100,   // raw printing
            5900,   // VNC
    };

    /** A scan is "a single source touching several distinct ports in a short window". */
    private static final int SCAN_PORT_THRESHOLD = 3;
    private static final long SCAN_WINDOW_MS = 60_000;
    private static final long ALERT_COOLDOWN_MS = 5 * 60_000;
    private static final int MAX_TRACKED_SOURCES = 512;

    public static class ProbeEvent {
        public final String sourceIp;
        public final int targetPort;
        public final long timestamp;
        public ProbeEvent(String sourceIp, int targetPort, long timestamp) {
            this.sourceIp = sourceIp; this.targetPort = targetPort; this.timestamp = timestamp;
        }
    }

    public static class ScanAlert {
        public String sourceIp;
        public List<Integer> portsTouched = new ArrayList<>();
        public long firstSeen;
        public long lastSeen;
        public boolean isLocalSubnet;
        public String description;
    }

    public interface ScanListener {
        void onScanDetected(ScanAlert alert);
        void onProbe(ProbeEvent event);
    }

    private static class SourceState {
        final Map<Integer, Long> ports = new LinkedHashMap<>();
        long firstSeen;
        long lastAlerted;
    }

    private final Context mContext;
    private final List<ServerSocket> mSockets = new ArrayList<>();
    private final Map<String, SourceState> mSources = new ConcurrentHashMap<>();
    private final AtomicBoolean mRunning = new AtomicBoolean(false);
    private ExecutorService mPool;
    private volatile ScanListener mListener;

    private static volatile InboundScanDetector sInstance;

    public static synchronized InboundScanDetector getInstance(Context ctx) {
        if (sInstance == null) sInstance = new InboundScanDetector(ctx.getApplicationContext());
        return sInstance;
    }

    private InboundScanDetector(Context ctx) {
        mContext = ctx;
    }

    public void setListener(ScanListener l) {
        mListener = l;
    }

    public boolean isRunning() {
        return mRunning.get();
    }

    // ------------------------------------------------------------------ lifecycle

    public synchronized void start() {
        if (mRunning.get()) return;
        mRunning.set(true);
        mPool = Executors.newCachedThreadPool();

        int bound = 0;
        for (int port : HONEYPOT_PORTS) {
            try {
                ServerSocket srv = new ServerSocket();
                srv.setReuseAddress(true);
                srv.bind(new InetSocketAddress(InetAddress.getByName("0.0.0.0"), port), 16);
                mSockets.add(srv);
                mPool.execute(() -> acceptLoop(srv, port));
                bound++;
            } catch (Exception e) {
                // Ports below 1024 need privilege; 23 will normally fail on Android.
                // That is fine — the higher ports carry most scan traffic.
                Log.d(TAG, "could not bind honeypot port " + port + ": " + e.getMessage());
            }
        }
        Log.i(TAG, "Inbound scan detector active on " + bound + " honeypot ports");

        if (bound == 0) {
            mRunning.set(false);
            Log.w(TAG, "No honeypot ports could be bound — inbound detection unavailable");
        }
    }

    public synchronized void stop() {
        mRunning.set(false);
        for (ServerSocket s : mSockets) closeQuietly(s);
        mSockets.clear();
        if (mPool != null) { mPool.shutdownNow(); mPool = null; }
        mSources.clear();
        Log.i(TAG, "Inbound scan detector stopped");
    }

    // ------------------------------------------------------------------ accept

    private void acceptLoop(ServerSocket srv, int port) {
        while (mRunning.get() && !srv.isClosed()) {
            Socket peer = null;
            try {
                peer = srv.accept();
                String src = peer.getInetAddress() != null
                        ? peer.getInetAddress().getHostAddress() : "unknown";
                // Close immediately. We never read attacker data.
                closeQuietly(peer);
                recordProbe(src, port);
            } catch (Exception e) {
                closeQuietly(peer);
                if (!mRunning.get()) break;
            }
        }
    }

    // ------------------------------------------------------------------ correlation

    private void recordProbe(String sourceIp, int port) {
        long now = System.currentTimeMillis();

        if (isSelf(sourceIp)) return;   // our own health checks

        ScanListener l = mListener;
        if (l != null) l.onProbe(new ProbeEvent(sourceIp, port, now));

        if (mSources.size() > MAX_TRACKED_SOURCES) pruneSources(now);

        SourceState st = mSources.computeIfAbsent(sourceIp, k -> {
            SourceState s = new SourceState();
            s.firstSeen = now;
            return s;
        });

        synchronized (st) {
            // Drop entries outside the window before counting.
            st.ports.entrySet().removeIf(e -> now - e.getValue() > SCAN_WINDOW_MS);
            st.ports.put(port, now);

            if (st.ports.size() >= SCAN_PORT_THRESHOLD
                    && (now - st.lastAlerted) > ALERT_COOLDOWN_MS) {
                st.lastAlerted = now;
                ScanAlert alert = new ScanAlert();
                alert.sourceIp = sourceIp;
                alert.portsTouched = new ArrayList<>(st.ports.keySet());
                alert.firstSeen = st.firstSeen;
                alert.lastSeen = now;
                alert.isLocalSubnet = isPrivateAddress(sourceIp);
                alert.description = buildDescription(alert);

                Log.w(TAG, "Port scan detected from " + sourceIp + " across ports " + alert.portsTouched);
                if (l != null) l.onScanDetected(alert);
            }
        }
    }

    private void pruneSources(long now) {
        mSources.entrySet().removeIf(e -> {
            SourceState s = e.getValue();
            synchronized (s) {
                return s.ports.isEmpty()
                        || now - java.util.Collections.max(s.ports.values()) > SCAN_WINDOW_MS * 2;
            }
        });
    }

    private String buildDescription(ScanAlert a) {
        StringBuilder sb = new StringBuilder();
        if (a.isLocalSubnet) {
            sb.append("A device on your local network (").append(a.sourceIp)
              .append(") is scanning your phone for open ports. ");
            sb.append("On a home network this is sometimes a router or a network tool. ");
            sb.append("On public Wi-Fi it usually means someone is looking for a way in — ");
            sb.append("disconnect from this network.");
        } else {
            sb.append("An address on the internet (").append(a.sourceIp)
              .append(") is probing your phone. ");
            sb.append("This normally means your carrier or router is exposing the device directly. ");
            sb.append("Check that port forwarding and UPnP are disabled on your router.");
        }
        sb.append(" Ports touched: ");
        for (int i = 0; i < a.portsTouched.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(a.portsTouched.get(i));
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------ helpers

    private static boolean isSelf(String ip) {
        return "127.0.0.1".equals(ip) || "::1".equals(ip) || "0:0:0:0:0:0:0:1".equals(ip);
    }

    public static boolean isPrivateAddress(String ip) {
        if (ip == null) return false;
        try {
            InetAddress addr = InetAddress.getByName(ip);
            return addr.isSiteLocalAddress() || addr.isLinkLocalAddress() || addr.isLoopbackAddress();
        } catch (Exception e) {
            return false;
        }
    }

    private static void closeQuietly(Closeable c) {
        if (c != null) try { c.close(); } catch (Exception ignored) {}
    }

    private static void closeQuietly(Socket s) {
        if (s != null) try { s.close(); } catch (Exception ignored) {}
    }
}
