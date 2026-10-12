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

package com.kotsafe.security.tls;

import android.content.Context;
import android.net.Uri;

import com.kotsafe.security.CaptureService;
import com.kotsafe.security.Log;
import com.kotsafe.security.MitmReceiver;
import com.kotsafe.security.Utils;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Built-in high performance SOCKS5 and TLS interception engine.
 * Runs on 127.0.0.1:7780 to intercept TCP connections redirected by VPN capture_vpn.c.
 */
public class TlsMitmServer implements Runnable {
    private static final String TAG = "TlsMitmServer";
    public static final int BUFFER_SIZE = 16384;

    private final Context mContext;
    private final int mPort;
    private final String mAuth;
    private final MitmReceiver mReceiver;
    private final TlsCaManager mCaManager;

    private ServerSocket mServerSocket;
    private Thread mServerThread;
    private ExecutorService mThreadPool;
    private volatile boolean mRunning;

    public TlsMitmServer(Context context, int port, String auth, MitmReceiver receiver) {
        mContext = context;
        mPort = port;
        mAuth = auth;
        mReceiver = receiver;
        mCaManager = TlsCaManager.getInstance(context);
    }

    public synchronized boolean start() {
        if (mRunning) return true;
        try {
            mServerSocket = new ServerSocket(mPort, 128, InetAddress.getByName("127.0.0.1"));
            mServerSocket.setReuseAddress(true);
            mRunning = true;
            mThreadPool = new java.util.concurrent.ThreadPoolExecutor(
                    4, 24, 30L, TimeUnit.SECONDS,
                    new java.util.concurrent.LinkedBlockingQueue<>(128),
                    new java.util.concurrent.ThreadPoolExecutor.DiscardPolicy()
            );

            mServerThread = new Thread(this, "TlsMitmServer");
            mServerThread.start();
            Log.i(TAG, "Built-in TLS Decryption Server started on 127.0.0.1:" + mPort);
            return true;
        } catch (IOException e) {
            Log.e(TAG, "Failed to start TLS Mitm Server on port " + mPort + ": " + e.getMessage());
            stop();
            return false;
        }
    }

    public synchronized void stop() {
        mRunning = false;
        Utils.safeClose(mServerSocket);
        mServerSocket = null;

        if (mThreadPool != null) {
            mThreadPool.shutdownNow();
            try {
                mThreadPool.awaitTermination(1, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {}
            mThreadPool = null;
        }

        if (mServerThread != null) {
            mServerThread.interrupt();
            try {
                mServerThread.join(1000);
            } catch (InterruptedException ignored) {}
            mServerThread = null;
        }

        Log.i(TAG, "Built-in TLS Decryption Server stopped");
    }

    public boolean isRunning() {
        return mRunning;
    }

    @Override
    public void run() {
        if (mReceiver != null) {
            mReceiver.dispatchRunningStatus();
        }

        while (mRunning && mServerSocket != null && !mServerSocket.isClosed()) {
            try {
                Socket clientSocket = mServerSocket.accept();
                if (!mRunning) {
                    Utils.safeClose(clientSocket);
                    break;
                }
                if (mThreadPool != null && !mThreadPool.isShutdown()) {
                    mThreadPool.execute(() -> handleClient(clientSocket));
                } else {
                    Utils.safeClose(clientSocket);
                }
            } catch (IOException e) {
                if (mRunning) {
                    Log.w(TAG, "Accept exception: " + e.getMessage());
                }
            }
        }
    }

    private static void readExact(InputStream in, byte[] buf, int off, int len) throws IOException {
        int total = 0;
        while (total < len) {
            int r = in.read(buf, off + total, len - total);
            if (r < 0) throw new java.io.EOFException("Premature EOF");
            total += r;
        }
    }

    private void handleClient(Socket clientSocket) {
        int clientPort = clientSocket.getPort();
        int ipver = (clientSocket.getInetAddress() instanceof Inet6Address) ? 6 : 4;

        try {
            clientSocket.setSoTimeout(10000);
            clientSocket.setTcpNoDelay(true);

            InputStream in = clientSocket.getInputStream();
            OutputStream out = clientSocket.getOutputStream();

            // 1. SOCKS5 Handshake (RFC 1928) - direct unbuffered reading
            int ver = in.read();
            if (ver != 0x05) {
                Log.w(TAG, "Unsupported SOCKS version: " + ver);
                Utils.safeClose(clientSocket);
                return;
            }

            int nmethods = in.read();
            if (nmethods < 0) return;
            byte[] methods = new byte[nmethods];
            readExact(in, methods, 0, nmethods);

            // Server selects auth method (0x00 NO AUTH)
            out.write(new byte[]{0x05, 0x00});
            out.flush();

            // 2. SOCKS5 Request
            int reqVer = in.read();
            int cmd = in.read();
            in.read(); // RSV
            int atyp = in.read();

            if (reqVer != 0x05 || cmd != 0x01) { // 0x01 = CONNECT
                Log.w(TAG, "Unsupported SOCKS command: " + cmd);
                sendSocksReply(out, (byte) 0x07); // Command not supported
                Utils.safeClose(clientSocket);
                return;
            }

            String targetHost;
            if (atyp == 0x01) { // IPv4
                byte[] ip = new byte[4];
                readExact(in, ip, 0, 4);
                targetHost = InetAddress.getByAddress(ip).getHostAddress();
            } else if (atyp == 0x03) { // Domain name
                int len = in.read();
                if (len < 0) return;
                byte[] domain = new byte[len];
                readExact(in, domain, 0, len);
                targetHost = new String(domain, StandardCharsets.UTF_8);
            } else if (atyp == 0x04) { // IPv6
                byte[] ip6 = new byte[16];
                readExact(in, ip6, 0, 16);
                targetHost = InetAddress.getByAddress(ip6).getHostAddress();
            } else {
                Log.w(TAG, "Unsupported ATYP: " + atyp);
                sendSocksReply(out, (byte) 0x08); // Address type not supported
                Utils.safeClose(clientSocket);
                return;
            }

            int p1 = in.read();
            int p2 = in.read();
            if (p1 < 0 || p2 < 0) return;
            int targetPort = ((p1 & 0xFF) << 8) | (p2 & 0xFF);

            // 3. SOCKS5 Connect Success Reply
            sendSocksReply(out, (byte) 0x00);

            // 4. Determine if connection is TLS or Plaintext
            boolean isTls = (targetPort == 443) || (targetPort == 8443);

            // If target is blocked by firewall blocklist, serve HTTP block page directly on this connection
            com.kotsafe.security.model.SecurityRulesDb.SecurityRule blockRule =
                    com.kotsafe.security.model.SecurityBlocklistManager.getInstance(mContext).findBlockRule(targetHost);
            if (!isTls && blockRule != null) {
                try {
                    byte[] reqBuf = new byte[4096];
                    int n = in.read(reqBuf);
                } catch (Exception ignored) {}

                String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date());
                String reason = blockRule.reason != null ? blockRule.reason : "Security Policy";
                String targetType = blockRule.type != null ? blockRule.type : "SITE";
                String html = com.kotsafe.security.server.FirewallBlockHttpServer.getInstance(mContext)
                        .generateBlockHtml(targetHost, reason, "Web Browser", timestamp, targetType);
                byte[] bodyBytes = html.getBytes(StandardCharsets.UTF_8);

                String httpResponse = "HTTP/1.1 200 OK\r\n"
                        + "Content-Type: text/html; charset=UTF-8\r\n"
                        + "Content-Length: " + bodyBytes.length + "\r\n"
                        + "Cache-Control: no-cache, no-store, must-revalidate\r\n"
                        + "Connection: close\r\n\r\n";
                out.write(httpResponse.getBytes(StandardCharsets.UTF_8));
                out.write(bodyBytes);
                out.flush();
                try { Thread.sleep(150); } catch (Exception ignored) {}
                return;
            }

            if (isTls) {
                handleTlsTunnel(clientSocket, in, out, targetHost, targetPort, ipver, clientPort);
            } else {
                handlePlainTunnel(clientSocket, in, out, targetHost, targetPort, ipver, clientPort);
            }
        } catch (Exception e) {
            // Report TLS / Handshake / Connection error to UI
            String err = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            if (mReceiver != null) {
                mReceiver.dispatchDecryptedMessage(System.currentTimeMillis(), ipver, 6, clientPort,
                        MitmReceiver.MsgType.TLS_ERROR, err.getBytes(StandardCharsets.US_ASCII));
            }
            Log.d(TAG, "Client handler exception: " + e.getMessage());
        } finally {
            Utils.safeClose(clientSocket);
        }
    }

    private void sendSocksReply(OutputStream out, byte rep) throws IOException {
        byte[] reply = new byte[]{
                0x05, // VER
                rep,  // REP (0x00 = success)
                0x00, // RSV
                0x01, // ATYP (IPv4)
                0x00, 0x00, 0x00, 0x00, // BND.ADDR
                0x00, 0x00  // BND.PORT
        };
        out.write(reply);
        out.flush();
    }

    private static void protectSocket(Socket socket) {
        if (CaptureService.isServiceActive()) {
            try {
                CaptureService.requireInstance().protect(socket);
            } catch (Exception e) {
                Log.w(TAG, "Failed to protect socket: " + e.getMessage());
            }
        }
    }

    private void handleTlsTunnel(Socket rawClientSocket, InputStream rawIn, OutputStream rawOut,
                                 String targetHost, int targetPort, int ipver, int clientPort) {
        SSLSocket sslClientSocket = null;
        SSLSocket sslUpstreamSocket = null;
        Socket rawUpstream = null;

        try {
            // Create dynamically signed server SSL context for this host
            SSLContext serverContext = mCaManager.getOrCreateServerSSLContext(targetHost);
            SSLSocketFactory serverFactory = serverContext.getSocketFactory();

            // Wrap downstream client socket with TLS
            sslClientSocket = (SSLSocket) serverFactory.createSocket(rawClientSocket, targetHost, targetPort, false);
            sslClientSocket.setUseClientMode(false);
            sslClientSocket.setSoTimeout(10000);
            sslClientSocket.startHandshake();

            // Check if target is blocked by firewall blocklist
            com.kotsafe.security.model.SecurityRulesDb.SecurityRule tlsBlockRule =
                    com.kotsafe.security.model.SecurityBlocklistManager.getInstance(mContext).findBlockRule(targetHost);
            if (tlsBlockRule != null) {
                try {
                    byte[] sslReqBuf = new byte[4096];
                    int n = sslClientSocket.getInputStream().read(sslReqBuf);
                } catch (Exception ignored) {}

                String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date());
                String reason = tlsBlockRule.reason != null ? tlsBlockRule.reason : "Security Policy";
                String targetType = tlsBlockRule.type != null ? tlsBlockRule.type : "SITE";
                String html = com.kotsafe.security.server.FirewallBlockHttpServer.getInstance(mContext)
                        .generateBlockHtml(targetHost, reason, "Web Browser", timestamp, targetType);
                byte[] bodyBytes = html.getBytes(StandardCharsets.UTF_8);

                String httpResponse = "HTTP/1.1 200 OK\r\n"
                        + "Content-Type: text/html; charset=UTF-8\r\n"
                        + "Content-Length: " + bodyBytes.length + "\r\n"
                        + "Cache-Control: no-cache, no-store, must-revalidate\r\n"
                        + "Connection: close\r\n\r\n";
                OutputStream sslOut = sslClientSocket.getOutputStream();
                sslOut.write(httpResponse.getBytes(StandardCharsets.UTF_8));
                sslOut.write(bodyBytes);
                sslOut.flush();
                try { Thread.sleep(150); } catch (Exception ignored) {}
                return;
            }

            // Connect upstream to destination server with TLS
            SSLContext upstreamContext = mCaManager.getUpstreamSSLContext();
            SSLSocketFactory upstreamFactory = upstreamContext.getSocketFactory();
            rawUpstream = new Socket();
            protectSocket(rawUpstream);
            rawUpstream.connect(new InetSocketAddress(targetHost, targetPort), 5000);
            rawUpstream.setSoTimeout(10000);
            rawUpstream.setTcpNoDelay(true);

            sslUpstreamSocket = (SSLSocket) upstreamFactory.createSocket(rawUpstream, targetHost, targetPort, true);
            sslUpstreamSocket.setUseClientMode(true);
            sslUpstreamSocket.startHandshake();

            // Bidirectional proxy with real-time plaintext payload interception
            relayStreams(sslClientSocket.getInputStream(), sslUpstreamSocket.getOutputStream(),
                    sslUpstreamSocket.getInputStream(), sslClientSocket.getOutputStream(),
                    ipver, clientPort);

        } catch (Exception e) {
            String err = (e.getMessage() != null) ? e.getMessage() : "TLS Handshake Failed";
            if (mReceiver != null) {
                mReceiver.dispatchDecryptedMessage(System.currentTimeMillis(), ipver, 6, clientPort,
                        MitmReceiver.MsgType.TLS_ERROR, err.getBytes(StandardCharsets.US_ASCII));
            }
            Log.w(TAG, "TLS interception failed for " + targetHost + ":" + targetPort + ": " + err);
        } finally {
            Utils.safeClose(sslClientSocket);
            Utils.safeClose(sslUpstreamSocket);
            Utils.safeClose(rawUpstream);
        }
    }

    private void handlePlainTunnel(Socket rawClientSocket, InputStream in, OutputStream out,
                                   String targetHost, int targetPort, int ipver, int clientPort) {
        Socket upstreamSocket = null;
        try {
            upstreamSocket = new Socket();
            protectSocket(upstreamSocket);
            upstreamSocket.connect(new InetSocketAddress(targetHost, targetPort), 5000);
            upstreamSocket.setSoTimeout(10000);
            upstreamSocket.setTcpNoDelay(true);

            relayStreams(rawClientSocket.getInputStream(), upstreamSocket.getOutputStream(),
                    upstreamSocket.getInputStream(), rawClientSocket.getOutputStream(),
                    ipver, clientPort);
        } catch (Exception e) {
            String err = (e.getMessage() != null) ? e.getMessage() : "Connection Failed";
            if (mReceiver != null) {
                mReceiver.dispatchDecryptedMessage(System.currentTimeMillis(), ipver, 6, clientPort,
                        MitmReceiver.MsgType.TCP_ERROR, err.getBytes(StandardCharsets.US_ASCII));
            }
        } finally {
            Utils.safeClose(upstreamSocket);
        }
    }

    private void relayStreams(InputStream clientIn, OutputStream upstreamOut,
                              InputStream upstreamIn, OutputStream clientOut,
                              int ipver, int clientPort) {
        if (mThreadPool == null || mThreadPool.isShutdown()) return;

        // Client -> Upstream (Requests)
        mThreadPool.execute(() -> {
            byte[] buffer = new byte[BUFFER_SIZE];
            int read;
            try {
                while ((read = clientIn.read(buffer)) != -1) {
                    byte[] data = new byte[read];
                    System.arraycopy(buffer, 0, data, 0, read);

                    // Dispatch decrypted HTTP request payload to KotSafe engine
                    if (mReceiver != null) {
                        MitmReceiver.MsgType msgType = isHttpPayload(data) ?
                                MitmReceiver.MsgType.HTTP_REQUEST : MitmReceiver.MsgType.TCP_CLIENT_MSG;
                        mReceiver.dispatchDecryptedMessage(System.currentTimeMillis(), ipver, 6, clientPort, msgType, data);
                    }

                    upstreamOut.write(buffer, 0, read);
                    upstreamOut.flush();
                }
            } catch (IOException ignored) {
            } finally {
                Utils.safeClose(clientIn);
                Utils.safeClose(upstreamOut);
            }
        });

        // Upstream -> Client (Replies)
        byte[] buffer = new byte[BUFFER_SIZE];
        int read;
        try {
            while ((read = upstreamIn.read(buffer)) != -1) {
                byte[] data = new byte[read];
                System.arraycopy(buffer, 0, data, 0, read);

                // Dispatch decrypted HTTP reply payload to KotSafe engine
                if (mReceiver != null) {
                    MitmReceiver.MsgType msgType = isHttpPayload(data) ?
                            MitmReceiver.MsgType.HTTP_REPLY : MitmReceiver.MsgType.TCP_SERVER_MSG;
                    mReceiver.dispatchDecryptedMessage(System.currentTimeMillis(), ipver, 6, clientPort, msgType, data);
                }

                clientOut.write(buffer, 0, read);
                clientOut.flush();
            }
        } catch (IOException ignored) {
        } finally {
            Utils.safeClose(upstreamIn);
            Utils.safeClose(clientOut);
        }
    }

    private static boolean isHttpPayload(byte[] data) {
        if (data == null || data.length < 4) return false;
        return com.kotsafe.security.decoders.HttpsDecoder.isHttpsOrHttp(data);
    }
}
