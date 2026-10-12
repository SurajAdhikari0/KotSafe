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

package com.kotsafe.security.model;

import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;

import androidx.annotation.NonNull;

import com.kotsafe.security.Log;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Lightweight RFC 1035 UDP probe to measure DNS server round-trip latency (RTT ms).
 */
public class DnsLatencyBenchmark {
    private static final String TAG = "DnsLatencyBenchmark";
    private static final int SOCKET_TIMEOUT_MS = 2500;

    public interface BenchmarkListener {
        void onProviderTested(@NonNull DnsProvider provider, int latencyMs);
        void onBenchmarkFinished(@NonNull Map<String, Integer> results);
    }

    private final Handler mMainHandler = new Handler(Looper.getMainLooper());
    private ExecutorService mExecutor;
    private final AtomicBoolean mIsRunning = new AtomicBoolean(false);

    // RFC 1035 Query for 'google.com' (Type A, Class IN, Recursion Desired)
    private static final byte[] DNS_QUERY_PACKET = new byte[] {
            (byte) 0xAA, (byte) 0xBB, // ID
            0x01, 0x00,               // Flags: RD=1
            0x00, 0x01,               // QDCOUNT = 1
            0x00, 0x00,               // ANCOUNT = 0
            0x00, 0x00,               // NSCOUNT = 0
            0x00, 0x00,               // ARCOUNT = 0
            // QNAME: 6 'g' 'o' 'o' 'g' 'l' 'e' 3 'c' 'o' 'm' 0
            0x06, 'g', 'o', 'o', 'g', 'l', 'e',
            0x03, 'c', 'o', 'm',
            0x00,
            0x00, 0x01,               // QTYPE = A (1)
            0x00, 0x01                // QCLASS = IN (1)
    };

    public void runBenchmark(@NonNull List<DnsProvider> providers, @NonNull BenchmarkListener listener) {
        if (mIsRunning.getAndSet(true)) {
            Log.w(TAG, "Benchmark is already running");
            return;
        }

        mExecutor = Executors.newFixedThreadPool(4);
        Map<String, Integer> results = new HashMap<>();

        new Thread(() -> {
            for (DnsProvider provider : providers) {
                if (!mIsRunning.get()) break;

                mExecutor.submit(() -> {
                    if (!mIsRunning.get()) return;

                    int latency = probeServer(provider.getPrimaryIpv4());
                    synchronized (results) {
                        results.put(provider.getId(), latency);
                    }

                    mMainHandler.post(() -> listener.onProviderTested(provider, latency));
                });
            }

            mExecutor.shutdown();
            try {
                mExecutor.awaitTermination(8, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            mIsRunning.set(false);
            mMainHandler.post(() -> listener.onBenchmarkFinished(results));
        }).start();
    }

    public void cancel() {
        mIsRunning.set(false);
        if (mExecutor != null) {
            mExecutor.shutdownNow();
        }
    }

    public boolean isRunning() {
        return mIsRunning.get();
    }

    public static int probeServer(@NonNull String ipAddress) {
        long start = SystemClock.elapsedRealtime();
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(SOCKET_TIMEOUT_MS);
            InetAddress address = InetAddress.getByName(ipAddress);
            DatagramPacket query = new DatagramPacket(DNS_QUERY_PACKET, DNS_QUERY_PACKET.length, address, 53);

            socket.send(query);

            byte[] buffer = new byte[512];
            DatagramPacket response = new DatagramPacket(buffer, buffer.length);
            socket.receive(response);

            if (response.getLength() >= 12) {
                long duration = SystemClock.elapsedRealtime() - start;
                return (int) Math.max(1, duration);
            }
        } catch (Exception e) {
            Log.d(TAG, "Probe to " + ipAddress + " failed: " + e.getMessage());
        }
        return -1; // Timeout / Unreachable
    }
}
