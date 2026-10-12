package com.kotsafe.p2p;

import java.util.ArrayDeque;
import java.util.Arrays;

/** Prevents a SOCKS/TCP greeting from being lost while the exit connects. */
public final class BufferedTunnelStream {
    public interface Sender {
        void send(byte[] data) throws Exception;
    }

    private static final int MAX_PENDING_BYTES = 64 * 1024;
    private final Sender sender;
    private final ArrayDeque<byte[]> pending = new ArrayDeque<>();
    private int pendingBytes;
    private boolean ready;
    private boolean closed;

    public BufferedTunnelStream(Sender sender) {
        if (sender == null) throw new IllegalArgumentException("sender is required");
        this.sender = sender;
    }

    public synchronized void write(byte[] data) throws Exception {
        if (closed) throw new IllegalStateException("stream is closed");
        if (data == null) throw new IllegalArgumentException("data is required");
        if (ready) {
            sender.send(data);
            return;
        }
        if (data.length > MAX_PENDING_BYTES - pendingBytes) {
            throw new IllegalStateException("exit did not become ready before pending buffer filled");
        }
        pending.add(Arrays.copyOf(data, data.length));
        pendingBytes += data.length;
    }

    /** Call only after a verified ready frame arrives from the exit device. */
    public synchronized void onReady() throws Exception {
        if (closed || ready) return;
        ready = true;
        while (!pending.isEmpty()) sender.send(pending.remove());
        pendingBytes = 0;
    }

    public synchronized void close() {
        closed = true;
        pending.clear();
        pendingBytes = 0;
    }
}
