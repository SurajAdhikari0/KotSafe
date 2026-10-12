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
 * * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.model;

import android.content.Context;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.kotsafe.security.AppsResolver;
import com.kotsafe.security.CaptureService;
import com.kotsafe.security.HTTPReassembly;
import com.kotsafe.security.HttpLog;
import com.kotsafe.security.Log;
import com.kotsafe.security.KotSafe;
import com.kotsafe.security.R;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.concurrent.atomic.AtomicReference;

/* Holds the telemetry and metadata for an active or closed network connection.
 * Used across the KotEngine capture pipeline, connection table, and UI inspector.
 *
 * Connections are stored in ConnectionsRegister. Concurrent access is thread-safe
 * as updates only increment atomic counters or set previously unpopulated metadata.
 */
public class ConnectionDescriptor implements HTTPReassembly.ReassemblyListener {
    public static final String TAG = "ConnectionDescriptor";

    // Engine Connection Statuses
    public static final int CONN_STATUS_NEW = 0,
        CONN_STATUS_CONNECTING = 1,
        CONN_STATUS_CONNECTED = 2,
        CONN_STATUS_CLOSED = 3,
        CONN_STATUS_ERROR = 4,
        CONN_STATUS_SOCKET_ERROR = 5,
        CONN_STATUS_CLIENT_ERROR = 6,
        CONN_STATUS_RESET = 7,
        CONN_STATUS_UNREACHABLE = 8;

    // High level status for UI and flow telemetry
    public enum Status {
        STATUS_INVALID,
        STATUS_ACTIVE,
        STATUS_CLOSED,
        STATUS_UNREACHABLE,
        STATUS_ERROR,
    }

    public enum DecryptionStatus {
        INVALID,
        ENCRYPTED,
        CLEARTEXT,
        DECRYPTED,
        NOT_DECRYPTABLE,
        WAITING_DATA,
        ERROR,
    }

    public enum FilteringStatus {
        INVALID,
        ALLOWED,
        BLOCKED
    }

    /* Metadata */
    public final int ipver;
    public final int ipproto;
    public final String src_ip;
    public final String dst_ip;
    public final int src_port;
    public final int dst_port;
    public final int local_port; // in VPN mode, this is the local port of the Internet connection

    /* Data */
    public long first_seen;
    public long last_seen;
    public long payload_length;
    public long sent_bytes;
    public long rcvd_bytes;
    public int sent_pkts;
    public int rcvd_pkts;
    public int blocked_pkts;
    public String info;
    public String url;
    public int http_log_pos = -1;
    public String l7proto;
    private final ArrayList<PayloadChunk> payload_chunks; // must be synchronized
    public int uid;
    public final int ifidx;
    public final int incr_id;
    private final boolean mitm_decrypt; // true if the connection is under mitm for TLS decryption
    private boolean internal_decrypt;
    public int status;
    public int error;
    private int tcp_flags;
    private boolean blacklisted_ip;
    private boolean blacklisted_host;
    public boolean is_blocked;
    public String block_reason;
    public String block_type;
    private boolean port_mapping_applied;
    private boolean decryption_ignored;
    public boolean netd_block_missed;
    private boolean payload_truncated;
    private boolean encrypted_l7;     // application layer is encrypted (e.g. TLS)
    public boolean encrypted_payload; // actual payload is encrypted (e.g. telegram - see Utils.hasEncryptedPayload)
    private boolean has_websocket_data;
    public String decryption_error;
    public String js_injected_scripts;
    public String country;
    public String src_country;
    public Geomodel.ASN asn;
    public String ja4 = "";
    public float entropy = 0.0f;
    public double tx_speed_bps = 0.0;
    public double rx_speed_bps = 0.0;
    public int query_count = 1;
    public int aggregated_flows = 1;

    /* Internal */
    public boolean alerted;
    public boolean block_accounted;
    public boolean dns_accounted;
    public boolean logged_to_firewall = false;
    public boolean spyware_inspected = false;
    public boolean uid_checked = false;
    private HTTPReassembly mHttpReqReassembly;
    private HTTPReassembly mHttpReplyReassembly;
    private int mFirstReqChunkPos = -1;
    private int mFirstReplyChunkPos = -1;
    private LinkedList<HttpLog.HttpRequest> mPendingRequests;

    // NOTE: invoked from JNI
    public ConnectionDescriptor(int _incr_id, int _ipver, int _ipproto, String _src_ip, String _dst_ip, String _country,
                                int _src_port, int _dst_port, int _local_port, int _uid, int _ifidx,
                                boolean _mitm_decrypt, long when) {
        incr_id = _incr_id;
        ipver = _ipver;
        ipproto = _ipproto;
        src_ip = _src_ip;
        dst_ip = _dst_ip;
        src_port = _src_port;
        dst_port = _dst_port;
        local_port = _local_port;
        uid = _uid;
        ifidx = _ifidx;
        first_seen = last_seen = when;
        l7proto = "";
        country = _country;
        src_country = "";
        asn = new Geomodel.ASN();
        payload_chunks = new ArrayList<>();
        mitm_decrypt = _mitm_decrypt;
        internal_decrypt = false;
        if (_src_port > 0) {
            recordSocketSession(this.ipproto, _src_port, _dst_port, sent_bytes, rcvd_bytes, status, l7proto, when, is_blocked, block_reason);
        }
    }

    public ConnectionDescriptor(ConnectionDescriptor o) {
        incr_id = o.incr_id;
        ipver = o.ipver;
        ipproto = o.ipproto;
        src_ip = o.src_ip;
        dst_ip = o.dst_ip;
        src_port = o.src_port;
        dst_port = o.dst_port;
        local_port = o.local_port;
        uid = o.uid;
        ifidx = o.ifidx;
        first_seen = o.first_seen;
        last_seen = o.last_seen;
        payload_length = o.payload_length;
        sent_bytes = o.sent_bytes;
        rcvd_bytes = o.rcvd_bytes;
        sent_pkts = o.sent_pkts;
        rcvd_pkts = o.rcvd_pkts;
        blocked_pkts = o.blocked_pkts;
        info = o.info;
        url = o.url;
        http_log_pos = o.http_log_pos;
        l7proto = o.l7proto;
        payload_chunks = new ArrayList<>(o.payload_chunks);
        mitm_decrypt = o.mitm_decrypt;
        internal_decrypt = o.internal_decrypt;
        status = o.status;
        error = o.error;
        tcp_flags = o.tcp_flags;
        blacklisted_ip = o.blacklisted_ip;
        blacklisted_host = o.blacklisted_host;
        is_blocked = o.is_blocked;
        block_reason = o.block_reason;
        block_type = o.block_type;
        port_mapping_applied = o.port_mapping_applied;
        decryption_ignored = o.decryption_ignored;
        netd_block_missed = o.netd_block_missed;
        payload_truncated = o.payload_truncated;
        encrypted_l7 = o.encrypted_l7;
        encrypted_payload = o.encrypted_payload;
        has_websocket_data = o.has_websocket_data;
        decryption_error = o.decryption_error;
        js_injected_scripts = o.js_injected_scripts;
        country = o.country;
        src_country = o.src_country;
        asn = o.asn;
        ja4 = o.ja4;
        entropy = o.entropy;
        tx_speed_bps = o.tx_speed_bps;
        rx_speed_bps = o.rx_speed_bps;
        query_count = o.query_count;
        aggregated_flows = o.aggregated_flows;
        alerted = o.alerted;
        block_accounted = o.block_accounted;
        dns_accounted = o.dns_accounted;
        logged_to_firewall = o.logged_to_firewall;
        spyware_inspected = o.spyware_inspected;
        uid_checked = o.uid_checked;
        if (o.mSocketSessions.isEmpty()) {
            recordSocketSession(o.ipproto, o.src_port, o.dst_port, o.sent_bytes, o.rcvd_bytes, o.status, o.l7proto, o.first_seen, o.is_blocked, o.block_reason);
        } else {
            for (SocketSession s : o.getSocketSessions()) {
                recordSocketSession(s.proto, s.src_port, s.dst_port, s.sent_bytes, s.rcvd_bytes, s.tcp_state, s.l7proto, s.last_seen, s.is_blocked, s.block_reason);
            }
        }
    }

    /**
     * Diagnostic descriptor for an individual ephemeral socket session within an aggregated connection.
     */
    public static class SocketSession {
        public final int proto;
        public final int src_port;
        public final int dst_port;
        public final long first_seen;
        public long last_seen;
        public long sent_bytes;
        public long rcvd_bytes;
        public int tcp_state;
        public String l7proto;
        public boolean is_blocked;
        public String block_reason;

        public SocketSession(int proto, int src_port, int dst_port, long sent_bytes, long rcvd_bytes, int tcp_state, String l7proto, long now) {
            this.proto = proto;
            this.src_port = src_port;
            this.dst_port = dst_port;
            this.sent_bytes = sent_bytes;
            this.rcvd_bytes = rcvd_bytes;
            this.tcp_state = tcp_state;
            this.l7proto = (l7proto != null) ? l7proto : "";
            this.first_seen = now;
            this.last_seen = now;
        }

        public SocketSession(int src_port, int dst_port, long sent_bytes, long rcvd_bytes, int tcp_state, String l7proto, long now) {
            this(6, src_port, dst_port, sent_bytes, rcvd_bytes, tcp_state, l7proto, now);
        }

        public void update(long sent_bytes, long rcvd_bytes, int tcp_state, String l7proto, long now) {
            this.sent_bytes = Math.max(this.sent_bytes, sent_bytes);
            this.rcvd_bytes = Math.max(this.rcvd_bytes, rcvd_bytes);
            if (tcp_state != 0) this.tcp_state = tcp_state;
            if (l7proto != null && !l7proto.isEmpty()) this.l7proto = l7proto;
            this.last_seen = now;
        }

        public String getTcpStateString() {
            if (proto == 17) {
                return (sent_bytes > 0 && rcvd_bytes > 0) ? "TRANSFERRED" : "UDP";
            } else if (proto == 1 || proto == 58) {
                return "ICMP";
            }
            switch (tcp_state) {
                case 1: return "SYN_SENT";
                case 2: return "ESTABLISHED";
                case 3: return "FIN_WAIT";
                case 4: return "CLOSED";
                case 5: return "RESET";
                default: return "ACTIVE";
            }
        }

        public long getDurationMs() {
            return Math.max(0, last_seen - first_seen);
        }

        public String getFormattedDuration() {
            long duration = getDurationMs();
            if (duration < 1000) {
                return duration + " ms";
            } else if (duration < 60000) {
                return String.format(java.util.Locale.US, "%.1f s", duration / 1000.0);
            } else {
                long mins = duration / 60000;
                long secs = (duration % 60000) / 1000;
                return mins + "m " + secs + "s";
            }
        }
    }

    private final java.util.Map<Integer, SocketSession> mSocketSessions = new java.util.concurrent.ConcurrentHashMap<>();

    public void recordSocketSession(int proto, int src_port, int dst_port, long sent_bytes, long rcvd_bytes, int tcp_state, String l7proto, long now, boolean blocked, String blockReason) {
        int key = (src_port > 0) ? src_port : -(mSocketSessions.size() + 1);
        SocketSession session = mSocketSessions.get(key);
        if (session == null) {
            if (mSocketSessions.size() < 256) {
                session = new SocketSession(proto, src_port, dst_port, sent_bytes, rcvd_bytes, tcp_state, l7proto, now);
                session.is_blocked = blocked;
                session.block_reason = blockReason;
                mSocketSessions.put(key, session);
            }
        } else {
            session.update(sent_bytes, rcvd_bytes, tcp_state, l7proto, now);
            if (blocked) {
                session.is_blocked = true;
                if (blockReason != null && !blockReason.isEmpty()) {
                    session.block_reason = blockReason;
                }
            }
        }
    }

    public void recordSocketSession(int proto, int src_port, int dst_port, long sent_bytes, long rcvd_bytes, int tcp_state, String l7proto, long now) {
        recordSocketSession(proto, src_port, dst_port, sent_bytes, rcvd_bytes, tcp_state, l7proto, now, false, null);
    }

    public void recordSocketSession(int src_port, int dst_port, long sent_bytes, long rcvd_bytes, int tcp_state, String l7proto, long now) {
        recordSocketSession(this.ipproto, src_port, dst_port, sent_bytes, rcvd_bytes, tcp_state, l7proto, now, false, null);
    }

    public java.util.List<SocketSession> getSocketSessions() {
        if (mSocketSessions.isEmpty() && src_port > 0) {
            recordSocketSession(ipproto, src_port, dst_port, sent_bytes, rcvd_bytes, status, l7proto, first_seen, is_blocked, block_reason);
        }
        if (this.status >= CONN_STATUS_CLOSED && mSocketSessions.size() == 1) {
            for (SocketSession s : mSocketSessions.values()) {
                if (s.tcp_state < CONN_STATUS_CLOSED) {
                    s.tcp_state = this.status;
                }
            }
        }
        java.util.List<SocketSession> list = new ArrayList<>(mSocketSessions.values());
        java.util.Collections.sort(list, (a, b) -> Long.compare(b.last_seen, a.last_seen));
        return list;
    }

    // NOTE: invoked from either JNI (dumpNewConnection) or ConnectionsRegister
    public void processUpdate(ConnectionUpdate update) {
        // The "update_type" is used to limit the amount of data sent via the JNI
        if((update.update_type & ConnectionUpdate.UPDATE_STATS) != 0) {
            sent_bytes = update.sent_bytes;
            rcvd_bytes = update.rcvd_bytes;
            sent_pkts = update.sent_pkts;
            rcvd_pkts = update.rcvd_pkts;
            blocked_pkts = update.blocked_pkts;
            status = (update.status & 0x00FF);
            error = (update.status & 0xFF0000) >> 16;
            port_mapping_applied = (update.status & 0x2000) != 0;
            decryption_ignored = (update.status & 0x1000) != 0;
            netd_block_missed = (update.status & 0x0800) != 0;
            is_blocked = (update.status & 0x0400) != 0;
            blacklisted_host = (update.status & 0x0200) != 0;
            blacklisted_ip = (update.status & 0x0100) != 0;
            last_seen = update.last_seen;
            tcp_flags = update.tcp_flags; // NOTE: only for root capture

            // see MitmReceiver.handlePayload
            if((status == ConnectionDescriptor.CONN_STATUS_CLOSED) && (decryption_error != null))
                status = ConnectionDescriptor.CONN_STATUS_CLIENT_ERROR;

            // with mitm we account the TLS payload length instead
            if(!mitm_decrypt)
                payload_length = update.payload_length;
        }
        if((update.update_type & ConnectionUpdate.UPDATE_INFO) != 0) {
            info = update.info;
            url = update.url;
            l7proto = update.l7proto;
            encrypted_l7 = ((update.info_flags & ConnectionUpdate.UPDATE_INFO_FLAG_ENCRYPTED_L7) != 0);
        }
        if((update.update_type & ConnectionUpdate.UPDATE_PAYLOAD) != 0) {
            // Payload for decryptable connections should be received via the MitmReceiver
            assert(decryption_ignored || isNotDecryptable() || KotSafe.getInstance().isDecryptingPcap());

            synchronized (this) {
                // Some pending updates with payload may still be received after low memory has been
                // triggered and payload disabled
                if(!CaptureService.isLowMemory()) {
                    if (update.payload_chunks != null) {
                        boolean has_http_log = (CaptureService.getHttpLog() != null);
                        int chunk_pos = payload_chunks.size();

                        for (PayloadChunk chunk: update.payload_chunks) {
                            if (has_http_log && (chunk.type == PayloadChunk.ChunkType.HTTP))
                                logHttpChunk(chunk, chunk_pos);

                            // NOTE: logHttpChunk may change the chunk type
                            // from HTTP to WEBSOCKET after detecting a websocket upgrade
                            // so this condition should be checked separately
                            if (chunk.type == PayloadChunk.ChunkType.WEBSOCKET)
                                has_websocket_data = true;

                            chunk_pos++;
                        }

                        payload_chunks.addAll(update.payload_chunks);
                    }
                    payload_truncated = update.payload_truncated;
                    internal_decrypt = update.payload_decrypted;
                }
            }
        }
    }

    // See HttpLog
    private void logHttpChunk(PayloadChunk chunk, int chunk_pos) {
        assert (chunk.type == PayloadChunk.ChunkType.HTTP);

        if (CaptureService.getHttpLog() == null)
            return;

        if (mHttpReqReassembly == null) {
            // use a lightweight reassembly, without dumping the payload
            mHttpReqReassembly = new HTTPReassembly(true, this, false);
            mHttpReplyReassembly = new HTTPReassembly(true, this, false);
            mPendingRequests = new LinkedList<>();
        }

        // will call onChunkReassembled
        if (chunk.is_sent) {
            if ((mFirstReqChunkPos == -1) && !chunk.isHttp2Rst())
                mFirstReqChunkPos = chunk_pos;
            mHttpReqReassembly.handleChunk(chunk);
        } else {
            if ((mFirstReplyChunkPos == -1) && !chunk.isHttp2Rst())
                mFirstReplyChunkPos = chunk_pos;
            mHttpReplyReassembly.handleChunk(chunk);
        }
    }

    public InetAddress getDstAddr() {
        try {
            return InetAddress.getByName(dst_ip);
        } catch (UnknownHostException e) {
            e.printStackTrace();
            return null;
        }
    }

    public InetAddress getSrcAddr() {
        try {
            return InetAddress.getByName(src_ip);
        } catch (UnknownHostException e) {
            e.printStackTrace();
            return null;
        }
    }

    public Status getStatus() {
        if(status >= CONN_STATUS_CLOSED) {
            switch(status) {
                case CONN_STATUS_CLOSED:
                case CONN_STATUS_RESET:
                    return Status.STATUS_CLOSED;
                case CONN_STATUS_UNREACHABLE:
                    return Status.STATUS_UNREACHABLE;
                default:
                    return Status.STATUS_ERROR;
            }
        }
        return Status.STATUS_ACTIVE;
    }

    public static String getStatusLabel(Status status, Context ctx) {
        int resid;

        switch(status) {
            case STATUS_ACTIVE: resid = R.string.conn_status_active; break;
            case STATUS_CLOSED: resid = R.string.conn_status_closed; break;
            case STATUS_UNREACHABLE: resid = R.string.conn_status_unreachable; break;
            default: resid = R.string.error;
        }

        return(ctx.getString(resid));
    }

    public String getStatusLabel(Context ctx) {
        return getStatusLabel(getStatus(), ctx);
    }

    public boolean isDns() {
        return (dst_port == 53 || src_port == 53 || dst_port == 5353 || src_port == 5353
                || (l7proto != null && (l7proto.equalsIgnoreCase("DNS") || l7proto.equalsIgnoreCase("MDNS"))));
    }

    public boolean matches(AppsResolver res, String filter) {
        filter = filter.toLowerCase();
        AppDescriptor app = res.getAppByUid(uid, 0);

        return(((info != null) && (info.contains(filter))) ||
                dst_ip.contains(filter) ||
                l7proto.toLowerCase().equals(filter) ||
                Integer.toString(uid).equals(filter) ||
                Integer.toString(dst_port).contains(filter) ||
                Integer.toString(src_port).equals(filter) ||
                ((app != null) && (app.matches(filter, true)))
        );
    }

    public DecryptionStatus getDecryptionStatus() {
        if(isCleartext())
            return DecryptionStatus.CLEARTEXT;
        else if(decryption_error != null)
            return DecryptionStatus.ERROR;
        else if(isNotDecryptable())
            return DecryptionStatus.NOT_DECRYPTABLE;
        else if(decryption_ignored || (KotSafe.getInstance().isDecryptingPcap() && !internal_decrypt))
            return DecryptionStatus.ENCRYPTED;
        else if(isDecrypted())
            return DecryptionStatus.DECRYPTED;
        else
            return DecryptionStatus.WAITING_DATA;
    }

    public static String getDecryptionStatusLabel(DecryptionStatus status, Context ctx) {
        int resid;

        switch (status) {
            case CLEARTEXT: resid = R.string.not_encrypted; break;
            case NOT_DECRYPTABLE: resid = R.string.not_decryptable; break;
            case DECRYPTED: resid = R.string.decrypted; break;
            case ENCRYPTED: resid = R.string.status_encrypted; break;
            case WAITING_DATA: resid = R.string.waiting_application_data; break;
            default: resid = R.string.error;
        }

        return(ctx.getString(resid));
    }

    public String getDecryptionStatusLabel(Context ctx) {
        return getDecryptionStatusLabel(getDecryptionStatus(), ctx);
    }

    public int getSentTcpFlags() {
        return (tcp_flags >> 8);
    }

    public int getRcvdTcpFlags() {
        return (tcp_flags & 0xFF);
    }

    public boolean isBlacklistedIp() { return blacklisted_ip; }
    public boolean isBlacklistedHost() { return blacklisted_host; }
    public boolean isBlacklisted() {
        return isBlacklistedIp() || isBlacklistedHost();
    }

    public void setPayloadTruncatedByAddon() {
        // only for the mitm addon
        assert(!isNotDecryptable());
        payload_truncated = true;
    }

    public boolean isPayloadTruncated() { return payload_truncated; }
    public boolean isPortMappingApplied() { return port_mapping_applied; }
    public boolean hasWebsocketData() { return has_websocket_data; }

    public boolean isMitmDecrypt()      { return mitm_decrypt; }
    public boolean isNotDecryptable()   { return !decryption_ignored && (encrypted_payload || !mitm_decrypt) && !KotSafe.getInstance().isDecryptingPcap(); }
    public boolean isDecrypted()        { return !decryption_ignored && !isNotDecryptable() && (mitm_decrypt || internal_decrypt) && (getNumPayloadChunks() > 0); }
    public boolean isCleartext()        { return !encrypted_payload && !encrypted_l7; }

    public synchronized int getNumPayloadChunks() { return payload_chunks.size(); }

    public synchronized @Nullable PayloadChunk getPayloadChunk(int idx) {
        if(getNumPayloadChunks() <= idx)
            return null;
        return payload_chunks.get(idx);
    }

    public synchronized void addPayloadChunkMitm(PayloadChunk chunk) {
        if (chunk.type == PayloadChunk.ChunkType.HTTP)
            logHttpChunk(chunk, payload_chunks.size());
        else if (chunk.type == PayloadChunk.ChunkType.WEBSOCKET)
            has_websocket_data = true;

        payload_chunks.add(chunk);
        payload_length += chunk.payload.length;
    }

    public synchronized void dropPayload() {
        payload_chunks.clear();
    }

    private synchronized boolean hasHttp(boolean is_sent) {
        for(PayloadChunk chunk: payload_chunks) {
            if(chunk.is_sent == is_sent)
                return (chunk.type == PayloadChunk.ChunkType.HTTP);
        }

        return false;
    }
    public boolean hasHttpRequest() { return hasHttp(true); }
    public boolean hasHttpResponse() { return hasHttp(false); }

    private synchronized PayloadChunk getHttpChunks(boolean is_sent, int firstChunkPos) {
        if((getNumPayloadChunks() == 0) || (firstChunkPos < 0))
            return null;

        // Need to wrap the chunk to set it from the lambda
        final AtomicReference<PayloadChunk> rv = new AtomicReference<>();
        HTTPReassembly reassembly = new HTTPReassembly(
                CaptureService.getCurPayloadMode() == Prefs.PayloadMode.FULL,
                rv::set
        );

        // Possibly reassemble/decode the request
        for (int i = firstChunkPos; i < payload_chunks.size(); i++) {
            PayloadChunk chunk = payload_chunks.get(i);

            if(chunk.is_sent == is_sent)
                reassembly.handleChunk(chunk);

            // Stop at the first reassembly/chunk
            if(rv.get() != null)
                break;
        }

        return rv.get();
    }

    private String getHttpAsString(boolean is_sent) {
        PayloadChunk reassembled = getHttpChunks(is_sent, 0);
        if (reassembled == null)
            return "";

        return new String(reassembled.payload, StandardCharsets.UTF_8);
    }

    public String getHttpRequest() { return getHttpAsString(true); }
    public String getHttpResponse() { return getHttpAsString(false); }

    public PayloadChunk getHttpRequestChunk(int firstChunkPos) { return getHttpChunks(true, firstChunkPos); }
    public PayloadChunk getHttpResponseChunk(int firstChunkPos) { return getHttpChunks(false, firstChunkPos); }

    @Override
    public void onChunkReassembled(PayloadChunk chunk) {
        if (chunk.type != PayloadChunk.ChunkType.HTTP)
            return;

        HttpLog httplog = CaptureService.getHttpLog();
        if (httplog == null)
            return;

        if (chunk.is_sent && !chunk.isHttp2Rst()) {
            HttpLog.HttpRequest request = new HttpLog.HttpRequest(this, mFirstReqChunkPos);
            request.host = !chunk.httpHost.isEmpty() ? chunk.httpHost : info;
            request.method = chunk.httpMethod;
            request.path = chunk.httpPath;
            request.query = chunk.httpQuery;
            request.bodyLength = chunk.httpBodyLength;
            request.streamId = chunk.stream_id;
            request.timestamp = chunk.timestamp;
            httplog.addHttpRequest(request);

            mPendingRequests.add(request);
            mFirstReqChunkPos = -1;
        } else {
            // match the reply to the request
            HttpLog.HttpRequest request = null;

            if (chunk.stream_id == 0) {
                // if HTTP/1, then the request is the first in the list
                if (!mPendingRequests.isEmpty())
                    request = mPendingRequests.remove(0);
            } else {
                // if HTTP/2, use the stream ID for the matching
                int idx = 0;
                for (HttpLog.HttpRequest req: mPendingRequests) {
                    if (req.streamId == chunk.stream_id)
                        break;

                    idx++;
                }

                if (idx < mPendingRequests.size())
                    request = mPendingRequests.remove(idx);
            }

            if (request != null) {
                if (!chunk.isHttp2Rst()) {
                    HttpLog.HttpReply reply = new HttpLog.HttpReply(request, mFirstReplyChunkPos);
                    reply.responseCode = chunk.httpResponseCode;
                    reply.responseStatus = chunk.httpResponseStatus;
                    reply.contentType = chunk.httpContentType;
                    reply.bodyLength = chunk.httpBodyLength;
                    request.reply = reply;

                    httplog.addHttpReply(reply);
                    mFirstReplyChunkPos = -1;
                } else {
                    request.httpRst = true;
                    Log.d(TAG, "Got RST: " + request.getUrl());
                }
            } else if (!chunk.is_sent) { // ignore HTTP requests with RST
                if (chunk.isHttp2Rst())
                    Log.w(TAG, "Unmatched HTTP RST (sent=" + chunk.is_sent + ", stream=" + chunk.stream_id + ")");
                else
                    Log.w(TAG, "Unmatched HTTP reply (sent=" + chunk.is_sent + ", stream=" + chunk.stream_id + ")");
            }
        }
    }

    public boolean hasSeenStart() {
        if((ipproto != 6 /* TCP */) || !CaptureService.isCapturingAsRoot())
            return true;

        return (getSentTcpFlags() & 0x2) != 0; // SYN
    }

    public String getBlockReasonLabel(Context ctx) {
        if (block_reason != null && !block_reason.isEmpty()) {
            return block_reason;
        }
        if (isBlacklistedHost() || isBlacklistedIp()) {
            if (info != null && (SecurityBlocklistManager.isOfficialDomain(info) || SecurityBlocklistManager.isSpeedTestOrDiagnosticDomain(info))) {
                return "Firewall: Rule Block";
            }
            try {
                if (ctx != null && info != null && !info.isEmpty()) {
                    AdBlockSubscriptionManager adMgr = AdBlockSubscriptionManager.getInstance(ctx);
                    if (adMgr != null && adMgr.isAdBlockEnabled() && adMgr.isBlocked(info)) {
                        return "Ads & Trackers Shield: Blocked ad/tracker service";
                    }
                }
            } catch (Exception ignored) {}
            return isBlacklistedHost() ? "Threat Intelligence: Malicious Domain" : "Threat Intelligence: Malicious IP";
        }
        if (is_blocked) {
            return "Blocked by Firewall Policy";
        }
        return "Allowed";
    }

    public String getBlockCategory() {
        if (!is_blocked && !isBlacklisted()) return "ALLOWED";
        if (block_type != null && !block_type.isEmpty()) {
            return block_type.toUpperCase();
        }
        if (info != null && (SecurityBlocklistManager.isOfficialDomain(info) || SecurityBlocklistManager.isSpeedTestOrDiagnosticDomain(info))) {
            return "FIREWALL";
        }
        String r = (block_reason != null) ? block_reason.toLowerCase() : "";
        if (r.contains("ad") || r.contains("track") || r.contains("telemetry") || r.contains("stevenblack") || r.contains("oisd")) {
            return "ADS";
        }
        if (r.contains("malware") || r.contains("malicious") || r.contains("c2") || isBlacklisted()) {
            return "MALICIOUS";
        }
        if (r.contains("phish")) {
            return "PHISHING";
        }
        if (r.contains("rate limit") || r.contains("flood guard")) {
            return "RATE_LIMIT";
        }
        if (r.contains("wifi") || r.contains("mobile") || r.contains("roaming") || r.contains("screen-off") || r.contains("firewall")) {
            return "FIREWALL";
        }
        return "POLICY";
    }

    @Override
    public @NonNull String toString() {
        return "[proto=" + ipproto + "/" + l7proto + "]: " + src_ip + ":" + src_port + " -> " +
                dst_ip + ":" + dst_port + " [" + uid + "] " + info;
    }
}
