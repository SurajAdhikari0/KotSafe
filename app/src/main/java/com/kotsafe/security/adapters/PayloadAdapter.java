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

package com.kotsafe.security.adapters;

import android.annotation.SuppressLint;
import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.CheckResult;
import androidx.annotation.NonNull;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.RecyclerView;

import com.kotsafe.security.CaptureService;
import com.kotsafe.security.HTTPReassembly;
import com.kotsafe.security.HttpLog;
import com.kotsafe.security.Log;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.ConnectionDescriptor;
import com.kotsafe.security.model.PayloadChunk;
import com.kotsafe.security.model.PayloadChunk.ChunkType;
import com.kotsafe.security.model.Prefs;
import com.google.android.material.button.MaterialButton;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.kotsafe.security.activities.HttpRepeaterActivity;

import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/* An adapter to show PayloadChunk items.
 * Each item is wrapped into an AdapterChunk. An item can either be collapsed or expanded.
 * Since the text of a chunk can be very long (hundreds of KB) and rendering it would freeze the UI,
 * it is split into pages of VISUAL_PAGE_SIZE. */
public class PayloadAdapter extends RecyclerView.Adapter<PayloadAdapter.PayloadViewHolder> implements HTTPReassembly.ReassemblyListener {
    private static final String TAG = "PayloadAdapter";
    public static final int COLLAPSE_CHUNK_SIZE = 1500;
    public static final int VISUAL_PAGE_SIZE = 4020; // must be a multiple of 67 to avoid splitting the hexdump
    private final LayoutInflater mLayoutInflater;
    private final ConnectionDescriptor mConn;
    private final Context mContext;
    private final ChunkType mMode;
    private int mHandledChunks;
    private final ArrayList<AdapterChunk> mUnrepliedHttpReqs = new ArrayList<>();
    private final ArrayList<AdapterChunk> mChunks = new ArrayList<>();
    private int mTotalPages = 0;
    private final HTTPReassembly mHttpReq;
    private final HTTPReassembly mHttpRes;
    private final boolean mSupportsFileDialog;
    private final PayloadChunk mSingleChunk;
    private boolean mShowAsPrintable;
    private ExportPayloadHandler mExportHandler;

    public interface ExportPayloadHandler {
        void exportPayload(String payload);
        void exportPayload(byte[] payload, String contentType, String fname);
    }

    /* if singleChunk is set, this adapter will only show that chunk */
    private PayloadAdapter(Context context, ConnectionDescriptor conn, ChunkType mode,
                          boolean showAsPrintable, PayloadChunk singleChunk) {
        mLayoutInflater = (LayoutInflater)context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
        mConn = conn;
        mContext = context;
        mMode = mode;
        mShowAsPrintable = showAsPrintable;
        mSupportsFileDialog = Utils.supportsFileDialog(context);
        mSingleChunk = singleChunk;

        if (mSingleChunk == null) {
            // Note: in minimal mode, only the first chunk is captured, so don't reassemble them
            boolean reassemble = (CaptureService.getCurPayloadMode() == Prefs.PayloadMode.FULL);

            // each direction must have its separate reassembly
            mHttpReq = new HTTPReassembly(reassemble, this);
            mHttpRes = new HTTPReassembly(reassemble, this);

            handleChunksAdded(mConn.getNumPayloadChunks());
        } else {
            mHttpReq = null;
            mHttpRes = null;

            if (mSingleChunk.payload.length > 0) {
                AdapterChunk chunk = new AdapterChunk(mSingleChunk, 0);
                mChunks.add(chunk);
                mTotalPages = chunk.getNumPages();
                notifyItemInserted(0);
            }
        }
    }

    public PayloadAdapter(Context context, ConnectionDescriptor conn, ChunkType mode,  boolean showAsPrintable) {
        this(context, conn, mode, showAsPrintable, null);
    }

    public PayloadAdapter(Context context, HttpLog.HttpRequest req, boolean show_reply) {
        this(context, req.conn, ChunkType.HTTP, true, getChunk(req, show_reply));
    }

    private static PayloadChunk getChunk(HttpLog.HttpRequest req, boolean show_reply) {
        PayloadChunk chunk = null;
        if (show_reply) {
            if (req.reply != null && req.reply.firstChunkPos >= 0)
                chunk = req.conn.getHttpResponseChunk(req.reply.firstChunkPos);
        } else if (req.firstChunkPos >= 0) {
            chunk = req.conn.getHttpRequestChunk(req.firstChunkPos);
        }

        if (chunk != null && chunk.payload != null && chunk.payload.length > 0)
            return chunk;

        // If raw chunk is not captured or reassembled (e.g. no dump, minimal mode, or TLS tunnel),
        // synthesize a clean, structured HTTP request or response so it can be inspected
        return show_reply ? synthesizeReplyChunk(req) : synthesizeRequestChunk(req);
    }

    public static PayloadChunk synthesizeRequestChunk(HttpLog.HttpRequest req) {
        StringBuilder sb = new StringBuilder();
        String method = (req.method != null && !req.method.isEmpty()) ? req.method : "GET";
        String path = (req.path != null && !req.path.isEmpty()) ? req.path : "/";
        if (req.query != null && !req.query.isEmpty())
            path += req.query;

        String host = (req.host != null && !req.host.isEmpty()) ? req.host :
                (req.conn != null && req.conn.info != null ? req.conn.info :
                        (req.conn != null && req.conn.dst_ip != null ? req.conn.dst_ip : ""));

        boolean isHttps = (req.conn != null && !req.conn.isCleartext()) ||
                (req.conn != null && req.conn.dst_port == 443) ||
                method.equalsIgnoreCase("CONNECT");

        if (method.equalsIgnoreCase("CONNECT")) {
            String targetHost = host;
            if (!targetHost.contains(":") && req.conn != null && req.conn.dst_port > 0)
                targetHost += ":" + req.conn.dst_port;

            sb.append("CONNECT ").append(targetHost).append(" HTTP/1.1\r\n");
            sb.append("Host: ").append(targetHost).append("\r\n");
            sb.append("User-Agent: KotSafe\r\n");
            sb.append("Proxy-Connection: keep-alive\r\n\r\n");

            if (req.conn != null) {
                sb.append(String.format(Locale.US,
                        "[Encrypted TLS Tunnel]\n• Transferred: %s sent, %s received\n• Remote Endpoint: %s:%d\n• Protocol: %s\n\n[Tip: Enable TLS Decryption in Settings to inspect cleartext payload]",
                        Utils.formatBytes(req.conn.sent_bytes),
                        Utils.formatBytes(req.conn.rcvd_bytes),
                        req.conn.dst_ip, req.conn.dst_port,
                        req.conn.l7proto != null ? req.conn.l7proto : "TLS"));
            }
        } else {
            sb.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
            if (!host.isEmpty())
                sb.append("Host: ").append(host).append("\r\n");
            sb.append("User-Agent: Mozilla/5.0 (Android; Mobile)\r\n");
            sb.append("Accept: */*\r\n");
            sb.append("Accept-Encoding: gzip, deflate\r\n");
            sb.append("Connection: keep-alive\r\n");
            if (req.bodyLength > 0)
                sb.append("Content-Length: ").append(req.bodyLength).append("\r\n");
            sb.append("\r\n");

            if (req.bodyLength > 0) {
                sb.append(String.format(Locale.US,
                        "[Request body: %d bytes (raw payload not buffered - enable Full Payload mode in Settings to inspect raw bytes)]",
                        req.bodyLength));
            } else if (isHttps) {
                sb.append("[Encrypted HTTPS traffic - enable TLS Decryption in Settings to inspect full body]");
            }
        }

        byte[] bytes = sb.toString().getBytes(StandardCharsets.UTF_8);
        PayloadChunk chunk = new PayloadChunk(bytes, ChunkType.HTTP, true, req.timestamp, req.streamId);
        chunk.httpMethod = method;
        chunk.httpHost = host;
        chunk.httpPath = req.path;
        chunk.httpQuery = req.query;
        chunk.httpBodyLength = (req.bodyLength > 0) ? req.bodyLength : bytes.length;
        return chunk;
    }

    public static PayloadChunk synthesizeReplyChunk(HttpLog.HttpRequest req) {
        StringBuilder sb = new StringBuilder();
        HttpLog.HttpReply reply = req.reply;

        int code = (reply != null && reply.responseCode > 0) ? reply.responseCode : 200;
        String status = (reply != null && reply.responseStatus != null && !reply.responseStatus.isEmpty())
                ? reply.responseStatus : (code == 200 ? "OK" : "HTTP Response");
        String contentType = (reply != null && reply.contentType != null && !reply.contentType.isEmpty())
                ? reply.contentType : "text/html; charset=UTF-8";
        int bodyLength = (reply != null) ? reply.bodyLength :
                (req.conn != null ? (int) Math.min(req.conn.rcvd_bytes, Integer.MAX_VALUE) : 0);

        boolean isConnect = req.method != null && req.method.equalsIgnoreCase("CONNECT");

        if (isConnect) {
            sb.append("HTTP/1.1 200 Connection Established\r\n");
            sb.append("Proxy-Agent: KotSafe\r\n\r\n");
            if (req.conn != null) {
                sb.append(String.format(Locale.US,
                        "[Encrypted TLS session established]\n• Received: %s\n• Remote Endpoint: %s:%d\n\n[Tip: Enable TLS Decryption in Settings to inspect decrypted responses]",
                        Utils.formatBytes(req.conn.rcvd_bytes),
                        req.conn.dst_ip, req.conn.dst_port));
            }
        } else {
            sb.append("HTTP/1.1 ").append(code).append(" ").append(status).append("\r\n");
            sb.append("Content-Type: ").append(contentType).append("\r\n");
            if (bodyLength > 0)
                sb.append("Content-Length: ").append(bodyLength).append("\r\n");
            sb.append("Connection: keep-alive\r\n\r\n");

            if (bodyLength > 0) {
                sb.append(String.format(Locale.US,
                        "[Response body: %s (raw payload not buffered - enable Full Payload mode in Settings to inspect raw content)]",
                        Utils.formatBytes(bodyLength)));
            } else if (reply == null) {
                sb.append("[Waiting for server response...]");
            }
        }

        byte[] bytes = sb.toString().getBytes(StandardCharsets.UTF_8);
        PayloadChunk chunk = new PayloadChunk(bytes, ChunkType.HTTP, false,
                (req.conn != null && req.conn.last_seen > 0) ? req.conn.last_seen : req.timestamp,
                req.streamId);
        chunk.httpResponseCode = code;
        chunk.httpResponseStatus = status;
        chunk.httpContentType = contentType;
        chunk.httpBodyLength = (bodyLength > 0) ? bodyLength : bytes.length;
        return chunk;
    }

    public void refreshHttpChunk(HttpLog.HttpRequest req, boolean show_reply) {
        PayloadChunk chunk = getChunk(req, show_reply);
        if (chunk == null || chunk.payload == null || chunk.payload.length == 0)
            return;

        if (mChunks.isEmpty()) {
            AdapterChunk newChunk = new AdapterChunk(chunk, 0);
            mChunks.add(newChunk);
            mTotalPages = newChunk.getNumPages();
            notifyItemInserted(0);
        } else {
            AdapterChunk oldChunk = mChunks.get(0);
            AdapterChunk newChunk = new AdapterChunk(chunk, 0);
            mTotalPages = mTotalPages - oldChunk.getNumPages() + newChunk.getNumPages();
            mChunks.set(0, newChunk);
            notifyItemChanged(0);
        }
    }

    public void setExportPayloadHandler(ExportPayloadHandler handler) {
        mExportHandler = handler;
    }

    static final int MAX_JSON_FORMAT_SIZE = 1024 * 1024;

    private static final Gson prettyGson = new GsonBuilder().setPrettyPrinting().create();

    static String formatHttpPayload(String text, String contentType) {
        if ((contentType == null) || !contentType.equals("application/json"))
            return text;
        if (text.length() > MAX_JSON_FORMAT_SIZE)
            return text;

        int sep = text.indexOf("\r\n\r\n");
        if ((sep < 0) || (sep + 4 >= text.length()))
            return text;

        String headers = text.substring(0, sep + 4);
        String body = text.substring(sep + 4);

        try {
            String pretty = prettyGson.toJson(JsonParser.parseString(body));
            return headers + pretty;
        } catch (JsonSyntaxException e) {
            return text;
        }
    }

    private class AdapterChunk {
        private final PayloadChunk mChunk;
        private String mTheText;
        private boolean mIsExpanded;
        private int mNumPages = 1;
        public final int incrId;

        AdapterChunk(PayloadChunk _chunk, int incr_id) {
            mChunk = _chunk;
            incrId = incr_id;
        }

        boolean canBeExpanded() {
            return mChunk.payload.length > COLLAPSE_CHUNK_SIZE;
        }

        boolean isExpanded() {
            return mIsExpanded;
        }

        int getNumPages() {
            return mNumPages;
        }

        PayloadChunk getPayloadChunk() {
            return mChunk;
        }

        @CheckResult
        private String makeText(boolean as_printable, boolean expanded) {
            int dump_len = expanded ? mChunk.payload.length : Math.min(mChunk.payload.length, COLLAPSE_CHUNK_SIZE);

            if(!as_printable)
                return Utils.hexdump(mChunk.payload, 0, dump_len);
            else
                return new String(mChunk.payload, 0, dump_len, StandardCharsets.UTF_8);
        }

        @CheckResult
        private String makeText() {
            String text = makeText(mShowAsPrintable, mIsExpanded);
            if (mShowAsPrintable && (mMode == ChunkType.HTTP))
                text = formatHttpPayload(text, mChunk.httpContentType);
            return text;
        }

        void expand() {
            mIsExpanded = true;
            mTheText = makeText();

            // round up div
            mNumPages = (mTheText.length() + VISUAL_PAGE_SIZE - 1) / VISUAL_PAGE_SIZE;
        }

        // collapses the item and returns the old number of pages
        void collapse() {
            mIsExpanded = false;
            mTheText = null;

            mNumPages = 1;
        }

        String getText(int start, int end) {
            if(mTheText == null)
                mTheText = makeText();

            if((start == 0) && (end >= mTheText.length() - 1)) {
                return mTheText;
            }

            return mTheText.substring(start, end);
        }

        String getExpandedText(boolean as_printable) {
            return makeText(as_printable, true);
        }

        Page getPage(int pageIdx) {
            assert(pageIdx < mNumPages);

            if(mTheText == null)
                mTheText = makeText();

            if(!mIsExpanded)
                return new Page(this, 0, mTheText.length() - 1, true);
            else
                return new Page(this, pageIdx * VISUAL_PAGE_SIZE,
                        Math.min(((pageIdx + 1) * VISUAL_PAGE_SIZE) - 1, mTheText.length() - 1),
                        pageIdx == (mNumPages - 1));
        }
    }

    private static class Page {
        AdapterChunk adaptChunk;
        int textStart;
        int textEnd;
        boolean isLast;

        Page(AdapterChunk _adaptChunk, int _textStart, int _textEnd, boolean _isLast) {
            adaptChunk = _adaptChunk;
            textStart = _textStart;
            textEnd = _textEnd;
            isLast = _isLast;
        }

        boolean isFirst() {
            return (textStart == 0);
        }

        String getText() {
            return adaptChunk.getText(textStart, textEnd);
        }
    }

    protected static class PayloadViewHolder extends RecyclerView.ViewHolder {
        View headerLine;
        View dumpBox;
        TextView header;
        TextView dump;
        TextView directionBadge;
        MaterialButton expandButton;
        MaterialButton copybutton;
        MaterialButton exportbutton;
        MaterialButton curlbutton;
        MaterialButton editResendButton;
        MaterialButton jwtbutton;
        MaterialButton protobufbutton;
        MaterialButton dohbutton;

        public PayloadViewHolder(View view) {
            super(view);

            headerLine = view.findViewById(R.id.header_line);
            header = view.findViewById(R.id.header);
            dump = view.findViewById(R.id.dump);
            dumpBox = view.findViewById(R.id.dump_box);
            directionBadge = view.findViewById(R.id.direction_badge);
            expandButton = view.findViewById(R.id.expand_button);
            copybutton = view.findViewById(R.id.copy_button);
            exportbutton = view.findViewById(R.id.export_button);
            curlbutton = view.findViewById(R.id.curl_button);
            editResendButton = view.findViewById(R.id.edit_resend_button);
            jwtbutton = view.findViewById(R.id.jwt_button);
            protobufbutton = view.findViewById(R.id.protobuf_button);
            dohbutton = view.findViewById(R.id.doh_button);
        }
    }

    @NonNull
    @Override
    public PayloadViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = mLayoutInflater.inflate(R.layout.payload_item, parent, false);
        PayloadViewHolder holder = new PayloadViewHolder(view);

        holder.expandButton.setOnClickListener(v -> {
            int pos = holder.getAbsoluteAdapterPosition();
            Page page = getItem(pos);

            if(page.adaptChunk.isExpanded()) {
                int numPages = page.adaptChunk.getNumPages();
                int firstPagePos = pos - (numPages - 1);
                page.adaptChunk.collapse();
                int newPages = page.adaptChunk.getNumPages();
                mTotalPages += (newPages - numPages);
                notifyItemChanged(firstPagePos);
                notifyItemRangeRemoved(firstPagePos + 1, numPages - 1);
            } else {
                int oldPages = page.adaptChunk.getNumPages();
                page.adaptChunk.expand();
                int newPages = page.adaptChunk.getNumPages();
                mTotalPages += (newPages - oldPages);
                notifyItemChanged(pos);
                notifyItemRangeInserted(pos + 1, page.adaptChunk.getNumPages() - 1);
            }
        });

        holder.copybutton.setOnClickListener(v -> handleCopyExportButtons(holder, false));
        holder.exportbutton.setOnClickListener(v -> handleCopyExportButtons(holder, true));
        holder.exportbutton.setVisibility(mSupportsFileDialog ? View.VISIBLE : View.GONE);
        if (holder.curlbutton != null) {
            holder.curlbutton.setOnClickListener(v -> {
                int pos = holder.getAbsoluteAdapterPosition();
                Page page = getItem(pos);
                if (page != null && page.adaptChunk != null) {
                    copyAsCurl(page.adaptChunk);
                }
            });
        }
        if (holder.editResendButton != null) {
            holder.editResendButton.setOnClickListener(v -> {
                int pos = holder.getAbsoluteAdapterPosition();
                Page page = getItem(pos);
                if (page != null && page.adaptChunk != null) {
                    openInRepeater(page.adaptChunk);
                }
            });
        }

        return holder;
    }

    private void copyAsCurl(AdapterChunk chunk) {
        if (chunk == null || chunk.mChunk == null)
            return;
        PayloadChunk p = chunk.mChunk;
        boolean isTls = (mConn != null) && (!mConn.isCleartext() || "TLS".equals(mConn.l7proto) || "HTTPS".equals(mConn.l7proto) || mConn.dst_port == 443);
        String scheme = isTls ? "https://" : "http://";
        String host = (p.httpHost != null && !p.httpHost.isEmpty()) ? p.httpHost : mConn.info;
        if (host == null || host.isEmpty())
            host = mConn.dst_ip;
        String path = (p.httpPath != null && !p.httpPath.isEmpty()) ? p.httpPath : "/";
        String method = (p.httpMethod != null && !p.httpMethod.isEmpty()) ? p.httpMethod : "GET";

        StringBuilder sb = new StringBuilder();
        sb.append("curl -X ").append(method).append(" '").append(scheme).append(host).append(path).append("'");

        String text = chunk.getExpandedText(true);
        if (text != null) {
            String[] lines = text.split("\r?\n");
            for (int i = 1; i < lines.length; i++) {
                String line = lines[i].trim();
                if (line.isEmpty()) break;
                if (line.contains(":")) {
                    sb.append(" -H '").append(line.replace("'", "\\'")).append("'");
                }
            }
        }
        Utils.copyToClipboard(mContext, sb.toString());
        Utils.showToast(mContext, R.string.copied);
    }

    private void openInRepeater(AdapterChunk chunk) {
        if (chunk == null || chunk.mChunk == null)
            return;
        PayloadChunk p = chunk.mChunk;
        boolean isTls = (mConn != null) && (!mConn.isCleartext() || "TLS".equals(mConn.l7proto) || "HTTPS".equals(mConn.l7proto) || mConn.dst_port == 443);
        String scheme = isTls ? "https://" : "http://";
        String host = (p.httpHost != null && !p.httpHost.isEmpty()) ? p.httpHost : (mConn != null ? mConn.info : "");
        if (host == null || host.isEmpty())
            host = (mConn != null) ? mConn.dst_ip : "localhost";
        String path = (p.httpPath != null && !p.httpPath.isEmpty()) ? p.httpPath : "/";
        String method = (p.httpMethod != null && !p.httpMethod.isEmpty()) ? p.httpMethod : "GET";
        String fullUrl = scheme + host + path;

        String headers = "";
        String body = "";
        String text = chunk.getExpandedText(true);
        if (text != null) {
            int crlf2 = text.indexOf("\r\n\r\n");
            if (crlf2 != -1) {
                String rawHeaders = text.substring(0, crlf2);
                int firstLineBreak = rawHeaders.indexOf("\r\n");
                if (firstLineBreak != -1 && firstLineBreak + 2 < rawHeaders.length()) {
                    headers = rawHeaders.substring(firstLineBreak + 2).trim();
                } else {
                    headers = rawHeaders.trim();
                }
                body = text.substring(crlf2 + 4);
            } else {
                int firstLineBreak = text.indexOf("\r\n");
                if (firstLineBreak != -1 && firstLineBreak + 2 < text.length()) {
                    headers = text.substring(firstLineBreak + 2).trim();
                } else {
                    headers = text.trim();
                }
            }
        }

        Intent intent = HttpRepeaterActivity.createIntent(mContext, method, fullUrl, headers, body);
        mContext.startActivity(intent);
    }

    private void handleCopyExportButtons(PayloadViewHolder holder, boolean is_export) {
        if(is_export && (mExportHandler == null))
            return;

        int payload_pos = holder.getAbsoluteAdapterPosition();
        int title = is_export ? R.string.export_ellipsis : R.string.copy_action;
        int positive_action = is_export ? R.string.export_action : R.string.copy_to_clipboard;

        AdapterChunk chunk = getItem(payload_pos).adaptChunk;
        if (chunk == null)
            return;

        if(mMode == ChunkType.HTTP) {
            String payload = chunk.getExpandedText(true);
            int crlf_pos = payload.indexOf("\r\n\r\n");
            String content_type = ((chunk.mChunk.httpContentType != null) && (!chunk.mChunk.httpContentType.isEmpty())) ?
                    chunk.mChunk.httpContentType : "text/plain";

            Log.d(TAG, "Export body content type: " + content_type);

            String fname = "";
            if (chunk.mChunk.is_sent && (chunk.mChunk.httpPath != null))
                fname = chunk.mChunk.httpPath;
            else if (payload_pos > 0) {
                // Try to match the HTTP request, to determine the file name
                AdapterChunk req_chunk = getItem(payload_pos - 1).adaptChunk;
                if (req_chunk.mChunk.is_sent && (req_chunk.mChunk.httpPath != null))
                    fname = req_chunk.mChunk.httpPath;
            }

            if (!fname.isEmpty()) {
                int last_slash = fname.lastIndexOf('/');
                if (last_slash >= 0)
                    fname = fname.substring(last_slash + 1);
            }

            if (fname.contains("."))
                Log.d(TAG, "File name: " + fname);
            else
                fname = "";

            String filename = fname;

            boolean has_body = (crlf_pos > 0) && (crlf_pos < (payload.length() - 4));
            if (!has_body) {
                // only HTTP headers
                if (is_export) {
                    if (mExportHandler != null)
                        mExportHandler.exportPayload(payload);
                } else
                    Utils.copyToClipboard(mContext, payload);
                return;
            }

            String[] choices = {
                    mContext.getString(R.string.headers),
                    mContext.getString(R.string.body),
                    mContext.getString(R.string.both),
            };

            AlertDialog.Builder builder = new AlertDialog.Builder(mContext);
            builder.setTitle(title);
            builder.setSingleChoiceItems(choices, 1, (dialogInterface, i) -> {});
            builder.setNeutralButton(R.string.cancel_action, (dialogInterface, i) -> {});
            builder.setPositiveButton(positive_action, (dialogInterface, i) -> {
                int choice = ((AlertDialog)dialogInterface).getListView().getCheckedItemPosition();
                String to_copy = payload;

                if (choice != 2) {
                    if (choice == 0 /* Headers */)
                        to_copy = to_copy.substring(0, crlf_pos);
                    else /* body */
                        to_copy = to_copy.substring(crlf_pos + 4);
                }

                if (is_export) {
                    if (mExportHandler != null) {
                        boolean only_body = (choice == 1);

                        if (only_body) {
                            // export the raw body bytes
                            byte[] payload_bytes = chunk.mChunk.payload;

                            if (crlf_pos < (payload_bytes.length - 4))
                                payload_bytes = Arrays.copyOfRange(payload_bytes, crlf_pos + 4, payload_bytes.length);

                            mExportHandler.exportPayload(payload_bytes, content_type, filename);
                        } else
                            mExportHandler.exportPayload(to_copy);
                    }
                } else
                    Utils.copyToClipboard(mContext, to_copy);
            });
            builder.create().show();
        } else {
            List<String> choices = new ArrayList<>(Arrays.asList(
                    mContext.getString(R.string.text),
                    mContext.getString(R.string.hexdump)
            ));
            if (is_export)
                choices.add(mContext.getString(R.string.raw_bytes));

            AlertDialog.Builder builder = new AlertDialog.Builder(mContext);
            builder.setTitle(title);
            builder.setSingleChoiceItems(choices.toArray(new String[]{}), mShowAsPrintable ? 0 : 1, (dialogInterface, i) -> {});

            builder.setNeutralButton(R.string.cancel_action, (dialogInterface, i) -> {});
            builder.setPositiveButton(positive_action, (dialogInterface, i) -> {
                int choice = ((AlertDialog)dialogInterface).getListView().getCheckedItemPosition();

                if (choice == 2 /* raw bytes */) {
                    assert (is_export);

                    if (mExportHandler != null)
                        mExportHandler.exportPayload(chunk.mChunk.payload, "application/octet-stream", "");
                } else {
                    String payload = getItem(payload_pos).adaptChunk.getExpandedText(choice == 0);

                    if (is_export) {
                        if (mExportHandler != null)
                            mExportHandler.exportPayload(payload);
                    } else
                        Utils.copyToClipboard(mContext, payload);
                }
            });
            builder.create().show();
        }
    }

    private String getHeaderTag(PayloadChunk chunk) {
        if(mMode == ChunkType.HTTP)
            return (chunk.is_sent) ? mContext.getString(R.string.request) : mContext.getString(R.string.response);
        else
            return chunk.is_sent ? mContext.getString(R.string.tx_direction) : mContext.getString(R.string.rx_direction);
    }

    @Override
    public void onBindViewHolder(@NonNull PayloadViewHolder holder, int position) {
        Page page = getItem(position);
        PayloadChunk chunk = page.adaptChunk.getPayloadChunk();

        if(page.isFirst()) {
            holder.headerLine.setVisibility(View.VISIBLE);

            Locale locale = Utils.getPrimaryLocale(mContext);
            String formattedTstamp = (new SimpleDateFormat("HH:mm:ss.SSS", locale)).format(new Date(chunk.timestamp));

            String formattedBytes;
            if (mMode == ChunkType.HTTP)
                formattedBytes = Utils.formatBytes((chunk.httpBodyLength > 0) ? chunk.httpBodyLength : chunk.payload.length);
            else
                formattedBytes = Utils.formatBytes(chunk.payload.length);

            if (holder.directionBadge != null) {
                if (chunk.is_sent) {
                    holder.directionBadge.setText(mMode == ChunkType.HTTP ? "REQUEST" : "TX");
                    holder.directionBadge.setBackgroundResource(R.drawable.badge_pill_tx);
                    holder.directionBadge.setTextColor(ContextCompat.getColor(mContext, R.color.badgeTxFg));
                } else {
                    holder.directionBadge.setText(mMode == ChunkType.HTTP ? "RESPONSE" : "RX");
                    holder.directionBadge.setBackgroundResource(R.drawable.badge_pill_rx);
                    holder.directionBadge.setTextColor(ContextCompat.getColor(mContext, R.color.badgeRxFg));
                }
            }

            if (holder.curlbutton != null) {
                holder.curlbutton.setVisibility((mMode == ChunkType.HTTP && chunk.is_sent) ? View.VISIBLE : View.GONE);
            }

            if (holder.editResendButton != null) {
                holder.editResendButton.setVisibility((mMode == ChunkType.HTTP && chunk.is_sent) ? View.VISIBLE : View.GONE);
            }

            if (holder.jwtbutton != null) {
                String text = page.adaptChunk.getExpandedText(true);
                com.kotsafe.security.decoders.JwtDecoder.JwtTokenInfo jwtInfo =
                        com.kotsafe.security.decoders.JwtDecoder.findAndParseJwt(text);

                if (jwtInfo != null) {
                    holder.jwtbutton.setVisibility(View.VISIBLE);
                    holder.jwtbutton.setOnClickListener(v -> {
                        if (mContext instanceof androidx.fragment.app.FragmentActivity fa) {
                            com.kotsafe.security.views.JwtInspectorDialog.newInstance(jwtInfo.rawToken)
                                    .show(fa.getSupportFragmentManager(), com.kotsafe.security.views.JwtInspectorDialog.TAG);
                        }
                    });
                } else {
                    holder.jwtbutton.setVisibility(View.GONE);
                }
            }

            byte[] bodyBytes = extractBodyBytes(chunk);
            String dohBase64 = extractDohBase64Param(chunk);

            if (holder.dohbutton != null) {
                boolean isDoh = (dohBase64 != null) ||
                        (chunk.httpContentType != null && chunk.httpContentType.contains("application/dns-message")) ||
                        (bodyBytes != null && com.kotsafe.security.decoders.DohDecoder.decode(bodyBytes) != null);

                if (isDoh) {
                    holder.dohbutton.setVisibility(View.VISIBLE);
                    holder.dohbutton.setOnClickListener(v -> {
                        if (mContext instanceof androidx.fragment.app.FragmentActivity fa) {
                            if (dohBase64 != null) {
                                com.kotsafe.security.views.DohInspectorDialog.newInstanceFromBase64Url(dohBase64)
                                        .show(fa.getSupportFragmentManager(), com.kotsafe.security.views.DohInspectorDialog.TAG);
                            } else if (bodyBytes != null) {
                                com.kotsafe.security.views.DohInspectorDialog.newInstance(bodyBytes)
                                        .show(fa.getSupportFragmentManager(), com.kotsafe.security.views.DohInspectorDialog.TAG);
                            }
                        }
                    });
                } else {
                    holder.dohbutton.setVisibility(View.GONE);
                }
            }

            if (holder.protobufbutton != null) {
                boolean isProto = bodyBytes != null && bodyBytes.length >= 2 && (
                        (chunk.httpContentType != null && (chunk.httpContentType.contains("application/grpc") ||
                                chunk.httpContentType.contains("application/x-protobuf") ||
                                chunk.httpContentType.contains("application/protobuf"))) ||
                                (com.kotsafe.security.decoders.ProtobufDecoder.detectAndDecode(bodyBytes) != null));

                if (isProto) {
                    holder.protobufbutton.setVisibility(View.VISIBLE);
                    holder.protobufbutton.setOnClickListener(v -> {
                        if (mContext instanceof androidx.fragment.app.FragmentActivity fa) {
                            com.kotsafe.security.views.ProtobufInspectorDialog.newInstance(bodyBytes)
                                    .show(fa.getSupportFragmentManager(), com.kotsafe.security.views.ProtobufInspectorDialog.TAG);
                        }
                    });
                } else {
                    holder.protobufbutton.setVisibility(View.GONE);
                }
            }

            if (mSingleChunk == null)
                holder.header.setText(String.format(locale,
                        "#%d • %s • %s", page.adaptChunk.incrId + 1,
                        formattedTstamp, formattedBytes));
            else
                holder.header.setText(String.format(locale,
                        "%s • %s",
                        formattedTstamp, formattedBytes));
        } else
            holder.headerLine.setVisibility(View.GONE);

        if(page.isLast && page.adaptChunk.canBeExpanded()) {
            holder.expandButton.setVisibility(View.VISIBLE);
            holder.expandButton.setRotation(page.adaptChunk.isExpanded() ? 180 : 0);
        } else
            holder.expandButton.setVisibility(View.GONE);

        holder.dump.setText(page.getText());
        holder.dumpBox.setBackgroundResource(R.drawable.payload_box_inner_bg);
        holder.dump.setTextColor(ContextCompat.getColor(mContext, chunk.is_sent ? R.color.badgeTxFg : R.color.metricTextPrimary));
    }

    @Override
    public int getItemCount() {
        return mTotalPages;
    }

    private void recomputeTotalPages() {
        int count = 0;
        for (AdapterChunk aChunk : mChunks) {
            count += aChunk.getNumPages();
        }
        mTotalPages = count;
    }

    public Page getItem(int pos) {
        if(pos < 0)
            return null;

        int count = 0;
        int i;

        // Find the AdapterChunk for the given page pos
        for(i=0; i < mChunks.size(); i++) {
            AdapterChunk aChunk = mChunks.get(i);
            int new_count = count + aChunk.getNumPages();

            if((pos >= count) && (pos < new_count))
                break;

            count = new_count;
        }

        if(i >= mChunks.size())
            return null;

        int pageIdx = pos - count;
        return mChunks.get(i).getPage(pageIdx);
    }

    @SuppressLint("NotifyDataSetChanged")
    public void setDisplayAsPrintableText(boolean asText) {
        if(mShowAsPrintable != asText) {
            mShowAsPrintable = asText;

            // Chunk pagination depends on the displayed data length, collapsing everything is simpler
            // than handling individual changes
            for(AdapterChunk chunk: mChunks)
                chunk.collapse(); // resets the chunk text
            recomputeTotalPages();
            notifyDataSetChanged();
        }
    }

    private int getAdapterPosition(AdapterChunk chunk) {
        int i;
        int count = 0;

        for(i=0; i < mChunks.size(); i++) {
            AdapterChunk aChunk = mChunks.get(i);
            if(aChunk == chunk)
                break;

            count += aChunk.getNumPages();
        }

        return count;
    }

    public void handleChunksAdded(int tot_chunks) {
        boolean readingFromPcap = CaptureService.isReadingFromPcapFile();

        for(int i = mHandledChunks; i < tot_chunks; i++) {
            PayloadChunk chunk = mConn.getPayloadChunk(i);
            if(chunk == null)
                continue;

            // when reading from pcap, websocket data must be extracted from HTTP chunks
            boolean websocketFromHttp = readingFromPcap &&
                    (mMode == ChunkType.WEBSOCKET) &&
                    (chunk.type != ChunkType.RAW);

            // Exclude unrelated chunks
            if((mMode != ChunkType.RAW) && (mMode != chunk.type) && !websocketFromHttp)
                continue;

            if((mMode == ChunkType.HTTP) || websocketFromHttp) {
                // will call onChunkReassembled
                if(chunk.is_sent)
                    mHttpReq.handleChunk(chunk);
                else
                    mHttpRes.handleChunk(chunk);
            } else {
                AdapterChunk adapterChunk = new AdapterChunk(chunk, mChunks.size());
                int insertPos = mTotalPages;
                mChunks.add(adapterChunk);
                int pages = adapterChunk.getNumPages();
                mTotalPages += pages;
                if (pages == 1) {
                    notifyItemInserted(insertPos);
                } else {
                    notifyItemRangeInserted(insertPos, pages);
                }
            }
        }

        mHandledChunks = tot_chunks;
    }

    private AdapterChunk findMatchingRequest(PayloadChunk chunk) {
        if (mUnrepliedHttpReqs.isEmpty())
            return null;

        if (chunk.stream_id == 0) {
            // HTTP/1: FIFO matching
            return mUnrepliedHttpReqs.get(0);
        } else {
            // HTTP/2: match by stream ID
            for (AdapterChunk req : mUnrepliedHttpReqs) {
                if (req.mChunk.stream_id == chunk.stream_id)
                    return req;
            }
        }

        return null;
    }

    @SuppressLint("DefaultLocale")
    @Override
    public void onChunkReassembled(PayloadChunk chunk) {
        if((mMode != ChunkType.RAW) && (mMode != chunk.type))
            // unrelated chunk (mainly for HTTP data before Websocket)
            return;

        AdapterChunk adapterChunk = new AdapterChunk(chunk, mChunks.size());
        int adapterPos = getItemCount();
        int insertPos = mChunks.size();
        boolean is_http2_rst = chunk.isHttp2Rst();

        // Need to determine where to add the chunk. If HTTP request, always add it to the bottom.
        // If HTTP reply/reset, it should be added right after the matching un-replied HTTP request
        if(!chunk.is_sent || is_http2_rst) {
            AdapterChunk matchedReq = findMatchingRequest(chunk);

            if (matchedReq != null) {
                int reqPos = mChunks.indexOf(matchedReq);
                assert(reqPos >= 0);

                if (!is_http2_rst) {
                    insertPos = reqPos + 1;
                    adapterPos = getAdapterPosition(matchedReq) + matchedReq.getNumPages();
                    Log.d(TAG, String.format("chunk #%d reply of #%d at %d", adapterChunk.incrId, matchedReq.incrId, insertPos));
                } else
                    Log.d(TAG, String.format("chunk #%d reset of #%d", adapterChunk.incrId, matchedReq.incrId));

                mUnrepliedHttpReqs.remove(matchedReq);
            }
        } else if(!is_http2_rst)
            mUnrepliedHttpReqs.add(adapterChunk);

        if (!is_http2_rst) {
            mChunks.add(insertPos, adapterChunk);
            int pages = adapterChunk.getNumPages();
            mTotalPages += pages;
            if (pages == 1) {
                notifyItemInserted(adapterPos);
            } else {
                notifyItemRangeInserted(adapterPos, pages);
            }
        }
    }

    private static byte[] extractBodyBytes(PayloadChunk chunk) {
        if (chunk == null || chunk.payload == null || chunk.payload.length == 0) return null;
        byte[] data = chunk.payload;
        if (chunk.type == ChunkType.HTTP) {
            for (int i = 0; i < data.length - 3; i++) {
                if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' && data[i + 3] == '\n') {
                    return Arrays.copyOfRange(data, i + 4, data.length);
                }
            }
        }
        return data;
    }

    private static String extractDohBase64Param(PayloadChunk chunk) {
        if (chunk == null || chunk.httpPath == null) return null;
        int idx = chunk.httpPath.indexOf("dns=");
        if (idx >= 0) {
            String sub = chunk.httpPath.substring(idx + 4);
            int amp = sub.indexOf('&');
            if (amp >= 0) sub = sub.substring(0, amp);
            return sub;
        }
        return null;
    }
}
