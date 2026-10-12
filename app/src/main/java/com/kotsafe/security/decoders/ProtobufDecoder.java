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
 *
 * Copyright 2026 - KotSafe
 */

package com.kotsafe.security.decoders;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Raw Protocol Buffers (Protobuf) & gRPC wire-format decoder.
 * Unpacks binary protobuf payloads into structured, readable JSON without requiring .proto schema files.
 */
public class ProtobufDecoder {
    private static final String TAG = "ProtobufDecoder";
    private static final Gson GSON_PRETTY = new GsonBuilder().setPrettyPrinting().create();

    public static final int WIRE_VARINT = 0;
    public static final int WIRE_FIXED64 = 1;
    public static final int WIRE_LENGTH_DELIMITED = 2;
    public static final int WIRE_START_GROUP = 3;
    public static final int WIRE_END_GROUP = 4;
    public static final int WIRE_FIXED32 = 5;

    public static class ProtobufResult {
        public final boolean isGrpc;
        public final boolean isCompressed;
        public final int totalFields;
        public final JsonObject jsonTree;
        public final String prettyJson;
        public final String rawHex;
        public final int payloadSize;

        public ProtobufResult(boolean isGrpc, boolean isCompressed, int totalFields,
                              JsonObject jsonTree, String prettyJson, String rawHex, int payloadSize) {
            this.isGrpc = isGrpc;
            this.isCompressed = isCompressed;
            this.totalFields = totalFields;
            this.jsonTree = jsonTree;
            this.prettyJson = prettyJson;
            this.rawHex = rawHex;
            this.payloadSize = payloadSize;
        }
    }

    /**
     * Checks if the binary payload is a gRPC frame or raw Protobuf message, and decodes it.
     */
    @Nullable
    public static ProtobufResult detectAndDecode(@Nullable byte[] data) {
        if (data == null || data.length < 2) return null;

        // 1. Check if it is a gRPC frame (5-byte prefix: 1 byte compressed flag, 4 bytes big-endian length)
        if (data.length >= 5) {
            byte compFlag = data[0];
            if (compFlag == 0x00 || compFlag == 0x01) {
                int grpcLen = ((data[1] & 0xFF) << 24) |
                        ((data[2] & 0xFF) << 16) |
                        ((data[3] & 0xFF) << 8) |
                        (data[4] & 0xFF);

                if (grpcLen > 0 && grpcLen == (data.length - 5)) {
                    byte[] grpcPayload = Arrays.copyOfRange(data, 5, data.length);
                    ProtobufResult res = decodeRaw(grpcPayload, 0, true, compFlag == 0x01);
                    if (res != null) return res;
                }
            }
        }

        // 2. Try raw Protobuf decode
        return decodeRaw(data, 0, false, false);
    }

    @Nullable
    private static ProtobufResult decodeRaw(@NonNull byte[] data, int depth, boolean isGrpc, boolean isCompressed) {
        if (data.length == 0) return null;

        ByteBuffer buffer = ByteBuffer.wrap(data);
        buffer.order(ByteOrder.LITTLE_ENDIAN);

        JsonObject root = new JsonObject();
        int fieldCount = 0;

        try {
            while (buffer.hasRemaining()) {
                long key = readVarint(buffer);
                if (key < 0) return null;

                int wireType = (int) (key & 0x07);
                int fieldNumber = (int) (key >>> 3);

                if (fieldNumber <= 0 || fieldNumber > 536870911) {
                    return null; // Invalid protobuf field tag
                }

                String fieldKey = String.valueOf(fieldNumber);
                JsonElement element;

                switch (wireType) {
                    case WIRE_VARINT: {
                        long val = readVarint(buffer);
                        element = new JsonPrimitive(val);
                        fieldCount++;
                        break;
                    }
                    case WIRE_FIXED64: {
                        if (buffer.remaining() < 8) return null;
                        long val = buffer.getLong();
                        double asDouble = Double.longBitsToDouble(val);
                        if (!Double.isNaN(asDouble) && !Double.isInfinite(asDouble) && Math.abs(asDouble) > 1e-10 && Math.abs(asDouble) < 1e15) {
                            element = new JsonPrimitive(asDouble);
                        } else {
                            element = new JsonPrimitive(val);
                        }
                        fieldCount++;
                        break;
                    }
                    case WIRE_LENGTH_DELIMITED: {
                        long len = readVarint(buffer);
                        if (len < 0 || len > buffer.remaining() || len > (10 * 1024 * 1024)) return null;

                        byte[] bytes = new byte[(int) len];
                        buffer.get(bytes);

                        // Try recursive sub-message decode if depth allows
                        JsonElement subMessage = null;
                        if (depth < 6 && bytes.length > 0) {
                            subMessage = tryDecodeSubMessage(bytes, depth + 1);
                        }

                        if (subMessage != null) {
                            element = subMessage;
                        } else if (isUtf8Printable(bytes)) {
                            element = new JsonPrimitive(new String(bytes, StandardCharsets.UTF_8));
                        } else {
                            element = new JsonPrimitive("0x" + bytesToHex(bytes));
                        }
                        fieldCount++;
                        break;
                    }
                    case WIRE_FIXED32: {
                        if (buffer.remaining() < 4) return null;
                        int val = buffer.getInt();
                        float asFloat = Float.intBitsToFloat(val);
                        if (!Float.isNaN(asFloat) && !Float.isInfinite(asFloat) && Math.abs(asFloat) > 1e-6 && Math.abs(asFloat) < 1e9) {
                            element = new JsonPrimitive(asFloat);
                        } else {
                            element = new JsonPrimitive(val);
                        }
                        fieldCount++;
                        break;
                    }
                    case WIRE_START_GROUP:
                    case WIRE_END_GROUP:
                        // Groups are deprecated in proto3, ignore / stop
                        return null;
                    default:
                        return null; // Unknown wire type
                }

                // Add to root object (repeated fields wrapped in array)
                if (root.has(fieldKey)) {
                    JsonElement existing = root.get(fieldKey);
                    if (existing.isJsonArray()) {
                        existing.getAsJsonArray().add(element);
                    } else {
                        JsonArray arr = new JsonArray();
                        arr.add(existing);
                        arr.add(element);
                        root.add(fieldKey, arr);
                    }
                } else {
                    root.add(fieldKey, element);
                }
            }

            if (fieldCount == 0) return null;

            String pretty = GSON_PRETTY.toJson(root);
            String hex = bytesToHex(data);
            return new ProtobufResult(isGrpc, isCompressed, fieldCount, root, pretty, hex, data.length);
        } catch (Exception e) {
            return null;
        }
    }

    @Nullable
    private static JsonElement tryDecodeSubMessage(@NonNull byte[] bytes, int depth) {
        try {
            ProtobufResult sub = decodeRaw(bytes, depth, false, false);
            if (sub != null && sub.totalFields > 0) {
                return sub.jsonTree;
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private static long readVarint(ByteBuffer buffer) {
        long result = 0;
        int shift = 0;
        while (buffer.hasRemaining() && shift < 64) {
            byte b = buffer.get();
            result |= (long) (b & 0x7F) << shift;
            if ((b & 0x80) == 0) {
                return result;
            }
            shift += 7;
        }
        return -1; // malformed varint
    }

    private static boolean isUtf8Printable(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return false;
        try {
            String str = new String(bytes, StandardCharsets.UTF_8);
            if (!str.equals(new String(str.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8))) {
                return false;
            }
            int printable = 0;
            for (char c : str.toCharArray()) {
                if (c == '\r' || c == '\n' || c == '\t' || (c >= 32 && c <= 126)) {
                    printable++;
                }
            }
            return ((double) printable / str.length()) >= 0.85;
        } catch (Exception e) {
            return false;
        }
    }

    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
}
