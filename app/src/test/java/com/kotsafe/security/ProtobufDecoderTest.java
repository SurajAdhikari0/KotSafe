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

package com.kotsafe.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.kotsafe.security.decoders.ProtobufDecoder;
import com.kotsafe.security.decoders.ProtobufDecoder.ProtobufResult;

import org.junit.Test;

public class ProtobufDecoderTest {

    @Test
    public void testVarintDecode() {
        // Field 1, wireType 0 (varint), value 150 (0x96 0x01)
        // Tag = (1 << 3) | 0 = 8 = 0x08
        byte[] payload = new byte[] {0x08, (byte) 0x96, 0x01};

        ProtobufResult res = ProtobufDecoder.detectAndDecode(payload);
        assertNotNull(res);
        assertFalse(res.isGrpc);
        assertEquals(1, res.totalFields);
        assertTrue(res.jsonTree.has("1"));
        assertEquals(150, res.jsonTree.get("1").getAsLong());
    }

    @Test
    public void testStringLengthDelimitedDecode() {
        // Field 2, wireType 2 (length delimited), length 7, "testing"
        // Tag = (2 << 3) | 2 = 18 = 0x12
        byte[] payload = new byte[] {
                0x12, 0x07, 't', 'e', 's', 't', 'i', 'n', 'g'
        };

        ProtobufResult res = ProtobufDecoder.detectAndDecode(payload);
        assertNotNull(res);
        assertFalse(res.isGrpc);
        assertEquals(1, res.totalFields);
        assertTrue(res.jsonTree.has("2"));
        assertEquals("testing", res.jsonTree.get("2").getAsString());
    }

    @Test
    public void testGrpcFrameDetectionAndDecode() {
        // gRPC frame header:
        // byte 0: 0x00 (uncompressed)
        // bytes 1-4: big-endian length = 3
        // bytes 5-7: Protobuf payload {0x08, 0x96, 0x01} (field 1 = 150)
        byte[] grpcFrame = new byte[] {
                0x00, 0x00, 0x00, 0x00, 0x03,
                0x08, (byte) 0x96, 0x01
        };

        ProtobufResult res = ProtobufDecoder.detectAndDecode(grpcFrame);
        assertNotNull(res);
        assertTrue(res.isGrpc);
        assertFalse(res.isCompressed);
        assertEquals(1, res.totalFields);
        assertTrue(res.jsonTree.has("1"));
        assertEquals(150, res.jsonTree.get("1").getAsLong());
    }

    @Test
    public void testNestedProtobufDecode() {
        // Inner message: Field 1 = 42 -> 0x08, 0x2A
        // Outer message: Field 3 (wireType 2, len 2), value = {0x08, 0x2A}
        // Tag = (3 << 3) | 2 = 26 = 0x1A
        byte[] payload = new byte[] {
                0x1A, 0x02, 0x08, 0x2A
        };

        ProtobufResult res = ProtobufDecoder.detectAndDecode(payload);
        assertNotNull(res);
        assertTrue(res.jsonTree.has("3"));
        assertTrue(res.jsonTree.get("3").isJsonObject());
        assertEquals(42, res.jsonTree.get("3").getAsJsonObject().get("1").getAsLong());
    }

    @Test
    public void testInvalidBytesReturnNull() {
        assertNull(ProtobufDecoder.detectAndDecode(null));
        assertNull(ProtobufDecoder.detectAndDecode(new byte[0]));
        assertNull(ProtobufDecoder.detectAndDecode(new byte[] {0x01}));
    }
}
