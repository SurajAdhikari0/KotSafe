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

package com.kotsafe.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.kotsafe.security.decoders.HttpsDecoder;

import org.junit.Test;

import java.nio.charset.StandardCharsets;

public class HttpsDecoderTest {

    @Test
    public void testHttp1RequestDecoding() {
        String rawRequest = "GET /api/v1/users?page=1 HTTP/1.1\r\n" +
                "Host: example.com\r\n" +
                "User-Agent: Mozilla/5.0 Android\r\n" +
                "Accept: application/json\r\n" +
                "Authorization: Bearer test_token\r\n\r\n";

        byte[] payload = rawRequest.getBytes(StandardCharsets.UTF_8);
        assertTrue(HttpsDecoder.isHttpsOrHttp(payload));

        HttpsDecoder.DecodedHttps decoded = HttpsDecoder.decode(payload);
        assertNotNull(decoded);
        assertEquals(HttpsDecoder.ProtocolType.HTTP_1_1_REQUEST, decoded.type);
        assertEquals("GET", decoded.method);
        assertEquals("https://example.com/api/v1/users?page=1", decoded.pathOrUrl);
        assertEquals("example.com", decoded.sniHost);
        assertEquals("Mozilla/5.0 Android", decoded.headers.get("User-Agent"));
        assertTrue(decoded.json.contains("\"method\": \"GET\""));
        assertTrue(decoded.json.contains("example.com"));
    }

    @Test
    public void testHttp1ResponseDecoding() {
        String rawResponse = "HTTP/1.1 200 OK\r\n" +
                "Content-Type: application/json\r\n" +
                "Content-Length: 17\r\n\r\n" +
                "{\"status\":\"success\"}";

        byte[] payload = rawResponse.getBytes(StandardCharsets.UTF_8);
        assertTrue(HttpsDecoder.isHttpsOrHttp(payload));

        HttpsDecoder.DecodedHttps decoded = HttpsDecoder.decode(payload);
        assertNotNull(decoded);
        assertEquals(HttpsDecoder.ProtocolType.HTTP_1_1_RESPONSE, decoded.type);
        assertEquals(200, decoded.statusCode);
        assertEquals("OK", decoded.statusMessage);
        assertEquals("application/json", decoded.headers.get("Content-Type"));
        assertEquals("{\"status\":\"success\"}", decoded.body);
    }

    @Test
    public void testHttp2PrefaceDecoding() {
        byte[] preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
        byte[] frame = new byte[]{
                0x00, 0x00, 0x06, // length = 6
                0x04,             // type = 4 (SETTINGS)
                0x00,             // flags = 0
                0x00, 0x00, 0x00, 0x00, // stream ID = 0
                0x00, 0x01, 0x00, 0x00, 0x10, 0x00 // payload
        };

        byte[] combined = new byte[preface.length + frame.length];
        System.arraycopy(preface, 0, combined, 0, preface.length);
        System.arraycopy(frame, 0, combined, preface.length, frame.length);

        assertTrue(HttpsDecoder.isHttpsOrHttp(combined));
        HttpsDecoder.DecodedHttps decoded = HttpsDecoder.decode(combined);
        assertNotNull(decoded);
        assertEquals(HttpsDecoder.ProtocolType.HTTP_2, decoded.type);
        assertEquals("h2", decoded.alpn);
        assertTrue(decoded.json.contains("SETTINGS"));
    }

    @Test
    public void testTlsHandshakeClientHelloDecoding() {
        // Construct a synthetic ClientHello TLS Record
        byte[] sniBytes = "subdomain.domain.org".getBytes(StandardCharsets.US_ASCII);
        int sniLen = sniBytes.length;

        // TLS Record Header: 0x16 0x03 0x03 (TLS 1.2 record), length = 85
        byte[] record = new byte[]{
                0x16, 0x03, 0x03, 0x00, (byte) (65 + sniLen),
                0x01, 0x00, 0x00, (byte) (61 + sniLen), // Handshake ClientHello, length
                0x03, 0x03, // TLS 1.2 client version
                // 32-byte random
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                0x00, // Session ID len = 0
                0x00, 0x04, (byte) 0xC0, 0x2F, (byte) 0xC0, 0x30, // 2 ciphers
                0x01, 0x00, // 1 compression (null)
                0x00, (byte) (9 + sniLen), // Extensions length
                // SNI extension: 0x0000
                0x00, 0x00, 0x00, (byte) (5 + sniLen),
                0x00, (byte) (3 + sniLen), // list length
                0x00, // host name type
                0x00, (byte) sniLen // name length
        };

        byte[] fullPacket = new byte[record.length + sniLen];
        System.arraycopy(record, 0, fullPacket, 0, record.length);
        System.arraycopy(sniBytes, 0, fullPacket, record.length, sniLen);

        assertTrue(HttpsDecoder.isHttpsOrHttp(fullPacket));
        HttpsDecoder.DecodedHttps decoded = HttpsDecoder.decode(fullPacket);
        assertNotNull(decoded);
        assertEquals(HttpsDecoder.ProtocolType.TLS_HANDSHAKE, decoded.type);
        assertEquals("subdomain.domain.org", decoded.sniHost);
        assertEquals("https://subdomain.domain.org", decoded.pathOrUrl);
        assertTrue(decoded.summary.contains("ClientHello"));
    }

    @Test
    public void testNonHttpPayload() {
        byte[] randomJunk = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05};
        assertFalse(HttpsDecoder.isHttpsOrHttp(randomJunk));
        assertEquals(null, HttpsDecoder.decode(randomJunk));
    }
}
