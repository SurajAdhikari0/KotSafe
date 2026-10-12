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

import com.kotsafe.security.decoders.DohDecoder;
import com.kotsafe.security.decoders.DohDecoder.DohResult;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class DohDecoderTest {

    private byte[] createDnsQuery(int id, String domain, int qtype) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        // Header: ID, Flags (0x0100 = RD), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        dos.writeShort(id);
        dos.writeShort(0x0100);
        dos.writeShort(1);
        dos.writeShort(0);
        dos.writeShort(0);
        dos.writeShort(0);

        // QNAME: labels
        String[] parts = domain.split("\\.");
        for (String part : parts) {
            dos.writeByte(part.length());
            dos.writeBytes(part);
        }
        dos.writeByte(0); // root label

        // QTYPE, QCLASS (1 = IN)
        dos.writeShort(qtype);
        dos.writeShort(1);

        return baos.toByteArray();
    }

    private byte[] createDnsResponse(int id, String domain, int type, byte[] rdata, int ttl) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        // Header: ID, Flags (0x8180 = QR | RD | RA | NOERROR), QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
        dos.writeShort(id);
        dos.writeShort(0x8180);
        dos.writeShort(1);
        dos.writeShort(1);
        dos.writeShort(0);
        dos.writeShort(0);

        // QNAME: labels
        int qnameStart = 12;
        String[] parts = domain.split("\\.");
        for (String part : parts) {
            dos.writeByte(part.length());
            dos.writeBytes(part);
        }
        dos.writeByte(0);

        // QTYPE, QCLASS
        dos.writeShort(type);
        dos.writeShort(1);

        // ANSWER SECTION
        // NAME: Pointer to offset 12 (0xC00C)
        dos.writeShort(0xC000 | qnameStart);
        dos.writeShort(type);
        dos.writeShort(1); // CLASS IN
        dos.writeInt(ttl);
        dos.writeShort(rdata.length);
        dos.write(rdata);

        return baos.toByteArray();
    }

    @Test
    public void testDnsQueryDecode() throws Exception {
        byte[] packet = createDnsQuery(0x1A2B, "example.com", DohDecoder.TYPE_A);
        DohResult res = DohDecoder.decode(packet);

        assertNotNull(res);
        assertEquals(0x1A2B, res.id);
        assertFalse(res.isResponse);
        assertTrue(res.recursionDesired);
        assertEquals("NOERROR", res.rcodeName);
        assertEquals(1, res.questions.size());
        assertEquals("example.com", res.questions.get(0).name);
        assertEquals("A", res.questions.get(0).typeName);
        assertTrue(res.answers.isEmpty());
    }

    @Test
    public void testDnsResponseWithPointerCompression() throws Exception {
        // Answer RDATA: 93.184.216.34 (0x5D, 0xB8, 0xD8, 0x22)
        byte[] ip = new byte[] {(byte) 93, (byte) 184, (byte) 216, 34};
        byte[] packet = createDnsResponse(0x4321, "example.com", DohDecoder.TYPE_A, ip, 300);

        DohResult res = DohDecoder.decode(packet);
        assertNotNull(res);
        assertEquals(0x4321, res.id);
        assertTrue(res.isResponse);
        assertEquals(0, res.rcode);
        assertEquals("NOERROR", res.rcodeName);
        assertEquals(1, res.questions.size());
        assertEquals("example.com", res.questions.get(0).name);

        assertEquals(1, res.answers.size());
        DohDecoder.DnsRecord ans = res.answers.get(0);
        assertEquals("example.com", ans.name);
        assertEquals("A", ans.typeName);
        assertEquals(300, ans.ttl);
        assertEquals("93.184.216.34", ans.data);
    }

    @Test
    public void testDnsBase64UrlDecode() throws Exception {
        byte[] packet = createDnsQuery(0x1122, "dns.google", DohDecoder.TYPE_AAAA);
        String base64Url = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(packet);

        DohResult res = DohDecoder.decodeBase64Url(base64Url);
        assertNotNull(res);
        assertEquals(0x1122, res.id);
        assertFalse(res.isResponse);
        assertEquals(1, res.questions.size());
        assertEquals("dns.google", res.questions.get(0).name);
        assertEquals("AAAA", res.questions.get(0).typeName);
    }

    @Test
    public void testInvalidPacketReturnsNull() {
        assertNull(DohDecoder.decode(null));
        assertNull(DohDecoder.decode(new byte[5])); // smaller than 12-byte header
        assertNull(DohDecoder.decodeBase64Url(""));
        assertNull(DohDecoder.decodeBase64Url(null));
    }
}
