/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.kotsafe.security.decoders.DnsSinkholeResponder;
import com.kotsafe.security.decoders.DohDecoder;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class DnsSinkholeResponderTest {

    private byte[] createDnsQuery(int txId, String domain, int qType) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write((txId >> 8) & 0xFF);
        out.write(txId & 0xFF);
        out.write(0x01); // QR=0, RD=1
        out.write(0x00);
        out.write(0x00); out.write(0x01); // QDCOUNT = 1
        out.write(0x00); out.write(0x00); // ANCOUNT = 0
        out.write(0x00); out.write(0x00);
        out.write(0x00); out.write(0x00);

        for (String label : domain.split("\\.")) {
            out.write(label.length());
            out.write(label.getBytes());
        }
        out.write(0x00); // null terminator

        out.write((qType >> 8) & 0xFF);
        out.write(qType & 0xFF);
        out.write(0x00); out.write(0x01); // IN class
        return out.toByteArray();
    }

    @Test
    public void testSynthesizeIpv4SinkholeResponse() throws Exception {
        byte[] query = createDnsQuery(0x5432, "malware-c2.evil.org", DohDecoder.TYPE_A);
        byte[] sinkholeResp = DnsSinkholeResponder.synthesizeResponse(query, "0.0.0.0", 60);

        assertNotNull(sinkholeResp);
        // Verify with DohDecoder that response is valid RFC 1035
        DohDecoder.DohResult decoded = DohDecoder.decode(sinkholeResp);
        assertNotNull(decoded);
        assertTrue(decoded.isResponse);
        assertEquals(0x5432, decoded.id);
        assertEquals("NOERROR", decoded.rcodeName);
        assertEquals(1, decoded.questions.size());
        assertEquals("malware-c2.evil.org", decoded.questions.get(0).name);
        assertEquals(1, decoded.answers.size());

        DohDecoder.DnsRecord ans = decoded.answers.get(0);
        assertEquals("A", ans.typeName);
        assertEquals("0.0.0.0", ans.data);
        assertEquals(60, ans.ttl);
    }

    @Test
    public void testSynthesizeIpv6SinkholeResponse() throws Exception {
        byte[] query = createDnsQuery(0x9876, "botnet-beacon.xyz", DohDecoder.TYPE_AAAA);
        byte[] sinkholeResp = DnsSinkholeResponder.synthesizeResponse(query, null, 120);

        assertNotNull(sinkholeResp);
        DohDecoder.DohResult decoded = DohDecoder.decode(sinkholeResp);
        assertNotNull(decoded);
        assertTrue(decoded.isResponse);
        assertEquals(0x9876, decoded.id);
        assertEquals(1, decoded.answers.size());

        DohDecoder.DnsRecord ans = decoded.answers.get(0);
        assertEquals("AAAA", ans.typeName);
        assertEquals(120, ans.ttl);
    }

    @Test
    public void testSynthesizeNxDomain() throws Exception {
        byte[] query = createDnsQuery(0x1122, "nonexistent-threat.com", DohDecoder.TYPE_A);
        byte[] nxResp = DnsSinkholeResponder.synthesizeNxDomain(query);

        assertNotNull(nxResp);
        DohDecoder.DohResult decoded = DohDecoder.decode(nxResp);
        assertNotNull(decoded);
        assertTrue(decoded.isResponse);
        assertEquals(0x1122, decoded.id);
        assertEquals("NXDOMAIN", decoded.rcodeName);
        assertEquals(0, decoded.answers.size());
    }

    @Test
    public void testDnsTunnelingExfiltrationDetection() {
        // Normal domain
        assertFalse(DohDecoder.isPossibleDnsTunnel("google.com"));
        assertFalse(DohDecoder.isPossibleDnsTunnel("api.github.com"));

        // DNS Tunneling with long high-entropy data exfiltration subdomain label
        String exfilSubdomain = "dGhpcyBpcyBhbiBleGZpbHRyYXRpb24gcGF5bG9hZCBzYW1wbGU.attacker-c2.net";
        assertTrue(DohDecoder.isPossibleDnsTunnel(exfilSubdomain));

        String hexExfilSubdomain = "4a8f1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c.tunnel.evil.com";
        assertTrue(DohDecoder.isPossibleDnsTunnel(hexExfilSubdomain));
    }
}
