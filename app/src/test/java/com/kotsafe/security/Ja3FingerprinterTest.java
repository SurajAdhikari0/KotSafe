/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.kotsafe.security.decoders.HttpsDecoder;
import com.kotsafe.security.decoders.Ja3Fingerprinter;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;

public class Ja3FingerprinterTest {

    @Test
    public void testGreaseFilter() {
        assertTrue(Ja3Fingerprinter.isGrease(0x0a0a));
        assertTrue(Ja3Fingerprinter.isGrease(0x1a1a));
        assertTrue(Ja3Fingerprinter.isGrease(0x2a2a));
        assertTrue(Ja3Fingerprinter.isGrease(0xfafa));

        assertFalse(Ja3Fingerprinter.isGrease(0x002f)); // TLS_RSA_WITH_AES_128_CBC_SHA
        assertFalse(Ja3Fingerprinter.isGrease(0xc02f)); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        assertFalse(Ja3Fingerprinter.isGrease(0x0000)); // SNI extension
    }

    @Test
    public void testJa3CalculationAndMd5() {
        // Sample standard handshake components:
        // Version: 771 (0x0303 - TLS 1.2)
        // Ciphers: 49199, 49200 (0xc02f, 0xc030) + GREASE (0x1a1a - should be ignored)
        // Extensions: 0 (SNI), 10 (supported_groups), 11 (ec_point_formats)
        // Curves: 23, 24
        // Point Formats: 0
        Ja3Fingerprinter.Ja3Result result = Ja3Fingerprinter.compute(
                771,
                Arrays.asList(0x1a1a, 49199, 49200),
                Arrays.asList(0, 10, 11),
                Arrays.asList(23, 24),
                Collections.singletonList(0)
        );

        assertNotNull(result);
        assertEquals("771,49199-49200,0-10-11,23-24,0", result.raw);

        // MD5 of "771,49199-49200,0-10-11,23-24,0"
        String expectedMd5 = Ja3Fingerprinter.computeMd5("771,49199-49200,0-10-11,23-24,0");
        assertEquals(expectedMd5, result.hash);
        assertFalse(result.hash.isEmpty());
    }

    @Test
    public void testKnownMaliciousSignatureDetection() {
        // Cobalt Strike default beacon: a0e9f5d64349fb13191bc781f81f42e1
        Ja3Fingerprinter.MaliciousJa3Info csInfo = Ja3Fingerprinter.detectMalicious("a0e9f5d64349fb13191bc781f81f42e1");
        assertNotNull(csInfo);
        assertTrue(csInfo.name.contains("Cobalt Strike"));
        assertEquals("C2", csInfo.category);

        // Metasploit stager: 650b0ee312d46e2746ebf49e49cb79e0
        Ja3Fingerprinter.MaliciousJa3Info msfInfo = Ja3Fingerprinter.detectMalicious("650b0ee312d46e2746ebf49e49cb79e0");
        assertNotNull(msfInfo);
        assertTrue(msfInfo.name.contains("Metasploit"));

        // Clean unknown browser
        assertFalse(Ja3Fingerprinter.compute(771, Collections.singletonList(49199), Collections.singletonList(0), null, null).isSuspicious);
    }

    @Test
    public void testHttpsDecoderExtractsJa3() {
        // Build synthetic ClientHello with SNI and Supported Groups
        byte[] sniBytes = "c2.malicious-domain.com".getBytes(StandardCharsets.US_ASCII);
        int sniLen = sniBytes.length;

        // Extensions:
        // 1. SNI (type 0x0000, ext len = 5 + sniLen)
        // 2. Supported groups (type 0x000a, len = 4, groups: 23 (0x0017))
        // 3. EC point formats (type 0x000b, len = 2, formats: 0 (0x00))
        int extTotalLen = (4 + 5 + sniLen) + (4 + 4) + (4 + 2);

        byte[] record = new byte[]{
                0x16, 0x03, 0x03, 0x00, (byte) (56 + extTotalLen),
                0x01, 0x00, 0x00, (byte) (52 + extTotalLen), // ClientHello
                0x03, 0x03, // TLS 1.2
                // 32-byte random
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
                0x00, // session ID
                0x00, 0x04, (byte) 0xC0, 0x2F, (byte) 0xC0, 0x30, // 2 ciphers: 49199, 49200
                0x01, 0x00, // 1 compression
                0x00, (byte) extTotalLen, // extensions length
                // Ext 1: SNI
                0x00, 0x00, 0x00, (byte) (5 + sniLen),
                0x00, (byte) (3 + sniLen),
                0x00,
                0x00, (byte) sniLen
        };

        byte[] extTail = new byte[]{
                // Ext 2: Supported groups (0x000a)
                0x00, 0x0a, 0x00, 0x04,
                0x00, 0x02, 0x00, 0x17, // group 23 (secp256r1)
                // Ext 3: EC point formats (0x000b)
                0x00, 0x0b, 0x00, 0x02,
                0x01, 0x00 // uncompressed (0)
        };

        byte[] fullPacket = new byte[record.length + sniLen + extTail.length];
        System.arraycopy(record, 0, fullPacket, 0, record.length);
        System.arraycopy(sniBytes, 0, fullPacket, record.length, sniLen);
        System.arraycopy(extTail, 0, fullPacket, record.length + sniLen, extTail.length);

        assertTrue(HttpsDecoder.isHttpsOrHttp(fullPacket));
        HttpsDecoder.DecodedHttps decoded = HttpsDecoder.decode(fullPacket);
        assertNotNull(decoded);
        assertEquals(HttpsDecoder.ProtocolType.TLS_HANDSHAKE, decoded.type);
        assertEquals("c2.malicious-domain.com", decoded.sniHost);

        assertNotNull(decoded.ja3Result);
        assertEquals("771,49199-49200,0-10-11,23,0", decoded.ja3Raw);
        assertFalse(decoded.ja3Hash.isEmpty());
        assertTrue(decoded.json.contains("ja3_hash"));
    }
}
