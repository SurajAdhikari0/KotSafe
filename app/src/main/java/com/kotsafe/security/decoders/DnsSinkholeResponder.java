/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.decoders;

import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.nio.ByteBuffer;

/**
 * Active DNS Sinkholing Engine.
 *
 * Synthesizes RFC 1035 compliant binary DNS response packets targeting sinkhole IPs
 * (e.g. 0.0.0.0 or 127.0.0.1) for malicious domains and C2 infrastructure, terminating
 * threat communication before TCP handshakes or TLS negotiations occur.
 */
public class DnsSinkholeResponder {

    public static final String DEFAULT_IPV4_SINKHOLE = "0.0.0.0";
    public static final byte[] DEFAULT_IPV6_SINKHOLE = new byte[16]; // :: (all zeroes)

    /**
     * Synthesizes an RFC 1035 DNS response packet pointing the queried domain to a sinkhole IP.
     *
     * @param queryPacket Raw binary DNS query packet
     * @param sinkholeIp IPv4 string address (defaults to 0.0.0.0 if null or invalid)
     * @param ttl Response TTL in seconds (e.g. 60)
     * @return Binary DNS response packet
     */
    public static byte[] synthesizeResponse(byte[] queryPacket, String sinkholeIp, int ttl) {
        if (queryPacket == null || queryPacket.length < 12) {
            return null;
        }

        try {
            int txId = ((queryPacket[0] & 0xFF) << 8) | (queryPacket[1] & 0xFF);
            int flags = ((queryPacket[2] & 0xFF) << 8) | (queryPacket[3] & 0xFF);
            int qdCount = ((queryPacket[4] & 0xFF) << 8) | (queryPacket[5] & 0xFF);

            if (qdCount <= 0) return null;

            // Find end of Question section
            int pos = 12;
            // Read question QNAME
            while (pos < queryPacket.length) {
                int len = queryPacket[pos] & 0xFF;
                if (len == 0) {
                    pos++; // null terminator
                    break;
                }
                pos += (len + 1);
            }

            if (pos + 4 > queryPacket.length) {
                return null;
            }

            int qType = ((queryPacket[pos] & 0xFF) << 8) | (queryPacket[pos + 1] & 0xFF);
            int qClass = ((queryPacket[pos + 2] & 0xFF) << 8) | (queryPacket[pos + 3] & 0xFF);
            pos += 4;
            int questionSectionEnd = pos;

            ByteArrayOutputStream out = new ByteArrayOutputStream();

            // 1. Transaction ID
            out.write((txId >> 8) & 0xFF);
            out.write(txId & 0xFF);

            // 2. Flags: Response (QR=1), Opcode=0, Authoritative (AA=1), Recursion Desired (from query), Recursion Available (RA=1), RCODE=0 (NoError)
            int respFlags = 0x8180; // Standard query response, NoError, RA=1
            if ((flags & 0x0100) != 0) { // Preserve RD (Recursion Desired)
                respFlags |= 0x0100;
            }
            out.write((respFlags >> 8) & 0xFF);
            out.write(respFlags & 0xFF);

            // 3. QDCOUNT = 1
            out.write(0x00);
            out.write(0x01);

            // 4. ANCOUNT = 1
            out.write(0x00);
            out.write(0x01);

            // 5. NSCOUNT = 0
            out.write(0x00);
            out.write(0x00);

            // 6. ARCOUNT = 0
            out.write(0x00);
            out.write(0x00);

            // 7. Write Question section verbatim (from offset 12 to questionSectionEnd)
            out.write(queryPacket, 12, questionSectionEnd - 12);

            // 8. Write Answer Section
            // Name pointer to question at offset 12: 0xC0 0x0C
            out.write(0xC0);
            out.write(0x0C);

            // Type & Class
            if (qType == DohDecoder.TYPE_AAAA) {
                out.write(0x00);
                out.write(0x1C); // TYPE_AAAA (28)
                out.write((qClass >> 8) & 0xFF);
                out.write(qClass & 0xFF);

                // TTL
                writeTtl(out, ttl);

                // RDLENGTH = 16
                out.write(0x00);
                out.write(0x10);

                // RDATA: 16 zero bytes (::)
                out.write(DEFAULT_IPV6_SINKHOLE);
            } else {
                // Default TYPE_A
                out.write(0x00);
                out.write(0x01); // TYPE_A (1)
                out.write((qClass >> 8) & 0xFF);
                out.write(qClass & 0xFF);

                // TTL
                writeTtl(out, ttl);

                // RDLENGTH = 4
                out.write(0x00);
                out.write(0x04);

                // RDATA: IPv4 address bytes
                byte[] ipBytes = parseIpv4Bytes(sinkholeIp);
                out.write(ipBytes);
            }

            return out.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Synthesizes an NXDOMAIN (RCODE 3 - Name Error) response.
     */
    public static byte[] synthesizeNxDomain(byte[] queryPacket) {
        if (queryPacket == null || queryPacket.length < 12) return null;
        try {
            int txId = ((queryPacket[0] & 0xFF) << 8) | (queryPacket[1] & 0xFF);

            // Find question end
            int pos = 12;
            while (pos < queryPacket.length) {
                int len = queryPacket[pos] & 0xFF;
                if (len == 0) {
                    pos++;
                    break;
                }
                pos += (len + 1);
            }
            if (pos + 4 > queryPacket.length) return null;
            int questionSectionEnd = pos + 4;

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write((txId >> 8) & 0xFF);
            out.write(txId & 0xFF);

            // Flags: QR=1, RA=1, RCODE=3 (NXDOMAIN) -> 0x8183
            out.write(0x81);
            out.write(0x83);

            // Counts: QD=1, AN=0, NS=0, AR=0
            out.write(0x00); out.write(0x01);
            out.write(0x00); out.write(0x00);
            out.write(0x00); out.write(0x00);
            out.write(0x00); out.write(0x00);

            // Question
            out.write(queryPacket, 12, questionSectionEnd - 12);

            return out.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    private static void writeTtl(ByteArrayOutputStream out, int ttl) {
        int safeTtl = ttl > 0 ? ttl : 60;
        out.write((safeTtl >> 24) & 0xFF);
        out.write((safeTtl >> 16) & 0xFF);
        out.write((safeTtl >> 8) & 0xFF);
        out.write(safeTtl & 0xFF);
    }

    private static byte[] parseIpv4Bytes(String ip) {
        if (ip == null || ip.isEmpty()) return new byte[]{0, 0, 0, 0};
        try {
            InetAddress addr = InetAddress.getByName(ip);
            byte[] b = addr.getAddress();
            if (b.length == 4) return b;
        } catch (Exception ignored) {}
        return new byte[]{0, 0, 0, 0};
    }
}
