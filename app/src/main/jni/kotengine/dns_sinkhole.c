#define _POSIX_C_SOURCE 200809L
#include "dns_sinkhole.h"
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <stdio.h>

#define UDP_HDR_LEN 8

static inline uint16_t read_be16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint16_t compute_ip_checksum(const void *data, size_t len) {
    const uint16_t *p = data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint32_t csum_add(uint32_t sum, const uint8_t *data, uint32_t len) {
    while (len > 1) { sum += ((uint32_t)data[0] << 8) | data[1]; data += 2; len -= 2; }
    if (len) sum += (uint32_t)data[0] << 8;
    return sum;
}

static uint16_t csum_fold(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return htons((uint16_t)~sum);
}

bool netcap_is_dns_query(uint8_t proto, uint16_t dst_port, const uint8_t *dns_payload, size_t len) {
    if (proto != 17 /* UDP */ || (dst_port != 53 && dst_port != 5353)) return false;
    if (!dns_payload || len < 12) return false;

    uint16_t flags = read_be16(dns_payload + 2);
    bool is_query = (flags & 0x8000) == 0;
    uint16_t qdcount = read_be16(dns_payload + 4);

    return is_query && qdcount > 0;
}

bool netcap_dns_extract_qname(const uint8_t *dns_payload, size_t len, char *out_qname, size_t max_len) {
    if (!dns_payload || len < 12 || !out_qname || max_len == 0) return false;

    size_t offset = 12;
    size_t out_idx = 0;

    while (offset < len) {
        uint8_t label_len = dns_payload[offset++];
        if (label_len == 0) {
            if (out_idx > 0 && out_qname[out_idx - 1] == '.') {
                out_qname[out_idx - 1] = '\0';
            } else {
                out_qname[out_idx] = '\0';
            }
            return (out_idx > 0);
        }

        if ((label_len & 0xC0) == 0xC0) {
            /* Compression not expected in query QNAME, but terminate safely */
            if (out_idx > 0 && out_qname[out_idx - 1] == '.') {
                out_qname[out_idx - 1] = '\0';
            } else {
                out_qname[out_idx] = '\0';
            }
            return (out_idx > 0);
        }

        if (offset + label_len > len) return false;

        for (uint8_t i = 0; i < label_len; i++) {
            if (out_idx + 1 < max_len) {
                out_qname[out_idx++] = (char)tolower(dns_payload[offset + i]);
            }
        }
        offset += label_len;

        if (out_idx + 1 < max_len) {
            out_qname[out_idx++] = '.';
        }
    }

    return false;
}

size_t netcap_dns_synthesize_sinkhole_packet(const uint8_t *query_packet, size_t packet_len,
                                             size_t ip_hdr_len, uint8_t family,
                                             uint8_t *out_pkt, size_t max_out_len) {
    if (!query_packet || packet_len < ip_hdr_len + UDP_HDR_LEN + 12 || !out_pkt || max_out_len < 512) {
        return 0;
    }

    const uint8_t *dns_query = query_packet + ip_hdr_len + UDP_HDR_LEN;
    size_t dns_query_len = packet_len - ip_hdr_len - UDP_HDR_LEN;

    /* Verify QR = 0 (Query) */
    uint16_t query_flags = read_be16(dns_query + 2);
    if ((query_flags & 0x8000) != 0) return 0;

    uint16_t qdcount = read_be16(dns_query + 4);
    if (qdcount == 0) return 0;

    /* Find the end of the first Question */
    size_t pos = 12;
    while (pos < dns_query_len) {
        uint8_t len = dns_query[pos++];
        if (len == 0) break;
        if ((len & 0xC0) == 0xC0) {
            pos++; /* 2-byte pointer */
            break;
        }
        pos += len;
    }

    if (pos + 4 > dns_query_len) return 0;

    uint16_t qtype = read_be16(dns_query + pos);
    /* uint16_t qclass = read_be16(dns_query + pos + 2); */
    pos += 4;
    size_t question_section_len = pos - 12;

    /* Decide Answer Type: A (IPv4) or AAAA (IPv6) */
    bool is_aaaa = (qtype == 28);
    uint16_t ans_type = is_aaaa ? 28 : 1;
    uint16_t rdata_len = is_aaaa ? 16 : 4;
    size_t answer_section_len = 2 /* Name ptr */ + 2 /* Type */ + 2 /* Class */ + 4 /* TTL */ + 2 /* RDLength */ + rdata_len;

    size_t dns_resp_len = 12 + question_section_len + answer_section_len;
    size_t udp_total_len = UDP_HDR_LEN + dns_resp_len;
    size_t total_pkt_len = ip_hdr_len + udp_total_len;

    if (total_pkt_len > max_out_len) return 0;

    memset(out_pkt, 0, total_pkt_len);

    /* 1. IP Header */
    if (family == 4) {
        out_pkt[0] = 0x45; /* Version 4, IHL 5 */
        out_pkt[2] = (uint8_t)(total_pkt_len >> 8);
        out_pkt[3] = (uint8_t)total_pkt_len;
        out_pkt[6] = 0x40; /* DF */
        out_pkt[8] = 64;   /* TTL */
        out_pkt[9] = 17;   /* UDP */
        /* Swap IPs: src = query dst, dst = query src */
        memcpy(out_pkt + 12, query_packet + 16, 4);
        memcpy(out_pkt + 16, query_packet + 12, 4);
        uint16_t ipcsum = compute_ip_checksum(out_pkt, 20);
        memcpy(out_pkt + 10, &ipcsum, 2);
    } else {
        out_pkt[0] = 0x60; /* IPv6 */
        out_pkt[4] = (uint8_t)(udp_total_len >> 8);
        out_pkt[5] = (uint8_t)udp_total_len;
        out_pkt[6] = 17;   /* Next header = UDP */
        out_pkt[7] = 64;   /* Hop limit */
        /* Swap IPv6: src = query dst, dst = query src */
        memcpy(out_pkt + 8, query_packet + 24, 16);
        memcpy(out_pkt + 24, query_packet + 8, 16);
    }

    /* 2. UDP Header */
    uint8_t *udp = out_pkt + ip_hdr_len;
    /* Swap Ports: src_port = query dst_port, dst_port = query src_port */
    memcpy(udp, query_packet + ip_hdr_len + 2, 2);
    memcpy(udp + 2, query_packet + ip_hdr_len, 2);
    udp[4] = (uint8_t)(udp_total_len >> 8);
    udp[5] = (uint8_t)udp_total_len;
    udp[6] = 0;
    udp[7] = 0;

    /* 3. DNS Response Payload */
    uint8_t *dns = udp + UDP_HDR_LEN;

    /* Transaction ID */
    dns[0] = dns_query[0];
    dns[1] = dns_query[1];

    /* Flags: QR=1, AA=1, RA=1, preserve RD */
    uint16_t resp_flags = 0x8180;
    if (query_flags & 0x0100) resp_flags |= 0x0100;
    dns[2] = (uint8_t)(resp_flags >> 8);
    dns[3] = (uint8_t)resp_flags;

    /* QDCOUNT = 1 */
    dns[4] = 0x00; dns[5] = 0x01;
    /* ANCOUNT = 1 */
    dns[6] = 0x00; dns[7] = 0x01;
    /* NSCOUNT = 0, ARCOUNT = 0 */
    dns[8] = 0; dns[9] = 0; dns[10] = 0; dns[11] = 0;

    /* Question verbatim */
    memcpy(dns + 12, dns_query + 12, question_section_len);

    /* Answer Section */
    uint8_t *ans = dns + 12 + question_section_len;
    ans[0] = 0xC0; ans[1] = 0x0C; /* Name pointer to QNAME at offset 12 */
    ans[2] = (uint8_t)(ans_type >> 8);
    ans[3] = (uint8_t)ans_type;
    ans[4] = 0x00; ans[5] = 0x01; /* Class IN */
    ans[6] = 0x00; ans[7] = 0x00; ans[8] = 0x00; ans[9] = 0x3C; /* TTL = 60s */
    ans[10] = (uint8_t)(rdata_len >> 8);
    ans[11] = (uint8_t)rdata_len;
    memset(ans + 12, 0, rdata_len); /* 0.0.0.0 or :: */

    /* 4. UDP Checksum */
    if (family == 6) {
        uint8_t ph[8] = { 0, 0, (uint8_t)(udp_total_len >> 8), (uint8_t)udp_total_len, 0, 0, 0, 17 };
        uint32_t sum = csum_add(0, out_pkt + 8, 32);
        sum = csum_add(sum, ph, 8);
        sum = csum_add(sum, udp, (uint32_t)udp_total_len);
        uint16_t ucsum = csum_fold(sum);
        if (ucsum == 0) ucsum = 0xFFFF;
        memcpy(udp + 6, &ucsum, 2);
    } else {
        /* Optional in IPv4, but compute cleanly */
        uint8_t ph[8] = { 0, 0, (uint8_t)(udp_total_len >> 8), (uint8_t)udp_total_len, 0, 0, 0, 17 };
        uint32_t sum = csum_add(0, out_pkt + 12, 8);
        sum = csum_add(sum, ph, 8);
        sum = csum_add(sum, udp, (uint32_t)udp_total_len);
        uint16_t ucsum = csum_fold(sum);
        if (ucsum == 0) ucsum = 0xFFFF;
        memcpy(udp + 6, &ucsum, 2);
    }

    return total_pkt_len;
}
