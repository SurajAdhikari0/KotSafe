#include "dns_sinkhole.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

int main(void) {
    printf("=== Testing Native RFC 1035 DNS Sinkhole Engine ===\n");

    /*
     * Build sample IPv4 UDP DNS query packet:
     * IP: 10.215.173.1 -> 1.1.1.1
     * UDP: 54321 -> 53
     * DNS: ID 0x4321, Query: ads.trackers.xyz (Type A, Class IN)
     */
    uint8_t query_pkt[20 + 8 + 12 + 18 + 4] = {0};

    /* IP Header (20 bytes) */
    query_pkt[0] = 0x45;
    query_pkt[2] = 0; query_pkt[3] = sizeof(query_pkt);
    query_pkt[9] = 17; /* UDP */
    query_pkt[12] = 10; query_pkt[13] = 215; query_pkt[14] = 173; query_pkt[15] = 1; /* Src */
    query_pkt[16] = 1; query_pkt[17] = 1; query_pkt[18] = 1; query_pkt[19] = 1;       /* Dst */

    /* UDP Header (8 bytes) */
    uint16_t src_p = htons(54321);
    uint16_t dst_p = htons(53);
    uint16_t ulen = htons(sizeof(query_pkt) - 20);
    memcpy(query_pkt + 20, &src_p, 2);
    memcpy(query_pkt + 22, &dst_p, 2);
    memcpy(query_pkt + 24, &ulen, 2);

    /* DNS Query (offset 28) */
    uint8_t *dns = query_pkt + 28;
    dns[0] = 0x43; dns[1] = 0x21; /* Tx ID */
    dns[2] = 0x01; dns[3] = 0x00; /* Flags: Standard query, RD=1 */
    dns[4] = 0x00; dns[5] = 0x01; /* QDCOUNT=1 */

    /* QNAME: \x03ads\x08trackers\x03xyz\x00 */
    size_t qpos = 12;
    dns[qpos++] = 3; memcpy(dns + qpos, "ads", 3); qpos += 3;
    dns[qpos++] = 8; memcpy(dns + qpos, "trackers", 8); qpos += 8;
    dns[qpos++] = 3; memcpy(dns + qpos, "xyz", 3); qpos += 3;
    dns[qpos++] = 0;

    /* QTYPE=1 (A), QCLASS=1 (IN) */
    dns[qpos++] = 0; dns[qpos++] = 1;
    dns[qpos++] = 0; dns[qpos++] = 1;

    /* 1. Test detection */
    bool is_query = netcap_is_dns_query(17, 53, dns, qpos);
    assert(is_query);
    printf("1. netcap_is_dns_query: OK (true)\n");

    /* 2. Test QNAME extraction */
    char qname[256] = {0};
    bool extracted = netcap_dns_extract_qname(dns, qpos, qname, sizeof(qname));
    assert(extracted);
    assert(strcmp(qname, "ads.trackers.xyz") == 0);
    printf("2. netcap_dns_extract_qname: OK (%s)\n", qname);

    /* 3. Synthesize Sinkhole Response */
    uint8_t resp_buf[1024] = {0};
    size_t resp_len = netcap_dns_synthesize_sinkhole_packet(query_pkt, sizeof(query_pkt), 20, 4,
                                                            resp_buf, sizeof(resp_buf));
    assert(resp_len > 0);
    printf("3. Synthesized sinkhole packet length: %zu bytes\n", resp_len);

    /* Verify IP addresses swapped */
    assert(resp_buf[12] == 1 && resp_buf[13] == 1 && resp_buf[14] == 1 && resp_buf[15] == 1);
    assert(resp_buf[16] == 10 && resp_buf[17] == 215 && resp_buf[18] == 173 && resp_buf[19] == 1);

    /* Verify UDP ports swapped */
    uint16_t r_src_p, r_dst_p;
    memcpy(&r_src_p, resp_buf + 20, 2);
    memcpy(&r_dst_p, resp_buf + 22, 2);
    assert(ntohs(r_src_p) == 53);
    assert(ntohs(r_dst_p) == 54321);

    /* Verify DNS Header */
    uint8_t *r_dns = resp_buf + 28;
    assert(r_dns[0] == 0x43 && r_dns[1] == 0x21); /* matching ID */
    assert((r_dns[2] & 0x80) != 0);                /* QR = 1 */
    assert(r_dns[4] == 0 && r_dns[5] == 1);        /* QDCOUNT = 1 */
    assert(r_dns[6] == 0 && r_dns[7] == 1);        /* ANCOUNT = 1 */

    /* Verify Answer section points to 0.0.0.0 */
    /* Answer is after question (12 + qpos - 12 = qpos) */
    uint8_t *ans = r_dns + qpos;
    assert(ans[0] == 0xC0 && ans[1] == 0x0C);      /* Name ptr */
    assert(ans[2] == 0x00 && ans[3] == 0x01);      /* Type A */
    assert(ans[10] == 0x00 && ans[11] == 0x04);    /* RDLENGTH = 4 */
    assert(ans[12] == 0 && ans[13] == 0 && ans[14] == 0 && ans[15] == 0); /* 0.0.0.0 */

    printf("4. DNS Answer verification: OK (0.0.0.0 sinkhole)\n");
    printf("=== ALL DNS SINKHOLE TESTS PASSED! ===\n");
    return 0;
}
