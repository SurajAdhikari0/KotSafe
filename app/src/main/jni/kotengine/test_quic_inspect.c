#include "quic_inspect.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

int main(void) {
    printf("--- Testing QUIC & HTTP/3 SNI Inspector ---\n");

    /* 1. Construct a mock Google QUIC CHLO packet */
    uint8_t gquic_pkt[256];
    memset(gquic_pkt, 0, sizeof(gquic_pkt));

    gquic_pkt[0] = 0x0c;
    size_t offset = 9;
    memcpy(gquic_pkt + offset, "CHLO", 4);
    offset += 4;

    uint16_t tag_count = 2;
    memcpy(gquic_pkt + offset, &tag_count, 2);
    offset += 2;
    offset += 2; /* padding */

    const char domain[] = "www.youtube.com";
    uint32_t sni_end = (uint32_t)strlen(domain);
    memcpy(gquic_pkt + offset, "SNI\0", 4);
    memcpy(gquic_pkt + offset + 4, &sni_end, 4);
    offset += 8;

    uint32_t ver_end = sni_end + 4;
    memcpy(gquic_pkt + offset, "VER\0", 4);
    memcpy(gquic_pkt + offset + 4, &ver_end, 4);
    offset += 8;

    memcpy(gquic_pkt + offset, domain, strlen(domain));
    offset += strlen(domain);
    memcpy(gquic_pkt + offset, "Q043", 4);
    offset += 4;

    netcap_quic_info_t qinfo;
    bool res = netcap_quic_inspect(gquic_pkt, offset, &qinfo);
    assert(res == true);
    assert(qinfo.is_gquic == true);
    assert(qinfo.has_sni == true);
    assert(strcmp(qinfo.domain, "www.youtube.com") == 0);
    printf("gQUIC CHLO SNI: OK -> '%s'\n", qinfo.domain);

    /* 2. Test IETF QUIC Long Header Initial with raw ClientHello */
    uint8_t ietf_quic[256];
    memset(ietf_quic, 0, sizeof(ietf_quic));
    ietf_quic[0] = 0xc0; /* Long header Initial */
    ietf_quic[1] = 0x00; ietf_quic[2] = 0x00; ietf_quic[3] = 0x00; ietf_quic[4] = 0x01; /* v1 */

    uint8_t raw_ch[] = {
        0x01,                   /* Handshake Type: ClientHello */
        0x00, 0x00, 0x3c,       /* Handshake length: 60 bytes */
        0x03, 0x03,             /* Version TLS 1.2 */
        /* 32 bytes client random */
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
        0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,
        0x00,                   /* Session ID len 0 */
        0x00, 0x02, 0x13, 0x01, /* Cipher suites length 2, TLS_AES_128_GCM_SHA256 */
        0x01, 0x00,             /* Compression methods len 1, method null (0) */
        0x00, 0x17,             /* Extensions length: 23 bytes */
        /* Extension 0x0000 (Server Name Indication) */
        0x00, 0x00,             /* Ext type 0x0000 */
        0x00, 0x13,             /* Ext length: 19 bytes */
        0x00, 0x11,             /* Server Name list length: 17 bytes */
        0x00,                   /* Server Name Type: host_name (0) */
        0x00, 0x0e,             /* Server Name length: 14 bytes */
        'c','l','o','u','d','f','l','a','r','e','.','c','o','m'
    };

    memcpy(ietf_quic + 10, raw_ch, sizeof(raw_ch));

    memset(&qinfo, 0, sizeof(qinfo));
    res = netcap_quic_inspect(ietf_quic, 10 + sizeof(raw_ch), &qinfo);
    assert(res == true);
    assert(qinfo.has_sni == true);
    assert(strcmp(qinfo.domain, "cloudflare.com") == 0);
    printf("IETF QUIC Initial TLS 1.3 SNI: OK -> '%s'\n", qinfo.domain);

    printf("ALL QUIC INSPECT TESTS PASSED!\n");
    return 0;
}
